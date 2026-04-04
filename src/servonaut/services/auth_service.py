"""Authentication service for servonaut.dev API."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict

from .interfaces import AuthServiceInterface

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    HAS_HTTPX = False

AUTH_FILE = Path.home() / '.servonaut' / 'auth.json'
API_BASE = "https://api.servonaut.dev"
CLIENT_ID = "servonaut-cli"
ENTITLEMENT_TTL = 3600  # 1 hour cache


@dataclass
class AuthToken:
    """Stored authentication token."""
    access_token: str
    refresh_token: str
    expires_at: float  # unix timestamp
    plan: str = "free"
    entitlements: Dict = field(default_factory=dict)
    entitlements_fetched_at: float = 0

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    @property
    def is_authenticated(self) -> bool:
        return bool(self.access_token) and not self.is_expired


class AuthService(AuthServiceInterface):
    """Manages OAuth2 device flow and token lifecycle."""

    def __init__(self) -> None:
        self._token: Optional[AuthToken] = None
        self._load_token()

    @property
    def is_authenticated(self) -> bool:
        return self._token is not None and self._token.is_authenticated

    @property
    def plan(self) -> str:
        if not self.is_authenticated:
            return "free"
        return self._token.plan

    @property
    def access_token(self) -> Optional[str]:
        if self._token and self._token.is_authenticated:
            return self._token.access_token
        return None

    def has_feature(self, feature: str) -> bool:
        """Check if user has access to a specific feature."""
        if not self.is_authenticated:
            return False
        ents = self._get_cached_entitlements()
        if ents is None:
            return False
        # Map plan names to feature availability
        plan = ents.get("plan", "free")
        features = ents.get("features", {})
        return features.get(feature, False)

    async def start_device_flow(self) -> dict:
        """Initiate device flow. Returns user_code, verification_uri, etc."""
        if not HAS_HTTPX:
            raise RuntimeError(
                "httpx not installed. Install with: pip install 'servonaut[pro]'"
            )
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{API_BASE}/api/oauth/device",
                json={"client_id": CLIENT_ID},
            )
            if response.status_code >= 400:
                raise RuntimeError(
                    f"Device flow initiation failed ({response.status_code}): "
                    f"{response.text}"
                )
            return response.json()

    async def poll_for_token(self, device_code: str, interval: int = 5) -> bool:
        """Poll until user authorizes or timeout. Returns True on success."""
        if not HAS_HTTPX:
            raise RuntimeError("httpx not installed")

        import asyncio

        max_attempts = 120 // interval  # 2 minute timeout
        for _ in range(max_attempts):
            await asyncio.sleep(interval)
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    response = await client.post(
                        f"{API_BASE}/api/oauth/token",
                        json={
                            "client_id": CLIENT_ID,
                            "device_code": device_code,
                            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        },
                    )
                    if response.status_code == 200:
                        data = response.json()
                        self._token = AuthToken(
                            access_token=data["access_token"],
                            refresh_token=data["refresh_token"],
                            expires_at=time.time() + data.get("expires_in", 3600),
                            plan=data.get("plan", "free"),
                        )
                        self._save_token()
                        # Fetch entitlements immediately after login
                        await self.fetch_entitlements()
                        logger.info("Authentication successful, plan: %s", self._token.plan)
                        return True
                    elif response.status_code == 428:
                        # authorization_pending — keep polling
                        continue
                    elif response.status_code == 410:
                        # expired
                        logger.warning("Device code expired")
                        return False
                    elif response.status_code == 429:
                        # slow_down — increase interval
                        interval += 2
                        continue
                    else:
                        logger.error("Token poll error: %s %s", response.status_code, response.text)
                        return False
            except httpx.HTTPError as e:
                logger.warning("Network error during token poll: %s", e)
                continue

        logger.warning("Token poll timed out")
        return False

    async def refresh_token(self) -> bool:
        """Use refresh_token to get new access_token. Returns True on success."""
        if not self._token or not self._token.refresh_token:
            return False
        if not HAS_HTTPX:
            return False

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{API_BASE}/api/oauth/refresh",
                    json={
                        "client_id": CLIENT_ID,
                        "refresh_token": self._token.refresh_token,
                        "grant_type": "refresh_token",
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    self._token.access_token = data["access_token"]
                    self._token.refresh_token = data.get(
                        "refresh_token", self._token.refresh_token
                    )
                    self._token.expires_at = time.time() + data.get("expires_in", 3600)
                    self._save_token()
                    logger.info("Token refreshed successfully")
                    return True
                else:
                    logger.error("Token refresh failed: %s", response.status_code)
                    return False
        except Exception as e:
            logger.error("Token refresh error: %s", e)
            return False

    async def logout(self) -> None:
        """Revoke tokens and clear local auth."""
        if self._token and HAS_HTTPX:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    await client.post(
                        f"{API_BASE}/api/oauth/revoke",
                        json={
                            "client_id": CLIENT_ID,
                            "token": self._token.access_token,
                        },
                    )
            except Exception as e:
                logger.warning("Token revocation failed (continuing logout): %s", e)

        self._token = None
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()
        logger.info("Logged out")

    async def fetch_entitlements(self) -> Optional[dict]:
        """Fetch entitlements from API and cache them."""
        if not self.is_authenticated or not HAS_HTTPX:
            return None
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{API_BASE}/api/entitlements",
                    headers={"Authorization": f"Bearer {self._token.access_token}"},
                )
                if response.status_code == 200:
                    ents = response.json()
                    self._token.entitlements = ents
                    self._token.entitlements_fetched_at = time.time()
                    self._token.plan = ents.get("plan", self._token.plan)
                    self._save_token()
                    return ents
                elif response.status_code == 401:
                    # Try refresh
                    if await self.refresh_token():
                        return await self.fetch_entitlements()
                    return None
                else:
                    logger.warning("Entitlements fetch failed: %s", response.status_code)
                    return None
        except Exception as e:
            logger.warning("Entitlements fetch error: %s", e)
            return None

    def get_status(self) -> dict:
        """Get current auth status for CLI display."""
        if not self.is_authenticated:
            return {"authenticated": False, "plan": "free"}
        return {
            "authenticated": True,
            "plan": self._token.plan,
            "entitlements": self._token.entitlements,
        }

    def _get_cached_entitlements(self) -> Optional[dict]:
        """Return cached entitlements, None if stale and no cache."""
        if not self._token:
            return None
        if not self._token.entitlements:
            return None
        # Entitlements valid even if stale (graceful degradation)
        return self._token.entitlements

    def _load_token(self) -> None:
        """Load token from ~/.servonaut/auth.json."""
        if not AUTH_FILE.exists():
            return
        try:
            data = json.loads(AUTH_FILE.read_text())
            self._token = AuthToken(**data)
        except Exception as e:
            logger.warning("Failed to load auth token: %s", e)
            self._token = None

    def _save_token(self) -> None:
        """Persist token to ~/.servonaut/auth.json."""
        if not self._token:
            return
        try:
            AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
            AUTH_FILE.write_text(json.dumps(asdict(self._token), indent=2))
        except Exception as e:
            logger.error("Failed to save auth token: %s", e)
