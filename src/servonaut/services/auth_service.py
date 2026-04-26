"""Authentication service for servonaut.dev API."""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict

from .interfaces import AuthServiceInterface

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    HAS_HTTPX = False

AUTH_FILE = Path.home() / '.servonaut' / 'auth.json'
_DEFAULT_API_BASE = "https://api.servonaut.dev"
CLIENT_ID = "servonaut-cli"


def _api_base() -> str:
    """Read API base URL at call time so secrets loaded after import are picked up."""
    return os.environ.get("SERVONAUT_API_URL", _DEFAULT_API_BASE)
ENTITLEMENT_TTL = 3600  # 1 hour cache


@dataclass
class AuthToken:
    """Stored authentication token."""
    access_token: str
    refresh_token: str
    expires_at: float  # unix timestamp
    plan: str = "free"
    email: str = ""
    entitlements: Dict = field(default_factory=dict)
    entitlements_fetched_at: float = 0
    user_id: Optional[int] = None

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

    @property
    def user_id(self) -> Optional[int]:
        """Return the authenticated user's numeric ID, or None if not logged in.

        Used by memory crypto to populate recipient_user_id in DEK wraps.
        Populated from the entitlements payload on first login; falls back to
        a /api/v1/me round-trip if the cached token pre-dates this field.
        """
        if not self.is_authenticated:
            return None
        if self._token and self._token.user_id is not None:
            return self._token.user_id
        return None

    async def fetch_user_id(self) -> Optional[int]:
        """Fetch and cache the user_id from /api/v1/me.

        Called lazily when user_id is None after login.  Callers that need a
        guaranteed non-None value should await this and check the result.
        """
        if not self.is_authenticated or not HAS_HTTPX:
            return None
        if self._token and self._token.user_id is not None:
            return self._token.user_id
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{_api_base()}/api/v1/me",
                    headers={"Authorization": f"Bearer {self._token.access_token}"},
                )
                if response.status_code == 200:
                    data = response.json()
                    uid = data.get("id") or data.get("user_id")
                    if uid is not None:
                        self._token.user_id = int(uid)
                        self._save_token()
                    return self._token.user_id
                logger.warning("fetch_user_id: unexpected status %s", response.status_code)
                return None
        except Exception as e:
            logger.warning("fetch_user_id error: %s", e)
            return None

    async def list_teams(self) -> List[dict]:
        """Return the current user's teams as [{"slug": ..., "name": ..., "role": ...}].

        Delegates to GET /api/v1/teams.  Used by ShareInstanceModal to discover
        team slugs for memory grant operations.  Prefers TeamService when
        available; this implementation is for contexts where only AuthService is
        injected (MCP headless, CLI).
        """
        if not self.is_authenticated or not HAS_HTTPX:
            return []
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{_api_base()}/api/v1/teams",
                    headers={"Authorization": f"Bearer {self._token.access_token}"},
                )
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list):
                        return data
                    return data.get("teams", [])
                logger.warning("list_teams: unexpected status %s", response.status_code)
                return []
        except Exception as e:
            logger.warning("list_teams error: %s", e)
            return []

    # Plan → feature mapping (fallback when /api/entitlements is unavailable)
    _PLAN_FEATURES: dict = {
        "solo": {
            "config_sync": True,
            "premium_ai": True,
            "gcp_provider": False,
            "azure_provider": False,
            "team_workspaces": False,
            "memory_sync": True,
            "memory_drift": True,
            "memory_digest": True,
            "memory_team_share": False,
            "memory_ai_summary": False,
            "memory_compliance_export": False,
        },
        "team": {
            "config_sync": True,
            "premium_ai": True,
            "gcp_provider": True,
            "azure_provider": True,
            "team_workspaces": True,
            "memory_sync": True,
            "memory_drift": True,
            "memory_digest": True,
            "memory_team_share": True,
            "memory_ai_summary": True,
            "memory_compliance_export": True,
        },
    }

    def get_plan_features(self) -> dict:
        """Return features for the current plan.

        Resolution order:
        1. Cached entitlements ``["features"]`` sub-dict (legacy nested shape).
        2. Cached entitlements with feature keys at the top level (current
           staging shape — e.g. ``{"memory_sync": 1, "memory_drift": 1, ...}``).
           Numeric quotas are ignored; only known boolean-style features are
           returned. Truthy ints (>0) and ``True`` both count as enabled.
        3. Plan→feature mapping fallback (offline / never fetched).
        """
        ents = self._get_cached_entitlements()
        if ents and isinstance(ents.get("features"), dict):
            return ents["features"]
        if ents:
            top_level = self._features_from_top_level(ents)
            if top_level:
                return top_level
        plan = self._token.plan if self._token else "free"
        return dict(self._PLAN_FEATURES.get(plan, {}))

    @staticmethod
    def _features_from_top_level(ents: dict) -> dict:
        """Project boolean-style entitlement keys from a flat entitlements dict.

        Staging returns ``{"memory_sync": 1, "memory_envelope_soft_cap": 50000, ...}``
        — boolean features and numeric quotas mixed at the top level. We only
        treat keys whose value is a bool or in {0, 1} as features so a quota
        like ``memory_envelope_soft_cap=50000`` doesn't accidentally satisfy
        ``has_feature("memory_envelope_soft_cap")``.
        """
        out: dict = {}
        for key, value in ents.items():
            if isinstance(value, bool):
                out[key] = value
            elif isinstance(value, int) and value in (0, 1):
                out[key] = bool(value)
        return out

    def has_feature(self, feature: str) -> bool:
        """Check if user has access to a specific feature."""
        if not self.is_authenticated:
            return False
        return bool(self.get_plan_features().get(feature, False))

    async def start_device_flow(self) -> dict:
        """Initiate device flow. Returns user_code, verification_uri, etc."""
        if not HAS_HTTPX:
            raise RuntimeError(
                "httpx not installed. Install with: pip install 'servonaut[pro]'"
            )
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{_api_base()}/api/oauth/device",
                json={"client_id": CLIENT_ID},
            )
            if response.status_code >= 400:
                # Try to extract a meaningful error; avoid dumping raw HTML
                detail = ""
                try:
                    body = response.json()
                    err = body.get("error", "")
                    if isinstance(err, dict):
                        detail = err.get("message", "")
                    elif isinstance(err, str) and err:
                        detail = err
                    if not detail:
                        detail = body.get("message", "")
                except Exception:
                    pass
                if not detail:
                    detail = f"HTTP {response.status_code}"
                raise RuntimeError(
                    f"Device flow initiation failed: {detail}"
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
                        f"{_api_base()}/api/oauth/token",
                        json={
                            "client_id": CLIENT_ID,
                            "device_code": device_code,
                            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        },
                    )
                    if response.status_code == 200:
                        data = response.json()
                        uid = data.get("user_id")
                        self._token = AuthToken(
                            access_token=data["access_token"],
                            refresh_token=data["refresh_token"],
                            expires_at=time.time() + data.get("expires_in", 3600),
                            plan=data.get("plan", "free"),
                            email=data.get("email", ""),
                            user_id=int(uid) if uid is not None else None,
                        )
                        self._save_token()
                        # Fetch entitlements immediately after login
                        await self.fetch_entitlements()
                        logger.info("Authentication successful, plan: %s", self._token.plan)
                        return True
                    elif response.status_code == 410:
                        # expired
                        logger.warning("Device code expired")
                        return False
                    elif response.status_code == 429:
                        # slow_down — increase interval
                        interval += 2
                        continue
                    else:
                        # RFC 8628: authorization_pending and slow_down
                        # are returned as HTTP 400 with error in body
                        try:
                            err = response.json().get("error", "")
                        except Exception:
                            err = ""
                        if err == "authorization_pending":
                            continue
                        elif err == "slow_down":
                            interval += 2
                            continue
                        else:
                            logger.error("Token poll error: %s (error=%s)", response.status_code, err)
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
                    f"{_api_base()}/api/oauth/refresh",
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
                    if data.get("email"):
                        self._token.email = data["email"]
                    self._save_token()
                    logger.info("Token refreshed successfully")
                    return True
                else:
                    logger.error("Token refresh failed: %s", response.status_code)
                    return False
        except Exception as e:
            logger.error("Token refresh error: %s", e)
            return False

    async def validate_token(self) -> bool:
        """Check if the stored token is still valid server-side.

        Attempts a token refresh. If the server rejects it (revoked session),
        clears local auth state.

        Returns:
            True if token is still valid, False if revoked or invalid.
        """
        if not self.is_authenticated:
            return False
        if not HAS_HTTPX:
            return True  # Can't check, assume valid

        refreshed = await self.refresh_token()
        if not refreshed:
            # Server rejected — session was revoked
            logger.info("Token validation failed, clearing local auth")
            self._token = None
            if AUTH_FILE.exists():
                AUTH_FILE.unlink()
            return False
        return True

    async def logout(self) -> None:
        """Revoke tokens and clear local auth."""
        if self._token and HAS_HTTPX:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    await client.post(
                        f"{_api_base()}/api/oauth/revoke",
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
                    f"{_api_base()}/api/entitlements",
                    headers={"Authorization": f"Bearer {self._token.access_token}"},
                )
                if response.status_code == 200:
                    ents = response.json()
                    self._token.entitlements = ents
                    self._token.entitlements_fetched_at = time.time()
                    self._token.plan = ents.get("plan", self._token.plan)
                    if ents.get("email"):
                        self._token.email = ents["email"]
                    if ents.get("user_id") is not None:
                        self._token.user_id = int(ents["user_id"])
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
            return
        self._ensure_secure_mode()

    @staticmethod
    def _ensure_secure_mode() -> None:
        """Re-chmod auth.json to 0600 if a prior version left it world-readable.

        Why: auth.json contains OAuth access + refresh tokens. Users upgrading
        from versions that wrote the file with umask defaults have mode 0644 on
        disk; fix silently on first load.
        """
        try:
            mode = AUTH_FILE.stat().st_mode & 0o777
        except OSError:
            return
        if mode != 0o600:
            try:
                os.chmod(AUTH_FILE, 0o600)
                logger.info(
                    "Tightened permissions on %s (%o → 0600)", AUTH_FILE, mode
                )
            except OSError as e:
                logger.warning("Could not chmod %s: %s", AUTH_FILE, e)

    def _save_token(self) -> None:
        """Persist token to ~/.servonaut/auth.json via atomic 0600 write."""
        if not self._token:
            return
        try:
            AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = AUTH_FILE.with_suffix(AUTH_FILE.suffix + ".tmp")
            # Open with O_CREAT|O_TRUNC|O_WRONLY + explicit 0600 so we never
            # materialise a world-readable copy between open() and chmod().
            fd = os.open(
                tmp_path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(asdict(self._token), f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
                raise
            # Belt-and-suspenders in case umask masked bits off the open() mode.
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, AUTH_FILE)
        except Exception as e:
            logger.error("Failed to save auth token: %s", e)
