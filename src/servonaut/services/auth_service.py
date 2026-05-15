"""Authentication service for servonaut.dev API."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict, fields as dataclass_fields
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

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
    # Premium-AI fields (additive — defaulted so v1 tokens load via dataclass
    # defaults; surplus keys on disk are dropped defensively in _load_token to
    # protect against forward-compat skew when a user downgrades their CLI).
    premium_ai_was_active: bool = False  # transition detection (Risk §5)
    allow_dangerous_ai_tools: bool = False  # F4 cache from entitlements
    last_used_provider: str = ""  # T4.5 lapse fallback ranking
    settings_last_visited_at: float = 0.0  # T4.5 paying-twice banner gating

    @property
    def is_expired(self) -> bool:
        """True iff the access_token's local TTL has elapsed.

        Informational only — never use it to decide whether the user is
        "logged in" (the 1-hour access TTL is meant to be healed by the
        refresh token + 401-retry, not surfaced as a logout). See
        :pyattr:`AuthService.is_authenticated`.
        """
        return time.time() >= self.expires_at

    @property
    def is_authenticated(self) -> bool:
        """Have we got credentials to talk to the server?

        Local clock expiry of the access_token is intentionally ignored
        — :class:`AuthService` lets the server be the source of truth
        via the 401-retry-refresh path. As long as a refresh_token is
        on hand, the session is alive until the server says otherwise.
        """
        return bool(self.access_token) and bool(self.refresh_token)


class AuthService(AuthServiceInterface):
    """Manages OAuth2 device flow and token lifecycle."""

    def __init__(self) -> None:
        self._token: Optional[AuthToken] = None
        # asyncio.Lock can only be created inside an event loop; lazy-init
        # in _get_refresh_lock so __init__ stays sync-safe.
        self._refresh_lock: Optional[asyncio.Lock] = None
        # Sticky flag set when the server tells us the refresh_token is
        # revoked/expired (HTTP 400 invalid_grant or 401 on /oauth/refresh).
        # Cleared on a successful login or refresh. Transient failures
        # (429/5xx) MUST NOT set this — they'd nuke the session over a
        # passing blip. See _classify_refresh_failure.
        self._refresh_grant_revoked: bool = False
        self._load_token()

    def _get_refresh_lock(self) -> asyncio.Lock:
        """Return the per-process refresh lock, creating it lazily.

        ``asyncio.Lock()`` binds to the current event loop, so we
        cannot allocate it in ``__init__`` (often called from sync
        code before any loop exists).
        """
        if self._refresh_lock is None:
            self._refresh_lock = asyncio.Lock()
        return self._refresh_lock

    @property
    def is_authenticated(self) -> bool:
        if self._refresh_grant_revoked:
            return False
        return self._token is not None and self._token.is_authenticated

    @property
    def plan(self) -> str:
        if not self.is_authenticated:
            return "free"
        return self._token.plan

    @property
    def access_token(self) -> Optional[str]:
        # Once the server has told us the refresh_token is dead, no point
        # leaking the (also-dead) access_token to API callers — they'd
        # just hit 401 → trigger another refresh attempt → fail again.
        if self._refresh_grant_revoked:
            return None
        if self._token and self._token.access_token:
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
        """Fetch and cache the user_id.

        Tries two sources, since staging's /api/oauth/token doesn't include
        user_id in the response and /api/v1/me 404s on staging:

        1. ``GET /api/v1/me`` (preferred — explicit endpoint, but absent
           on staging at time of writing).
        2. ``GET /api/cli/mercure-token`` — the Mercure JWT's ``subscribe``
           claim is scoped to ``/cli/{user_id}/commands``; the user_id is
           encoded in the topic path. This endpoint is guaranteed to exist
           because the relay listener already depends on it.
        """
        if not self.is_authenticated or not HAS_HTTPX:
            return None
        if self._token and self._token.user_id is not None:
            return self._token.user_id
        headers = {"Authorization": f"Bearer {self._token.access_token}"}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{_api_base()}/api/v1/me", headers=headers,
                )
                if response.status_code == 200:
                    data = response.json()
                    uid = data.get("id") or data.get("user_id")
                    if uid is not None:
                        self._token.user_id = int(uid)
                        self._save_token()
                        return self._token.user_id
                else:
                    logger.info(
                        "fetch_user_id: /api/v1/me returned %s; trying mercure-token fallback",
                        response.status_code,
                    )
                # Fallback: decode user_id from the Mercure JWT topic claim.
                uid = await self._user_id_from_mercure_jwt(client, headers)
                if uid is not None:
                    self._token.user_id = uid
                    self._save_token()
                    return uid
                return None
        except Exception as e:
            logger.warning("fetch_user_id error: %s", e)
            return None

    async def _user_id_from_mercure_jwt(
        self, client: "httpx.AsyncClient", headers: dict
    ) -> Optional[int]:
        """Decode the user_id from /api/cli/mercure-token's JWT subscribe claim.

        The Mercure JWT is scoped to ``/cli/{user_id}/commands`` server-side,
        so the user_id is provable from the token without an extra endpoint.
        """
        try:
            r = await client.get(
                f"{_api_base()}/api/cli/mercure-token", headers=headers,
            )
            if r.status_code != 200:
                logger.warning(
                    "fetch_user_id: mercure-token returned %s", r.status_code
                )
                return None
            token = r.json().get("token")
            if not isinstance(token, str) or token.count(".") != 2:
                logger.warning("fetch_user_id: mercure-token payload invalid")
                return None
            import base64
            import json as _json
            import re
            payload_b64 = token.split(".")[1]
            padding = "=" * (-len(payload_b64) % 4)
            claims = _json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
            for topic in claims.get("mercure", {}).get("subscribe", []):
                m = re.match(r"^/cli/(\d+)/", str(topic))
                if m:
                    return int(m.group(1))
            logger.warning(
                "fetch_user_id: no /cli/{id}/ topic in mercure subscribe claim"
            )
            return None
        except Exception as exc:
            logger.warning("fetch_user_id mercure fallback error: %s", exc)
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

        Resolution: start from the plan→feature fallback, then overlay any
        backend-provided entitlements on top so explicit backend values win
        but missing keys fall back to plan defaults.

        Backend payload shapes supported:
        - Nested ``{"features": {...}}`` (legacy)
        - Flat ``{"memory_sync": 1, "memory_envelope_soft_cap": 50000, ...}``
          (current staging) — numeric quotas are ignored, only bool/0/1 keys
          are treated as feature flags.

        Without the merge, a flat backend payload that omits ``config_sync``
        would silently strip it from a Solo user's feature set.
        """
        plan = self._token.plan if self._token else "free"
        merged = dict(self._PLAN_FEATURES.get(plan, {}))
        ents = self._get_cached_entitlements()
        if ents:
            if isinstance(ents.get("features"), dict):
                merged.update(ents["features"])
            else:
                merged.update(self._features_from_top_level(ents))
        return merged

    # Explicit allowlist of keys the backend exposes as boolean feature flags.
    # Anything outside this set — including 0/1-valued quotas like
    # ``mcp_connections=1`` or ``team_members=0`` — is treated as a quota and
    # is NOT projected into the features dict. Without this allowlist, users
    # saw quotas rendered as "✗ memory_envelope_soft_cap" in the account
    # screen and `has_feature("mcp_connections")` returned True for everyone.
    _KNOWN_BOOL_FEATURES: frozenset = frozenset({
        "config_sync",
        "premium_ai",
        "allow_dangerous_ai_tools",  # F4 — Teams admin custom_limit, gates dangerous AI tools
        "gcp_provider",
        "azure_provider",
        "team_workspaces",
        "memory_sync",
        "memory_drift",
        "memory_digest",
        "memory_team_share",
        "memory_ai_summary",
        "memory_compliance_export",
    })

    @classmethod
    def _features_from_top_level(cls, ents: dict) -> dict:
        """Project the known-bool feature flags from a flat entitlements dict.

        Backend payloads mix boolean features with numeric quotas at the top
        level. We only consider keys in :pyattr:`_KNOWN_BOOL_FEATURES` and
        coerce ``True``/``False``/``1``/``0`` into the bool. Unknown keys
        — including new quotas or features the client doesn't know about
        yet — are silently skipped.
        """
        out: dict = {}
        for key, value in ents.items():
            if key not in cls._KNOWN_BOOL_FEATURES:
                continue
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
                        # Clear the sticky revoked flag — this is a brand new
                        # token pair from a successful device-flow grant.
                        self._refresh_grant_revoked = False
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
        """Exchange the stored refresh_token for a fresh pair.

        Refresh tokens are single-use server-side — the moment the server
        issues a new pair it revokes the one we presented (confirmed by
        servonaut-web-backend on agent-bus thread 0ab60c52). Without
        serialisation, two concurrent 401-retries would both present the
        same ``R_0``: the first succeeds, the second hits a revoked
        token and gets ``400 invalid_grant`` → session killed mid-flight.

        Two guards protect against that:

        1. A per-process :class:`asyncio.Lock` serialises in-flight
           refresh attempts.
        2. Inside the lock we re-read ``auth.json`` and, if its
           refresh_token differs from the one we entered with, adopt
           the on-disk pair without a network round-trip — somebody
           else already rotated for us.

        Returns ``True`` on success (in-memory + on-disk token are
        now the freshly issued pair). Returns ``False`` on any kind
        of failure; check :pyattr:`is_authenticated` afterwards to
        distinguish "session genuinely dead" from "transient hiccup".
        """
        if not self._token or not self._token.refresh_token:
            return False
        if not HAS_HTTPX:
            return False

        attempted_with = self._token.refresh_token
        async with self._get_refresh_lock():
            # Concurrent-rotation dedup: another task may have completed a
            # refresh between this caller's 401 and our acquiring the lock.
            # Detect that by re-reading auth.json; if its refresh_token has
            # already moved on, adopt that pair instead of presenting the
            # stale (now-revoked) one. Re-read is silent (does NOT mutate
            # self._token on parse failures — we'd rather keep the in-memory
            # copy than wipe the user's session over a transient FS hiccup).
            disk_token = self._load_token_from_disk_silent()
            if (
                disk_token is not None
                and disk_token.refresh_token
                and disk_token.refresh_token != attempted_with
            ):
                self._token = disk_token
                self._refresh_grant_revoked = False
                logger.info(
                    "refresh_token: adopted newer token from disk (another "
                    "task rotated while we waited for the lock)"
                )
                return True

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
            except Exception as e:
                # Network-layer failure: connection refused, timeout, etc.
                # Treat as transient — session credentials are still good,
                # the user just can't reach the server right now.
                logger.warning("Token refresh network error: %s", e)
                return False

            if response.status_code == 200:
                data = response.json()
                self._token.access_token = data["access_token"]
                self._token.refresh_token = data.get(
                    "refresh_token", self._token.refresh_token
                )
                self._token.expires_at = time.time() + data.get("expires_in", 3600)
                if data.get("email"):
                    self._token.email = data["email"]
                self._refresh_grant_revoked = False
                self._save_token()
                logger.info("Token refreshed successfully")
                return True

            self._classify_refresh_failure(response)
            return False

    def _classify_refresh_failure(self, response: "httpx.Response") -> None:
        """Decide whether a non-200 refresh response means the session is dead.

        Backend (OAuthController) maps a revoked/expired/unknown refresh
        token to ``400`` with ``error.code == "invalid_grant"``. Anything
        else — ``429`` from the per-IP rate limiter, ``5xx`` from a
        Symfony fault, even a 400 with a different error code — is
        transient and MUST NOT kill the session. Without this
        distinction, a brief blip would log every CLI user out.
        """
        status = response.status_code
        if status in (401, 403):
            # Server explicitly rejected our credentials.
            self._refresh_grant_revoked = True
            logger.warning(
                "Token refresh rejected (%s) — session is no longer valid",
                status,
            )
            return
        if status == 400:
            code = ""
            try:
                err = response.json().get("error", "")
                if isinstance(err, dict):
                    code = err.get("code", "") or ""
                elif isinstance(err, str):
                    code = err
            except Exception:
                code = ""
            if code == "invalid_grant":
                self._refresh_grant_revoked = True
                logger.warning(
                    "Refresh token revoked or expired (invalid_grant) — "
                    "user must re-authenticate"
                )
                return
            logger.warning(
                "Token refresh returned 400 with code=%r — treating as "
                "transient (not clearing session)",
                code,
            )
            return
        # 429 / 5xx / anything else — transient.
        logger.warning(
            "Token refresh transient failure (%s) — keeping current "
            "credentials, will retry on next 401",
            status,
        )

    def _load_token_from_disk_silent(self) -> Optional[AuthToken]:
        """Read ``auth.json`` without mutating in-memory state.

        Used by :meth:`refresh_token` to detect concurrent rotation by
        another task in the same process. Returns ``None`` if the file
        is missing, unreadable, or the payload doesn't satisfy
        :class:`AuthToken`'s field set (after the forward-compat
        unknown-key filter applied in :meth:`_load_token`).
        """
        if not AUTH_FILE.exists():
            return None
        try:
            data = json.loads(AUTH_FILE.read_text())
        except Exception:
            return None
        try:
            return AuthToken(**data)
        except TypeError:
            known = {f.name for f in dataclass_fields(AuthToken)}
            filtered = {k: v for k, v in data.items() if k in known}
            try:
                return AuthToken(**filtered)
            except Exception:
                return None
        except Exception:
            return None

    async def validate_token(self) -> bool:
        """Check if the stored token is still valid server-side.

        Attempts a token refresh. Only deletes the on-disk credentials
        if the server explicitly rejected the refresh_token
        (``_refresh_grant_revoked``) — a transient 429/5xx must not nuke
        the user's session over a passing blip.

        Returns:
            True if token is still valid; False on revoke or transient
            failure. Distinguish via ``self._refresh_grant_revoked`` if
            you need to react differently to the two cases.
        """
        if not self.is_authenticated:
            return False
        if not HAS_HTTPX:
            return True  # Can't check, assume valid

        if await self.refresh_token():
            return True

        if self._refresh_grant_revoked:
            logger.info("Token validation failed (revoked), clearing local auth")
            self._token = None
            if AUTH_FILE.exists():
                try:
                    AUTH_FILE.unlink()
                except OSError as e:
                    logger.warning("Could not delete %s: %s", AUTH_FILE, e)
            return False
        # Transient failure — keep credentials, just report not-validated.
        logger.warning(
            "Token validation could not complete (transient); keeping local auth"
        )
        return False

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
        self._refresh_grant_revoked = False
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()
        logger.info("Logged out")

    async def fetch_entitlements(self) -> Optional[dict]:
        """Fetch entitlements from API and cache them.

        Side effects on a successful fetch:
        - Stores the raw payload in ``_token.entitlements`` (so
          ``has_feature``'s flat-payload normalisation continues to work).
        - Extracts the two AI-specific bool flags (``premium_ai``,
          ``allow_dangerous_ai_tools``) into dedicated dataclass fields for
          O(1) access on hot paths (chat panel, picker re-render).
        - Updates ``premium_ai_was_active`` BEFORE writing the new value, so
          consumers (T4.5 first-run modal / lapse-toast resolver) can detect
          the False→True or True→False transition reliably (Risk §5).
        """
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
                    self._apply_entitlements(ents)
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

    def _apply_entitlements(self, ents: dict) -> None:
        """Apply a freshly fetched entitlements payload to ``_token``.

        Encapsulated so unit tests can exercise the transition-detection logic
        without spinning up the httpx mock dance.

        Notes on transition detection (Risk §5):
        - ``premium_ai_was_active`` is set to the *previous* current value
          BEFORE we overwrite ``allow_dangerous_ai_tools`` /
          ``entitlements``. This way a caller that fetches and immediately
          inspects ``(was_active, current)`` sees the edge.
        - We only update ``was_active`` when the payload contains an
          explicit ``premium_ai`` key. Transient errors that omit the key
          must not produce a phantom transition.
        """
        if not self._token:
            return
        # Resolve the new premium_ai value FIRST (need both nested+flat
        # support so the same code works whether the backend ships the
        # legacy ``{"features": {...}}`` shape or the current flat one).
        new_premium = self._extract_bool_feature(ents, "premium_ai")
        new_dangerous = self._extract_bool_feature(ents, "allow_dangerous_ai_tools")

        # Update the "was active" snapshot using the prior cached state. If
        # the payload didn't actually carry premium_ai we leave the
        # transition snapshot alone (don't manufacture an edge from None).
        if new_premium is not None:
            # Snapshot the old current value, then write the new one.
            prior_premium = bool(
                self._extract_bool_feature(self._token.entitlements, "premium_ai")
                or False
            )
            self._token.premium_ai_was_active = prior_premium
        if new_dangerous is not None:
            self._token.allow_dangerous_ai_tools = bool(new_dangerous)

        # Now persist the raw payload + standard metadata.
        self._token.entitlements = ents
        self._token.entitlements_fetched_at = time.time()
        self._token.plan = ents.get("plan", self._token.plan)
        if ents.get("email"):
            self._token.email = ents["email"]
        if ents.get("user_id") is not None:
            try:
                self._token.user_id = int(ents["user_id"])
            except (TypeError, ValueError):
                pass

    @classmethod
    def _extract_bool_feature(cls, ents: Optional[dict], key: str) -> Optional[bool]:
        """Pull a single bool feature flag from either payload shape.

        Returns ``None`` when the key is absent (so callers can distinguish
        "missing" from "explicitly false"). Mirrors the coercion rules in
        :meth:`_features_from_top_level`.
        """
        if not ents or not isinstance(ents, dict):
            return None
        # Nested shape first.
        nested = ents.get("features")
        if isinstance(nested, dict) and key in nested:
            value = nested[key]
            if isinstance(value, bool):
                return value
            if isinstance(value, int) and value in (0, 1):
                return bool(value)
            return None
        # Flat shape.
        if key in ents:
            value = ents[key]
            if isinstance(value, bool):
                return value
            if isinstance(value, int) and value in (0, 1):
                return bool(value)
        return None

    @property
    def has_dangerous_ai_tools(self) -> bool:
        """Convenience: True iff authed AND admin has enabled dangerous AI tools.

        Mirrors :meth:`has_feature("allow_dangerous_ai_tools")` but reads from
        the dedicated ``AuthToken.allow_dangerous_ai_tools`` cache so chat-panel
        re-renders don't re-walk the merged feature dict on every keystroke.
        """
        return bool(
            self._token
            and self._token.is_authenticated
            and self._token.allow_dangerous_ai_tools
        )

    async def schedule_post_topup_refresh(self) -> None:
        """Schedule two delayed entitlements refreshes after a top-up checkout.

        Stripe → Servonaut webhook latency is typically <30s, but worst-case
        we observe up to 60s in the wild. Two refreshes at +30s and +60s
        ensure ``tokens_topup_remaining`` lands in the chat-panel footer
        within the spec'd window without spamming the API. The plan's
        T8 acceptance criterion ("balance reflected in CLI within 60s")
        is satisfied by the second refresh.

        Implementation note:
            Tasks are created via :func:`asyncio.create_task` and tracked
            in a per-instance set so the GC doesn't drop the reference
            mid-flight (asyncio caveat — orphaned tasks can be cancelled
            by the event loop). Tasks self-discard on completion.

            This variant is for the *long-running TUI* — the +30s/+60s
            tasks die immediately if the calling event loop exits (which
            is what happens in a one-shot CLI invocation). For the CLI,
            use :meth:`await_post_topup_refresh` (B3 fix).
        """
        if not hasattr(self, "_post_topup_tasks"):
            # Lazy-initialised; lives for the lifetime of the AuthService.
            self._post_topup_tasks: Set[asyncio.Task] = set()

        async def _delayed(delay_s: float) -> None:
            try:
                await asyncio.sleep(delay_s)
                await self.fetch_entitlements()
            except Exception as exc:  # noqa: BLE001
                # We never want a missed refresh to crash the app — the
                # next user-initiated entitlement refresh will heal.
                logger.warning(
                    "Post-topup refresh at %.0fs failed: %s", delay_s, exc,
                )
            finally:
                # Self-cleanup so the set doesn't grow unboundedly. Use
                # ``current_task()`` rather than capturing ``task`` in a
                # closure to avoid the create_task/closure ordering quirk.
                current = asyncio.current_task()
                if current is not None:
                    self._post_topup_tasks.discard(current)

        for delay in (30.0, 60.0):
            task = asyncio.create_task(_delayed(delay))
            self._post_topup_tasks.add(task)

    async def await_post_topup_refresh(
        self,
        progress_callback: Optional[Callable[[str], None]] = None,
        *,
        wait_seconds: float = 45.0,
    ) -> None:
        """Inline-block variant of post-topup refresh for the one-shot CLI (B3).

        The TUI path (:meth:`schedule_post_topup_refresh`) creates +30s/+60s
        tasks via :func:`asyncio.create_task`; those tasks die when the
        loop exits, which is exactly what happens in
        ``servonaut ai topup`` after :func:`asyncio.run` returns. To deliver
        the entitlements refresh in a one-shot lifecycle, this method
        sleeps inline (~45s by default — middle of the +30s/+60s window)
        and then awaits :meth:`fetch_entitlements` once.

        Args:
            progress_callback: Optional callable invoked with progress
                strings ("Waiting 45s for Stripe webhook…", "Refreshing
                entitlements…", "Done."). When None we ``logger.info`` the
                same lines so a CLI caller sees them.
            wait_seconds: How long to sleep before refreshing. Default 45s
                threads the needle between the +30s task (typical webhook
                landing time) and the +60s safety net.

        Returns when the refresh completes (success OR failure — failures
        are logged at WARNING level and swallowed so the CLI still exits 0).
        """
        emit = progress_callback or (lambda msg: logger.info(msg))
        emit(
            f"Waiting {int(wait_seconds)}s for Stripe webhook to land "
            "before refreshing entitlements…"
        )
        try:
            await asyncio.sleep(wait_seconds)
            emit("Refreshing entitlements…")
            await self.fetch_entitlements()
            emit("Done.")
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "await_post_topup_refresh failed: %s — run "
                "`servonaut ai quota` later to confirm.", exc,
            )

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
        """Load token from ~/.servonaut/auth.json.

        Defensive against forward-compat skew (Risk §3 in the architect plan):
        a user who downgrades their CLI binary may have surplus keys on disk
        that this version's :class:`AuthToken` dataclass does not recognise.
        Naively constructing ``AuthToken(**data)`` would raise ``TypeError``
        and wipe their session. Instead, on TypeError we filter ``data`` down
        to known fields and try again, logging at INFO level.
        """
        if not AUTH_FILE.exists():
            return
        try:
            data = json.loads(AUTH_FILE.read_text())
        except Exception as e:
            logger.warning("Failed to read auth token file: %s", e)
            self._token = None
            return
        try:
            self._token = AuthToken(**data)
        except TypeError as e:
            # Surplus keys from a newer CLI version — drop unknown keys and
            # retry. We log at INFO (not WARNING) because this is the
            # expected recovery path on a binary downgrade, not a real error.
            known = {f.name for f in dataclass_fields(AuthToken)}
            filtered = {k: v for k, v in data.items() if k in known}
            dropped = sorted(set(data) - known)
            logger.info(
                "auth.json contains unknown keys %s (likely from a newer CLI "
                "version) — dropping and reloading: %s",
                dropped,
                e,
            )
            try:
                self._token = AuthToken(**filtered)
            except Exception as inner:
                logger.warning("Failed to load auth token: %s", inner)
                self._token = None
                return
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
