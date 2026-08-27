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
# Stale-while-revalidate window for the per-team
# ``GET /api/v1/teams/{slug}/secrets-config`` response. Deliberately
# the same as ``ENTITLEMENT_TTL``: one timer
# rather than two unrelated TTL knobs for state that admins rotate
# at the same human cadence (team-settings UI updates both).
SECRETS_CACHE_TTL = 3600

# Maximum size of a wire-shaped secrets-config payload we'll persist
# to disk. The legitimate payload is ``{provider, config:{project_id,
# token_env_var}, updated_at}`` — well under 1 KB. 16 KB gives plenty
# of slack for future optional fields without permitting a buggy /
# malicious server to dump a 100 MB blob into ``auth.json`` and fill
# the user's disk. Measured as the JSON-encoded size so it bounds
# what actually lands on disk, not the in-memory dict (which Python
# inflates with overhead).
SECRETS_PAYLOAD_MAX_BYTES = 16 * 1024

# TTL for the cached team list (``/api/v1/teams``). Matches the
# entitlement + secrets-config TTL so all three "cheap admin
# metadata" caches share the same staleness window — one mental
# model for operators ("data is at most an hour out of date").
# It is acceptable that newly-accepted team invites take up to an hour to
# appear in ``active_team_slug()`` bootstrap, since the alternative
# (no cache, list_teams per CLI invocation) is wasteful and a user
# in that exact race can run ``servonaut auth refresh`` to skip the
# wait.
TEAMS_CACHE_TTL = 3600


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
    # Secrets-management cache. Persisted as a raw
    # dict so it round-trips through ``json.dump`` without bespoke
    # serialisation; consumers wrap it in
    # :class:`servonaut.config.schema.SecretsConfig` via
    # ``AuthService.cached_secrets_config()``. ``secrets_fetched_at`` is
    # the unix timestamp of the last successful fetch; 0 means "never
    # fetched" and triggers a cold load on first need.
    secrets_config: Dict = field(default_factory=dict)
    secrets_fetched_at: float = 0.0
    # Personal (user-scope) secrets-management cache. Same wire shape and
    # semantics as ``secrets_config`` but sourced from
    # ``GET /api/v1/me/secrets-config`` instead of the per-team route.
    # Kept in a SEPARATE pair of fields so the two caches are fully
    # isolated: a personal-scope 402/403 must never clear the team cache
    # and vice versa (the precedence layer picks the winner —
    # ``AuthService.cached_secrets_config``). ``user_secrets_fetched_at``
    # of 0 means "never fetched".
    user_secrets_config: Dict = field(default_factory=dict)
    user_secrets_fetched_at: float = 0.0
    # Cached list of teams the user belongs to. Populated by
    # :meth:`AuthService.list_teams` on first call; subsequent calls
    # within :data:`TEAMS_CACHE_TTL` skip the network. Stored as a
    # raw list of dicts so it round-trips through ``json.dump``
    # without bespoke serialisation; consumers read the same shape
    # they'd get from a fresh ``/api/v1/teams`` fetch.
    teams_cached: List = field(default_factory=list)
    teams_fetched_at: float = 0.0

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

    async def active_team_slug(self) -> Optional[str]:
        """Return the slug of the team this CLI session operates against.

        Resolution order:

        1. **Cached team_slug** — if the secrets-config response
           body carried ``team_slug`` (additive server change
           coming alongside the post-deploy BLOCKER fix), the
           cache already knows which team it described. Cheapest
           path: no network call, no list_teams round-trip.

        2. **Bootstrap from team list** — first time we ask, or
           whenever the cache is cold, fall back to
           :meth:`list_teams` and pick the team whose role is
           ``owner``. If no owner team, take the first team in
           the response (servers return them in a deterministic
           order). Returns ``None`` if the user is in zero teams.

        The model is intentionally state-less on disk: the cached
        :class:`SecretsConfig` carries the slug implicitly, so a
        future "switch team" command can rebind without editing
        ``config.json``. Membership revocation (user removed from
        their cached team) surfaces as 403/404 on the next fetch,
        which clears the cache, which re-bootstraps from
        :meth:`list_teams` — graceful degrade with no UI
        intervention required.

        Returns:
            Slug string, or ``None`` when the user has no team
            membership or is unauthenticated.
        """
        if not self.is_authenticated:
            return None
        # Cached path — preferred.
        if self._token and isinstance(self._token.secrets_config, dict):
            slug = self._token.secrets_config.get("team_slug")
            if isinstance(slug, str) and slug:
                return slug
        # Cold bootstrap — list teams, pick owner-role first, else first.
        teams = await self.list_teams()
        if not teams:
            return None
        for team in teams:
            if isinstance(team, dict) and team.get("role") == "owner":
                slug = team.get("slug")
                if isinstance(slug, str) and slug:
                    return slug
        # No owner role — fall back to the first team's slug.
        first = teams[0]
        if isinstance(first, dict):
            slug = first.get("slug")
            if isinstance(slug, str) and slug:
                return slug
        return None

    async def list_teams(self, *, force_refresh: bool = False) -> List[dict]:
        """Return the current user's teams as
        ``[{"slug": ..., "name": ..., "role": ...}]``.

        Cached on :class:`AuthToken` with :data:`TEAMS_CACHE_TTL`
        (matches entitlements + secrets-config — one mental model
        for "cheap admin metadata"). Subsequent calls within the TTL
        skip the network round-trip.

        Args:
            force_refresh: Bypass the cache and re-fetch. Used by
                an explicit ``servonaut auth refresh`` command (and
                by the post-team-invite UX nudge, when wired).

        Cache invalidation:
            - Explicit ``force_refresh=True``.
            - Cold start (``teams_fetched_at == 0``).
            - Past the TTL window.
            - On logout (the whole token is dropped).

        Edge case:
            A user accepting a new team invite won't see the new team
            in ``active_team_slug()`` bootstrap until the cache expires.
            Acceptable for the MVP — same staleness as entitlements,
            and the explicit refresh path bypasses it.
        """
        if not self.is_authenticated or not HAS_HTTPX:
            return []

        now = time.time()
        if (
            not force_refresh
            and self._token is not None
            and self._token.teams_fetched_at > 0
            and (now - self._token.teams_fetched_at) < TEAMS_CACHE_TTL
        ):
            # Return a defensive copy so the caller mutating their
            # snapshot can't poison the cache.
            return [dict(t) if isinstance(t, dict) else t
                    for t in self._token.teams_cached]

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{_api_base()}/api/v1/teams",
                    headers={"Authorization": f"Bearer {self._token.access_token}"},
                )
                if response.status_code == 200:
                    data = response.json()
                    teams = data if isinstance(data, list) else data.get("teams", [])
                    # Persist to cache + disk so re-loads across a
                    # restart still see the cached list within the TTL.
                    self._token.teams_cached = list(teams)
                    self._token.teams_fetched_at = now
                    self._save_token()
                    return [dict(t) if isinstance(t, dict) else t for t in teams]
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
            # Secrets management (tier gating: Solo+).
            # LocalProvider available to Solo + Teams; team-shared
            # secrets are Teams-only.
            "secrets_management": True,
            "secrets_team_shared": False,
            # Proactive monitoring (findings) is included on Solo+.
            "proactive_monitoring": True,
        },
        "teams": {
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
            "secrets_management": True,
            "secrets_team_shared": True,
            "proactive_monitoring": True,
        },
    }

    def get_plan_features(self) -> dict:
        """Return features for the current plan.

        Resolution order is plan fallback → legacy nested flags → current flat
        flags → account-specific custom limits. Later values win, while missing
        keys retain the earlier fallback. This also handles hybrid payloads
        during backend migrations.

        Backend payload shapes supported:
        - Nested ``{"features": {...}}`` (legacy)
        - Flat ``{"memory_sync": 1, "memory_envelope_soft_cap": 50000, ...}``
          (current staging) — numeric quotas are ignored, only bool/0/1 keys
          are treated as feature flags.
        - Account-specific boolean overrides under ``{"custom_limits": {...}}``.
          These are applied last so an explicit override wins over plan and
          regular entitlement values.

        Without the merge, a flat backend payload that omits ``config_sync``
        would silently strip it from a Solo user's feature set.
        """
        plan = self._token.plan if self._token else "free"
        merged = dict(self._PLAN_FEATURES.get(plan, {}))
        ents = self._get_cached_entitlements()
        if ents:
            nested_features = ents.get("features")
            if isinstance(nested_features, dict):
                merged.update(
                    self._known_bool_features_from_mapping(nested_features)
                )
            merged.update(self._features_from_top_level(ents))
            custom_limits = ents.get("custom_limits")
            if isinstance(custom_limits, dict):
                merged.update(
                    self._known_bool_features_from_mapping(custom_limits)
                )
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
        # Secrets-management entitlement flags — server may project
        # these in a flat entitlements payload; honour them here so a
        # downgrade (Solo → Free) lands without a CLI release.
        "secrets_management",
        "secrets_team_shared",
        # Proactive monitoring (findings) — strict 0/1 flag; the
        # companion "monitoring_included_instances" int is a quota and
        # deliberately NOT listed here.
        "proactive_monitoring",
    })

    @staticmethod
    def _coerce_bool_feature(value: object) -> Optional[bool]:
        """Coerce a backend boolean or strict integer boolean."""
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        return None

    @classmethod
    def _known_bool_features_from_mapping(cls, values: dict) -> dict:
        """Return allowlisted boolean feature flags from one mapping."""
        out: dict = {}
        for key, value in values.items():
            if key not in cls._KNOWN_BOOL_FEATURES:
                continue
            coerced = cls._coerce_bool_feature(value)
            if coerced is not None:
                out[key] = coerced
        return out

    @classmethod
    def _features_from_top_level(cls, ents: dict) -> dict:
        """Project the known-bool feature flags from a flat entitlements dict.

        Backend payloads mix boolean features with numeric quotas at the top
        level. We only consider keys in :pyattr:`_KNOWN_BOOL_FEATURES` and
        coerce ``True``/``False``/``1``/``0`` into the bool. Unknown keys
        — including new quotas or features the client doesn't know about
        yet — are silently skipped.
        """
        out = cls._known_bool_features_from_mapping(ents)

        # Quota → boolean derivations. The backend prefers to ship a single
        # int quota and let clients derive the boolean feature flag, so any
        # explicit boolean in the payload above wins; otherwise we derive
        # from the quota when present. The derived value still overrides
        # any plan-fallback default, so a payload that sets the quota to 0
        # correctly disables the feature even on plans that default it on.
        if "config_sync" not in out:
            snapshots = ents.get("config_snapshots")
            if isinstance(snapshots, int) and not isinstance(snapshots, bool):
                out["config_sync"] = snapshots > 0
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

    async def poll_for_token(
        self,
        device_code: str,
        interval: int = 5,
        max_wait_seconds: int = 120,
    ) -> bool:
        """Poll until user authorizes or timeout. Returns True on success.

        ``max_wait_seconds`` bounds the total poll budget (default 120 —
        the TUI's historical window). Headless ``servonaut login`` passes
        the device code's ``expires_in`` so users have the full lifetime
        to approve from another device.
        """
        if not HAS_HTTPX:
            raise RuntimeError("httpx not installed")

        import asyncio

        deadline = time.monotonic() + max(max_wait_seconds, interval)
        while time.monotonic() < deadline:
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
        issues a new pair it revokes the one we presented (confirmed
        server-side). Without
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
        # Secrets cache lives inside the deleted token file, so dropping
        # ``_token`` already clears it from memory. Nothing extra to do
        # — but if ``auth.json`` is recreated by a subsequent login, the
        # new ``AuthToken`` starts with the default empty cache thanks
        # to the dataclass defaults (cold cache after re-login).
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
        """Pull one feature using nested → flat → custom-limit precedence.

        Returns ``None`` when the key is absent (so callers can distinguish
        "missing" from "explicitly false"). Mirrors the coercion rules in
        :meth:`get_plan_features`; invalid values are ignored rather than
        overriding an earlier valid value.
        """
        if not ents or not isinstance(ents, dict):
            return None

        resolved = None
        nested = ents.get("features")
        if isinstance(nested, dict) and key in nested:
            value = cls._coerce_bool_feature(nested[key])
            if value is not None:
                resolved = value

        if key in ents:
            value = cls._coerce_bool_feature(ents[key])
            if value is not None:
                resolved = value

        custom_limits = ents.get("custom_limits")
        if isinstance(custom_limits, dict) and key in custom_limits:
            value = cls._coerce_bool_feature(custom_limits[key])
            if value is not None:
                resolved = value

        return resolved

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

    # ------------------------------------------------------------------
    # Secrets-management cache
    #
    # Stale-while-revalidate model:
    #   - Callers always get an immediate answer from the cache via
    #     :meth:`cached_secrets_config` (defaulting to the LocalProvider
    #     config when nothing's been fetched yet).
    #   - :meth:`is_secrets_cache_fresh` tells the refresh path whether
    #     a background refetch is needed; if stale, kick a fetch via
    #     :class:`APIClient` (Step 4 wires that — Step 2 ships the
    #     helpers so the wiring is mechanical).
    #   - :meth:`apply_secrets_config` is the one mutation point —
    #     accepts a raw wire-shaped dict so the api_client path doesn't
    #     have to construct dataclasses just to throw them away.
    # ------------------------------------------------------------------

    def _wire_to_secrets_config(self, raw: Optional[Dict]) -> "SecretsConfig":
        """Parse a raw wire-shaped dict into a :class:`SecretsConfig`.

        Shared by the team + personal accessors so the malformed-payload
        recovery lives in one place. Empty / missing → LocalProvider
        default; a parse error logs and recovers to the same default.
        """
        # Lazy import to avoid a config↔auth cycle (config/schema.py is
        # imported widely by code that pre-dates this module).
        from servonaut.config.schema import SecretsConfig

        if not raw:
            return SecretsConfig.local_default()
        try:
            return SecretsConfig.from_wire(raw)
        except Exception as exc:  # noqa: BLE001 — log and recover
            logger.warning(
                "secrets cache: malformed payload on disk (%s); "
                "falling back to LocalProvider default",
                exc,
            )
            return SecretsConfig.local_default()

    def secrets_config_source(self) -> Optional[str]:
        """Which cache the precedence layer would serve right now.

        - ``"team"`` — a team config is cached (implies team context:
          the team fetch only runs when an active team slug resolves).
        - ``"user"`` — no team config, but a personal config is cached.
        - ``None`` — neither; :meth:`cached_secrets_config` returns the
          always-available LocalProvider default.

        Used by the status pill to distinguish "Bitwarden (team)" from
        "Bitwarden (personal)".
        """
        if self.is_secrets_cache_present():
            return "team"
        if self.is_user_secrets_cache_present():
            return "user"
        return None

    def cached_secrets_config(self) -> "SecretsConfig":
        """Return the precedence-winning cached :class:`SecretsConfig`.

        Precedence (the one real design call for the personal-scope
        feature): a cached **team** config wins when we're in team
        context, else the cached **personal** (user-scope) config, else
        the always-available LocalProvider fallback. Existing callers are
        unchanged — a Solo user with no team simply falls through to the
        personal config (or Local) instead of always Local.

        Always safe to call: returns the LocalProvider fallback when both
        caches are empty (fresh install, anonymous user, server returned
        404). Stale data is returned alongside any other — the freshness
        check is the caller's responsibility via
        :meth:`is_secrets_cache_fresh` / :meth:`is_user_secrets_cache_fresh`.
        """
        source = self.secrets_config_source()
        if source == "team":
            return self._wire_to_secrets_config(self._token.secrets_config)
        if source == "user":
            return self._wire_to_secrets_config(self._token.user_secrets_config)
        from servonaut.config.schema import SecretsConfig

        return SecretsConfig.local_default()

    def cached_user_secrets_config(self) -> "SecretsConfig":
        """Return the personal-scope cached config, ignoring team precedence.

        Symmetric with the team-only view :meth:`cached_secrets_config`
        gave before precedence landed. Handy for status surfaces that
        want to show the personal config regardless of team context.
        """
        raw = self._token.user_secrets_config if self._token else None
        return self._wire_to_secrets_config(raw)

    def is_secrets_cache_fresh(self, now: Optional[float] = None) -> bool:
        """``True`` iff the cached payload is younger than the TTL window.

        ``now`` is injectable so unit tests can pin a wall clock
        without monkeypatching :mod:`time`. Production code always
        leaves it ``None``.
        """
        if not self._token or self._token.secrets_fetched_at <= 0:
            return False
        clock = time.time() if now is None else now
        return (clock - self._token.secrets_fetched_at) < SECRETS_CACHE_TTL

    def is_secrets_cache_present(self) -> bool:
        """``True`` iff we have a server-supplied config on disk.

        Distinguishes "we've never asked the server" (False — caller
        should trigger a cold fetch) from "we have a value, possibly
        stale" (True — caller can return it now and refetch in the
        background). The two cases warrant different UI: a fresh
        install shouldn't block on the network just to render the
        sidebar.
        """
        return bool(
            self._token
            and self._token.secrets_fetched_at > 0
            and self._token.secrets_config
        )

    def apply_secrets_config(self, payload: Dict) -> None:
        """Persist a freshly fetched secrets-config payload.

        ``payload`` is the raw wire-shape dict returned by
        ``GET /api/v1/teams/{slug}/secrets-config``. Stored on the
        :class:`AuthToken` as-is so future schema additions on the
        server don't need a CLI release to land cleanly on disk.

        Sets ``secrets_fetched_at`` to the current wall clock and
        immediately flushes to ``auth.json`` so a crash post-fetch
        doesn't lose the user's team config — a re-fetch is cheap
        but a "session expired" cascade caused by an empty cache is
        much worse UX.

        Defensive caps:

        - Non-dict payloads silently coerce to ``{}`` (matches the
          existing forward-compat philosophy elsewhere in this file
          — we'd rather drop garbage than refuse to load auth.json).
        - JSON-encoded size is capped at
          :data:`SECRETS_PAYLOAD_MAX_BYTES`. A larger payload is
          almost certainly a server bug or worse; refuse to persist
          and log so the operator can investigate. The in-memory
          cache + on-disk file stay untouched so the user's session
          remains functional.
        """
        if not self._token:
            return
        # Defensive copy — callers (api_client, tests) may continue to
        # mutate the dict they handed us; we want a stable snapshot.
        if not isinstance(payload, dict):
            self._token.secrets_config = {}
            self._token.secrets_fetched_at = time.time()
            self._save_token()
            return
        snapshot = dict(payload)
        try:
            encoded_size = len(json.dumps(snapshot).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            logger.warning(
                "apply_secrets_config: payload is not JSON-serialisable "
                "(%s); refusing to persist", exc,
            )
            return
        if encoded_size > SECRETS_PAYLOAD_MAX_BYTES:
            logger.warning(
                "apply_secrets_config: payload size %d bytes exceeds "
                "cap of %d bytes; refusing to persist. The server may "
                "be returning unexpected data — check for a CLI update "
                "or a backend incident.",
                encoded_size, SECRETS_PAYLOAD_MAX_BYTES,
            )
            return
        self._token.secrets_config = snapshot
        self._token.secrets_fetched_at = time.time()
        self._save_token()

    def clear_secrets_cache(self) -> None:
        """Drop the cached secrets config.

        Called on logout (alongside :pyattr:`_refresh_grant_revoked`)
        and from an explicit ``servonaut secrets refresh --clear``
        path so users can recover from a poisoned cache without
        editing JSON by hand.
        """
        if not self._token:
            return
        self._token.secrets_config = {}
        self._token.secrets_fetched_at = 0.0
        self._save_token()

    # ------------------------------------------------------------------
    # Personal (user-scope) secrets-management cache
    #
    # Exact mirror of the team helpers above, backed by the separate
    # ``user_secrets_config`` / ``user_secrets_fetched_at`` fields so the
    # two caches stay isolated (a personal 402/403 clears only THIS cache).
    # ------------------------------------------------------------------

    def is_user_secrets_cache_fresh(self, now: Optional[float] = None) -> bool:
        """``True`` iff the personal payload is younger than the TTL window."""
        if not self._token or self._token.user_secrets_fetched_at <= 0:
            return False
        clock = time.time() if now is None else now
        return (clock - self._token.user_secrets_fetched_at) < SECRETS_CACHE_TTL

    def is_user_secrets_cache_present(self) -> bool:
        """``True`` iff a server-supplied personal config sits on disk."""
        return bool(
            self._token
            and self._token.user_secrets_fetched_at > 0
            and self._token.user_secrets_config
        )

    def apply_user_secrets_config(self, payload: Dict) -> None:
        """Persist a freshly fetched personal secrets-config payload.

        Same defensive caps as :meth:`apply_secrets_config` (non-dict
        coerces to ``{}``, non-serialisable refuses, oversize refuses)
        but writes the ``user_*`` fields.
        """
        if not self._token:
            return
        if not isinstance(payload, dict):
            self._token.user_secrets_config = {}
            self._token.user_secrets_fetched_at = time.time()
            self._save_token()
            return
        snapshot = dict(payload)
        try:
            encoded_size = len(json.dumps(snapshot).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            logger.warning(
                "apply_user_secrets_config: payload is not JSON-serialisable "
                "(%s); refusing to persist", exc,
            )
            return
        if encoded_size > SECRETS_PAYLOAD_MAX_BYTES:
            logger.warning(
                "apply_user_secrets_config: payload size %d bytes exceeds "
                "cap of %d bytes; refusing to persist.",
                encoded_size, SECRETS_PAYLOAD_MAX_BYTES,
            )
            return
        self._token.user_secrets_config = snapshot
        self._token.user_secrets_fetched_at = time.time()
        self._save_token()

    def clear_user_secrets_cache(self) -> None:
        """Drop the cached personal secrets config (isolated from team)."""
        if not self._token:
            return
        self._token.user_secrets_config = {}
        self._token.user_secrets_fetched_at = 0.0
        self._save_token()

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
