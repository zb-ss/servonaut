"""Team management service for shared workspaces."""
from __future__ import annotations

import asyncio
import logging
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
from urllib.parse import quote

from .interfaces import TeamServiceInterface
from servonaut.config.schema import AppConfig
from servonaut.services.bw_ssh_config_service import (
    BITWARDEN_PM_PROVIDER,
    VALID_VERIFY_STATUSES,
)

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)

# The server's team slug shape; a slug is checked before it goes into a URL.
_TEAM_SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

SHARED = "shared"
ALREADY_SHARED = "already_shared"
FAILED = "failed"


@dataclass(frozen=True)
class ShareResult:
    """What sharing one server of a batch did (:meth:`TeamService.push_servers`)."""

    payload: Dict[str, Any]
    status: str  # SHARED, ALREADY_SHARED or FAILED
    server: Optional[Dict[str, Any]] = None  # the team's new record
    error: Optional[str] = None  # why it failed, as plain text
    retry_after: Optional[float] = None  # seconds the service asked to wait


def _retry_after_seconds(exc: Exception) -> Optional[float]:
    """The wait a 429's ``Retry-After`` asks for (seconds or an HTTP date); None when absent."""
    headers = getattr(exc, "response_headers", None) or {}
    value = str(headers.get("retry-after") or "").strip()
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        pass
    else:
        # "inf", "nan" or an overflowing number name no wait that can be honoured.
        return max(0.0, seconds) if math.isfinite(seconds) else None
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _is_rate_limited(exc: Exception) -> bool:
    from servonaut.services.api_client import APIError

    return isinstance(exc, APIError) and exc.status == 429


def _wait_text(seconds: Optional[float]) -> str:
    if seconds is None:
        return "try again later"
    if seconds < 60:
        return f"try again in {max(1, round(seconds))} s"
    return f"try again in {max(1, round(seconds / 60))} min"

# RBAC permissions matrix
ROLE_PERMISSIONS = {
    "owner": {
        "manage_settings", "manage_billing", "invite_members", "change_roles",
        "add_servers", "push_config", "view_servers", "view_audit", "execute_commands",
    },
    "admin": {
        "invite_members", "change_roles", "add_servers", "push_config",
        "view_servers", "view_audit", "execute_commands",
    },
    "member": {
        "add_servers", "push_config", "view_servers", "view_audit", "execute_commands",
    },
    "viewer": {
        "view_servers", "view_audit",
    },
}


class TeamService(TeamServiceInterface):
    """Team CRUD operations via servonaut.dev API."""

    def __init__(self, api_client: 'APIClient', *, config: AppConfig | None = None) -> None:
        self._api = api_client
        self._config = config if config is not None else AppConfig()
        self._server_locks: dict[str, asyncio.Lock] = {}

    async def list_teams(self) -> List[dict]:
        """List user's teams.

        Accepts either a bare array `[...]` or an envelope `{"teams": [...]}`
        to tolerate minor backend contract drift.
        """
        result = await self._api.get("/api/v1/teams")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("teams", [])
        return []

    async def get_team(self, slug: str) -> dict:
        """Get team details with members."""
        return await self._api.get(f"/api/v1/teams/{slug}")

    async def create_team(self, name: str) -> dict:
        """Create a new team."""
        return await self._api.post("/api/v1/teams", json={"name": name})

    async def invite_member(self, slug: str, email: str, role: str = "member") -> dict:
        """Invite a member to a team.

        Returns the created member row. The response includes ``email_sent``
        (bool) — when ``False`` the invitation row was persisted with a valid
        token but the mailer failed; the owner can fall back to the ``accept_url``
        exposed on ``GET /teams/{slug}`` for pending rows.
        """
        return await self._api.post(
            f"/api/v1/teams/{slug}/members",
            json={"email": email, "role": role},
        )

    async def remove_member(self, slug: str, member_id: str) -> dict:
        """Remove a member from a team.

        ``member_id`` is the ``TeamMember`` row id, NOT the user id. The two
        diverge for pending invites where the user has not yet registered.
        """
        return await self._api.delete(f"/api/v1/teams/{slug}/members/{member_id}")

    async def update_role(self, slug: str, member_id: str, role: str) -> dict:
        """Update a team member's role.

        Backend route is ``PUT /api/v1/teams/{slug}/members/{memberId}`` — the
        ``/role`` suffix exists only on the web flow, not the API. ``member_id``
        is the ``TeamMember`` row id.
        """
        return await self._api.put(
            f"/api/v1/teams/{slug}/members/{member_id}",
            json={"role": role},
        )

    async def resend_invite(self, slug: str, member_id: str) -> dict:
        """Resend the invitation email for a pending member row.

        Preserves the existing invitation token and extends
        ``invitation_expires_at`` by 7 days from the resend moment. Returns the
        same shape as :meth:`invite_member` (including ``email_sent``).
        """
        return await self._api.post(
            f"/api/v1/teams/{slug}/members/{member_id}/resend",
            json={},
        )

    async def list_shared_servers(self, slug: str) -> List[dict]:
        """List servers shared with a team.

        Backend wraps the response in ``{"data": [...]}`` per
        ``Api/Team/SharedServerController::list``. Older shapes (bare array or
        ``{"servers": [...]}``) are tolerated for forward/backward compat.
        """
        result = await self._api.get(f"/api/v1/teams/{slug}/servers")
        if isinstance(result, list):
            servers = result
        elif isinstance(result, dict):
            servers = result.get("data") or result.get("servers", [])
        else:
            servers = []
        # Mark as shared team servers
        for server in servers:
            server["is_shared"] = True
            server["team_slug"] = slug
        return servers

    async def push_server(self, slug: str, server_data: dict) -> dict:
        """Share once, rechecking the live inventory even when the UI is stale."""
        from servonaut.services.api_client import APIError
        from servonaut.services.team_sharing import already_shared

        async with self._server_locks.setdefault(slug, asyncio.Lock()):
            servers = await self.list_shared_servers(slug)
            if already_shared(server_data, servers):
                raise APIError(code="already_shared", message="This server is already shared with the team.", status=409)
            result = await self._api.post(f"/api/v1/teams/{slug}/servers", json=server_data)
            return result.get("data", result) if isinstance(result, dict) else {}

    async def push_servers(
        self,
        slug: str,
        servers: Sequence[Mapping[str, Any]],
        *,
        on_progress: Optional[Callable[[int, int, ShareResult], None]] = None,
        max_wait_seconds: float | None = None,
    ) -> List[ShareResult]:
        """Share each of *servers* (share payloads) with team *slug* once; one result each, in order.

        The team's inventory is read once, under the same lock as
        :meth:`push_server`; a server already in it, or earlier in the batch,
        is not sent again. One server's failure does not stop the others. A
        rate limit (429) uses the configured retry count and a total wait
        budget per server, as ``Retry-After`` asks; when it persists, the
        remaining servers are not sent. *on_progress* gets ``(index, total,
        result)`` after each server, from 1.

        Raises:
            APIError: the team's inventory could not be read; nothing is sent.
        """
        from servonaut.services.team_sharing import already_shared

        wait_budget = float(self._config.team_share_rate_limit_wait_seconds if max_wait_seconds is None else max_wait_seconds)
        retries = self._config.team_share_rate_limit_retries
        default_wait = float(self._config.team_share_rate_limit_default_wait_seconds)
        if (
            not math.isfinite(wait_budget) or wait_budget < 0 or type(retries) is not int or retries < 0
            or not math.isfinite(default_wait) or default_wait < 0
        ):
            raise ValueError("Team sharing needs a non-negative finite wait and retry count.")
        payloads = [dict(server) for server in servers]
        results: List[ShareResult] = []
        async with self._server_locks.setdefault(slug, asyncio.Lock()):
            known: List[Mapping[str, Any]] = list(await self.list_shared_servers(slug))
            stopped: Optional[ShareResult] = None
            for index, payload in enumerate(payloads, start=1):
                if stopped is not None:
                    result = ShareResult(payload, FAILED, error=stopped.error, retry_after=stopped.retry_after)
                elif already_shared(payload, known):
                    result = ShareResult(payload, ALREADY_SHARED)
                else:
                    result = await self._share_once(slug, payload, wait_budget, retries, default_wait)
                    if result.status == SHARED:
                        known.append(result.server or {**payload, "instance_id": payload.get("instance_id")})
                    elif result.retry_after is not None or (result.error or "").startswith("rate limited"):
                        stopped = result
                results.append(result)
                if on_progress is not None:
                    on_progress(index, len(payloads), result)
        return results

    async def _share_once(
        self, slug: str, payload: Dict[str, Any], max_wait_seconds: float, retries: int,
        default_wait: float = 0.0,
    ) -> ShareResult:
        """POST one share with a bounded, configured rate-limit retry budget.

        A 429 that names no usable ``Retry-After`` waits *default_wait*, within
        what is left of the budget.
        """
        from servonaut.services.api_client import APIError

        remaining_wait = max_wait_seconds
        for attempt in range(retries + 1):
            try:
                created = await self._api.post(f"/api/v1/teams/{slug}/servers", json=payload)
            except Exception as exc:  # noqa: BLE001 - reported on its row, the batch goes on
                if not _is_rate_limited(exc):
                    reason = exc.message if isinstance(exc, APIError) else type(exc).__name__
                    logger.warning("Sharing a server failed", exc_info=True)
                    return ShareResult(payload, FAILED, error=reason)
                asked = _retry_after_seconds(exc)
                wait = asked if asked is not None else min(default_wait, remaining_wait)
                if attempt == retries or remaining_wait <= 0 or wait > remaining_wait:
                    return ShareResult(payload, FAILED, error=f"rate limited: {_wait_text(asked)}", retry_after=asked)
                await asyncio.sleep(wait)
                remaining_wait -= wait
                continue
            row = created.get("data", created) if isinstance(created, dict) else None
            return ShareResult(payload, SHARED, server=dict(row) if isinstance(row, Mapping) else None)
        raise AssertionError("unreachable")  # pragma: no cover

    async def list_team_configs(self, slug: str) -> List[dict]:
        """List every shared-config version for a team (any team member can read).

        Backend: ``GET /api/v1/teams/{slug}/configs`` →
        ``{"data": [{id, version, config_data, description, pushed_by, created_at}, ...]}``.
        """
        result = await self._api.get(f"/api/v1/teams/{slug}/configs")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data") or result.get("configs", [])
        return []

    async def get_latest_team_config(self, slug: str) -> Optional[dict]:
        """Return the most recent shared-config version, or None if the team has none.

        Backend: ``GET /api/v1/teams/{slug}/configs/latest`` → 200 with payload, OR
        404 ``{"error": "No configuration found"}`` when the team has never pushed one.
        We catch the 404 and return None rather than raising so callers can treat
        "no shared config yet" as a non-error state.
        """
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        try:
            result = await self._api.get(f"/api/v1/teams/{slug}/configs/latest")
        except APIError as exc:
            if exc.status == 404:
                return None
            raise
        if isinstance(result, dict):
            return result.get("data") or result
        return None

    async def push_team_config(
        self, slug: str, config_data: dict, description: Optional[str] = None
    ) -> dict:
        """Push a new shared-config version (admin/owner only).

        Backend rejects callers without ``hasAdminAccess`` with 403, and 400s
        when ``config_data`` is missing or not an object.
        """
        body: dict = {"config_data": config_data}
        if description:
            body["description"] = description
        result = await self._api.post(f"/api/v1/teams/{slug}/configs", json=body)
        # Backend wraps in {"data": ...} — unwrap for callers.
        if isinstance(result, dict) and "data" in result:
            return result["data"]
        return result if isinstance(result, dict) else {}

    async def remove_shared_server(self, slug: str, server_id: str) -> dict:
        """Remove the canonical shared-server record, even when names repeat."""
        if not isinstance(slug, str) or not _TEAM_SLUG_RE.fullmatch(slug):
            raise ValueError("a valid team slug is required")
        if not isinstance(server_id, str) or server_id.strip() in {"", ".", ".."}:
            raise ValueError("a shared server id is required")
        return await self._api.delete(f"/api/v1/teams/{slug}/servers/{quote(server_id, safe='')}")

    async def get_team_policy(self, slug: str) -> dict:
        """Get team MCP policy."""
        result = await self._api.get(f"/api/v1/teams/{slug}/policy")
        return result

    async def get_team_policy_with_date(self, slug: str) -> Tuple[Any, Optional[str]]:
        """The team's policy and the response's ``Date`` header (None if absent).

        The policy carries the team's signed agent rules; the date lets the
        caller judge their expiry by the server's clock (see ``team_policy``).

        Raises:
            ValueError: *slug* is not a team slug; nothing is sent.
        """
        if not isinstance(slug, str) or not _TEAM_SLUG_RE.fullmatch(slug):
            raise ValueError(f"not a team slug: {slug!r}")
        body, headers = await self._api.get_with_headers(f"/api/v1/teams/{slug}/policy")
        return body, headers.get("date")

    # ------------------------------------------------------------------
    # Team-side SSH config (vault wiring, admin/owner only for writes)
    # ------------------------------------------------------------------

    async def get_team_ssh_config(self, slug: str) -> Optional[dict]:
        """GET /teams/{slug}/ssh-config. Returns None on 404.

        Shape on 200::

            {"provider": "bitwarden_pm",
             "config": {"vault_url": "...", "default_collection_id": "..."?},
             "team_slug": "...", "updated_at": "..."}

        404 → team has not configured BW yet — caller should treat as
        "fall back to local ``~/.ssh``".
        """
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        try:
            return await self._api.get(f"/api/v1/teams/{slug}/ssh-config")
        except APIError as exc:
            if exc.status == 404:
                return None
            raise

    async def put_team_ssh_config(
        self,
        slug: str,
        vault_url: str,
        default_collection_id: Optional[str] = None,
        provider: str = BITWARDEN_PM_PROVIDER,
    ) -> dict:
        """PUT /teams/{slug}/ssh-config (admin/owner only — 403 otherwise).

        Caller is responsible for catching 403 (member-not-admin) and surfacing
        an appropriate error message; this method propagates it as ``APIError``.
        """
        config: Dict = {"vault_url": vault_url}
        if default_collection_id:
            config["default_collection_id"] = default_collection_id
        return await self._api.put(
            f"/api/v1/teams/{slug}/ssh-config",
            json={"provider": provider, "config": config},
        )

    # ------------------------------------------------------------------
    # Team-side per-server SSH refs
    # ------------------------------------------------------------------

    async def get_team_server_ssh_ref(self, slug: str, server_id: str) -> Optional[dict]:
        """GET /teams/{slug}/servers/{server_id}/ssh-ref. Returns None on 404."""
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        try:
            return await self._api.get(f"/api/v1/teams/{slug}/servers/{server_id}/ssh-ref")
        except APIError as exc:
            if exc.status == 404:
                return None
            raise

    async def put_team_server_ssh_ref(
        self,
        slug: str,
        server_id: str,
        ssh_credential_ref: dict,
        ssh_credential_provider: str = BITWARDEN_PM_PROVIDER,
    ) -> dict:
        """PUT /teams/{slug}/servers/{server_id}/ssh-ref. Admin/owner only.

        Body field is ``ssh_credential_ref`` (NOT ``ref`` — the deprecated alias
        must never appear in new code even though the server accepts it for one
        release). Caller is responsible for catching 403 (member-not-admin).

        ``ssh_credential_ref`` shape::

            {"item_id": "uuid",
             "collection_id": "uuid"?,
             "vault_url": "https://..."?}
        """
        return await self._api.put(
            f"/api/v1/teams/{slug}/servers/{server_id}/ssh-ref",
            json={
                "ssh_credential_provider": ssh_credential_provider,
                "ssh_credential_ref": ssh_credential_ref,
            },
        )

    async def delete_team_server_ssh_ref(self, slug: str, server_id: str) -> bool:
        """DELETE the SSH ref. Returns True on delete, False on 404."""
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        try:
            result = await self._api.delete(
                f"/api/v1/teams/{slug}/servers/{server_id}/ssh-ref"
            )
        except APIError as exc:
            if exc.status == 404:
                return False
            raise
        return bool(result.get("deleted", True)) if isinstance(result, dict) else True

    async def get_team_server_ssh_verify_status(
        self, slug: str, server_id: str
    ) -> Optional[dict]:
        """GET /teams/{slug}/servers/{server_id}/ssh-verify-status.

        Any team member may read. Returns None when no ref is stored (404).

        Shape on 200::

            {"server_id": "...", "ssh_verify_status": "...",
             "ssh_verified_at": "..."?,  <- NULL unless status == "verified"
             "checked_by_client": "...", "updated_at": "..."}
        """
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        try:
            return await self._api.get(
                f"/api/v1/teams/{slug}/servers/{server_id}/ssh-verify-status"
            )
        except APIError as exc:
            if exc.status == 404:
                return None
            raise

    async def report_team_server_ssh_verify(
        self,
        slug: str,
        server_id: str,
        status: str,
        checked_by_client: Optional[str] = None,
        resolution_tier: Optional[str] = None,
    ) -> dict:
        """POST /teams/{slug}/servers/{server_id}/ssh-verify-report.

        ``status`` must be one of :data:`VALID_VERIFY_STATUSES`
        (``verified``, ``not_found``, ``auth_failed``). Local validation is
        performed BEFORE any round-trip so the caller gets a ``ValueError``
        immediately rather than a remote 422.

        ``checked_by_client`` should be ``"servonaut-cli/<version>"`` so the
        audit row identifies which CLI version ran the probe.
        """
        if status not in VALID_VERIFY_STATUSES:
            allowed = ", ".join(sorted(VALID_VERIFY_STATUSES))
            raise ValueError(f"status must be one of {{{allowed}}}, got {status!r}")
        body: Dict = {"status": status}
        if resolution_tier is not None:
            if resolution_tier not in {"ca", "vault", "personal", "team", "local"}:
                raise ValueError("invalid SSH resolution tier")
            body["resolution_tier"] = resolution_tier
        if checked_by_client:
            body["checked_by_client"] = checked_by_client
        return await self._api.post(
            f"/api/v1/teams/{slug}/servers/{server_id}/ssh-verify-report",
            json=body,
        )

    def check_permission(self, role: str, permission: str) -> bool:
        """Check if a role has a specific permission."""
        perms = ROLE_PERMISSIONS.get(role, set())
        return permission in perms
