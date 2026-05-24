"""Team management service for shared workspaces."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, TYPE_CHECKING

from .interfaces import TeamServiceInterface

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)

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

    def __init__(self, api_client: 'APIClient') -> None:
        self._api = api_client

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
        """Push a local server to a team's shared inventory."""
        return await self._api.post(
            f"/api/v1/teams/{slug}/servers",
            json=server_data,
        )

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

    async def remove_shared_server(self, slug: str, server_name: str) -> dict:
        """Remove a shared server from team inventory."""
        return await self._api.delete(f"/api/v1/teams/{slug}/servers/{server_name}")

    async def get_team_policy(self, slug: str) -> dict:
        """Get team MCP policy."""
        result = await self._api.get(f"/api/v1/teams/{slug}/policy")
        return result

    def check_permission(self, role: str, permission: str) -> bool:
        """Check if a role has a specific permission."""
        perms = ROLE_PERMISSIONS.get(role, set())
        return permission in perms
