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
        """List user's teams."""
        result = await self._api.get("/api/v1/teams")
        return result.get("teams", [])

    async def get_team(self, slug: str) -> dict:
        """Get team details with members."""
        return await self._api.get(f"/api/v1/teams/{slug}")

    async def create_team(self, name: str) -> dict:
        """Create a new team."""
        return await self._api.post("/api/v1/teams", {"name": name})

    async def invite_member(self, slug: str, email: str, role: str = "member") -> dict:
        """Invite a member to a team."""
        return await self._api.post(
            f"/api/v1/teams/{slug}/members",
            {"email": email, "role": role},
        )

    async def remove_member(self, slug: str, user_id: str) -> dict:
        """Remove a member from a team."""
        return await self._api.delete(f"/api/v1/teams/{slug}/members/{user_id}")

    async def update_role(self, slug: str, user_id: str, role: str) -> dict:
        """Update a team member's role."""
        return await self._api.post(
            f"/api/v1/teams/{slug}/members/{user_id}/role",
            {"role": role},
        )

    async def list_shared_servers(self, slug: str) -> List[dict]:
        """List servers shared with a team."""
        result = await self._api.get(f"/api/v1/teams/{slug}/servers")
        servers = result.get("servers", [])
        # Mark as shared team servers
        for server in servers:
            server["is_shared"] = True
            server["team_slug"] = slug
        return servers

    async def push_server(self, slug: str, server_data: dict) -> dict:
        """Push a local server to a team's shared inventory."""
        return await self._api.post(
            f"/api/v1/teams/{slug}/servers",
            server_data,
        )

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
