"""Tests for TeamService."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.team_service import TeamService, ROLE_PERMISSIONS


def run(coro):
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


@pytest.fixture
def mock_api():
    api = MagicMock()
    api.get = AsyncMock()
    api.post = AsyncMock()
    api.delete = AsyncMock()
    return api


@pytest.fixture
def team_service(mock_api):
    return TeamService(mock_api)


class TestTeamService:
    def test_list_teams(self, team_service, mock_api):
        mock_api.get.return_value = {"teams": [{"name": "Team A", "slug": "team-a"}]}
        teams = run(team_service.list_teams())
        assert len(teams) == 1
        assert teams[0]["name"] == "Team A"
        mock_api.get.assert_called_with("/api/v1/teams")

    def test_get_team(self, team_service, mock_api):
        mock_api.get.return_value = {"name": "Team A", "members": []}
        team = run(team_service.get_team("team-a"))
        assert team["name"] == "Team A"

    def test_create_team(self, team_service, mock_api):
        mock_api.post.return_value = {"name": "New Team", "slug": "new-team"}
        run(team_service.create_team("New Team"))
        mock_api.post.assert_called_with("/api/v1/teams", {"name": "New Team"})

    def test_invite_member(self, team_service, mock_api):
        mock_api.post.return_value = {"success": True}
        run(team_service.invite_member("team-a", "user@example.com", "admin"))
        mock_api.post.assert_called_with(
            "/api/v1/teams/team-a/members",
            {"email": "user@example.com", "role": "admin"},
        )

    def test_remove_member(self, team_service, mock_api):
        mock_api.delete.return_value = {"success": True}
        run(team_service.remove_member("team-a", "user-123"))
        mock_api.delete.assert_called_with("/api/v1/teams/team-a/members/user-123")

    def test_list_shared_servers(self, team_service, mock_api):
        mock_api.get.return_value = {
            "servers": [{"name": "web-1", "host": "10.0.0.1"}]
        }
        servers = run(team_service.list_shared_servers("team-a"))
        assert len(servers) == 1
        assert servers[0]["is_shared"] is True
        assert servers[0]["team_slug"] == "team-a"

    def test_push_server(self, team_service, mock_api):
        mock_api.post.return_value = {"success": True}
        run(team_service.push_server("team-a", {"name": "web-1", "host": "10.0.0.1"}))
        mock_api.post.assert_called_with(
            "/api/v1/teams/team-a/servers",
            {"name": "web-1", "host": "10.0.0.1"},
        )


class TestRBAC:
    def test_owner_has_all_permissions(self, team_service):
        for perm in [
            "manage_settings", "manage_billing", "invite_members",
            "add_servers", "view_servers", "execute_commands",
        ]:
            assert team_service.check_permission("owner", perm)

    def test_viewer_limited_permissions(self, team_service):
        assert team_service.check_permission("viewer", "view_servers")
        assert team_service.check_permission("viewer", "view_audit")
        assert not team_service.check_permission("viewer", "execute_commands")
        assert not team_service.check_permission("viewer", "add_servers")

    def test_member_cannot_manage(self, team_service):
        assert not team_service.check_permission("member", "manage_settings")
        assert not team_service.check_permission("member", "invite_members")
        assert team_service.check_permission("member", "execute_commands")

    def test_unknown_role(self, team_service):
        assert not team_service.check_permission("unknown", "view_servers")
