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
    api.put = AsyncMock()
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
        mock_api.post.assert_called_with("/api/v1/teams", json={"name": "New Team"})

    def test_invite_member(self, team_service, mock_api):
        mock_api.post.return_value = {"success": True}
        run(team_service.invite_member("team-a", "user@example.com", "admin"))
        mock_api.post.assert_called_with(
            "/api/v1/teams/team-a/members",
            json={"email": "user@example.com", "role": "admin"},
        )

    def test_remove_member(self, team_service, mock_api):
        mock_api.delete.return_value = {"success": True}
        run(team_service.remove_member("team-a", "member-uuid-123"))
        mock_api.delete.assert_called_with("/api/v1/teams/team-a/members/member-uuid-123")

    def test_update_role_uses_put_without_role_suffix(self, team_service, mock_api):
        # Regression for the route mismatch: backend route is
        # PUT /api/v1/teams/{slug}/members/{memberId} — the /role suffix
        # exists only on the web flow and the original CLI code hit it via POST.
        mock_api.put.return_value = {"success": True}
        run(team_service.update_role("team-a", "member-uuid-123", "admin"))
        mock_api.put.assert_called_with(
            "/api/v1/teams/team-a/members/member-uuid-123",
            json={"role": "admin"},
        )
        mock_api.post.assert_not_called()

    def test_list_team_configs_unwraps_data_envelope(self, team_service, mock_api):
        mock_api.get.return_value = {"data": [
            {"id": "c1", "version": 2, "config_data": {}, "description": "v2", "pushed_by": 9, "created_at": "2026-05-24T00:00:00+00:00"},
            {"id": "c2", "version": 1, "config_data": {}, "description": "v1", "pushed_by": 9, "created_at": "2026-05-23T00:00:00+00:00"},
        ]}
        configs = run(team_service.list_team_configs("team-a"))
        assert [c["version"] for c in configs] == [2, 1]
        mock_api.get.assert_called_with("/api/v1/teams/team-a/configs")

    def test_list_team_configs_handles_bare_array_legacy_shape(self, team_service, mock_api):
        mock_api.get.return_value = [{"id": "c1", "version": 1}]
        configs = run(team_service.list_team_configs("team-a"))
        assert len(configs) == 1

    def test_get_latest_team_config_unwraps_data(self, team_service, mock_api):
        mock_api.get.return_value = {"data": {"id": "c1", "version": 3, "config_data": {"connection_profiles": []}}}
        latest = run(team_service.get_latest_team_config("team-a"))
        assert latest["version"] == 3
        mock_api.get.assert_called_with("/api/v1/teams/team-a/configs/latest")

    def test_get_latest_team_config_returns_none_on_404(self, team_service, mock_api):
        # Brand-new team has no configs yet — backend 404s, we treat as None.
        from servonaut.services.api_client import APIError
        mock_api.get.side_effect = APIError(code="not_found", message="No configuration found", status=404)
        latest = run(team_service.get_latest_team_config("team-a"))
        assert latest is None

    def test_push_team_config_posts_full_body(self, team_service, mock_api):
        mock_api.post.return_value = {"data": {"id": "c1", "version": 1, "config_data": {"connection_profiles": []}}}
        payload = {"connection_profiles": [{"name": "prod"}]}
        result = run(team_service.push_team_config("team-a", payload, "Initial baseline"))
        mock_api.post.assert_called_with(
            "/api/v1/teams/team-a/configs",
            json={"config_data": payload, "description": "Initial baseline"},
        )
        assert result["version"] == 1

    def test_push_team_config_omits_description_when_none(self, team_service, mock_api):
        mock_api.post.return_value = {"data": {"id": "c1", "version": 2}}
        run(team_service.push_team_config("team-a", {"scan_rules": []}, None))
        # Body must not carry a description key — backend treats absence and null differently.
        sent_body = mock_api.post.call_args.kwargs["json"]
        assert "description" not in sent_body

    def test_resend_invite(self, team_service, mock_api):
        mock_api.post.return_value = {"email_sent": True, "id": "member-uuid-123"}
        result = run(team_service.resend_invite("team-a", "member-uuid-123"))
        mock_api.post.assert_called_with(
            "/api/v1/teams/team-a/members/member-uuid-123/resend",
            json={},
        )
        assert result["email_sent"] is True

    def test_list_shared_servers_accepts_data_envelope(self):
        # Backend (Api/Team/SharedServerController::list) wraps in {"data": [...]}.
        api = MagicMock()
        api.get = AsyncMock(return_value={
            "data": [{"name": "web-1", "hostname": "10.0.0.1", "region": "eu-west-2"}]
        })
        svc = TeamService(api)
        servers = run(svc.list_shared_servers("team-a"))
        assert len(servers) == 1
        assert servers[0]["hostname"] == "10.0.0.1"
        assert servers[0]["is_shared"] is True

    def test_list_shared_servers(self, team_service, mock_api):
        # Legacy envelope kept working for back-compat.
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
            json={"name": "web-1", "host": "10.0.0.1"},
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
