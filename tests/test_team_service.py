"""Tests for TeamService."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIClient, APIError
from servonaut.services.team_service import TeamService, ROLE_PERMISSIONS


def run(coro):
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


@pytest.fixture
def mock_api():
    # spec=APIClient catches positional json= misuse (APIClient.post/put require json= kwarg)
    api = MagicMock(spec=APIClient)
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


class TestTeamSshConfig:
    """Tests for team-side SSH config methods."""

    # --- get_team_ssh_config ---

    def test_get_team_ssh_config_happy_path(self, team_service, mock_api):
        payload = {
            "provider": "bitwarden_pm",
            "config": {"vault_url": "https://vault.example.com"},
            "team_slug": "team-a",
            "updated_at": "2026-05-24T00:00:00+00:00",
        }
        mock_api.get.return_value = payload
        result = run(team_service.get_team_ssh_config("team-a"))
        assert result == payload
        mock_api.get.assert_called_with("/api/v1/teams/team-a/ssh-config")

    def test_get_team_ssh_config_returns_none_on_404(self, team_service, mock_api):
        mock_api.get.side_effect = APIError(
            code="not_found", message="Not configured", status=404
        )
        result = run(team_service.get_team_ssh_config("team-a"))
        assert result is None

    def test_get_team_ssh_config_propagates_non_404(self, team_service, mock_api):
        mock_api.get.side_effect = APIError(
            code="server_error", message="Unexpected", status=500
        )
        with pytest.raises(APIError) as exc_info:
            run(team_service.get_team_ssh_config("team-a"))
        assert exc_info.value.status == 500

    # --- put_team_ssh_config ---

    def test_put_team_ssh_config_body_shape(self, team_service, mock_api):
        mock_api.put.return_value = {"provider": "bitwarden_pm"}
        run(team_service.put_team_ssh_config(
            "team-a", "https://vault.example.com", "col-uuid-123"
        ))
        mock_api.put.assert_called_with(
            "/api/v1/teams/team-a/ssh-config",
            json={
                "provider": "bitwarden_pm",
                "config": {
                    "vault_url": "https://vault.example.com",
                    "default_collection_id": "col-uuid-123",
                },
            },
        )

    def test_put_team_ssh_config_omits_collection_id_when_none(self, team_service, mock_api):
        mock_api.put.return_value = {"provider": "bitwarden_pm"}
        run(team_service.put_team_ssh_config("team-a", "https://vault.example.com"))
        sent_body = mock_api.put.call_args.kwargs["json"]
        assert "default_collection_id" not in sent_body["config"]

    def test_put_team_ssh_config_uses_bitwarden_pm_provider_default(
        self, team_service, mock_api
    ):
        mock_api.put.return_value = {}
        run(team_service.put_team_ssh_config("team-a", "https://vault.example.com"))
        sent_body = mock_api.put.call_args.kwargs["json"]
        assert sent_body["provider"] == "bitwarden_pm"

    def test_put_team_ssh_config_propagates_403(self, team_service, mock_api):
        # Member-not-admin — must NOT be swallowed; caller handles it.
        mock_api.put.side_effect = APIError(
            code="forbidden", message="Admin required", status=403
        )
        with pytest.raises(APIError) as exc_info:
            run(team_service.put_team_ssh_config("team-a", "https://vault.example.com"))
        assert exc_info.value.status == 403


class TestTeamServerSshRef:
    """Tests for team-side per-server SSH ref methods."""

    # --- get_team_server_ssh_ref ---

    def test_get_team_server_ssh_ref_happy_path(self, team_service, mock_api):
        payload = {
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": {"item_id": "item-uuid"},
        }
        mock_api.get.return_value = payload
        result = run(team_service.get_team_server_ssh_ref("team-a", "srv-001"))
        assert result == payload
        mock_api.get.assert_called_with(
            "/api/v1/teams/team-a/servers/srv-001/ssh-ref"
        )

    def test_get_team_server_ssh_ref_returns_none_on_404(self, team_service, mock_api):
        mock_api.get.side_effect = APIError(
            code="not_found", message="No ref", status=404
        )
        result = run(team_service.get_team_server_ssh_ref("team-a", "srv-001"))
        assert result is None

    # --- put_team_server_ssh_ref ---

    def test_put_team_server_ssh_ref_uses_ssh_credential_ref_field_name(
        self, team_service, mock_api
    ):
        # Critical: body field is ssh_credential_ref, NOT the deprecated ref alias.
        mock_api.put.return_value = {"ssh_credential_ref": {"item_id": "item-uuid"}}
        ref = {"item_id": "item-uuid", "collection_id": "col-uuid"}
        run(team_service.put_team_server_ssh_ref("team-a", "srv-001", ref))
        sent_body = mock_api.put.call_args.kwargs["json"]
        assert "ssh_credential_ref" in sent_body
        assert "ref" not in sent_body
        assert sent_body["ssh_credential_ref"] == ref

    def test_put_team_server_ssh_ref_uses_bitwarden_pm_provider_default(
        self, team_service, mock_api
    ):
        mock_api.put.return_value = {}
        run(team_service.put_team_server_ssh_ref("team-a", "srv-001", {"item_id": "x"}))
        sent_body = mock_api.put.call_args.kwargs["json"]
        assert sent_body["ssh_credential_provider"] == "bitwarden_pm"

    def test_put_team_server_ssh_ref_correct_url(self, team_service, mock_api):
        mock_api.put.return_value = {}
        run(team_service.put_team_server_ssh_ref("team-a", "srv-001", {"item_id": "x"}))
        mock_api.put.assert_called_with(
            "/api/v1/teams/team-a/servers/srv-001/ssh-ref",
            json={
                "ssh_credential_provider": "bitwarden_pm",
                "ssh_credential_ref": {"item_id": "x"},
            },
        )

    def test_put_team_server_ssh_ref_propagates_403(self, team_service, mock_api):
        mock_api.put.side_effect = APIError(
            code="forbidden", message="Admin required", status=403
        )
        with pytest.raises(APIError) as exc_info:
            run(team_service.put_team_server_ssh_ref("team-a", "srv-001", {"item_id": "x"}))
        assert exc_info.value.status == 403

    # --- delete_team_server_ssh_ref ---

    def test_delete_team_server_ssh_ref_returns_true_on_success(
        self, team_service, mock_api
    ):
        mock_api.delete.return_value = {"deleted": True}
        result = run(team_service.delete_team_server_ssh_ref("team-a", "srv-001"))
        assert result is True
        mock_api.delete.assert_called_with(
            "/api/v1/teams/team-a/servers/srv-001/ssh-ref"
        )

    def test_delete_team_server_ssh_ref_returns_false_on_404(
        self, team_service, mock_api
    ):
        mock_api.delete.side_effect = APIError(
            code="not_found", message="No ref", status=404
        )
        result = run(team_service.delete_team_server_ssh_ref("team-a", "srv-001"))
        assert result is False


class TestTeamServerSshVerify:
    """Tests for team-side SSH verify-status and verify-report methods."""

    # --- get_team_server_ssh_verify_status ---

    def test_get_team_server_ssh_verify_status_happy_path(self, team_service, mock_api):
        payload = {
            "server_id": "srv-001",
            "ssh_verify_status": "verified",
            "ssh_verified_at": "2026-05-24T00:00:00+00:00",
            "checked_by_client": "servonaut-cli/2.10.2",
            "updated_at": "2026-05-24T00:00:00+00:00",
        }
        mock_api.get.return_value = payload
        result = run(team_service.get_team_server_ssh_verify_status("team-a", "srv-001"))
        assert result == payload
        mock_api.get.assert_called_with(
            "/api/v1/teams/team-a/servers/srv-001/ssh-verify-status"
        )

    def test_get_team_server_ssh_verify_status_returns_none_on_404(
        self, team_service, mock_api
    ):
        mock_api.get.side_effect = APIError(
            code="not_found", message="No ref stored", status=404
        )
        result = run(team_service.get_team_server_ssh_verify_status("team-a", "srv-001"))
        assert result is None

    # --- report_team_server_ssh_verify ---

    def test_report_verified_status(self, team_service, mock_api):
        mock_api.post.return_value = {"ok": True}
        run(team_service.report_team_server_ssh_verify("team-a", "srv-001", "verified"))
        mock_api.post.assert_called_with(
            "/api/v1/teams/team-a/servers/srv-001/ssh-verify-report",
            json={"status": "verified"},
        )

    def test_report_not_found_status(self, team_service, mock_api):
        mock_api.post.return_value = {"ok": True}
        run(team_service.report_team_server_ssh_verify("team-a", "srv-001", "not_found"))
        sent_body = mock_api.post.call_args.kwargs["json"]
        assert sent_body["status"] == "not_found"

    def test_report_auth_failed_status(self, team_service, mock_api):
        mock_api.post.return_value = {"ok": True}
        run(team_service.report_team_server_ssh_verify("team-a", "srv-001", "auth_failed"))
        sent_body = mock_api.post.call_args.kwargs["json"]
        assert sent_body["status"] == "auth_failed"

    def test_report_with_checked_by_client(self, team_service, mock_api):
        mock_api.post.return_value = {"ok": True}
        run(team_service.report_team_server_ssh_verify(
            "team-a", "srv-001", "verified", checked_by_client="servonaut-cli/2.10.2"
        ))
        sent_body = mock_api.post.call_args.kwargs["json"]
        assert sent_body["checked_by_client"] == "servonaut-cli/2.10.2"

    def test_report_omits_checked_by_client_when_none(self, team_service, mock_api):
        mock_api.post.return_value = {"ok": True}
        run(team_service.report_team_server_ssh_verify("team-a", "srv-001", "verified"))
        sent_body = mock_api.post.call_args.kwargs["json"]
        assert "checked_by_client" not in sent_body

    def test_report_rejects_invalid_status_locally_no_round_trip(
        self, team_service, mock_api
    ):
        # Local validation MUST raise ValueError before any API call.
        with pytest.raises(ValueError, match="status must be one of"):
            run(team_service.report_team_server_ssh_verify(
                "team-a", "srv-001", "invalid_status"
            ))
        mock_api.post.assert_not_called()

    def test_report_rejects_empty_status(self, team_service, mock_api):
        with pytest.raises(ValueError):
            run(team_service.report_team_server_ssh_verify("team-a", "srv-001", ""))
        mock_api.post.assert_not_called()


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
