"""Tests for TeamManagementScreen."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.screens.team_management import TeamManagementScreen
from servonaut.services.api_client import APIError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_team_service(teams: list[dict] | None = None) -> MagicMock:
    """Return a mock TeamService."""
    svc = MagicMock()
    svc.list_teams = AsyncMock(return_value=teams or [])
    svc.get_team = AsyncMock(
        return_value={
            "name": "Engineering",
            "slug": "engineering",
            "role": "owner",
            "members": [
                {
                    "id": "m1",
                    "invitation_email": "alice@example.com",
                    "user": {"id": 1, "name": "Alice"},
                    "role": "admin",
                    "is_accepted": True,
                },
                {
                    "id": "m2",
                    "invitation_email": "bob@example.com",
                    "user": None,
                    "role": "member",
                    "is_accepted": False,
                    "invitation_expires_at": "2099-01-01T00:00:00+00:00",
                    "accept_url": "https://staging.servonaut.dev/invite/abc123",
                },
            ],
        }
    )
    svc.list_shared_servers = AsyncMock(
        return_value=[
            {"name": "web-01", "host": "1.2.3.4", "provider": "aws"},
        ]
    )
    svc.create_team = AsyncMock(return_value={"slug": "new-team", "name": "New Team"})
    svc.invite_member = AsyncMock(return_value={"email_sent": True})
    svc.resend_invite = AsyncMock(return_value={"email_sent": True})
    svc.remove_member = AsyncMock(return_value={})
    svc.update_role = AsyncMock(return_value={})
    svc.push_server = AsyncMock(return_value={})
    return svc


def _make_auth_service(*, authenticated: bool = True) -> MagicMock:
    svc = MagicMock()
    svc.is_authenticated = authenticated
    return svc


_SAMPLE_TEAMS = [
    {"slug": "eng", "name": "Engineering", "role": "admin", "member_count": 3},
    {"slug": "ops", "name": "Ops", "role": "member", "member_count": 1},
]


class _WrapperApp(App):
    """Minimal host app to mount TeamManagementScreen for testing."""

    def __init__(
        self,
        *,
        auth_service=None,
        team_service=None,
        instances: list | None = None,
    ) -> None:
        super().__init__()
        self.auth_service = auth_service
        self.team_service = team_service
        self.instances = instances or []
        # Required by TeamManagementScreen's demo-mode guards.
        self.demo_mode = False
        self.redaction_service = None

    def on_mount(self) -> None:
        self.push_screen(TeamManagementScreen())


# ---------------------------------------------------------------------------
# Unauthenticated state
# ---------------------------------------------------------------------------


class TestTeamManagementScreenUnauthenticated:
    @pytest.mark.asyncio
    async def test_shows_login_required_message_when_not_authenticated(self):
        auth = _make_auth_service(authenticated=False)
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            notice = app.screen.query_one("#no_auth_notice", Static)
            assert notice.display is True

    @pytest.mark.asyncio
    async def test_shows_login_required_message_when_auth_service_is_none(self):
        app = _WrapperApp(auth_service=None)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            notice = app.screen.query_one("#no_auth_notice", Static)
            assert notice.display is True

    @pytest.mark.asyncio
    async def test_team_list_hidden_when_not_authenticated(self):
        auth = _make_auth_service(authenticated=False)
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            table = app.screen.query_one("#teams_table", DataTable)
            assert table.display is False

    @pytest.mark.asyncio
    async def test_team_service_not_called_when_not_authenticated(self):
        auth = _make_auth_service(authenticated=False)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            team_svc.list_teams.assert_not_called()


# ---------------------------------------------------------------------------
# Authenticated state — team list
# ---------------------------------------------------------------------------


class TestTeamManagementScreenAuthenticated:
    @pytest.mark.asyncio
    async def test_no_auth_notice_hidden_when_authenticated(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            notice = app.screen.query_one("#no_auth_notice", Static)
            assert notice.display is False

    @pytest.mark.asyncio
    async def test_teams_table_visible_when_authenticated(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service(_SAMPLE_TEAMS)
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            table = app.screen.query_one("#teams_table", DataTable)
            assert table.display is True

    @pytest.mark.asyncio
    async def test_list_teams_called_on_mount(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service(_SAMPLE_TEAMS)
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            team_svc.list_teams.assert_called_once()

    @pytest.mark.asyncio
    async def test_teams_table_populated_with_results(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service(_SAMPLE_TEAMS)
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            table = app.screen.query_one("#teams_table", DataTable)
            assert table.row_count == 2

    @pytest.mark.asyncio
    async def test_empty_teams_list_renders_without_error(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service([])
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            table = app.screen.query_one("#teams_table", DataTable)
            assert table.row_count == 0


# ---------------------------------------------------------------------------
# Team detail view
# ---------------------------------------------------------------------------


class TestTeamManagementScreenDetail:
    @pytest.mark.asyncio
    async def test_detail_section_hidden_on_initial_load(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service(_SAMPLE_TEAMS)
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            # Detail sections are wrapped in .settings_section cards; the
            # whole wrapper collapses pre-team-selection.
            assert app.screen.query_one("#team_header").display is False
            assert app.screen.query_one("#members_section").display is False
            assert app.screen.query_one("#servers_section").display is False

    @pytest.mark.asyncio
    async def test_create_form_hidden_on_initial_load(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            assert app.screen.query_one("#create_team_form").display is False

    @pytest.mark.asyncio
    async def test_invite_form_hidden_on_initial_load(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            assert app.screen.query_one("#invite_form").display is False


# ---------------------------------------------------------------------------
# Create team form
# ---------------------------------------------------------------------------


class TestTeamManagementCreateTeam:
    @pytest.mark.asyncio
    async def test_create_team_button_shows_form(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            await pilot.click("#btn_create_team")
            await pilot.pause()
            form = app.screen.query_one("#create_team_form")
            assert form.display is True

    @pytest.mark.asyncio
    async def test_save_team_calls_create_team(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            # Show the form
            await pilot.click("#btn_create_team")
            await pilot.pause()
            # Fill in team name
            inp = app.screen.query_one("#input_team_name")
            inp.value = "My New Team"
            await pilot.pause()
            # Submit
            await pilot.click("#btn_save_team")
            for _ in range(5):
                await pilot.pause()
            team_svc.create_team.assert_called_once_with("My New Team")

    @pytest.mark.asyncio
    async def test_empty_team_name_does_not_call_service(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            await pilot.click("#btn_create_team")
            await pilot.pause()
            # Leave name blank
            await pilot.click("#btn_save_team")
            await pilot.pause()
            team_svc.create_team.assert_not_called()


# ---------------------------------------------------------------------------
# Invite member form
# ---------------------------------------------------------------------------


class TestTeamManagementInviteMember:
    @pytest.mark.asyncio
    async def test_invite_button_shows_form_when_team_selected(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            # Directly call the show helper (avoids pilot.click focusing Input
            # which can open the command palette in some Textual versions)
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._show_invite_form()
            await pilot.pause()
            form = screen.query_one("#invite_form")
            assert form.display is True

    @pytest.mark.asyncio
    async def test_send_invite_calls_service(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._show_invite_form()
            await pilot.pause()
            screen._current_team_role = "owner"
            screen.query_one("#input_invite_email", Input).value = "newmember@example.com"
            screen.query_one("#select_invite_role", Select).value = "member"
            screen._submit_invite_member()
            for _ in range(5):
                await pilot.pause()
            team_svc.invite_member.assert_called_once_with(
                "eng", "newmember@example.com", "member"
            )

    @pytest.mark.asyncio
    async def test_invite_defaults_to_member_role_when_empty(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._show_invite_form()
            await pilot.pause()
            screen._current_team_role = "owner"
            screen.query_one("#input_invite_email", Input).value = "someone@example.com"
            # Select defaults to "member" via _show_invite_form()
            screen._submit_invite_member()
            for _ in range(5):
                await pilot.pause()
            team_svc.invite_member.assert_called_once_with(
                "eng", "someone@example.com", "member"
            )

    @pytest.mark.asyncio
    async def test_empty_email_does_not_call_service(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_invite_form()
            await pilot.pause()
            screen.query_one("#input_invite_email", Input).value = ""
            screen._submit_invite_member()
            await pilot.pause()
            team_svc.invite_member.assert_not_called()


# ---------------------------------------------------------------------------
# Missing services — graceful degradation
# ---------------------------------------------------------------------------


class TestTeamManagementMissingServices:
    @pytest.mark.asyncio
    async def test_no_crash_when_team_service_is_none_and_authenticated(self):
        auth = _make_auth_service(authenticated=True)
        app = _WrapperApp(auth_service=auth, team_service=None)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            # Screen should still be mounted without crashing
            assert app.screen.query_one("#teams_table") is not None

    @pytest.mark.asyncio
    async def test_no_crash_when_both_services_are_none(self):
        app = _WrapperApp(auth_service=None, team_service=None)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            notice = app.screen.query_one("#no_auth_notice", Static)
            assert notice.display is True

    @pytest.mark.asyncio
    async def test_back_button_is_always_rendered(self):
        app = _WrapperApp(auth_service=None, team_service=None)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            btn = app.screen.query_one("#btn_back", Button)
            assert btn is not None

    @pytest.mark.asyncio
    async def test_api_error_on_list_teams_notifies_user(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        team_svc.list_teams = AsyncMock(side_effect=Exception("Network error"))
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        # Should not raise — error is caught and notified
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            # Screen still mounts without crashing
            assert app.screen.query_one("#teams_table") is not None


# ---------------------------------------------------------------------------
# Caller role gating
# ---------------------------------------------------------------------------


class TestTeamManagementCallerRoleGating:
    @pytest.mark.asyncio
    async def test_member_caller_cannot_see_mutation_buttons(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service(_SAMPLE_TEAMS)
        # Override get_team to drop the caller-role hint so the screen falls
        # back to the slug -> role cache built from list_teams.
        team_svc.get_team = AsyncMock(
            return_value={
                "name": "Ops",
                "slug": "ops",
                "members": [],
            }
        )
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "ops"
            await screen._load_team_detail("ops")
            await pilot.pause()
            assert screen._current_team_role == "member"
            for btn_id in ("btn_invite", "btn_remove", "btn_change_role", "btn_resend", "btn_copy_url", "btn_share"):
                assert screen.query_one(f"#{btn_id}").display is False, btn_id

    @pytest.mark.asyncio
    async def test_owner_caller_sees_all_mutation_buttons(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service([{"slug": "eng", "name": "Eng", "role": "owner", "member_count": 1}])
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            await screen._load_team_detail("eng")
            await pilot.pause()
            for btn_id in ("btn_invite", "btn_remove", "btn_change_role", "btn_resend", "btn_copy_url", "btn_share"):
                assert screen.query_one(f"#{btn_id}").display is True, btn_id

    @pytest.mark.asyncio
    async def test_admin_caller_cannot_select_admin_role_option(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service([{"slug": "eng", "name": "Eng", "role": "admin", "member_count": 1}])
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "admin"
            options = screen._role_options_for_caller()
            values = [v for _, v in options]
            assert "admin" not in values
            assert "member" in values
            assert "viewer" in values


# ---------------------------------------------------------------------------
# Status column + email lookup
# ---------------------------------------------------------------------------


class TestTeamManagementMemberDisplay:
    def test_format_status_active(self):
        assert TeamManagementScreen._format_status({"is_accepted": True}) == "Active"

    def test_format_status_invited_with_expiry(self):
        result = TeamManagementScreen._format_status({
            "is_accepted": False,
            "invitation_expires_at": "2099-01-01T00:00:00+00:00",
        })
        assert result.startswith("Invited (expires in")

    def test_format_status_invited_expired(self):
        result = TeamManagementScreen._format_status({
            "is_accepted": False,
            "invitation_expires_at": "2000-01-01T00:00:00+00:00",
        })
        assert result == "Invited (expired)"

    def test_format_status_invited_without_expiry(self):
        assert TeamManagementScreen._format_status({"is_accepted": False}) == "Invited"

    def test_email_lookup_prefers_invitation_email(self):
        assert TeamManagementScreen._member_display_email({
            "invitation_email": "alice@example.com",
            "user": {"name": "Alice"},
        }) == "alice@example.com"

    def test_email_lookup_falls_back_to_user_name(self):
        assert TeamManagementScreen._member_display_email({
            "user": {"id": 1, "name": "Bob"},
        }) == "Bob"

    def test_email_lookup_legacy_email_field(self):
        # Tolerates pre-fix backend shape.
        assert TeamManagementScreen._member_display_email({
            "email": "legacy@example.com",
        }) == "legacy@example.com"

    def test_email_lookup_unknown_fallback(self):
        assert TeamManagementScreen._member_display_email({}) == "unknown"


# ---------------------------------------------------------------------------
# Invite / resend email_sent handling
# ---------------------------------------------------------------------------


class TestTeamManagementInviteOutcome:
    @pytest.mark.asyncio
    async def test_invite_response_email_sent_false_warns_user(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        team_svc.invite_member = AsyncMock(return_value={"email_sent": False})
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            notifications: list[tuple[str, str]] = []
            orig_notify = screen.notify

            def capture_notify(msg, *, severity="information", **kw):
                notifications.append((str(severity), str(msg)))
                return orig_notify(msg, severity=severity, **kw)

            screen.notify = capture_notify  # type: ignore[method-assign]
            await screen._do_invite_member("eng", "x@example.com", "member")
            await pilot.pause()
            assert any(sev == "warning" and "email delivery failed" in msg for sev, msg in notifications)

    @pytest.mark.asyncio
    async def test_resend_invite_calls_service_with_member_id(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._members = [
                {"id": "m2", "invitation_email": "bob@example.com", "role": "member", "is_accepted": False},
            ]
            tbl = screen.query_one("#members_table", DataTable)
            tbl.add_row("bob@example.com", "member", "Invited")
            tbl.move_cursor(row=0)
            screen._action_resend_invite()
            for _ in range(5):
                await pilot.pause()
            team_svc.resend_invite.assert_called_once_with("eng", "m2")


# ---------------------------------------------------------------------------
# Change role
# ---------------------------------------------------------------------------


class TestTeamManagementChangeRole:
    @pytest.mark.asyncio
    async def test_change_role_uses_put_via_member_id(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._members = [
                {"id": "m2", "invitation_email": "bob@example.com", "role": "member", "is_accepted": True},
            ]
            tbl = screen.query_one("#members_table", DataTable)
            tbl.add_row("bob@example.com", "member", "Active")
            tbl.move_cursor(row=0)
            screen._show_change_role_form(screen._members[0])
            await pilot.pause()
            screen.query_one("#select_change_role", Select).value = "admin"
            screen._submit_change_role()
            for _ in range(5):
                await pilot.pause()
            team_svc.update_role.assert_called_once_with("eng", "m2", "admin")

    @pytest.mark.asyncio
    async def test_admin_caller_cannot_promote_to_admin(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "admin"  # admin, NOT owner
            screen._members = [
                {"id": "m2", "invitation_email": "bob@example.com", "role": "member", "is_accepted": True},
            ]
            tbl = screen.query_one("#members_table", DataTable)
            tbl.add_row("bob@example.com", "member", "Active")
            tbl.move_cursor(row=0)
            screen._show_change_role_form(screen._members[0])
            await pilot.pause()
            # Force the bypass attempt — UI Select shouldn't even expose admin,
            # but mimic a client-side tamper to prove the floor holds.
            screen.query_one("#select_change_role", Select).set_options(_ROLE_OPTIONS_FULL)
            screen.query_one("#select_change_role", Select).value = "admin"
            screen._submit_change_role()
            await pilot.pause()
            team_svc.update_role.assert_not_called()


_ROLE_OPTIONS_FULL = [("Viewer", "viewer"), ("Member", "member"), ("Admin", "admin")]


# ---------------------------------------------------------------------------
# Copy accept URL
# ---------------------------------------------------------------------------


class TestTeamManagementCopyAcceptUrl:
    @pytest.mark.asyncio
    async def test_copy_accept_url_uses_app_clipboard(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._members = [
                {
                    "id": "m2",
                    "invitation_email": "bob@example.com",
                    "role": "member",
                    "is_accepted": False,
                    "accept_url": "https://staging.servonaut.dev/invite/xyz",
                },
            ]
            tbl = screen.query_one("#members_table", DataTable)
            tbl.add_row("bob@example.com", "member", "Invited")
            tbl.move_cursor(row=0)
            copied: list[str] = []
            app.copy_to_clipboard = lambda text: copied.append(text)  # type: ignore[method-assign]
            screen._action_copy_accept_url()
            await pilot.pause()
            assert copied == ["https://staging.servonaut.dev/invite/xyz"]

    @pytest.mark.asyncio
    async def test_copy_accept_url_noop_when_url_missing(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._members = [
                {"id": "m2", "invitation_email": "bob@example.com", "role": "member", "is_accepted": False},
            ]
            tbl = screen.query_one("#members_table", DataTable)
            tbl.add_row("bob@example.com", "member", "Invited")
            tbl.move_cursor(row=0)
            copied: list[str] = []
            app.copy_to_clipboard = lambda text: copied.append(text)  # type: ignore[method-assign]
            screen._action_copy_accept_url()
            await pilot.pause()
            assert copied == []


# ---------------------------------------------------------------------------
# Gap 1 — Create-team button gating + 403 message surfacing
# ---------------------------------------------------------------------------


class TestTeamManagementCreateTeamGate:
    @pytest.mark.asyncio
    async def test_create_team_button_hidden_when_caller_already_owns_a_team(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service([
            {"slug": "eng", "name": "Engineering", "role": "owner", "member_count": 3},
        ])
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            assert app.screen.query_one("#btn_create_team").display is False

    @pytest.mark.asyncio
    async def test_create_team_button_visible_when_caller_owns_none(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service([
            {"slug": "eng", "name": "Engineering", "role": "member", "member_count": 3},
        ])
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            assert app.screen.query_one("#btn_create_team").display is True

    @pytest.mark.asyncio
    async def test_create_team_403_surfaces_backend_message_verbatim(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        team_svc.create_team = AsyncMock(side_effect=APIError(
            code="forbidden",
            message="You already own a team workspace. Delete the existing team or contact support to lift this limit.",
            status=403,
        ))
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            notifications: list[tuple[str, str]] = []
            orig_notify = screen.notify

            def capture_notify(msg, *, severity="information", **kw):
                notifications.append((str(severity), str(msg)))
                return orig_notify(msg, severity=severity, **kw)

            screen.notify = capture_notify  # type: ignore[method-assign]
            await screen._do_create_team("My Team")
            await pilot.pause()
            assert any(sev == "error" and "already own a team workspace" in msg for sev, msg in notifications), notifications


# ---------------------------------------------------------------------------
# Gap 2 — 402 / 422 / other-4xx branching in invite + resend
# ---------------------------------------------------------------------------


def _capture_notifications(screen) -> list[tuple[str, str]]:
    """Install a notify capture on the screen. Returns the list that fills up."""
    notifications: list[tuple[str, str]] = []
    orig_notify = screen.notify

    def capture(msg, *, severity="information", **kw):
        notifications.append((str(severity), str(msg)))
        return orig_notify(msg, severity=severity, **kw)

    screen.notify = capture  # type: ignore[method-assign]
    return notifications


class TestTeamManagementMemberWriteErrors:
    @pytest.mark.asyncio
    async def test_invite_402_owner_caller_sees_billing_cta(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        team_svc.invite_member = AsyncMock(side_effect=APIError(
            code="payment_required",
            message="This team's current subscription does not include team invitations.",
            status=402,
        ))
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"  # owner sees billing link
            notes = _capture_notifications(screen)
            await screen._do_invite_member("eng", "x@example.com", "member")
            await pilot.pause()
            assert any(
                sev == "warning" and "Manage your subscription at https://servonaut.dev/account/billing" in msg
                for sev, msg in notes
            ), notes

    @pytest.mark.asyncio
    async def test_invite_402_non_owner_caller_sees_ask_owner(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        team_svc.invite_member = AsyncMock(side_effect=APIError(
            code="payment_required",
            message="This team's current subscription does not include team invitations.",
            status=402,
        ))
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "admin"  # admin can invite, but isn't billing owner
            notes = _capture_notifications(screen)
            await screen._do_invite_member("eng", "x@example.com", "member")
            await pilot.pause()
            assert any(
                sev == "warning" and "Ask the team owner to renew" in msg
                for sev, msg in notes
            ), notes

    @pytest.mark.asyncio
    async def test_invite_422_seat_cap_surfaces_remove_or_upgrade_hint(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        team_svc.invite_member = AsyncMock(side_effect=APIError(
            code="seats_exhausted",
            message='Team "Engineering" has reached its maximum of 5 seats.',
            status=422,
        ))
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            notes = _capture_notifications(screen)
            await screen._do_invite_member("eng", "x@example.com", "member")
            await pilot.pause()
            assert any(
                sev == "warning" and "Remove an existing member" in msg and "maximum of 5 seats" in msg
                for sev, msg in notes
            ), notes

    @pytest.mark.asyncio
    async def test_resend_402_uses_same_branch(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        team_svc.resend_invite = AsyncMock(side_effect=APIError(
            code="payment_required",
            message="This team's current subscription does not include team invitations.",
            status=402,
        ))
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            notes = _capture_notifications(screen)
            await screen._do_resend_invite("eng", "m1", "bob@example.com")
            await pilot.pause()
            assert any(sev == "warning" and "Manage your subscription" in msg for sev, msg in notes), notes

    @pytest.mark.asyncio
    async def test_invite_other_4xx_surfaces_backend_message(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        team_svc.invite_member = AsyncMock(side_effect=APIError(
            code="conflict",
            message="A pending invitation already exists for this email.",
            status=409,
        ))
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            notes = _capture_notifications(screen)
            await screen._do_invite_member("eng", "dup@example.com", "member")
            await pilot.pause()
            assert any(
                sev == "error" and "pending invitation already exists" in msg
                for sev, msg in notes
            ), notes


# ---------------------------------------------------------------------------
# Gap 3 — seats indicator in team header
# ---------------------------------------------------------------------------


class TestTeamManagementSeatLine:
    def test_seat_line_with_active_subscription(self):
        members = [{"id": f"m{i}"} for i in range(3)]
        team = {"max_seats": 5}
        assert TeamManagementScreen._format_seat_line(team, members) == "Seats: 3 / 5"

    def test_seat_line_counts_pending_invites_in_used(self):
        # Backend semantics: accepted + pending both reserve a seat.
        members = [
            {"id": "m1", "is_accepted": True},
            {"id": "m2", "is_accepted": False},
            {"id": "m3", "is_accepted": False},
        ]
        team = {"max_seats": 5}
        assert TeamManagementScreen._format_seat_line(team, members) == "Seats: 3 / 5"

    def test_seat_line_no_subscription_renders_explanatory_text(self):
        members = [{"id": "m1"}, {"id": "m2"}]
        team = {"max_seats": 0}
        line = TeamManagementScreen._format_seat_line(team, members)
        assert line == "Seats: 2 (no active Teams subscription)"

    def test_seat_line_missing_max_seats_field_treated_as_no_sub(self):
        # Defensive — pre-fix backend payloads / older snapshots may omit the field.
        members = [{"id": "m1"}]
        team = {}
        assert TeamManagementScreen._format_seat_line(team, members) == "Seats: 1 (no active Teams subscription)"


# ---------------------------------------------------------------------------
# Cancel buttons — escape hatch from stuck forms after server errors
# ---------------------------------------------------------------------------


class TestTeamManagementCancelButtons:
    @pytest.mark.asyncio
    async def test_cancel_create_team_hides_form(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._show_create_form()
            await pilot.pause()
            assert screen.query_one("#create_team_form").display is True
            screen.query_one("#btn_cancel_create_team", Button).press()
            await pilot.pause()
            assert screen.query_one("#create_team_form").display is False

    @pytest.mark.asyncio
    async def test_cancel_invite_member_hides_form(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_invite_form()
            await pilot.pause()
            assert screen.query_one("#invite_form").display is True
            screen.query_one("#btn_cancel_invite", Button).press()
            await pilot.pause()
            assert screen.query_one("#invite_form").display is False

    @pytest.mark.asyncio
    async def test_cancel_change_role_hides_form(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_change_role_form({"id": "m1", "invitation_email": "b@x.com", "role": "member"})
            await pilot.pause()
            assert screen.query_one("#change_role_form").display is True
            screen.query_one("#btn_cancel_change_role", Button).press()
            await pilot.pause()
            assert screen.query_one("#change_role_form").display is False

    @pytest.mark.asyncio
    async def test_cancel_share_server_hides_form(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [{"id": "i-1", "name": "web-01", "public_ip": "1.1.1.1"}]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            assert screen.query_one("#share_server_form").display is True
            screen.query_one("#btn_cancel_share", Button).press()
            await pilot.pause()
            assert screen.query_one("#share_server_form").display is False

    @pytest.mark.asyncio
    async def test_cancel_works_after_server_403_keeps_user_unblocked(self):
        # Regression: user reported that on a 403 from POST /teams the form
        # stayed open with no way to dismiss it. Cancel must still work after
        # the failed save attempt.
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        team_svc.create_team = AsyncMock(side_effect=APIError(
            code="forbidden",
            message="You already own a team workspace.",
            status=403,
        ))
        app = _WrapperApp(auth_service=auth, team_service=team_svc)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._show_create_form()
            screen.query_one("#input_team_name", Input).value = "Doomed Team"
            screen._submit_create_team()
            for _ in range(5):
                await pilot.pause()
            # Form intentionally stays open so user sees the error context.
            assert screen.query_one("#create_team_form").display is True
            # Cancel must close it.
            screen.query_one("#btn_cancel_create_team", Button).press()
            await pilot.pause()
            assert screen.query_one("#create_team_form").display is False


# ---------------------------------------------------------------------------
# Share server — wire-format contract
# ---------------------------------------------------------------------------


class TestTeamManagementShareServer:
    @pytest.mark.asyncio
    async def test_share_action_opens_picker_form(self):
        # Action button opens the form — does NOT push the first instance.
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [
            {"id": "i-0abc", "name": "web-01", "public_ip": "1.2.3.4"},
            {"id": "i-0xyz", "name": "web-02", "public_ip": "5.6.7.8"},
        ]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._action_share_server()
            await pilot.pause()
            assert screen.query_one("#share_server_form").display is True
            team_svc.push_server.assert_not_called()

    @pytest.mark.asyncio
    async def test_submit_share_sends_selected_instance_not_first(self):
        # Regression: picker MUST send the user's chosen row, not instances[0].
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [
            {"id": "i-0abc", "name": "web-01", "public_ip": "1.2.3.4", "region": "eu-west-2"},
            {"id": "i-0xyz", "name": "web-02", "public_ip": "5.6.7.8", "region": "us-east-1"},
        ]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            # Pick the SECOND instance — proves first-instance bias is gone.
            screen.query_one("#select_share_instance", Select).value = "i-0xyz"
            screen._submit_share_server()
            for _ in range(5):
                await pilot.pause()
            slug_arg, payload = team_svc.push_server.call_args.args
            assert slug_arg == "eng"
            assert payload["name"] == "web-02"
            assert payload["hostname"] == "5.6.7.8"
            assert payload["instance_id"] == "i-0xyz"
            assert payload["region"] == "us-east-1"
            # Stale fields from earlier contract must NOT leak through.
            for stale in ("host", "provider", "username", "port"):
                assert stale not in payload

    @pytest.mark.asyncio
    async def test_submit_share_falls_back_to_private_ip_when_public_missing(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [
            {"id": "i-internal", "name": "internal-db", "public_ip": "", "private_ip": "10.0.5.20"},
        ]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            screen.query_one("#select_share_instance", Select).value = "i-internal"
            screen._submit_share_server()
            for _ in range(5):
                await pilot.pause()
            _, payload = team_svc.push_server.call_args.args
            assert payload["hostname"] == "10.0.5.20"

    @pytest.mark.asyncio
    async def test_submit_share_with_nothing_selected_warns_and_does_not_push(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [{"id": "i-0abc", "name": "web-01", "public_ip": "1.2.3.4"}]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            screen.query_one("#select_share_instance", Select).clear()
            notes = _capture_notifications(screen)
            screen._submit_share_server()
            await pilot.pause()
            team_svc.push_server.assert_not_called()
            assert any("Pick a server" in msg for _, msg in notes), notes

    def test_build_share_options_filters_instances_with_no_ip(self):
        instances = [
            {"id": "i-1", "name": "good", "public_ip": "1.1.1.1"},
            {"id": "i-2", "name": "stopped", "public_ip": "", "private_ip": ""},
            {"id": "i-3", "name": "private-only", "public_ip": "", "private_ip": "10.0.0.3"},
            {"name": "no-id", "public_ip": "2.2.2.2"},  # no id → drop
        ]
        options = TeamManagementScreen._build_share_options(instances)
        values = [v for _, v in options]
        assert values == ["i-1", "i-3"]

    def test_build_share_options_label_shows_name_and_hostname(self):
        options = TeamManagementScreen._build_share_options([
            {"id": "i-1", "name": "web-01", "public_ip": "1.1.1.1"},
        ])
        assert options == [("web-01 (1.1.1.1)", "i-1")]

    def test_build_share_options_falls_back_to_id_when_name_missing(self):
        options = TeamManagementScreen._build_share_options([
            {"id": "i-noname", "public_ip": "9.9.9.9"},
        ])
        assert options == [("i-noname (9.9.9.9)", "i-noname")]

    @pytest.mark.asyncio
    async def test_submit_share_includes_username_and_port_when_provided(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [{"id": "i-1", "name": "web-01", "public_ip": "1.1.1.1"}]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            screen.query_one("#input_share_username", Input).value = "deploy"
            screen.query_one("#input_share_port", Input).value = "2222"
            screen._submit_share_server()
            for _ in range(5):
                await pilot.pause()
            _, payload = team_svc.push_server.call_args.args
            assert payload["username"] == "deploy"
            assert payload["port"] == 2222

    @pytest.mark.asyncio
    async def test_submit_share_omits_port_when_default_22(self):
        # Sending port=22 explicitly is noisy — backend defaults to 22 already.
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [{"id": "i-1", "name": "web-01", "public_ip": "1.1.1.1"}]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            screen.query_one("#input_share_port", Input).value = "22"
            screen._submit_share_server()
            for _ in range(5):
                await pilot.pause()
            _, payload = team_svc.push_server.call_args.args
            assert "port" not in payload

    @pytest.mark.asyncio
    async def test_submit_share_omits_username_when_blank(self):
        # Empty username = "use the consumer CLI's cloud default" (null at API).
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [{"id": "i-1", "name": "web-01", "public_ip": "1.1.1.1"}]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            screen.query_one("#input_share_username", Input).value = ""
            screen._submit_share_server()
            for _ in range(5):
                await pilot.pause()
            _, payload = team_svc.push_server.call_args.args
            assert "username" not in payload

    @pytest.mark.asyncio
    async def test_submit_share_rejects_invalid_port(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [{"id": "i-1", "name": "web-01", "public_ip": "1.1.1.1"}]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            # 70000 is out of the backend's 1-65535 range — surface client-side
            # to save a server round-trip + a worse error message.
            screen.query_one("#input_share_port", Input).value = "70000"
            notes = _capture_notifications(screen)
            screen._submit_share_server()
            await pilot.pause()
            team_svc.push_server.assert_not_called()
            assert any("between 1 and 65535" in msg for _, msg in notes), notes

    @pytest.mark.asyncio
    async def test_share_form_prefills_username_and_port_from_custom_server(self):
        # Custom servers carry username/port on the instance dict; AWS rows do not.
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [
            {"id": "custom-prod", "name": "prod-1", "public_ip": "10.0.0.1",
             "username": "ubuntu", "port": 2222, "is_custom": True},
        ]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            assert screen.query_one("#input_share_username", Input).value == "ubuntu"
            assert screen.query_one("#input_share_port", Input).value == "2222"

    @pytest.mark.asyncio
    async def test_share_all_pushes_every_eligible_instance(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        # Mix: two AWS rows, one custom row with non-default port, one stopped (no IP).
        instances = [
            {"id": "i-1", "name": "aws-1", "public_ip": "1.1.1.1", "region": "eu-west-2"},
            {"id": "i-2", "name": "aws-2", "public_ip": "2.2.2.2", "region": "us-east-1"},
            {"id": "custom-3", "name": "prod-db", "public_ip": "10.0.0.3",
             "username": "ubuntu", "port": 2222},
            {"id": "i-stop", "name": "stopped", "public_ip": "", "private_ip": ""},
        ]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = []  # nothing shared yet
            screen._action_share_all_servers()
            for _ in range(10):
                await pilot.pause()
            # 3 eligible (skipped stopped). Each gets its own POST.
            assert team_svc.push_server.call_count == 3
            sent_names = [c.args[1]["name"] for c in team_svc.push_server.call_args_list]
            assert sent_names == ["aws-1", "aws-2", "prod-db"]
            # Custom server's username + non-default port came through.
            custom_payload = team_svc.push_server.call_args_list[2].args[1]
            assert custom_payload["username"] == "ubuntu"
            assert custom_payload["port"] == 2222

    @pytest.mark.asyncio
    async def test_share_all_skips_already_shared_by_instance_id(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [
            {"id": "i-1", "name": "aws-1", "public_ip": "1.1.1.1"},
            {"id": "i-2", "name": "aws-2", "public_ip": "2.2.2.2"},
        ]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = [
                {"name": "aws-1", "hostname": "1.1.1.1", "instance_id": "i-1"},
            ]
            screen._action_share_all_servers()
            for _ in range(10):
                await pilot.pause()
            assert team_svc.push_server.call_count == 1
            assert team_svc.push_server.call_args.args[1]["name"] == "aws-2"

    @pytest.mark.asyncio
    async def test_share_all_skips_already_shared_by_hostname_when_no_instance_id(self):
        # Custom servers without instance_id should still dedupe by hostname.
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [
            {"id": "custom-x", "name": "no-id-server", "public_ip": "10.5.5.5"},
        ]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = [
                {"name": "no-id-server", "hostname": "10.5.5.5"},  # no instance_id field
            ]
            screen._action_share_all_servers()
            for _ in range(10):
                await pilot.pause()
            team_svc.push_server.assert_not_called()

    @pytest.mark.asyncio
    async def test_share_all_noop_when_everything_already_shared(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [{"id": "i-1", "name": "aws-1", "public_ip": "1.1.1.1"}]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = [
                {"name": "aws-1", "hostname": "1.1.1.1", "instance_id": "i-1"},
            ]
            notes = _capture_notifications(screen)
            screen._action_share_all_servers()
            await pilot.pause()
            team_svc.push_server.assert_not_called()
            assert any("Already shared: 1" in msg for _, msg in notes), notes

    @pytest.mark.asyncio
    async def test_share_all_continues_on_individual_failure_and_reports_summary(self):
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [
            {"id": "i-1", "name": "aws-1", "public_ip": "1.1.1.1"},
            {"id": "i-2", "name": "aws-2", "public_ip": "2.2.2.2"},
            {"id": "i-3", "name": "aws-3", "public_ip": "3.3.3.3"},
        ]
        # Middle one 409s; others succeed. Sequential loop must not abort.
        team_svc.push_server = AsyncMock(side_effect=[
            {"id": "share-1"},
            APIError(code="conflict", message="Server with that hostname already shared.", status=409),
            {"id": "share-3"},
        ])
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = []
            notes = _capture_notifications(screen)
            screen._action_share_all_servers()
            for _ in range(15):
                await pilot.pause()
            assert team_svc.push_server.call_count == 3
            summary_notes = [msg for sev, msg in notes if sev == "warning" and "Shared 2" in msg]
            assert summary_notes, notes
            assert any("failed 1" in msg for msg in summary_notes), summary_notes

    @pytest.mark.asyncio
    async def test_share_form_skips_port_prefill_when_default_22(self):
        # If the instance is on the SSH default, leave the field blank — placeholder
        # already tells the user that empty == 22.
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [
            {"id": "custom-prod", "name": "prod-1", "public_ip": "10.0.0.1",
             "username": "ubuntu", "port": 22, "is_custom": True},
        ]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._show_share_server_form(instances)
            await pilot.pause()
            assert screen.query_one("#input_share_username", Input).value == "ubuntu"
            assert screen.query_one("#input_share_port", Input).value == ""
