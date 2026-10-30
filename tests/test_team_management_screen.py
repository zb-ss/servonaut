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
                    "accept_url": "https://staging.example.com/invite/abc123",
                },
            ],
        }
    )
    svc.list_shared_servers = AsyncMock(
        return_value=[
            {"name": "web-01", "host": "1.2.3.4", "provider": "aws"},
        ]
    )
    svc.list_team_configs = AsyncMock(return_value=[])
    svc.create_team = AsyncMock(return_value={"slug": "new-team", "name": "New Team"})
    svc.invite_member = AsyncMock(return_value={"email_sent": True})
    svc.resend_invite = AsyncMock(return_value={"email_sent": True})
    svc.remove_member = AsyncMock(return_value={})
    svc.update_role = AsyncMock(return_value={})
    svc.push_server = AsyncMock(return_value={})
    async def push_servers(_slug, payloads, *, on_progress=None, **_options):
        from servonaut.services.team_service import FAILED, SHARED, ShareResult

        results = []
        for index, payload in enumerate(payloads, start=1):
            try:
                created = await svc.push_server(_slug, payload)
                result = ShareResult(payload, SHARED, server=created)
            except Exception as exc:
                result = ShareResult(payload, FAILED, error=getattr(exc, "message", str(exc)))
            results.append(result)
            if on_progress is not None:
                on_progress(index, len(payloads), result)
        return results
    svc.push_servers = AsyncMock(side_effect=push_servers)
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
                    "accept_url": "https://staging.example.com/invite/xyz",
                },
            ]
            tbl = screen.query_one("#members_table", DataTable)
            tbl.add_row("bob@example.com", "member", "Invited")
            tbl.move_cursor(row=0)
            copied: list[str] = []
            app.copy_to_clipboard = lambda text: copied.append(text)  # type: ignore[method-assign]
            screen._action_copy_accept_url()
            await pilot.pause()
            assert copied == ["https://staging.example.com/invite/xyz"]

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


async def _until(pilot, predicate, what: str, tries: int = 200) -> None:
    """Pause until *predicate* holds; fail naming *what* if it never does."""
    for _ in range(tries):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {what}")


async def _confirm_share_all(app, pilot) -> None:
    """Confirm Share All's server list as it opened (every server ticked)."""
    from servonaut.screens.team_share_confirm import ShareServersConfirmModal

    def listed() -> bool:
        modal = app.screen
        if not isinstance(modal, ShareServersConfirmModal):
            return False
        rows = modal.query("#share_confirm_list")
        return bool(rows) and rows.first().option_count > 0

    await _until(pilot, listed, "the Share All confirmation and its rows")
    app.screen.query_one("#share_confirm_share", Button).press()


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
        # Only a custom server's own username is a sharing default.
        instances[2]["is_custom"] = True
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._loaded_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = []  # nothing shared yet
            screen._action_share_all_servers()
            await _confirm_share_all(app, pilot)
            # 3 eligible (skipped stopped). Each gets its own POST.
            await _until(pilot, lambda: team_svc.push_server.call_count == 3, "three shares")
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
            screen._loaded_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = [
                {"name": "aws-1", "hostname": "1.1.1.1", "instance_id": "i-1"},
            ]
            screen._action_share_all_servers()
            await _confirm_share_all(app, pilot)
            await _until(pilot, lambda: team_svc.push_server.call_count == 1, "one share")
            assert team_svc.push_server.call_args.args[1]["name"] == "aws-2"

    @pytest.mark.asyncio
    async def test_share_all_skips_already_shared_by_public_hostname_when_no_instance_id(self):
        # Custom servers without instance_id should still dedupe by hostname.
        auth = _make_auth_service(authenticated=True)
        team_svc = _make_team_service()
        instances = [
            {"id": "custom-x", "name": "no-id-server", "public_ip": "web.example.com"},
        ]
        app = _WrapperApp(auth_service=auth, team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._loaded_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = [
                {"name": "no-id-server", "hostname": "web.example.com"},  # no instance_id field
            ]
            screen._action_share_all_servers()
            for _ in range(10):
                await pilot.pause()
            assert app.screen is screen
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
            screen._loaded_team_slug = "eng"
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
            screen._loaded_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = []
            notes = _capture_notifications(screen)
            screen._action_share_all_servers()
            await _confirm_share_all(app, pilot)
            await _until(pilot, lambda: any("Share All:" in msg for _, msg in notes), "the summary")
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


# ---------------------------------------------------------------------------
# Share Server / Share All: which address a server is shared under
# ---------------------------------------------------------------------------


def _routing(app, behind_bastion: set[str]) -> None:
    """Connection rules that reach the servers named in *behind_bastion* through a bastion."""
    from servonaut.config.schema import ConnectionProfile

    jump = ConnectionProfile(name="via-jump", bastion_host="jump-1.example.com", bastion_user="ops")
    app.connection_service = MagicMock()
    app.connection_service.resolve_profile.side_effect = (
        lambda instance: jump if instance.get("name") in behind_bastion else None
    )


_BEHIND = {"id": "i-0a1", "name": "app-1", "public_ip": "1.1.1.1", "private_ip": "10.0.1.5"}
_DIRECT = {"id": "i-0b2", "name": "web-1", "public_ip": "8.8.8.8", "private_ip": "10.0.1.6"}


class TestShareAddress:
    async def _open_form(self, pilot, app, instance_id: str):
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        screen._current_team_slug = "eng"
        screen._current_team_role = "owner"
        screen._show_share_server_form(app.instances)
        await pilot.pause()
        screen.query_one("#select_share_instance", Select).value = instance_id
        await pilot.pause()
        return screen

    @pytest.mark.asyncio
    @pytest.mark.parametrize("instance, expected", [(_BEHIND, "private"), (_DIRECT, "public")])
    async def test_share_form_defaults_to_the_private_address_behind_a_bastion(self, instance, expected):
        team_svc = _make_team_service()
        app = _WrapperApp(
            auth_service=_make_auth_service(authenticated=True), team_service=team_svc,
            instances=[dict(_BEHIND), dict(_DIRECT)],
        )
        _routing(app, {"app-1"})
        async with app.run_test(headless=True) as pilot:
            screen = await self._open_form(pilot, app, instance["id"])
            address = screen.query_one("#select_share_address", Select)
            note = str(screen.query_one("#share_address_note", Static).render())
            assert address.display is True and address.value == expected
            assert ("rules reach this server through a bastion" in note) is (expected == "private")
            screen._submit_share_server()
            await _until(pilot, lambda: team_svc.push_server.called, "the share")

        _, payload = team_svc.push_server.call_args.args
        assert payload["hostname"] == instance[f"{expected}_ip"]
        assert payload["instance_id"] == instance["id"]

    @pytest.mark.asyncio
    async def test_share_form_shares_the_address_the_user_chose(self):
        team_svc = _make_team_service()
        app = _WrapperApp(
            auth_service=_make_auth_service(authenticated=True), team_service=team_svc,
            instances=[dict(_BEHIND)],
        )
        _routing(app, {"app-1"})
        async with app.run_test(headless=True) as pilot:
            screen = await self._open_form(pilot, app, "i-0a1")
            screen.query_one("#select_share_address", Select).value = "public"
            screen._submit_share_server()
            await _until(pilot, lambda: team_svc.push_server.called, "the share")

        assert team_svc.push_server.call_args.args[1]["hostname"] == "1.1.1.1"

    @pytest.mark.asyncio
    async def test_share_form_offers_no_choice_for_a_server_with_one_address(self):
        app = _WrapperApp(
            auth_service=_make_auth_service(authenticated=True), team_service=_make_team_service(),
            instances=[{"id": "custom-a", "name": "db-1", "public_ip": "10.0.0.9", "private_ip": "10.0.0.9",
                        "is_custom": True}],
        )
        _routing(app, {"db-1"})
        async with app.run_test(headless=True) as pilot:
            screen = await self._open_form(pilot, app, "custom-a")
            assert screen.query_one("#select_share_address", Select).display is False
            assert screen.query_one("#share_address_note", Static).display is False

    @pytest.mark.asyncio
    async def test_share_all_shares_bastion_routed_servers_under_their_private_address(self):
        from servonaut.screens.team_share_confirm import ShareServersConfirmModal

        team_svc = _make_team_service()
        notices: list[str] = []
        app = _WrapperApp(
            auth_service=_make_auth_service(authenticated=True), team_service=team_svc,
            instances=[dict(_BEHIND), dict(_DIRECT)],
        )
        _routing(app, {"app-1"})
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            screen = app.screen
            screen.notify = lambda message, **_kwargs: notices.append(str(message))
            screen._current_team_slug = screen._loaded_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = []
            screen._action_share_all_servers()
            await _until(pilot, lambda: isinstance(app.screen, ShareServersConfirmModal), "the confirmation")
            await pilot.pause()
            modal = app.screen
            listing = modal.query_one("#share_confirm_list")
            rows = [str(listing.get_option_at_index(index).prompt) for index in range(listing.option_count)]
            assert "10.0.1.5" in rows[0] and "private address" in rows[0]
            assert "8.8.8.8" in rows[1] and "private address" not in rows[1]
            assert "bastion" in str(modal.query_one("#share_confirm_intro", Static).render())
            await _confirm_share_all(app, pilot)
            await _until(pilot, lambda: team_svc.push_server.call_count == 2, "two shares")
            await _until(pilot, lambda: any(n.startswith("Share All:") for n in notices), "the summary")

        hosts = {call.args[1]["name"]: call.args[1]["hostname"] for call in team_svc.push_server.call_args_list}
        assert hosts == {"app-1": "10.0.1.5", "web-1": "8.8.8.8"}
        summary = next(n for n in notices if n.startswith("Share All:"))
        assert "1 under its private address" in summary


def test_share_payload_uses_the_address_chosen_for_the_server() -> None:
    from servonaut.services.team_sharing import SHARE_ADDRESS, share_payload

    server = {"id": "i-0a1", "name": "app-1", "public_ip": "1.1.1.1", "private_ip": "10.0.1.5"}
    assert share_payload(server)["hostname"] == "1.1.1.1"
    assert share_payload({**server, SHARE_ADDRESS: "10.0.1.5"})["hostname"] == "10.0.1.5"
    assert SHARE_ADDRESS not in share_payload({**server, SHARE_ADDRESS: "10.0.1.5"})


# Two hosting accounts on one machine: same host and port, different logins.
def _account(name: str, username: str) -> dict:
    return {"id": f"custom-{name}", "name": name, "public_ip": "9.9.9.9", "private_ip": "9.9.9.9",
            "port": 22, "username": username, "is_custom": True}


_SITE_A, _SITE_B = _account("site-a", "alpha"), _account("site-b", "beta")
_SITE_A_SHARED = {"id": "srv-1", "name": "site-a", "hostname": "9.9.9.9", "instance_id": "custom-site-a",
                  "username": "alpha"}


def test_another_login_at_a_shared_address_is_another_server() -> None:
    from servonaut.services.team_sharing import already_shared

    assert already_shared(_SITE_A, [_SITE_A_SHARED])
    assert not already_shared(_SITE_B, [_SITE_A_SHARED])
    # A share recorded without an id is still matched by address and login.
    unrecorded = {k: v for k, v in _SITE_A_SHARED.items() if k != "instance_id"}
    assert already_shared({**_SITE_B, "id": "", "username": "alpha"}, [unrecorded])
    assert not already_shared({**_SITE_B, "id": ""}, [unrecorded])
    # Without a login on either side, the address and port still decide.
    assert already_shared({**_SITE_B, "username": ""}, [unrecorded])


def test_share_candidates_offer_every_login_on_one_machine() -> None:
    from servonaut.services.team_sharing import share_candidates

    offered, skipped, _missing = share_candidates([_SITE_A, _SITE_B], [])
    assert [row["name"] for row in offered] == ["site-a", "site-b"] and skipped == 0
    offered, skipped, _missing = share_candidates([_SITE_A, _SITE_B], [_SITE_A_SHARED])
    assert [row["name"] for row in offered] == ["site-b"] and skipped == 1


class TestEveryLoginCanBeShared:
    @pytest.mark.asyncio
    async def test_share_server_offers_and_shares_a_second_login_at_a_shared_address(self):
        team_svc = _make_team_service()
        app = _WrapperApp(
            auth_service=_make_auth_service(authenticated=True), team_service=team_svc,
            instances=[dict(_SITE_A), dict(_SITE_B)],
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "eng"
            screen._current_team_role = "owner"
            screen._shared_servers = [dict(_SITE_A_SHARED)]
            screen._show_share_server_form(app.instances)
            await pilot.pause()
            select = screen.query_one("#select_share_instance", Select)
            assert select.value == "custom-site-b"
            screen._submit_share_server()
            await _until(pilot, lambda: team_svc.push_server.called, "the share")

        _, payload = team_svc.push_server.call_args.args
        assert (payload["name"], payload["hostname"], payload["username"]) == ("site-b", "9.9.9.9", "beta")


@pytest.mark.asyncio
async def test_pushing_a_second_login_is_not_refused_as_already_shared() -> None:
    from servonaut.services.team_service import TeamService

    api = MagicMock()
    api.get = AsyncMock(return_value={"data": [dict(_SITE_A_SHARED)]})
    api.post = AsyncMock(return_value={"data": {"id": "srv-2"}})
    service = TeamService(api)

    assert await service.push_server("eng", {"name": "site-b", "hostname": "9.9.9.9", "username": "beta",
                                             "instance_id": "custom-site-b"}) == {"id": "srv-2"}


# ---------------------------------------------------------------------------
# Shared servers: listed in the server list, connected from here
# ---------------------------------------------------------------------------


class TestSharedServerConnect:
    _SERVERS = [
        {"id": "srv-1", "name": "web-01", "hostname": "web.example.com", "port": 22},
        {"id": "srv-2", "name": "db-01", "hostname": "db.example.com", "port": 2222},
    ]

    @staticmethod
    def _stub_server_actions(opened: list):
        from textual.screen import Screen

        class _ServerActions(Screen):
            def __init__(self, instance):
                super().__init__()
                opened.append(instance)

            def action_action_3(self) -> None:
                opened.append("connect")

        return _ServerActions

    @pytest.mark.asyncio
    async def test_a_viewed_team_s_servers_join_the_server_list(self):
        team_svc = _make_team_service(_SAMPLE_TEAMS)
        team_svc.list_shared_servers = AsyncMock(return_value=list(self._SERVERS))
        app = _WrapperApp(
            auth_service=_make_auth_service(), team_service=team_svc,
            instances=[{"id": "i-0abc", "name": "app-1"}],
        )
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await pilot.pause()
            await app.screen._load_team_detail("ops")
            await pilot.pause()

        names = [(row["name"], row.get("team_slug")) for row in app.instances]
        assert names == [("app-1", None), ("web-01", "ops"), ("db-01", "ops")]
        assert app.instances[2]["provider"] == "Team Engineering"

    @pytest.mark.asyncio
    async def test_connect_opens_the_selected_server_and_starts_ssh(self):
        from unittest.mock import patch

        team_svc = _make_team_service(_SAMPLE_TEAMS)
        team_svc.list_shared_servers = AsyncMock(return_value=list(self._SERVERS))
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=team_svc)
        opened: list = []
        with patch(
            "servonaut.screens.server_actions.ServerActionsScreen",
            self._stub_server_actions(opened),
        ):
            async with app.run_test(headless=True, size=(160, 50)) as pilot:
                await pilot.pause()
                screen = app.screen
                screen._current_team_slug = "ops"
                await screen._load_team_detail("ops")
                await pilot.pause()
                screen.query_one("#servers_table", DataTable).move_cursor(row=1)
                screen.query_one("#btn_connect_shared", Button).press()
                await pilot.pause()

        assert opened[0]["id"] == "srv-2"
        assert opened[0]["is_shared"] is True
        assert opened[0]["public_ip"] == "db.example.com"
        assert opened[0]["port"] == 2222
        assert opened[1] == "connect"

    @staticmethod
    def _admin_team_service(servers: list[dict]) -> MagicMock:
        teams = [
            {"id": 7, "slug": "eng", "name": "Engineering", "role": "admin", "member_count": 3},
            {"id": 8, "slug": "ops", "name": "Ops", "role": "member", "member_count": 1},
        ]
        team_svc = _make_team_service(teams)
        # The detail read names no role: the team list's role is the caller's.
        team_svc.get_team = AsyncMock(
            return_value={"id": 7, "slug": "eng", "name": "Engineering", "members": []},
        )
        team_svc.list_shared_servers = AsyncMock(return_value=list(servers))
        return team_svc

    @pytest.mark.asyncio
    async def test_viewing_a_team_keeps_the_callers_role_and_team_id_on_its_rows(self):
        # Regression: the rows were rebuilt from the slug and name alone, so
        # team_role and team_id came out '' and Auto-bind, Use Vault Key and
        # the team agent rules lost the caller's role until a restart.
        from servonaut.screens.server_actions import _can_bind_team

        team_svc = self._admin_team_service(self._SERVERS)
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=team_svc)
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await pilot.pause()
            await _until(pilot, lambda: bool(app.screen._team_roles), "the team list")
            await app.screen._load_team_detail("eng")
            await pilot.pause()

        shared = [row for row in app.instances if row.get("is_shared")]
        assert [row["name"] for row in shared] == ["web-01", "db-01"]
        for row in shared:
            assert row["team_slug"] == "eng"
            assert row["team_id"] == "7"
            assert row["team_role"] == "admin"
            assert row["team_name"] == "Engineering"
            assert _can_bind_team(row)

    @pytest.mark.asyncio
    async def test_share_all_keeps_the_callers_role_on_the_teams_rows(self):
        team_svc = self._admin_team_service(self._SERVERS)
        app = _WrapperApp(
            auth_service=_make_auth_service(), team_service=team_svc,
            instances=[{"id": "i-1", "name": "app-1", "public_ip": "1.1.1.1"}],
        )
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await pilot.pause()
            await _until(pilot, lambda: bool(app.screen._team_roles), "the team list")
            screen = app.screen
            screen._current_team_slug = "eng"
            await screen._load_team_detail("eng")
            screen._action_share_all_servers()
            await _confirm_share_all(app, pilot)
            await _until(pilot, lambda: team_svc.list_shared_servers.await_count >= 2, "the reload")
            await pilot.pause()

        shared = [row for row in app.instances if row.get("is_shared")]
        assert shared and all(row["team_role"] == "admin" for row in shared)
        assert all(row["team_id"] == "7" for row in shared)

    @pytest.mark.asyncio
    async def test_connect_with_nothing_shared_says_so(self):
        team_svc = _make_team_service(_SAMPLE_TEAMS)
        team_svc.list_shared_servers = AsyncMock(return_value=[])
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=team_svc)
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            await pilot.pause()
            screen = app.screen
            screen._current_team_slug = "ops"
            await screen._load_team_detail("ops")
            screen.query_one("#btn_connect_shared", Button).press()
            await pilot.pause()
            messages = [str(n.message) for n in app._notifications]

        assert "This team shares no servers yet." in messages


# ---------------------------------------------------------------------------
# What agents may do here (the team's agent rules, read-only)
# ---------------------------------------------------------------------------


class TestAgentRulesCard:
    """Viewing a team shows what members' agents may do on its servers now."""

    _SERVERS = [{"id": "srv-1", "name": "web-01", "hostname": "web.example.com"}]

    @staticmethod
    def _team_service(agent_rules=None):
        from tests._team_policy_fixtures import envelope, response, team_id_for

        team_svc = _make_team_service(
            [{"id": team_id_for("ops"), "slug": "ops", "name": "Ops", "role": "member",
              "member_count": 3}],
        )
        team_svc.get_team = AsyncMock(return_value={"name": "Ops", "slug": "ops", "members": []})
        team_svc.list_shared_servers = AsyncMock(return_value=list(TestAgentRulesCard._SERVERS))
        team_svc.get_team_policy_with_date = AsyncMock(
            return_value=(response(envelope(team_id_for("ops"), agent_rules)), None),
        )
        return team_svc

    @staticmethod
    def _app(team_svc, *, refresher=True):
        from servonaut.services.team_policy_refresh import TeamPolicyRefresher
        from tests._team_policy_fixtures import process_store, trust_test_key

        trust_test_key()
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=team_svc)
        app.team_policy = (
            TeamPolicyRefresher(process_store(), lambda: team_svc) if refresher else None
        )
        return app

    @staticmethod
    async def _open(app, pilot):
        await pilot.pause()
        screen = app.screen
        screen._current_team_slug = "ops"
        await screen._load_team_detail("ops")
        await pilot.pause()
        return str(screen.query_one("#agent_rules_body", Static).render())

    @pytest.mark.asyncio
    async def test_the_team_s_rules_are_fetched_and_shown(self):
        from tests._team_policy_fixtures import agent_rules_with, team_id_for

        team_svc = self._team_service(agent_rules_with(
            role_levels={"member": "readonly"},
            servers={"srv-1": {"role_levels": {"admin": "dangerous"}}},
            command_blocklist=[r"\bcurl\b"],
        ))
        app = self._app(team_svc)
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            text = await self._open(app, pilot)
            card = app.screen.query_one("#agent_rules_section")
            assert card.display is True

        assert "Owner: standard · Admin: standard · Member: readonly · Viewer: readonly" in text
        assert "Your role: member (readonly)" in text
        assert "web-01: Admin dangerous" in text
        assert "Servonaut's built-in list" in text
        assert r"\bcurl\b" in text
        assert "Version 1 · last refreshed" in text
        # Fetched by the team's id, without a second team-list request.
        team_svc.get_team_policy_with_date.assert_awaited_once_with("ops")
        assert team_svc.list_teams.await_count == 1
        assert app.team_policy.store.status("ops").team_id == team_id_for("ops")

    @pytest.mark.asyncio
    async def test_a_fallback_says_agents_run_readonly_and_why(self):
        from servonaut.services.team_policy import MISSING
        from tests._team_policy_fixtures import response

        team_svc = self._team_service()
        team_svc.get_team_policy_with_date = AsyncMock(return_value=(response(None), None))
        app = self._app(team_svc)
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            text = await self._open(app, pilot)

        assert (
            "Agents run at the readonly level on this team's shared servers, owners "
            f"included, because {MISSING.reason}."
        ) in " ".join(text.split())

    @pytest.mark.asyncio
    async def test_without_a_refresher_the_rules_this_device_has_are_shown(self):
        team_svc = self._team_service()
        app = self._app(team_svc, refresher=False)
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            text = await self._open(app, pilot)

        assert "have not been loaded yet" in " ".join(text.split())
        team_svc.get_team_policy_with_date.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_rules_of_a_team_that_used_the_slug_before_are_not_shown(self):
        from tests._team_policy_fixtures import agent_rules_with, envelope, process_store, response

        team_svc = self._team_service()
        app = self._app(team_svc, refresher=False)
        renamed = {"id": "team-id-renamed", "slug": "ops", "name": "Old Ops", "role": "member"}
        process_store().apply_response(renamed, response(envelope(
            "team-id-renamed", agent_rules_with(role_levels={"member": "dangerous"}),
        )))
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            text = " ".join((await self._open(app, pilot)).split())

        # The team opened is the team list's "ops", not the one saved under it.
        assert "Member: dangerous" not in text
        assert "have not been loaded yet" in text

    @pytest.mark.asyncio
    async def test_the_card_is_hidden_until_a_team_is_opened(self):
        app = self._app(self._team_service())
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            assert app.screen.query_one("#agent_rules_section").display is False

    @pytest.mark.asyncio
    async def test_team_text_is_shown_as_text_not_markup(self):
        from tests._team_policy_fixtures import agent_rules_with

        team_svc = self._team_service(agent_rules_with(command_blocklist=["[bold]x[/bold]"]))
        app = self._app(team_svc)
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            text = await self._open(app, pilot)

        assert "[bold]x[/bold]" in text

    @pytest.mark.asyncio
    async def test_demo_mode_redacts_server_names_and_team_text(self):
        from servonaut.services.redaction_service import RedactionService
        from tests._team_policy_fixtures import agent_rules_with

        team_svc = self._team_service(agent_rules_with(
            servers={"srv-1": {"role_levels": {"admin": "dangerous"}}},
            command_blocklist=[r"ssh 10\.50\.20\.1|10.50.20.1"],
        ))
        app = self._app(team_svc)
        app.demo_mode = True
        app.redaction_service = RedactionService()
        async with app.run_test(headless=True, size=(160, 50)) as pilot:
            text = await self._open(app, pilot)

        assert "web-01" not in text
        assert ": Admin dangerous" in text
        assert "10.50.20.1" not in text
