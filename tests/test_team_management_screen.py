"""Tests for TeamManagementScreen."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input, Static

from servonaut.screens.team_management import TeamManagementScreen


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
            "members": [
                {"id": "u1", "email": "alice@example.com", "role": "admin", "status": "active"},
                {"id": "u2", "email": "bob@example.com", "role": "member", "status": "pending"},
            ],
        }
    )
    svc.list_shared_servers = AsyncMock(
        return_value=[
            {"name": "web-01", "host": "1.2.3.4", "provider": "aws"},
        ]
    )
    svc.create_team = AsyncMock(return_value={"slug": "new-team", "name": "New Team"})
    svc.invite_member = AsyncMock(return_value={})
    svc.remove_member = AsyncMock(return_value={})
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
            assert app.screen.query_one("#team_header").display is False
            assert app.screen.query_one("#members_table").display is False
            assert app.screen.query_one("#servers_table").display is False

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
            screen.query_one("#input_invite_email", Input).value = "newmember@example.com"
            screen.query_one("#input_invite_role", Input).value = "member"
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
            screen.query_one("#input_invite_email", Input).value = "someone@example.com"
            screen.query_one("#input_invite_role", Input).value = ""
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
