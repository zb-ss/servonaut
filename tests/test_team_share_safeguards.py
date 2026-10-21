"""The Teams screen asks before servers leave for a team.

Share All lists every server it would share and sends nothing until the user
confirms; the push-config form shares only the custom servers the user ticks
(none by default) and shows the connection profiles that go with them.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.widgets import Button, SelectionList, Static

from servonaut.config.schema import AppConfig, ConnectionProfile, CustomServer
from servonaut.screens.team_management import TeamManagementScreen
from servonaut.screens.team_share_confirm import ShareServersConfirmModal
from servonaut.services.redaction_service import RedactionService
from tests.test_team_management_screen import (
    _WrapperApp,
    _capture_notifications,
    _make_auth_service,
    _make_team_service,
    _until,
)

pytestmark = pytest.mark.asyncio

TEAM = "Engineering"
SHAREABLE = [
    {"id": "i-1", "name": "web-1", "public_ip": "1.1.1.1", "region": "eu-west-2"},
    {"id": "i-2", "name": "db-1", "private_ip": "10.0.0.2"},
    {"id": "custom-3", "name": "lab-1", "public_ip": "9.9.9.9"},
]


class _ConfigApp(_WrapperApp):
    """The test host plus a config manager, for the push-config form."""

    def __init__(self, *, config: AppConfig, config_manager=None, **kwargs) -> None:
        super().__init__(**kwargs)
        if config_manager is None:
            config_manager = MagicMock()
            config_manager.get.return_value = config
        self.config_manager = config_manager


async def _open_team(app, pilot) -> TeamManagementScreen:
    await _until(pilot, lambda: isinstance(app.screen, TeamManagementScreen), "the Teams screen")
    screen = app.screen
    screen._current_team_slug = "eng"
    screen._current_team_name = TEAM
    screen._current_team_role = "owner"
    screen._shared_servers = []
    screen._show_detail_section()  # as View Team does: the team's cards are on screen
    return screen


async def _open_share_all(app, pilot) -> ShareServersConfirmModal:
    screen = await _open_team(app, pilot)
    screen._action_share_all_servers()

    def listed() -> bool:
        modal = app.screen
        return isinstance(modal, ShareServersConfirmModal) and bool(
            modal.query("#share_confirm_list") and modal.query_one("#share_confirm_list").option_count
        )

    await _until(pilot, listed, "the Share All confirmation")
    return app.screen


def _rows(listing: SelectionList) -> list[tuple[str, bool]]:
    selected = set(listing.selected)
    return [
        (str(listing.get_option_at_index(i).prompt), listing.get_option_at_index(i).value in selected)
        for i in range(listing.option_count)
    ]


def _text(widget: Static) -> str:
    return str(widget.render())


class TestShareAllConfirmation:
    async def test_lists_every_server_and_sends_nothing_until_confirmed(self):
        team_svc = _make_team_service()
        instances = [*SHAREABLE, {"id": "i-4", "name": "off-1"}]
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=team_svc, instances=instances)
        async with app.run_test(headless=True) as pilot:
            await _open_team(app, pilot)
            app.screen._shared_servers = [{"name": "old", "hostname": "8.8.8.8", "instance_id": "i-9"}]
            app.screen._action_share_all_servers()
            await _until(pilot, lambda: isinstance(app.screen, ShareServersConfirmModal), "the confirmation")
            modal = app.screen
            await _until(
                pilot,
                lambda: bool(modal.query("#share_confirm_list"))
                and modal.query_one("#share_confirm_list").option_count == 3,
                "the rows",
            )

            # Names are padded to the longest, so the addresses line up.
            assert _rows(modal.query_one("#share_confirm_list", SelectionList)) == [
                ("web-1  1.1.1.1", True), ("db-1   10.0.0.2", True), ("lab-1  9.9.9.9", True),
            ]
            assert _text(modal.query_one("#share_confirm_title", Static)) == f"Share servers with {TEAM}?"
            assert _text(modal.query_one("#share_confirm_skipped", Static)) == (
                "Not listed: 1 server without an address."
            )
            assert modal.query_one("#share_confirm_cancel", Button).has_focus
            assert str(modal.query_one("#share_confirm_share", Button).label) == "Share 3 servers"
            team_svc.push_server.assert_not_called()

    async def test_escape_cancels_and_shares_nothing(self):
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=team_svc, instances=SHAREABLE)
        async with app.run_test(headless=True) as pilot:
            await _open_share_all(app, pilot)
            await pilot.press("escape")
            await _until(pilot, lambda: isinstance(app.screen, TeamManagementScreen), "the Teams screen again")
            for _ in range(5):
                await pilot.pause()
            team_svc.push_server.assert_not_called()

    async def test_enter_on_the_focused_cancel_shares_nothing(self):
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=team_svc, instances=SHAREABLE)
        async with app.run_test(headless=True) as pilot:
            await _open_share_all(app, pilot)
            await pilot.press("enter")
            await _until(pilot, lambda: isinstance(app.screen, TeamManagementScreen), "the Teams screen again")
            for _ in range(5):
                await pilot.pause()
            team_svc.push_server.assert_not_called()

    async def test_unticked_servers_are_left_out(self):
        team_svc = _make_team_service()
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=team_svc, instances=SHAREABLE)
        async with app.run_test(headless=True) as pilot:
            notes = _capture_notifications(app.screen)
            modal = await _open_share_all(app, pilot)
            listing = modal.query_one("#share_confirm_list", SelectionList)
            listing.deselect(1)  # db-1
            button = modal.query_one("#share_confirm_share", Button)
            await _until(pilot, lambda: str(button.label) == "Share 2 servers", "the count to follow")
            button.press()
            await _until(pilot, lambda: any("Share All:" in msg for _, msg in notes), "the summary")

            assert [c.args[1]["name"] for c in team_svc.push_server.call_args_list] == ["web-1", "lab-1"]
            assert any(msg == "Share All: Shared 2, left out 1." for _, msg in notes), notes

    async def test_select_none_disables_share_and_select_all_restores_it(self):
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service(),
                          instances=SHAREABLE)
        async with app.run_test(headless=True) as pilot:
            modal = await _open_share_all(app, pilot)
            button = modal.query_one("#share_confirm_share", Button)
            modal.query_one("#share_confirm_none", Button).press()
            await _until(pilot, lambda: button.disabled, "Share to be disabled")
            assert str(button.label) == "Share 0 servers"
            modal.query_one("#share_confirm_all", Button).press()
            await _until(pilot, lambda: not button.disabled, "Share to be enabled")
            assert str(button.label) == "Share 3 servers"

    @pytest.mark.parametrize("size", [(160, 50), (100, 30), (80, 24)], ids=["160x50", "100x30", "80x24"])
    async def test_cancel_and_share_stay_on_screen_with_a_long_list(self, size):
        instances = [{"id": f"i-{n}", "name": f"server-{n}", "public_ip": f"10.0.9.{n}"} for n in range(1, 21)]
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service(),
                          instances=instances)
        async with app.run_test(headless=True, size=size) as pilot:
            modal = await _open_share_all(app, pilot)
            await pilot.pause()
            box = modal.query_one("#share_confirm_modal").region
            assert box.bottom <= size[1], (box, size)
            for button_id in ("#share_confirm_cancel", "#share_confirm_share"):
                button = modal.query_one(button_id).region
                assert button.height == 3 and box.contains_region(button), (button_id, button, box)

    async def test_server_names_are_shown_literally(self):
        instances = [{"id": "i-1", "name": "[bold]web[/bold]", "public_ip": "1.1.1.1"}]
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service(),
                          instances=instances)
        async with app.run_test(headless=True) as pilot:
            modal = await _open_share_all(app, pilot)
            [(label, _ticked)] = _rows(modal.query_one("#share_confirm_list", SelectionList))
            assert label == "[bold]web[/bold]  1.1.1.1"

    async def test_demo_mode_hides_the_team_name_and_the_toggle_redraws(self):
        app = _WrapperApp(auth_service=_make_auth_service(), team_service=_make_team_service(),
                          instances=SHAREABLE)
        async with app.run_test(headless=True) as pilot:
            app.demo_mode = True
            app.redaction_service = RedactionService()
            modal = await _open_share_all(app, pilot)
            title = modal.query_one("#share_confirm_title", Static)
            assert TEAM not in _text(title)

            modal.query_one("#share_confirm_list", SelectionList).deselect(0)
            app.demo_mode = False
            modal.refresh_after_demo_toggle()
            assert _text(title) == f"Share servers with {TEAM}?"
            assert [ticked for _label, ticked in _rows(modal.query_one("#share_confirm_list"))] == [
                False, True, True,
            ]


def _push_config() -> AppConfig:
    config = AppConfig()
    config.custom_servers = [
        CustomServer(name="team-box", host="10.0.0.5", ssh_key="/keys/team"),
        CustomServer(name="private-box", host="10.0.0.6"),
    ]
    config.connection_profiles = [
        ConnectionProfile(name="via-bastion", bastion_host="10.0.0.1", bastion_user="ec2-user",
                          bastion_key="/keys/bastion"),
        ConnectionProfile(name="plain"),
    ]
    return config


def _push_app(config: AppConfig) -> tuple[_ConfigApp, MagicMock]:
    team_svc = _make_team_service()
    team_svc.push_team_config = AsyncMock(return_value={"version": 1})
    team_svc.list_team_configs = AsyncMock(return_value=[])
    return _ConfigApp(config=config, auth_service=_make_auth_service(), team_service=team_svc), team_svc


async def _open_push_form(app, pilot) -> TeamManagementScreen:
    screen = await _open_team(app, pilot)
    screen._action_push_config()
    await _until(pilot, lambda: screen.query_one("#push_config_form").display, "the push form")
    return screen


class TestPushConfigServerPicker:
    async def test_lists_custom_servers_unticked_and_the_profiles_that_go_out(self):
        app, _svc = _push_app(_push_config())
        async with app.run_test(headless=True) as pilot:
            screen = await _open_push_form(app, pilot)
            listing = screen.query_one("#push_config_servers", SelectionList)
            assert _rows(listing) == [("team-box     10.0.0.5", False), ("private-box  10.0.0.6", False)]
            await _until(pilot, lambda: listing.has_focus, "the picker to take focus")
            assert _text(screen.query_one("#push_config_profiles", Static)) == (
                "Connection profiles — all of them are shared\n"
                "  • via-bastion  bastion ec2-user@10.0.0.1\n"
                "  • plain        no bastion"
            )
            # Only the bastion key is stripped while no server is ticked.
            assert _text(screen.query_one("#push_config_preview", Static)) == (
                "Will share: 0 of 2 custom servers, 2 connection profiles, 0 connection rules, "
                "0 scan rules.\n1 local SSH key path(s) will be stripped — teammates must "
                "re-bind them locally."
            )

    async def test_pushing_with_nothing_ticked_sends_no_custom_server(self):
        app, team_svc = _push_app(_push_config())
        async with app.run_test(headless=True) as pilot:
            screen = await _open_push_form(app, pilot)
            screen.query_one("#btn_confirm_push_config", Button).press()
            await _until(pilot, lambda: team_svc.push_team_config.await_count == 1, "the push")
            payload = team_svc.push_team_config.await_args.args[1]
            assert payload["custom_servers"] == []
            assert [p["name"] for p in payload["connection_profiles"]] == ["via-bastion", "plain"]

    async def test_only_the_ticked_server_is_pushed_and_counted(self):
        app, team_svc = _push_app(_push_config())
        async with app.run_test(headless=True) as pilot:
            screen = await _open_push_form(app, pilot)
            preview = screen.query_one("#push_config_preview", Static)
            listing = screen.query_one("#push_config_servers", SelectionList)
            await _until(pilot, lambda: listing.has_focus, "the picker to take focus")
            await pilot.press("space")  # ticks the highlighted first row: team-box
            await _until(pilot, lambda: "1 of 2 custom servers" in _text(preview), "the preview to follow")
            assert "2 local SSH key path(s)" in _text(preview)

            screen.query_one("#btn_confirm_push_config", Button).press()
            await _until(pilot, lambda: team_svc.push_team_config.await_count == 1, "the push")
            [server] = team_svc.push_team_config.await_args.args[1]["custom_servers"]
            assert (server["name"], server["host"], server["ssh_key"]) == ("team-box", "10.0.0.5", "")

    async def test_select_all_and_select_none(self):
        app, _svc = _push_app(_push_config())
        async with app.run_test(headless=True) as pilot:
            screen = await _open_push_form(app, pilot)
            listing = screen.query_one("#push_config_servers", SelectionList)
            preview = screen.query_one("#push_config_preview", Static)
            screen.query_one("#btn_push_servers_all", Button).press()
            await _until(pilot, lambda: "2 of 2 custom servers" in _text(preview), "all ticked")
            assert sorted(listing.selected) == ["private-box", "team-box"]
            screen.query_one("#btn_push_servers_none", Button).press()
            await _until(pilot, lambda: "0 of 2 custom servers" in _text(preview), "none ticked")
            assert listing.selected == []

    async def test_reopening_the_form_starts_with_nothing_ticked(self):
        app, _svc = _push_app(_push_config())
        async with app.run_test(headless=True) as pilot:
            screen = await _open_push_form(app, pilot)
            screen.query_one("#btn_push_servers_all", Button).press()
            listing = screen.query_one("#push_config_servers", SelectionList)
            await _until(pilot, lambda: len(listing.selected) == 2, "all ticked")
            screen.query_one("#btn_cancel_push_config", Button).press()
            await _until(pilot, lambda: not screen.query_one("#push_config_form").display, "form closed")
            await _open_push_form(app, pilot)
            assert listing.selected == []

    async def test_no_custom_servers_hides_the_picker(self):
        config = _push_config()
        config.custom_servers = []
        app, _svc = _push_app(config)
        async with app.run_test(headless=True) as pilot:
            screen = await _open_push_form(app, pilot)
            assert not screen.query_one("#push_config_servers").display
            assert not screen.query_one("#push_config_server_actions").display
            assert _text(screen.query_one("#push_config_servers_label", Static)) == (
                "No custom servers in your config."
            )
            description = screen.query_one("#input_push_description")
            await _until(pilot, lambda: description.has_focus, "the description to take focus")

    async def test_demo_mode_hides_server_and_profile_names(self):
        app, _svc = _push_app(_push_config())
        async with app.run_test(headless=True) as pilot:
            app.demo_mode = True
            app.redaction_service = RedactionService()
            screen = await _open_push_form(app, pilot)
            shown = " ".join(label for label, _ in _rows(screen.query_one("#push_config_servers")))
            shown += _text(screen.query_one("#push_config_profiles", Static))
            for real in ("team-box", "private-box", "10.0.0.5", "10.0.0.6", "via-bastion", "10.0.0.1"):
                assert real not in shown, real

