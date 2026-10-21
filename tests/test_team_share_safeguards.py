"""The Teams screen asks before servers leave for a team.

Share All lists every server it would share and sends nothing until the user
confirms.
"""

from __future__ import annotations

import pytest
from textual.widgets import Button, SelectionList, Static

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


async def _open_team(app, pilot) -> TeamManagementScreen:
    await _until(pilot, lambda: isinstance(app.screen, TeamManagementScreen), "the Teams screen")
    screen = app.screen
    screen._current_team_slug = "eng"
    screen._current_team_name = TEAM
    screen._current_team_role = "owner"
    screen._shared_servers = []
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

