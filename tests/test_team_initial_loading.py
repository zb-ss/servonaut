"""The initial Teams read exposes progress and retains native controls."""

from __future__ import annotations

import asyncio
from copy import deepcopy

import pytest
from rich.cells import cell_len
from textual.widget import Widget
from textual.worker import get_current_worker
from textual.widgets import Button, DataTable
from textual.widgets._toast import Toast

from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.team_management import TeamManagementScreen
from servonaut.widgets.busy_indicator import BusyIndicator
from tests._async_bounds import wait_until
from tests.test_team_management_screen import _SAMPLE_TEAMS
from tests.test_workspace_team import (
    _MUTATIONS,
    _TeamApp,
    _team_service,
    _inert_boundaries,  # noqa: F401 -- existing hermetic autouse fixture
    _open_teams,
)


LOADING = "Loading teams…"
# Short enough for the native Toast content even in the narrow viewport.
FAILURE = "offline [literal] Ω"


def _literal_painted(app: _TeamApp, widget: Widget, literal: str) -> str:
    """Require every literal glyph in actual compositor paint and native hits."""
    region = widget.content_region
    assert region.width > 0 and region.height > 0
    assert app.screen.region.contains_region(widget.region)
    strips = app.screen._compositor.render_strips()
    rows = [strips[y].crop(region.x, region.right).text
            for y in range(region.y, region.bottom)]
    for index, row in enumerate(rows):
        if literal not in row:
            continue
        left = region.x + cell_len(row[:row.index(literal)])
        for x in range(left, left + cell_len(literal)):
            hit = app.get_widget_at(x, region.y + index)[0]
            assert hit is widget or widget in hit.ancestors
        return row
    raise AssertionError(f"Literal not visible: {literal!r}; actual paint={rows!r}")


def _assert_whole_button_owned(app: _TeamApp, button: Button) -> None:
    body = app.screen.query_one("#team_management_container")
    assert button.region.width > 0 and button.region.height > 0
    assert body.scrollable_content_region.contains_region(button.region)
    assert app.screen.find_widget(button).clip.contains_region(button.region)
    for y in range(button.region.y, button.region.bottom):
        for x in range(button.region.x, button.region.right):
            hit = app.get_widget_at(x, y)[0]
            assert hit is button or button in hit.ancestors


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("fail", [False, True], ids=["success", "failure"])
async def test_initial_teams_read_paints_progress_and_stops_on_completion(
    size: tuple[int, int], fail: bool,
) -> None:
    app = _TeamApp(navigation_visible=True)
    bootstrap_service = app.team_service
    request_owners = []
    entered, release, exited = asyncio.Event(), asyncio.Event(), asyncio.Event()

    def bootstrap_reads() -> tuple:
        return tuple((name, getattr(bootstrap_service, name).call_count,
                      getattr(bootstrap_service, name).await_count)
                     for name in ("list_teams", "list_shared_servers", "get_team", "list_team_configs"))

    async def held_list() -> list[dict]:
        worker = get_current_worker()
        assert isinstance(worker.node, TeamManagementScreen) and worker.name == "load_teams"
        request_owners.append(worker.node)
        entered.set()
        try:
            await release.wait()
            if fail:
                raise RuntimeError(FAILURE)
            return deepcopy(_SAMPLE_TEAMS)
        finally:
            exited.set()

    async with app.run_test(size=size, notifications=True) as pilot:
        # The real fleet bootstrap has a separate, unheld Team-service fake.
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen) and app.screen.is_mounted)
        await wait_until(lambda: all(worker.is_finished for worker in app.workers))
        await pilot.pause()
        boot_reads = bootstrap_reads()
        for name in _MUTATIONS:
            getattr(bootstrap_service, name).assert_not_called()
            getattr(bootstrap_service, name).assert_not_awaited()
        app.team_service = _team_service()
        app.team_service.list_teams.side_effect = held_list
        app.team_service.list_teams.assert_not_called()
        assert not entered.is_set() and not exited.is_set()
        screen = await _open_teams(app, pilot)
        try:
            await wait_until(entered.is_set)
            assert request_owners == [screen]
            await pilot.pause()
            assert not release.is_set() and not exited.is_set()
            matches = list(screen.query("#team_list_busy"))
            assert len(matches) == 1, "Held initial Teams read has no loading indicator"
            indicator = matches[0]
            assert isinstance(indicator, BusyIndicator)
            await wait_until(lambda: indicator.is_active and indicator.region.height > 0)
            await pilot.pause()
            assert indicator.message == LOADING
            body = screen.query_one("#team_management_container")
            assert body.scrollable_content_region.contains_region(indicator.region)
            row = _literal_painted(app, indicator, LOADING)
            spinner = row[:row.index(LOADING)].rstrip()
            assert spinner and spinner[-1] in BusyIndicator._FRAMES
            spinner_x = indicator.content_region.x + cell_len(spinner) - 1
            assert app.get_widget_at(spinner_x, indicator.content_region.y)[0] is indicator
            table = screen.query_one("#teams_table", DataTable)
            assert table.row_count == 0
            focus = app.focused
            controls = [screen.query_one(selector, Button) for selector in
                        ("#btn_create_team", "#btn_view_team", "#btn_back")]
            disabled = [button.disabled for button in controls]
            for button in controls:
                assert not button.disabled
                _literal_painted(app, button, button.label.plain)
                _assert_whole_button_owned(app, button)
            assert not screen._server_busy and screen.navigation_hold_reason() is None
            assert screen.check_action("back", ()) is True
            assert not release.is_set() and not exited.is_set()

            release.set()
            await wait_until(exited.is_set)
            await wait_until(lambda: all(worker.is_finished for worker in screen.workers))
            await pilot.pause()
            assert not indicator.is_active and not indicator.display
            assert indicator.message == ""
            assert app.screen is screen and app.focused is focus
            assert [button.disabled for button in controls] == disabled
            assert not screen._server_busy and screen.navigation_hold_reason() is None
            app.team_service.list_teams.assert_awaited_once_with()
            if fail:
                assert table.row_count == 0
                message = f"Failed to load teams: {FAILURE}"
                await wait_until(lambda: any(
                    toast._notification.message == message and toast.is_mounted
                    and toast.content_region.width > 0 and toast.content_region.height > 0
                    for toast in screen.query(Toast)
                ))
                toast = next(toast for toast in screen.query(Toast)
                             if toast._notification.message == message)
                await pilot.pause()
                assert toast.render().plain == message
                assert toast._notification.severity == "error"
                assert toast._notification.markup is False
                _literal_painted(app, toast, message)
            else:
                assert table.row_count == len(_SAMPLE_TEAMS)
                assert screen._teams_by_slug == {
                    team["slug"]: team for team in _SAMPLE_TEAMS
                }
                for team in _SAMPLE_TEAMS:
                    _literal_painted(app, table, team["name"])
            for button in controls:
                _literal_painted(app, button, button.label.plain)
                _assert_whole_button_owned(app, button)
            for name in ("get_team", "list_shared_servers", "list_team_configs"):
                getattr(app.team_service, name).assert_not_called()
                getattr(app.team_service, name).assert_not_awaited()
            assert app._exception is None
        finally:
            release.set()
            if entered.is_set():
                await wait_until(exited.is_set)
                await wait_until(lambda: all(worker.is_finished for worker in screen.workers))
            assert bootstrap_reads() == boot_reads
            for name in _MUTATIONS:
                getattr(bootstrap_service, name).assert_not_called()
                getattr(bootstrap_service, name).assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_initial_teams_without_auth_stays_idle_and_makes_no_request(
    size: tuple[int, int],
) -> None:
    app = _TeamApp(navigation_visible=True)
    app.auth_service.is_authenticated = False
    async with app.run_test(size=size) as pilot:
        # Exercise the screen's existing no-auth branch, independent of route entitlement.
        await app.push_screen(TeamManagementScreen())
        screen = app.screen
        await pilot.pause()
        notice = screen.query_one("#no_auth_notice")
        assert notice.display
        _literal_painted(app, notice, "Login required to manage teams.")
        assert not screen.query_one("#teams_table").display
        assert not screen.query_one("#team_actions_row").display
        assert all(not widget.is_active and not widget.display
                   for widget in screen.query(BusyIndicator))
        app.team_service.list_teams.assert_not_called()
        app.team_service.list_teams.assert_not_awaited()
        assert not screen._server_busy and screen.navigation_hold_reason() is None
        _literal_painted(app, screen.query_one("#btn_back", Button), "Back")
        _assert_whole_button_owned(app, screen.query_one("#btn_back", Button))
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_long_team_list_preserves_selection_and_visible_back(size: tuple[int, int]) -> None:
    app = _TeamApp(navigation_visible=True)
    # More records than the bounded table can show, with short neutral labels.
    teams = [{"slug": f"team-{index:02}", "name": f"Team {index:02}",
              "role": "admin", "member_count": 1} for index in range(1, 26)]
    async with app.run_test(size=size) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen) and app.screen.is_mounted)
        await wait_until(lambda: all(worker.is_finished for worker in app.workers))
        app.team_service = _team_service()
        app.team_service.list_teams.return_value = teams
        screen = await _open_teams(app, pilot)
        table = screen.query_one("#teams_table", DataTable)
        await wait_until(lambda: table.row_count == len(teams)
                         and not screen.query_one("#team_list_busy", BusyIndicator).is_active)
        await pilot.pause()
        assert table.region.height == 7
        assert table.virtual_size.height > table.content_region.height
        assert table.max_scroll_y > 0
        back = screen.query_one("#btn_back", Button)
        back_region = back.region
        _literal_painted(app, back, "Back")
        _assert_whole_button_owned(app, back)
        table.focus()
        await pilot.pause()
        assert app.focused is table
        for key, row in (("ctrl+end", len(teams) - 1), ("ctrl+home", 0),
                         ("ctrl+end", len(teams) - 1)):
            await pilot.press(key)
            await wait_until(lambda: table.cursor_row == row)
            await pilot.pause()
            _literal_painted(app, table, teams[row]["name"])
            assert back.region == back_region
            _literal_painted(app, back, "Back")
            _assert_whole_button_owned(app, back)
        assert table.scroll_y > 0
        for selector in ("#btn_create_team", "#btn_view_team", "#btn_back"):
            await pilot.press("tab")
            await pilot.pause()
            button = screen.query_one(selector, Button)
            assert app.focused is button
            _literal_painted(app, button, button.label.plain)
            _assert_whole_button_owned(app, button)
            assert back.region == back_region
            assert table.cursor_row == len(teams) - 1
        if size == (100, 30):
            assert screen.query_one("#team_management_container").scroll_y > 0
        assert not screen._server_busy and screen.navigation_hold_reason() is None
        app.team_service.list_teams.assert_awaited_once_with()
        for name in ("get_team", "list_shared_servers", "list_team_configs"):
            getattr(app.team_service, name).assert_not_called()
            getattr(app.team_service, name).assert_not_awaited()
        assert app._exception is None
