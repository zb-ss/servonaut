"""The fleet screen's selected-server inspector, on the real app and stylesheet.

Runs the real application with its real stylesheets (see ``_harness``), so
visibility and geometry assertions describe what a user sees.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Awaitable, Callable, Dict, List

import pytest
from textual.widgets import Button, Input, Static

from servonaut.screens.instance_list import InstanceListScreen
from servonaut.widgets.instance_table import InstanceTable

from . import _harness

# Every inspector button and the screen action its label's shortcut runs.
_BUTTON_ACTIONS: Dict[str, str] = {
    "fleet_btn_ssh": "action_ssh_connect",
    "fleet_btn_browse": "action_browse_files",
    "fleet_btn_scp": "action_scp_transfer",
    "fleet_btn_command": "action_run_command",
    "fleet_btn_logs": "action_view_logs",
    "fleet_btn_memory": "action_open_memory",
    "fleet_btn_ai": "action_ai_analysis",
    "fleet_btn_actions": "action_select_instance",
}


def _run(
    scenario: Callable[[Any], Awaitable[None]],
    size: str = "160x50",
    *,
    demo: bool = False,
) -> None:
    """Run *scenario* on a loaded fleet screen at terminal size *size*."""

    async def main() -> None:
        app = _harness.SnapshotApp(demo=demo)
        async with app.run_test(size=_harness.SIZES[size]) as pilot:
            await _harness.wait_for_fleet(pilot)
            await scenario(pilot)

    asyncio.run(main())


def _header_text(screen: Any) -> str:
    return screen.query_one("#fleet_inspector_header", Static).visual.plain


def _buttons(screen: Any) -> List[Button]:
    return list(screen.query("#fleet_inspector Button"))


async def _search(pilot: Any, text: str) -> None:
    """Type into the search box and wait out the debounce."""
    screen = pilot.app.screen
    screen.query_one("#search_input", Input).value = text
    await pilot.pause(InstanceListScreen._SEARCH_DEBOUNCE + 0.2)


def test_header_follows_the_cursor() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        await _harness.select_fleet_row(pilot, "mail-1")
        text = _header_text(screen)
        assert "mail-1" in text and "OVH" in text and "9.9.9.10" in text
        assert "running" in text
        await _harness.select_fleet_row(pilot, "db-1")
        text = _header_text(screen)
        assert "db-1" in text and "stopped" in text and "mail-1" not in text

    _run(scenario)


def test_header_follows_the_search_filter() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        await _search(pilot, "cache")
        assert screen.query_one(InstanceTable).row_count == 1
        assert "cache-1" in _header_text(screen)
        assert not any(button.disabled for button in _buttons(screen))

    _run(scenario)


def test_empty_list_clears_the_header_and_disables_the_buttons() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        assert not any(button.disabled for button in _buttons(screen))
        await _search(pilot, "no-such-server")
        assert screen.query_one(InstanceTable).row_count == 0
        assert "No server selected" in _header_text(screen)
        assert all(button.disabled for button in _buttons(screen))
        await _search(pilot, "")
        assert all(not button.disabled for button in _buttons(screen))

    _run(scenario)


def test_header_survives_a_refresh_that_drops_the_selected_row() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        table = screen.query_one(InstanceTable)
        await _harness.select_fleet_row(pilot, "cache-1")
        screen._instances = screen._instances[:2]
        screen._update_table()
        screen._update_detail_panel()
        await pilot.pause()
        selected = table.get_selected_instance()
        assert selected is not None
        assert str(selected["name"]) in _header_text(screen)
        assert "cache-1" not in _header_text(screen)

        screen._instances = []
        screen._update_table()
        screen._update_detail_panel()
        await pilot.pause()
        assert "No server selected" in _header_text(screen)
        assert all(button.disabled for button in _buttons(screen))

    _run(scenario)


def test_a_missing_state_is_not_shown_as_running() -> None:
    badge = InstanceListScreen._inspector_state_badge
    for row in ({}, {"state": None}, {"state": ""}, {"state": "  "}):
        text = badge(row)
        assert "unknown" in text and "running" not in text
    assert "running" in badge({"state": "running"})
    assert "stopped" in badge({"state": "stopped"})


def test_state_text_cannot_inject_markup() -> None:
    assert "\\[" in InstanceListScreen._inspector_state_badge({"state": "[b]x"})


@pytest.mark.parametrize("button_id", sorted(_BUTTON_ACTIONS))
def test_each_button_runs_the_action_of_its_shortcut(
    button_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    action = _BUTTON_ACTIONS[button_id]
    calls: List[str] = []
    monkeypatch.setattr(InstanceListScreen, action, lambda self: calls.append(action))

    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        button = screen.query_one(f"#{button_id}", Button)
        assert not button.disabled
        key = re.search(r"\((.+)\)", str(button.label)).group(1).lower()
        bound = {b.key: b.action for b in InstanceListScreen.BINDINGS}
        assert bound[key] == action.removeprefix("action_")
        button.press()
        await pilot.pause()
        assert calls == [action]

    _run(scenario)


def test_buttons_do_not_take_keyboard_focus() -> None:
    async def scenario(pilot: Any) -> None:
        assert not any(button.can_focus for button in _buttons(pilot.app.screen))

    _run(scenario)


def test_inspector_is_visible_in_a_wide_terminal_and_hidden_in_a_narrow_one() -> None:
    async def wide(pilot: Any) -> None:
        screen = pilot.app.screen
        inspector = screen.query_one("#fleet_inspector")
        assert inspector.display and inspector.region.width == 38
        assert all(button.region.width > 0 for button in _buttons(screen))

    async def narrow(pilot: Any) -> None:
        screen = pilot.app.screen
        assert not screen.query_one("#fleet_inspector").display
        assert screen.query_one(InstanceTable).region.width >= 60

    _run(wide, "160x50")
    _run(narrow, "100x30")


@pytest.mark.parametrize("layout_class", ["-narrow", "-content-narrow", "-chat-open"])
def test_inspector_yields_its_width_to_the_table(layout_class: str) -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        table = screen.query_one(InstanceTable)
        before = table.region.width
        screen.add_class(layout_class)
        await pilot.pause()
        assert not screen.query_one("#fleet_inspector").display
        assert table.region.width > before

    _run(scenario)


def test_table_scrollbars_are_one_cell() -> None:
    async def scenario(pilot: Any) -> None:
        table = pilot.app.screen.query_one(InstanceTable)
        assert table.styles.scrollbar_size_horizontal == 1
        assert table.styles.scrollbar_size_vertical == 1

    _run(scenario, "100x30")


def test_demo_mode_never_puts_a_real_name_or_address_in_the_header() -> None:
    real_rows = [*_harness.AWS_ROWS, *_harness.OVH_ROWS, *_harness.HETZNER_ROWS]
    real_values = {
        str(row[field])
        for row in real_rows
        for field in ("name", "public_ip", "private_ip", "id")
        if row.get(field)
    }
    real_values.update(server.name for server in _harness.CUSTOM_SERVERS)

    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        for name in _harness.FLEET_NAMES:
            await _harness.select_fleet_row(pilot, name)
            text = _header_text(screen)
            assert text.strip() and "No server selected" not in text
            leaked = {value for value in real_values if value in text}
            assert not leaked, f"{name}: {leaked} shown in demo mode: {text!r}"

    _run(scenario, demo=True)
