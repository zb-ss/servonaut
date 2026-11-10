"""The fleet list's chips, freshness, summary line, footer, inspector and columns.

Real app, real stylesheet, seeded fleet (see ``_harness``).
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

import pytest
from textual.widgets import Static

from servonaut.screens.instance_list import FleetChip
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.status_bar import StatusBar

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]
sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


def _run(scenario: Scenario, size: str = "160x50", *, demo: bool = False) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp(demo=demo)
        async with app.run_test(size=_harness.SIZES[size]) as pilot:
            await _harness.wait_for_fleet(pilot)
            await scenario(pilot)

    asyncio.run(main())


def _screen(pilot: Any) -> Any:
    return pilot.app.screen


def _chips(pilot: Any) -> list[FleetChip]:
    return [chip for chip in _screen(pilot).query(FleetChip) if chip.display]


# --- chips ---------------------------------------------------------------


def test_chips_are_outlined_pills_on_a_roomy_terminal() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        assert screen.has_class("-roomy")
        chips = _chips(pilot)
        assert chips and all(chip.region.height == 3 for chip in chips)
        chosen = [chip for chip in chips if chip.has_class("--chosen")]
        others = [chip for chip in chips if not chip.has_class("--chosen")]
        assert len(chosen) == 1
        assert chosen[0].styles.border_top[0] == "round"
        # Accent outline for the chosen chip, a dim one for the others.
        assert chosen[0].styles.border_top[1] != others[0].styles.border_top[1]
        table = screen.query_one(InstanceTable)
        assert all(chip.region.bottom <= table.region.y for chip in chips)

    _run(scenario)


def test_chips_are_one_row_on_a_short_terminal() -> None:
    async def scenario(pilot: Any) -> None:
        assert not _screen(pilot).has_class("-roomy")
        assert all(chip.region.height == 1 for chip in _chips(pilot))

    _run(scenario, "100x30")


def test_chips_fall_back_to_one_row_with_the_chat_open() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        assert all(chip.region.height == 3 for chip in _chips(pilot))
        await pilot.press("f2")
        await _harness.wait_until(pilot, lambda: screen.has_class("-chat-open"), "the chat")
        await _harness.wait_until(pilot, lambda: not screen.has_class("-roomy"), "one-row chips")
        await pilot.pause()
        assert all(chip.region.height == 1 for chip in _chips(pilot))
        await pilot.press("f2")
        await _harness.wait_until(pilot, lambda: screen.has_class("-roomy"), "pills again")

    _run(scenario)


def test_chips_stay_pills_with_the_navigation_hidden() -> None:
    async def scenario(pilot: Any) -> None:
        await pilot.click("#workspace_navigation")
        await pilot.pause()
        assert _screen(pilot).has_class("-roomy")
        assert all(chip.region.height == 3 for chip in _chips(pilot))

    _run(scenario)


def test_the_chosen_pill_follows_the_filter_and_keeps_the_separator() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        screen.query_one("#chip_state_running").press()
        await pilot.pause()
        assert [c.value for c in _chips(pilot) if c.has_class("--chosen")] == ["running"]
        assert screen.query_one(".fleet-chip-divider").region.width == 1

    _run(scenario)


# --- freshness and summary -------------------------------------------------


def test_freshness_sits_on_the_chip_row_at_wide_sizes() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        fresh = screen.query_one("#fleet_fresh")
        chip = _chips(pilot)[0]
        assert chip.region.y <= fresh.region.y < chip.region.bottom
        refresh = screen.query_one("#fleet_refresh")
        assert refresh.region.width > 0 and refresh.region.right <= fresh.region.right
        assert "Refresh" in str(refresh.label)

    _run(scenario)


def test_freshness_has_its_own_right_aligned_row_at_narrow_sizes() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        fresh = screen.query_one("#fleet_fresh")
        last_chip_row = max(chip.region.bottom for chip in _chips(pilot))
        assert fresh.region.y >= last_chip_row
        table = screen.query_one(InstanceTable)
        assert fresh.region.bottom <= table.region.y

    _run(scenario, "100x30")


@sizes
def test_the_summary_line_sits_right_under_the_table(size: str) -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        table = screen.query_one(InstanceTable)
        summary = screen.query_one("#fleet_summary", Static)
        assert summary.region.y == table.region.bottom and summary.region.height == 1
        text = summary.visual.plain
        assert text.startswith("Showing 7 of 7 · filters: none")
        screen.query_one("#chip_state_running").press()
        await pilot.pause()
        assert summary.visual.plain.startswith("Showing 4 of 7 · filters: Running")

    _run(scenario, size)


@sizes
def test_the_status_bar_no_longer_repeats_the_count(size: str) -> None:
    async def scenario(pilot: Any) -> None:
        bar = _screen(pilot).query_one(StatusBar)
        assert "instances" not in bar.visual.plain

    _run(scenario, size)


def test_demo_mode_summary_and_values_use_the_redacted_rows() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        assert screen.query_one("#fleet_summary", Static).visual.plain.startswith("Showing 7 of 7")

    _run(scenario, demo=True)


# --- footer ----------------------------------------------------------------


def _footer_keys(screen: Any) -> set:
    return {key for key, active in screen.active_bindings.items() if active.binding.show}


def test_the_footer_shows_the_filter_keys_and_leaves_out_the_inspector_keys() -> None:
    async def scenario(pilot: Any) -> None:
        keys = _footer_keys(_screen(pilot))
        assert {"f", "p", "r", "slash", "s"} <= keys
        assert not {"b", "c", "t", "l", "a", "m"} & keys

    _run(scenario)


def test_the_footer_does_not_hide_those_keys_when_the_inspector_is_hidden() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        assert not screen.query_one("#fleet_inspector").display
        from textual.screen import Screen

        raw = Screen.active_bindings.fget(screen)
        assert screen._without_inspector_keys(raw) == raw

    _run(scenario, "100x30")


def test_footer_descriptions_are_sentence_case() -> None:
    from servonaut.screens.instance_list import InstanceListScreen

    for binding in InstanceListScreen.BINDINGS:
        words = binding.description.split()
        assert not any(word.istitle() and not word.isupper() for word in words[1:]), binding.description


# --- inspector buttons -----------------------------------------------------

_EXPECTED_BUTTONS = {
    "fleet_btn_ssh": ("SSH connect", "s"),
    "fleet_btn_browse": ("Browse", "b"),
    "fleet_btn_scp": ("Transfer", "t"),
    "fleet_btn_command": ("Command", "c"),
    "fleet_btn_logs": ("Logs", "l"),
    "fleet_btn_memory": ("Memory", "m"),
    "fleet_btn_ai": ("AI", "a"),
    "fleet_btn_actions": ("All actions", "enter"),
}


def test_inspector_buttons_are_action_buttons_with_quiet_key_hints() -> None:
    from servonaut.widgets.action_button import ActionButton

    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        inspector = screen.query_one("#fleet_inspector")
        for button_id, (words, key) in _EXPECTED_BUTTONS.items():
            button = screen.query_one(f"#{button_id}", ActionButton)
            assert (button.words, button._key) == (words, key)
            assert not button.can_focus
            assert inspector.region.contains_region(button.region), button_id
            assert "(" not in button.label.plain
        assert screen.query_one("#fleet_btn_ssh", ActionButton).variant == "primary"
        others = [b for b_id, b in ((i, screen.query_one(f"#{i}", ActionButton)) for i in _EXPECTED_BUTTONS) if b_id != "fleet_btn_ssh"]
        assert all(b.variant == "default" for b in others)

    _run(scenario)


# --- columns ---------------------------------------------------------------


def test_the_table_does_not_scroll_sideways_at_160x50() -> None:
    async def scenario(pilot: Any) -> None:
        table = _screen(pilot).query_one(InstanceTable)
        assert table.virtual_size.width <= table.scrollable_content_region.width
        assert table.border_subtitle == ""
        assert [str(c.label) for c in table.columns.values()] == [
            "#", "Name", "State", "Provider", "Public IP", "Type", "Region",
        ]

    _run(scenario)


def test_the_memory_status_moved_to_the_inspector() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        header = screen.query_one("#fleet_inspector_header", Static)
        for name in ("app-1", "mail-1", "db-1"):
            await _harness.select_fleet_row(pilot, name)
            assert "emory" in header.visual.plain, header.visual.plain

    _run(scenario)


def test_the_inspector_list_always_has_the_values_the_table_dropped() -> None:
    from servonaut.widgets.fleet_values import ValueRow

    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        await _harness.select_fleet_row(pilot, "app-1")
        fields = {r.field for r in screen.query_one("#fleet_values").query(ValueRow) if r.display}
        assert {"private_ip", "id", "key_name"} <= fields

    _run(scenario)
