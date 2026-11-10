"""Copying one value of the selected server, on the real app and stylesheet.

The values sit in the inspector, or in a short block under the table where the
inspector is hidden. A click or ``Y`` then enter copies one value; ``y`` still
copies the whole row.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Iterator, List

import pytest

from servonaut.screens.instance_list import InstanceListScreen
from servonaut.utils import platform_utils
from servonaut.widgets import fleet_values
from servonaut.widgets.fleet_values import FleetValueLine, FleetValues, ValueRow
from servonaut.widgets.instance_table import InstanceTable

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


class _Clipboard:
    def __init__(self) -> None:
        self.calls: List[str] = []

    def __call__(self, text: str) -> bool:
        self.calls.append(text)
        return True


@pytest.fixture
def clipboard() -> Iterator[_Clipboard]:
    previous = platform_utils.clipboard_writer()
    recorder = _Clipboard()
    platform_utils.set_clipboard_writer(recorder)
    try:
        yield recorder
    finally:
        platform_utils.set_clipboard_writer(previous)


def _run(scenario: Scenario, size: str = "160x50", *, demo: bool = False) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp(demo=demo)
        async with app.run_test(size=_harness.SIZES[size]) as pilot:
            await _harness.wait_for_fleet(pilot)
            await scenario(pilot)

    asyncio.run(main())


def _row(pilot: Any, field: str, *, line: bool = False) -> ValueRow:
    host = "#fleet_value_line" if line else "#fleet_values"
    return pilot.app.screen.query_one(host).query_one(f"#fleet_value_{'line' if line else 'list'}_{field}", ValueRow)


def _values(pilot: Any, size: str) -> FleetValues | FleetValueLine:
    host = "#fleet_value_line" if size == "100x30" else "#fleet_values"
    return pilot.app.screen.query_one(host)


async def _mail(pilot: Any) -> dict:
    await _harness.select_fleet_row(pilot, "mail-1")
    return pilot.app.screen.query_one(InstanceTable).get_selected_instance()


def test_a_click_copies_the_value_and_confirms_in_place(
    clipboard: _Clipboard, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fleet_values, "COPIED_SECONDS", 0.3)

    async def scenario(pilot: Any) -> None:
        instance = await _mail(pilot)
        row = _row(pilot, "public_ip")
        assert row.value == instance["public_ip"]
        toasts = len(pilot.app._notifications)
        await pilot.click(row, offset=(1, 1))
        await pilot.pause()
        assert clipboard.calls == [instance["public_ip"]]
        assert row.copied and "✓ copied" in row.visual.plain
        assert len(pilot.app._notifications) == toasts
        await _harness.wait_until(pilot, lambda: not row.copied, "the confirmation to clear")
        assert "✓ copied" not in row.visual.plain and instance["public_ip"] in row.visual.plain

    _run(scenario)


def test_dragging_inside_a_value_copies_only_the_highlighted_part(clipboard: _Clipboard) -> None:
    async def scenario(pilot: Any) -> None:
        instance = await _mail(pilot)
        row = _row(pilot, "name")
        assert await pilot.mouse_down(row, offset=(1, 1))
        await pilot.hover(row, offset=(4, 1))
        assert await pilot.mouse_up(row, offset=(4, 1))
        await pilot.pause()
        assert clipboard.calls and clipboard.calls[-1] != instance["name"]
        assert clipboard.calls[-1] in instance["name"]
        assert not row.copied

    _run(scenario)


@sizes
def test_y_then_arrows_and_enter_copy_the_chosen_value(clipboard: _Clipboard, size: str) -> None:
    narrow = size == "100x30"
    forward, back = ("right", "left") if narrow else ("down", "up")

    async def scenario(pilot: Any) -> None:
        instance = await _mail(pilot)
        values = _values(pilot, size)
        await pilot.press("Y")
        rows = [r for r in values.query(ValueRow) if r.display]
        assert pilot.app.focused is rows[0]
        await pilot.press(forward, forward, forward, back)
        assert pilot.app.focused is rows[2]
        await pilot.press("enter")
        await pilot.pause()
        assert clipboard.calls == [rows[2].value]
        assert rows[2].copied
        await pilot.press("escape")
        assert isinstance(pilot.app.focused, InstanceTable)
        assert instance["name"] in {r.value for r in rows}

    _run(scenario, size)


@sizes
def test_the_values_are_not_in_the_tab_chain(size: str) -> None:
    async def scenario(pilot: Any) -> None:
        assert not any(isinstance(w, ValueRow) for w in pilot.app.screen.focus_chain)

    _run(scenario, size)


def test_y_still_copies_the_row_with_its_toast(
    clipboard: _Clipboard, monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario(pilot: Any) -> None:
        instance = await _mail(pilot)
        toasts: List[str] = []
        monkeypatch.setattr(pilot.app, "notify", lambda message, **kw: toasts.append(message))
        await pilot.press("y")
        await pilot.pause()
        assert clipboard.calls and instance["name"] in clipboard.calls[0]
        assert toasts == [f"Copied: {instance['name']}"]

    _run(scenario)


@sizes
def test_the_copy_row_button_copies_the_row(clipboard: _Clipboard, size: str) -> None:
    async def scenario(pilot: Any) -> None:
        await _mail(pilot)
        button = "#fleet_copy_row_line" if size == "100x30" else "#fleet_copy_row"
        await pilot.click(button)
        await pilot.pause()
        assert len(clipboard.calls) == 1 and "mail-1" in clipboard.calls[0]

    _run(scenario, size)


@pytest.mark.parametrize("size", ["160x50", "100x30"])
def test_demo_mode_shows_and_copies_only_stand_ins(clipboard: _Clipboard, size: str) -> None:
    from servonaut.screens._demo_resolve import connection_instance

    async def scenario(pilot: Any) -> None:
        app = pilot.app
        table = app.screen.query_one(InstanceTable)
        table.focus()
        table.move_cursor(row=1)
        await pilot.pause()
        shown = table.get_selected_instance()
        real = connection_instance(app, shown)
        real_values = {str(v) for k, v in real.items() if v and shown.get(k) != v and isinstance(v, (str, int))}
        assert real_values
        values = _values(pilot, size)
        rows = [r for r in values.query(ValueRow) if r.display]
        assert rows
        await pilot.press("Y")
        for _ in rows:
            await pilot.press("enter", "right" if size == "100x30" else "down")
        await pilot.pause()
        painted = " ".join(r.value for r in rows)
        assert not any(v in painted for v in real_values)
        assert len(clipboard.calls) >= len(rows) - 1
        assert not any(v in call for call in clipboard.calls for v in real_values)

    _run(scenario, size, demo=True)


@sizes
def test_the_bottom_strip_is_gone_and_the_table_has_the_rows(size: str) -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        assert not screen.query("#fleet-detail-toolbar") and not screen.query("#instance_detail")
        bottom = screen.query_one("#fleet-bottom")
        fixed = screen.query_one("StatusBar").region.height + screen.query_one("Footer").region.height
        bar = screen.query_one("#fleet_value_bar")
        if size == "100x30":
            assert bar.display and 1 <= bar.region.height <= 2
            assert bottom.region.height == fixed + bar.region.height
        else:
            assert not bar.display
            assert bottom.region.height == fixed
            assert screen.query_one("#fleet_values").region.height >= 8

    _run(scenario, size)


async def _selected(pilot: Any) -> None:
    await _harness.select_fleet_row(pilot, "mail-1")
    pilot.app.screen.query_one(InstanceTable).focus()


@sizes
def test_fleet_values_in_the_inspector_or_on_one_line(screen_snapshot, size: str) -> None:
    """The selected server's values: a list beside the actions, or a short block."""
    async def before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await _selected(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], before)
