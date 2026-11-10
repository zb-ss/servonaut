"""Fleet list follow-ups: chip widths, freshness measure, summary and columns."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

from rich.cells import cell_len
from textual.widgets import Static

from servonaut.screens.instance_list import FleetChip
from servonaut.widgets.instance_table import InstanceTable

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]


def _run(scenario: Scenario, size: tuple[int, int] = (160, 50), *, hide_navigation: bool = False) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp()
        async with app.run_test(size=size) as pilot:
            await _harness.wait_for_fleet(pilot)
            if hide_navigation:
                await pilot.click("#workspace_navigation")
                await pilot.pause()
            await scenario(pilot)

    asyncio.run(main())


def _rows(count: int) -> list[dict]:
    base = dict(_harness.AWS_ROWS[0])
    return [{**base, "id": f"i-{n:017d}", "name": f"web-{n}"} for n in range(count)]


def test_a_chip_widens_when_its_count_gains_digits() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        chip = screen.query_one("#chip_state_all", FleetChip)
        for count in (1, 12, 120, 1244):
            screen._instances = _rows(count)
            screen._update_table()
            screen._update_status_bar()
            await pilot.pause()
            await pilot.pause()
            text = chip.label.plain
            assert text == f"All {count}"
            assert chip.region.width >= cell_len(text), (count, chip.region.width)
            strips = screen._compositor.render_strips()
            region = chip.region
            painted = "".join(
                strips[y].crop(region.x, region.right).text for y in range(region.y, region.bottom)
            )
            assert text in painted, (count, painted)

    _run(scenario)


def test_the_age_and_refresh_stay_inside_the_row_at_every_width_with_a_long_age() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        screen._last_updated = time.time() - 12 * 60
        for width in range(118, 200):
            await pilot.resize_terminal(width, 44)
            await pilot.pause()
            screen._sync_updated()
            await pilot.pause()
            filters = screen.query_one("#fleet_filters")
            refresh = screen.query_one("#fleet_refresh")
            assert refresh.region.right <= filters.region.right, (width, refresh.region, filters.region)

    _run(scenario, hide_navigation=True)


def _verified_fleet() -> list[dict]:
    rows = [dict(r) for r in _harness.AWS_ROWS]
    rows[0].update(ssh_verify_status="verified", ssh_verified_at="2026-03-02T08:30:00+00:00")
    return rows


def test_the_summary_drops_its_key_reminder_before_it_is_cut() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        for width in (100, 112, 125, 132, 140, 160, 200):
            await pilot.resize_terminal(width, 44)
            await pilot.pause()
            await pilot.pause()
            line = screen.query_one("#fleet_summary", Static)
            text = line.visual.plain
            assert text.startswith("Showing 7 of 7 · filters: none")
            assert cell_len(text) <= line.size.width, (width, text)
            if "f cycle state filter" not in text:
                assert "p cycle provider" not in text

    _run(scenario)


def test_the_ssh_column_steps_aside_instead_of_making_the_table_scroll() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        screen._instances = _verified_fleet()
        screen._update_table()
        table = screen.query_one(InstanceTable)
        stepped_aside = False
        for width in range(120, 200, 2):
            await pilot.resize_terminal(width, 44)
            await pilot.pause()
            await pilot.pause()
            keys = [str(c.key.value) for c in table.columns.values()]
            scrolls = table.virtual_size.width > table.scrollable_content_region.width
            if "ssh" in keys and scrolls:
                # Dropping the column must not have helped: without it, it still scrolls.
                ssh = next(c for c in table.columns.values() if str(c.key.value) == "ssh")
                without = table.virtual_size.width - ssh.get_render_width(table)
                assert without > table.scrollable_content_region.width, width
            elif not scrolls and "region" in keys:
                stepped_aside = True
        assert stepped_aside

    _run(scenario)


def test_the_ssh_column_is_shown_when_there_is_room() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        await pilot.resize_terminal(220, 44)
        screen._instances = _verified_fleet()
        screen._update_table()
        await pilot.pause()
        await pilot.pause()
        keys = [str(c.key.value) for c in screen.query_one(InstanceTable).columns.values()]
        assert "ssh" in keys

    _run(scenario)


def _long_fleet() -> list[dict]:
    rows = []
    for number, base in enumerate(_harness.AWS_ROWS):
        rows.append({**base, "name": f"{'n' * 30}-{number:02d}", "public_ip": f"123.123.123.{100 + number}"})
    return rows


async def _sweep(pilot: Any, rows: list[dict]) -> dict[int, list[str]]:
    screen = pilot.app.screen
    screen._instances = rows
    screen._update_table()
    table = screen.query_one(InstanceTable)
    seen = {}
    for width in range(118, 201, 2):
        await pilot.resize_terminal(width, 44)
        await pilot.pause()
        await pilot.pause()
        keys = [str(c.key.value) for c in table.columns.values()]
        seen[width] = keys
        assert table.virtual_size.width <= table.scrollable_content_region.width, (width, keys)
        assert table._name_cap is None or table._name_cap >= 16, width
        for key in ("#", "name", "state", "provider", "public_ip"):
            assert key in keys or key == "#", (width, key)
    return seen


def test_the_fixture_fleet_never_scrolls_sideways_from_118_columns() -> None:
    async def scenario(pilot: Any) -> None:
        seen = await _sweep(pilot, [dict(r) for r in _harness.AWS_ROWS])
        assert "region" in seen[160] and "type" in seen[160]

    _run(scenario)


def test_long_names_and_addresses_never_scroll_sideways_from_118_columns() -> None:
    async def scenario(pilot: Any) -> None:
        seen = await _sweep(pilot, _long_fleet())
        assert "region" in seen[200]

    _run(scenario)


def test_long_names_never_scroll_sideways_with_the_navigation_hidden() -> None:
    async def scenario(pilot: Any) -> None:
        await _sweep(pilot, _long_fleet())

    _run(scenario, hide_navigation=True)


def test_columns_give_way_in_order_and_come_back_in_reverse() -> None:
    async def scenario(pilot: Any) -> None:
        screen = pilot.app.screen
        screen._instances = [dict(r) for r in _harness.AWS_ROWS]
        screen._update_table()
        table = screen.query_one(InstanceTable)
        order = []
        for width in range(200, 118, -2):
            await pilot.resize_terminal(width, 44)
            await pilot.pause()
            await pilot.pause()
            order.append((width, tuple(table._given_way), table._name_cap))
        given = [g for _, g, _ in order]
        # Once Type has given way, Region has too (the order never skips back).
        for g in given:
            assert "type" not in g or "region" in g
        back = []
        for width in range(120, 202, 2):
            await pilot.resize_terminal(width, 44)
            await pilot.pause()
            await pilot.pause()
            back.append(tuple(table._given_way))
        for g in back:
            assert "type" not in g or "region" in g
        assert back[-1] == ()

    _run(scenario)
