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
