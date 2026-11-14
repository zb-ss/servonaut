"""Screenshot tests: Fleet Memory with its action row, populated and empty.

Captured at both terminal sizes (see ``test_screens.py``).
"""

from __future__ import annotations

from typing import Any

import pytest
from textual.widgets import DataTable

from . import _harness

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


async def _open(pilot: Any, *, cached: bool, listed_only_with_memory: bool = False) -> None:
    from unittest.mock import AsyncMock, MagicMock

    from servonaut.screens.fleet_memory import FleetMemoryScreen
    from servonaut.services.memory.fleet_service import FleetService

    app = pilot.app
    if not cached:
        # Nothing cached for any server: the seeded memory is removed first.
        app.memory_service.clear("i-00000000000000001", provider="aws")
    if listed_only_with_memory:
        # The service lists only servers that have memory, as it does in use.
        api = MagicMock()
        api.get = AsyncMock(side_effect=RuntimeError("offline"))
        app.fleet_service = FleetService(api, app.memory_service)
    app.push_screen(FleetMemoryScreen())
    screen = await _harness.wait_for_screen(pilot, "FleetMemoryScreen")
    await _harness.wait_until(
        pilot, lambda: not any(w.group == "memory_fleet" for w in app.workers), "the rows to settle",
    )
    table = screen.query_one("#fleet-memory-table", DataTable)
    if not listed_only_with_memory:
        await _harness.wait_until(pilot, lambda: table.row_count >= 3, "the fleet memory rows")
    await pilot.pause()


def _capture(screen_snapshot: Any, size: str, **options: bool) -> None:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await _open(pilot, **options)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], run_before)


@sizes
def test_fleet_memory_populated(screen_snapshot, size: str) -> None:
    """The action row above the table, which takes the rest of the screen."""
    _capture(screen_snapshot, size, cached=True)


@sizes
def test_fleet_memory_banner(screen_snapshot, size: str) -> None:
    """Servers listed but none cached: a banner offers the scan above the visible table."""
    _capture(screen_snapshot, size, cached=False)


@sizes
def test_fleet_memory_empty(screen_snapshot, size: str) -> None:
    """No server has memory and none is listed: the explanation card replaces the table."""
    _capture(screen_snapshot, size, cached=False, listed_only_with_memory=True)
