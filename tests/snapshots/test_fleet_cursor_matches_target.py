"""The server a fleet action opens is the one whose row the cursor is on."""

from __future__ import annotations

import pytest

from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.widgets.instance_table import InstanceTable

from . import _harness

pytestmark = pytest.mark.asyncio

SIZES = [(100, 30), (160, 50)]
# Provider, state and search changes the fleet screen offers, then a refresh.
STEPS = {
    "search_then_escape": ["/", "w", "e", "b", "escape"],
    "search_then_enter_key": ["/", "w", "e", "b", "enter"],
    "state_filter": ["f"],
    "state_filter_twice": ["f", "f"],
    "provider_filter": ["p"],
    "provider_filter_twice": ["p", "p"],
    "provider_then_search": ["p", "/", "w", "e", "b", "escape"],
    "refresh": ["r"],
}


def _name_of_row(table: InstanceTable, row: int) -> str:
    """The name the table paints in its row (column after the index)."""
    cells = table.get_row_at(row)
    return str(cells[1].plain if hasattr(cells[1], "plain") else cells[1])


async def _check(pilot, table: InstanceTable, where: str) -> None:
    if not table.row_count:
        return
    selected = table.get_selected_instance()
    assert selected is not None, where
    painted = _name_of_row(table, table.cursor_row)
    assert selected["name"] in painted or painted.rstrip("…") in selected["name"], (
        where, painted, selected["name"],
    )


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("name", list(STEPS))
async def test_the_opened_server_is_the_highlighted_row(size, name) -> None:
    app = _harness.MultiAccountSnapshotApp()
    async with app.run_test(size=size) as pilot:
        await _harness.wait_for_fleet(pilot, _harness.MULTI_ACCOUNT_FLEET_SIZE)
        table = pilot.app.screen.query_one(InstanceTable)
        table.focus()
        for key in STEPS[name]:
            await pilot.press(key)
            await pilot.pause()
        await pilot.pause()
        table.focus()
        await pilot.pause()
        await _check(pilot, table, name)
        table.focus()
        for move in (None, ["down", "down"], ["pagedown"], ["ctrl+end"], ["home"], ["down"]):
            table.focus()
            await pilot.pause()
            for key in move or []:
                await pilot.press(key)
                await pilot.pause()
            if not table.row_count:
                break
            where = f"{name}:{move}"
            await _check(pilot, table, where)
            row = table.cursor_row
            expected = table.get_selected_instance()
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            screen = pilot.app.screen
            assert isinstance(screen, ServerActionsScreen), (where, row, type(screen))
            assert screen._instance["id"] == expected["id"], (where, row)
            assert screen._instance["name"] == expected["name"], (where, row)
            await pilot.press("escape")
            await pilot.pause()
