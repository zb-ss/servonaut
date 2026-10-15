"""keep_selected_row: a redrawn table keeps the row the user picked."""
from __future__ import annotations

from typing import Iterable

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable

from servonaut.screens._table_cursor import keep_selected_row


class _TableApp(App):
    def compose(self) -> ComposeResult:
        yield DataTable(cursor_type="row")

    def on_mount(self) -> None:
        self.query_one(DataTable).add_columns("Name", "State")


def _fill(table: DataTable, names: Iterable[str]) -> None:
    with keep_selected_row(table):
        table.clear()
        for name in names:
            table.add_row(name, "running", key=name)


def _selected(table: DataTable) -> str:
    return str(table.get_row_at(table.cursor_row)[0])


@pytest.mark.asyncio
async def test_the_cursor_stays_on_the_same_row_after_a_redraw():
    async with _TableApp().run_test() as pilot:
        table = pilot.app.query_one(DataTable)
        _fill(table, ["web-1", "web-2", "web-3"])
        table.move_cursor(row=2)
        await pilot.pause()

        _fill(table, ["web-1", "web-2", "web-3"])
        await pilot.pause()

        assert _selected(table) == "web-3"


@pytest.mark.asyncio
async def test_the_cursor_follows_its_row_when_the_order_changes():
    async with _TableApp().run_test() as pilot:
        table = pilot.app.query_one(DataTable)
        _fill(table, ["web-1", "web-2", "web-3"])
        table.move_cursor(row=1)
        await pilot.pause()

        _fill(table, ["web-3", "web-1", "web-0", "web-2"])
        await pilot.pause()

        assert table.cursor_row == 3
        assert _selected(table) == "web-2"


@pytest.mark.asyncio
async def test_a_removed_row_leaves_the_cursor_at_its_position():
    async with _TableApp().run_test() as pilot:
        table = pilot.app.query_one(DataTable)
        _fill(table, ["web-1", "web-2", "web-3"])
        table.move_cursor(row=1)
        await pilot.pause()

        _fill(table, ["web-1", "web-3"])
        await pilot.pause()
        assert _selected(table) == "web-3"

        _fill(table, ["web-1"])
        await pilot.pause()
        assert _selected(table) == "web-1"


@pytest.mark.asyncio
async def test_empty_tables_before_or_after_are_fine():
    async with _TableApp().run_test() as pilot:
        table = pilot.app.query_one(DataTable)
        _fill(table, ["web-1", "web-2"])
        await pilot.pause()
        assert table.cursor_row == 0

        _fill(table, [])
        await pilot.pause()
        assert table.row_count == 0

        _fill(table, ["web-1"])
        await pilot.pause()
        assert _selected(table) == "web-1"
