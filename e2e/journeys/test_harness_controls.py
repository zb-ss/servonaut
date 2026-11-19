"""Contract checks for pointer operations on real table widgets."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Static

from e2e.harness.controls import click_row
from e2e.harness.pilot import TuiDriver

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


class _TableHost(App):
    CSS = """
    DataTable { height: 1fr; }
    #highlighted { height: 1; }
    """

    def compose(self) -> ComposeResult:
        table = DataTable(id="rows", cursor_type="row")
        table.add_column("Name")
        self.result_label = Static("No row highlighted", id="highlighted")
        yield table
        yield self.result_label

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        name = event.data_table.get_row(event.row_key)[0]
        self.result_label.update(f"Highlighted {name}")


async def test_click_row_after_rows_arrive(journey) -> None:
    app = _TableHost()
    async with app.run_test(size=(80, 15)) as pilot:
        table = app.query_one("#rows", DataTable)
        driver = TuiDriver(app, pilot, [], journey.staging)
        # Enough rows to require scrolling before their dimensions have been processed.
        rows = [(f"row-{index}",) for index in range(100)]
        table.add_rows(rows)
        await click_row(driver, table, len(rows) - 1)
        await driver.wait_for_text(f"Highlighted {rows[-1][0]}")
