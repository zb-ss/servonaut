"""Regression tests for the scan results screen."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from textual.app import App
from textual.widgets import DataTable, Static

from servonaut.screens.scan_results import ScanResultsScreen


class _ScanResultsApp(App):
    """Minimal host app for mounting the scan results screen."""

    def __init__(self, results: list[dict[str, str]]) -> None:
        super().__init__()
        self.demo_mode = False
        self.redaction_service = None
        self.keyword_store = MagicMock()
        self.keyword_store.get_results.return_value = results

    def on_mount(self) -> None:
        self.push_screen(
            ScanResultsScreen({"id": "i-example", "name": "Example server"})
        )


@pytest.mark.asyncio
async def test_cached_results_populate_after_table_columns_are_created() -> None:
    """Cached rows must not be inserted before the table has columns."""
    results = [
        {
            "source": "path:~",
            "content": "first line\nsecond line",
            "timestamp": "2026-08-25T12:00:00",
        }
    ]
    app = _ScanResultsApp(results)

    async with app.run_test(headless=True) as pilot:
        await pilot.pause()

        table = app.screen.query_one("#results_table", DataTable)
        status = app.screen.query_one("#scan_status", Static)

        assert [str(column.label) for column in table.columns.values()] == [
            "Source",
            "Content",
            "Timestamp",
        ]
        assert table.row_count == 1
        assert table.get_row_at(0) == [
            "path:~",
            "first line second line",
            "2026-08-25T12:00:00",
        ]
        assert "Loaded 1 cached results" in str(status.render())

    app.keyword_store.get_results.assert_called_once_with("i-example")
