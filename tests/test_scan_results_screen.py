"""Regression tests for the scan results screen."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import DataTable, Static, TextArea

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
        assert [str(cell) for cell in table.get_row_at(0)] == [
            "path:~",
            "first line second line",
            "2026-08-25T12:00:00",
        ]
        assert "Loaded 1 cached results" in str(status.render())

    app.keyword_store.get_results.assert_called_once_with("i-example")


@pytest.mark.asyncio
async def test_successful_empty_scan_clears_cached_rows_and_complete_match() -> None:
    """An empty refresh replaces previous matches in both reading surfaces."""
    match = {
        "source": "path:/var/log/app.log",
        "content": "first line\n" + "complete match content " * 8,
        "timestamp": "2026-08-25T12:00:00",
    }
    app = _ScanResultsApp([match])
    scan_server = AsyncMock(return_value=[])
    app.scan_service = SimpleNamespace(scan_server=scan_server)
    app.ssh_service = object()
    app.connection_service = object()

    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        screen = app.screen
        table = screen.query_one("#results_table", DataTable)
        detail = screen.query_one("#scan_match_detail", TextArea)
        assert table.row_count == 1
        assert match["content"] in detail.text

        screen._instance["state"] = "running"
        screen.action_scan_now()
        await screen.workers.wait_for_complete()
        await pilot.pause()

        assert table.row_count == 0
        assert detail.text == "Select a keyword match to read its complete content."
        assert "No matches found" in str(screen.query_one("#scan_status", Static).render())
        assert app.screen is screen

    scan_server.assert_awaited_once()
    app.keyword_store.save_results.assert_called_once_with("i-example", [])
