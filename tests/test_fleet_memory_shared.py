"""Fleet Memory lists the servers a team shares with the user, read-only."""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer, Static

from servonaut.config.schema import MemoryConfig
from servonaut.screens.fleet_memory import FleetMemoryScreen
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.shared_view import SharedListing
from servonaut.services.memory.store import MemoryStore
from servonaut.widgets.safe_header import SafeHeader

pytestmark = pytest.mark.asyncio

# Captured at import (collection), before any test runs: another suite
# replaces FleetMemoryScreen.app with a stand-in and never restores it.
_REAL_APP_PROPERTY = FleetMemoryScreen.__dict__["app"]


@pytest.fixture(autouse=True)
def _real_screen_app(monkeypatch):
    monkeypatch.setattr(FleetMemoryScreen, "app", _REAL_APP_PROPERTY)

SHARED_ROW: Dict[str, Any] = {
    "id": "share-1", "name": "web-1", "provider": "Team Team A", "is_shared": True,
    "team_slug": "team-a", "team_name": "Team A", "instance_id": "i-owner-1",
    "public_ip": "9.9.9.9", "port": 22, "username": "deploy", "state": "shared",
}


def _host(tmp_path, reader):
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)

    class Host(App):
        CSS = ""
        memory_service = MemoryService(store=store, config=MemoryConfig(), probers=[])
        shared_memory_reader = reader
        demo_mode = False
        instances = [dict(SHARED_ROW)]
        fleet_service = None

        def compose(self) -> ComposeResult:
            yield SafeHeader()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen(FleetMemoryScreen())

    return Host()


def _reader() -> MagicMock:
    reader = MagicMock()
    listing = SharedListing("team-a", 3, "2026-10-20T08:00:00+00:00")
    reader.cached_listing = MagicMock(side_effect=lambda slug, iid: (
        listing if reader.prefetch_listing.await_count else None))
    reader.prefetch_listing = AsyncMock()
    return reader


async def _wait_for(app, pilot, cond):
    for _ in range(200):
        await pilot.pause(0.05)
        if cond():
            return
    raise AssertionError("timed out")


async def test_a_shared_server_with_no_local_record_shows_its_age_and_module_count(tmp_path):
    reader = _reader()
    app = _host(tmp_path, reader)
    async with app.run_test(headless=True) as pilot:
        table_of = lambda: app.screen.query_one("#fleet-memory-table", DataTable)
        await _wait_for(app, pilot, lambda: table_of().row_count == 1 and "team" in str(table_of().get_row_at(0)[3]))
        row = table_of().get_row_at(0)
        assert "Shared" in str(row[4]) and str(row[5]) == "3"
        assert row[7] != "—"
        status = str(app.screen.query_one("#fleet-memory-status", Static).render())
        assert "1 shared by a team" in status
    reader.prefetch_listing.assert_awaited_once_with("team-a")


async def test_one_row_per_server_even_when_the_team_lists_it_twice(tmp_path):
    reader = _reader()
    app = _host(tmp_path, reader)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(app, pilot, lambda: reader.prefetch_listing.await_count >= 1)
        for _ in range(5):
            await pilot.pause()
        assert app.screen.query_one("#fleet-memory-table", DataTable).row_count == 1


async def test_a_team_that_lists_nothing_leaves_the_row_as_it_was(tmp_path):
    reader = MagicMock()
    reader.cached_listing = MagicMock(return_value=None)
    reader.prefetch_listing = AsyncMock()
    app = _host(tmp_path, reader)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(app, pilot, lambda: reader.prefetch_listing.await_count >= 1)
        row = app.screen.query_one("#fleet-memory-table", DataTable).get_row_at(0)
        assert "Shared" not in str(row[4])
