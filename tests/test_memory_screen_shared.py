"""The Memory screen shows what a team shares when there is no (newer) local copy."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer, Static

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.shared_view import SharedMemory
from servonaut.services.memory.store import MemoryStore
from servonaut.widgets.safe_header import SafeHeader

pytestmark = pytest.mark.asyncio

SHARED_ROW: Dict[str, Any] = {
    "id": "share-1", "name": "web-1", "provider": "Team Team A", "is_shared": True,
    "team_slug": "team-a", "team_name": "Team A", "instance_id": "i-owner-1",
    "public_ip": "9.9.9.9", "port": 22, "username": "deploy", "state": "shared",
}


def _shared(team_name: str = "Team A", probed_at: str = "2026-10-20T08:00:00+00:00") -> SharedMemory:
    return SharedMemory("team-a", team_name, {
        "os": {"observed": {"distro": "Debian 12"}, "declared": {}, "probed_at": probed_at},
    })


def _service(tmp_path: Path) -> MemoryService:
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    return MemoryService(store=store, config=MemoryConfig(), probers=[])


def _host(tmp_path: Path, row: Dict[str, Any], reader: Any, *, demo: bool = False, fleet=None):
    from servonaut.screens.memory import MemoryScreen

    class Host(App):
        CSS = ""
        memory_service = _service(tmp_path)
        shared_memory_reader = reader
        demo_mode = demo
        instances = fleet if fleet is not None else [row]

        def compose(self) -> ComposeResult:
            yield SafeHeader()
            yield Footer()

        def on_mount(self) -> None:
            if demo:
                self.redaction_service = MagicMock()
                self.redaction_service.redact_name = lambda n: "stand-in"
                self.redaction_service.scrub_stream = lambda t: t
            self.push_screen(MemoryScreen(row))

    return Host()


def _reader(shared: Any) -> MagicMock:
    reader = MagicMock()
    reader.read = AsyncMock(return_value=shared)
    return reader


async def _cells(app, pilot) -> list:
    for _ in range(40):
        await pilot.pause()
        table = app.screen.query_one("#memory-table", DataTable)
        if table.row_count:
            return [table.get_row_at(i) for i in range(table.row_count)]
    return []


async def test_a_member_sees_the_shared_os_module_and_where_it_comes_from(tmp_path):
    reader = _reader(_shared())
    app = _host(tmp_path, dict(SHARED_ROW), reader)
    async with app.run_test(headless=True) as pilot:
        rows = await _cells(app, pilot)
        assert [r[:3] for r in rows] == [["os", "distro", "Debian 12"]]
        label = str(app.screen.query_one("#memory-shared-source", Static).render())
        assert label == "Shared by Team A, probed 2026-10-20 08:00"
    # The share is asked for with the OWNER's instance id, not the row's.
    reader.read.assert_awaited_once_with("team-a", "Team A", "i-owner-1")


async def test_without_a_grant_nothing_is_shown(tmp_path):
    app = _host(tmp_path, dict(SHARED_ROW), _reader(None))
    async with app.run_test(headless=True) as pilot:
        assert await _cells(app, pilot) == []
        assert app.screen.query_one("#memory-shared-source").has_class("hidden")


async def test_a_newer_local_snapshot_wins(tmp_path):
    app = _host(tmp_path, dict(SHARED_ROW), _reader(_shared(probed_at="2020-01-01T00:00:00+00:00")))
    from datetime import datetime, timezone
    app.memory_service._store.save_module("share-1", "os", {
        "module": "os", "instance_id": "share-1", "observed": {"distro": "Local 13"},
        "declared": {}, "probed_at": datetime.now(tz=timezone.utc).isoformat(),
        "ttl_seconds": 86400, "sudo_used": False, "truncated": False, "partial": False,
        "raw_output": "",
    }, provider="shared")
    async with app.run_test(headless=True) as pilot:
        rows = await _cells(app, pilot)
        for _ in range(10):
            await pilot.pause()
        rows = [app.screen.query_one("#memory-table", DataTable).get_row_at(0)]
        assert rows[0][2] == "Local 13"
        assert app.screen.query_one("#memory-shared-source").has_class("hidden")


async def test_a_team_name_with_markup_is_shown_literally(tmp_path):
    app = _host(tmp_path, dict(SHARED_ROW), _reader(_shared("[bold]Odd[/bold] Team")))
    async with app.run_test(headless=True) as pilot:
        await _cells(app, pilot)
        label = str(app.screen.query_one("#memory-shared-source", Static).render())
        assert "[bold]Odd[/bold] Team" in label


async def test_demo_mode_shows_a_stand_in_team_name(tmp_path):
    app = _host(tmp_path, dict(SHARED_ROW), _reader(_shared("Real Team")), demo=True)
    async with app.run_test(headless=True) as pilot:
        await _cells(app, pilot)
        label = str(app.screen.query_one("#memory-shared-source", Static).render())
        assert "Real Team" not in label and "stand-in" in label


async def test_an_own_server_the_team_also_shares_falls_back_to_the_team_copy(tmp_path):
    own = {"id": "i-owner-1", "name": "web-1", "provider": "aws", "public_ip": "9.9.9.9", "port": 22}
    reader = _reader(_shared())
    app = _host(tmp_path, dict(own), reader, fleet=[own, dict(SHARED_ROW)])
    async with app.run_test(headless=True) as pilot:
        rows = await _cells(app, pilot)
        assert rows and rows[0][2] == "Debian 12"
    reader.read.assert_awaited_once_with("team-a", "Team A", "i-owner-1")


async def test_a_server_no_team_shares_asks_nothing(tmp_path):
    reader = _reader(_shared())
    row = {"id": "i-mine", "name": "mine", "provider": "aws", "public_ip": "9.9.9.9"}
    app = _host(tmp_path, row, reader)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.3)
    reader.read.assert_not_awaited()
