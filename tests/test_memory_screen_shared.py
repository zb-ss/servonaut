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
    for _ in range(200):
        await pilot.pause(0.05)
        table = app.screen.query_one("#memory-table", DataTable)
        if table.row_count:
            return [table.get_row_at(i) for i in range(table.row_count)]
    return []


async def test_a_member_sees_the_shared_os_module_and_where_it_comes_from(tmp_path):
    reader = _reader(_shared())
    app = _host(tmp_path, dict(SHARED_ROW), reader)
    async with app.run_test(headless=True) as pilot:
        rows = await _cells(app, pilot)
        assert [[str(c) for c in r[:3]] for r in rows] == [["os", "distro", "Debian 12"]]
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
        assert rows and str(rows[0][2]) == "Debian 12"
    reader.read.assert_awaited_once_with("team-a", "Team A", "i-owner-1")


async def test_a_server_no_team_shares_asks_nothing(tmp_path):
    reader = _reader(_shared())
    row = {"id": "i-mine", "name": "mine", "provider": "aws", "public_ip": "9.9.9.9"}
    app = _host(tmp_path, row, reader)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.3)
    reader.read.assert_not_awaited()


async def test_shared_notes_and_findings_are_shown_read_only(tmp_path):
    shared = SharedMemory("team-a", "Team A", {
        "annotations": {"observed": {"note": "Restart workers after deploy."}, "declared": {},
                        "content": "Restart workers after deploy.",
                        "probed_at": "2026-10-20T08:00:00+00:00"},
    })
    app = _host(tmp_path, dict(SHARED_ROW), _reader(shared))
    async with app.run_test(headless=True) as pilot:
        rows = await _cells(app, pilot)
        assert ["annotations", "note", "Restart workers after deploy."] == [str(c) for c in rows[0][:3]]
    # Nothing was written into the member's own editable record.
    assert app.memory_service.get_all_modules("share-1", "shared") == {}


MEMORY_ONLY_ROW: Dict[str, Any] = {
    "id": "i-owner-1", "name": "owner-web", "provider": "aws", "is_shared": True,
    "state": "shared", "memory_only": True, "team_slug": "team-a",
    "team_name": "Team A", "instance_id": "i-owner-1",
}


async def test_a_memory_only_row_cannot_be_probed_refreshed_or_cleared(tmp_path):
    from textual.widgets import Button

    app = _host(tmp_path, dict(MEMORY_ONLY_ROW), _reader(_shared()))
    async with app.run_test(headless=True) as pilot:
        await _cells(app, pilot)
        screen = app.screen
        for button in ("btn_refresh_all", "btn_refresh_module", "btn_pin_key",
                       "btn_clear_module", "btn_sync_now"):
            assert screen.query_one(f"#{button}", Button).disabled, button
        for action in ("refresh_all", "refresh_module", "pin_key", "clear_module", "sync_now"):
            assert not screen.check_action(action, ()), action
        label = str(screen.query_one("#memory-shared-source", Static).render())
        assert "read-only" in label.lower()


async def test_a_row_with_a_host_keeps_its_actions(tmp_path):
    from textual.widgets import Button

    app = _host(tmp_path, dict(SHARED_ROW), _reader(_shared()))
    async with app.run_test(headless=True) as pilot:
        await _cells(app, pilot)
        assert not app.screen.query_one("#btn_refresh_all", Button).disabled
        assert app.screen.check_action("refresh_all", ())


async def test_every_grant_candidate_is_tried_until_one_is_readable(tmp_path):
    from servonaut.services.memory.shared_view import ShareCandidate

    row = dict(MEMORY_ONLY_ROW)
    row["grant_candidates"] = [ShareCandidate("team-a", "Team A", "i-owner-1"),
                               ShareCandidate("team-b", "Team B", "i-owner-1")]
    reader = MagicMock()
    reader.read = AsyncMock(side_effect=[None, _shared("Team B")])
    app = _host(tmp_path, row, reader)
    async with app.run_test(headless=True) as pilot:
        rows = await _cells(app, pilot)
        assert rows and str(rows[0][2]) == "Debian 12"
    assert [c.args[0] for c in reader.read.await_args_list] == ["team-a", "team-b"]


async def test_an_own_row_reads_the_team_copy_through_its_candidates(tmp_path):
    from servonaut.services.memory.shared_view import ShareCandidate

    own = {"id": "i-owner-1", "name": "owner-web", "provider": "aws", "public_ip": "8.8.8.8",
           "grant_candidates": [ShareCandidate("team-a", "Team A", "i-owner-1")]}
    app = _host(tmp_path, own, _reader(_shared()), fleet=[dict(own)])
    async with app.run_test(headless=True) as pilot:
        rows = await _cells(app, pilot)
        assert rows and str(rows[0][2]) == "Debian 12"


async def test_a_memory_only_title_follows_demo_mode_while_open(tmp_path):
    row = dict(MEMORY_ONLY_ROW)
    row["real_name"], row["real_id"], row["real_provider"] = "owner-web", "i-owner-1", "aws"
    app = _host(tmp_path, row, _reader(_shared()))
    async with app.run_test(headless=True) as pilot:
        await _cells(app, pilot)
        screen = app.screen
        title = lambda: str(screen.query_one("#memory-title", Static).render())
        assert "owner-web" in title()
        app.demo_mode = True
        app.redaction_service = MagicMock()
        app.redaction_service.redact_name = lambda n: "stand-in-name"
        app.redaction_service.redact_instance_id = lambda n: "i-stand-in"
        app.redaction_service.redact_provider = lambda n: "stand-in-provider"
        app.redaction_service.scrub_stream = lambda t: t
        screen.refresh_after_demo_toggle()
        await pilot.pause(0.1)
        assert "owner-web" not in title() and "stand-in-name" in title()
        app.demo_mode = False
        screen.refresh_after_demo_toggle()
        await pilot.pause(0.1)
        assert "owner-web" in title()


async def test_annotate_is_off_for_a_memory_only_row(tmp_path):
    from textual.widgets import Button

    app = _host(tmp_path, dict(MEMORY_ONLY_ROW), _reader(_shared()))
    async with app.run_test(headless=True) as pilot:
        await _cells(app, pilot)
        assert app.screen.query_one("#btn_annotate", Button).disabled
        assert not app.screen.check_action("annotate", ())


async def test_shared_authored_text_is_shown_literally(tmp_path):
    from rich.text import Text

    shared = SharedMemory("team-a", "Team A", {
        "annotations": {"observed": {"note": "[bold]Keep literal[/bold] and [/]"}, "declared": {},
                        "probed_at": "2026-10-20T08:00:00+00:00"},
    })
    app = _host(tmp_path, dict(SHARED_ROW), _reader(shared))
    async with app.run_test(headless=True) as pilot:
        rows = await _cells(app, pilot)
        cell = rows[0][2]
        assert isinstance(cell, Text) and cell.plain == "[bold]Keep literal[/bold] and [/]"


async def test_disjoint_grants_from_two_teams_both_show_with_their_own_label(tmp_path):
    from servonaut.services.memory.shared_view import ShareCandidate

    row = dict(MEMORY_ONLY_ROW)
    row["grant_candidates"] = [ShareCandidate("team-a", "Team A", "i-owner-1"),
                               ShareCandidate("team-b", "Team B", "i-owner-1")]
    a = SharedMemory("team-a", "Team A", {"os": {"observed": {"distro": "Debian 12"}, "declared": {},
                                                  "probed_at": "2026-10-20T08:00:00+00:00"}})
    b = SharedMemory("team-b", "Team B", {"services": {"observed": {"nginx": "up"}, "declared": {},
                                                        "probed_at": "2026-10-21T08:00:00+00:00"}})
    reader = MagicMock()
    reader.read = AsyncMock(side_effect=[a, b])
    app = _host(tmp_path, row, reader)
    async with app.run_test(headless=True) as pilot:
        for _ in range(100):
            await pilot.pause(0.05)
            if app.screen.query_one("#memory-table", DataTable).row_count >= 2:
                break
        names = sorted(str(app.screen.query_one("#memory-table", DataTable).get_row_at(i)[0])
                       for i in range(app.screen.query_one("#memory-table", DataTable).row_count))
        assert names == ["os", "services"]
        label = str(app.screen.query_one("#memory-shared-source", Static).render())
        assert "Team A (os)" in label and "Team B (services)" in label


def _team_copy(slug, name, module, probed_at):
    return SharedMemory(slug, name, {module: {"observed": {"k": "v"}, "declared": {},
                                              "probed_at": probed_at}})


async def test_overlapping_grants_label_the_team_whose_copy_won(tmp_path):
    from servonaut.services.memory.shared_view import ShareCandidate, combine_shared

    row = dict(MEMORY_ONLY_ROW)
    row["grant_candidates"] = [ShareCandidate("team-a", "Team A", "i-owner-1"),
                               ShareCandidate("team-b", "Team B", "i-owner-1")]
    reader = MagicMock()
    reader.read = AsyncMock(side_effect=[
        _team_copy("team-a", "Team A", "os", "2026-10-20T08:00:00+00:00"),
        _team_copy("team-b", "Team B", "os", "2026-10-22T08:00:00+00:00"),
    ])
    app = _host(tmp_path, row, reader)
    async with app.run_test(headless=True) as pilot:
        await _cells(app, pilot)
        for _ in range(20):
            await pilot.pause(0.05)
        label = str(app.screen.query_one("#memory-shared-source", Static).render())
        assert "Team B" in label and "Team A" not in label
    # The combined map says the same for a sole source.
    combined = combine_shared([_team_copy("team-a", "Team A", "os", "2026-10-20T08:00:00+00:00"),
                               _team_copy("team-b", "Team B", "os", "2026-10-22T08:00:00+00:00")])
    from servonaut.services.memory.shared_view import shared_source_text
    assert shared_source_text(combined, combined.team_name).startswith("Shared by Team B")


async def test_a_module_replaced_by_local_data_makes_no_shared_claim(tmp_path):
    from datetime import datetime, timezone
    from servonaut.services.memory.shared_view import ShareCandidate

    row = dict(SHARED_ROW)
    row["grant_candidates"] = [ShareCandidate("team-a", "Team A", "i-owner-1"),
                               ShareCandidate("team-b", "Team B", "i-owner-1")]
    reader = MagicMock()
    reader.read = AsyncMock(side_effect=[
        _team_copy("team-a", "Team A", "os", "2020-01-01T00:00:00+00:00"),
        _team_copy("team-b", "Team B", "services", "2026-10-22T08:00:00+00:00"),
    ])
    app = _host(tmp_path, row, reader)
    app.memory_service._store.save_module("share-1", "os", {
        "module": "os", "instance_id": "share-1", "observed": {"distro": "Local 13"},
        "declared": {}, "probed_at": datetime.now(tz=timezone.utc).isoformat(),
        "ttl_seconds": 86400, "sudo_used": False, "truncated": False, "partial": False,
        "raw_output": ""}, provider="shared")
    async with app.run_test(headless=True) as pilot:
        await _cells(app, pilot)
        for _ in range(30):
            await pilot.pause(0.05)
        label = str(app.screen.query_one("#memory-shared-source", Static).render())
        assert "Team B (services)" in label or label.startswith("Shared by Team B")
        assert "Team A" not in label
