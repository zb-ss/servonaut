"""Fleet Memory lists the servers a team shares with the user, read-only."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer, Static

from servonaut.config.schema import MemoryConfig
from servonaut.screens.fleet_memory import FleetMemoryScreen
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.shared_view import SharedMemoryReader
from servonaut.services.memory.store import MemoryStore
from servonaut.services.memory.team_service import Grant, SharedInstance
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
TEAMS = [{"slug": "team-a", "name": "Team A"}, {"slug": "team-b", "name": "Team B"}]


def _shared(instance_id: str = "i-owner-1", modules: int = 3, name: str = "owner-web") -> SharedInstance:
    grant = Grant(
        id="g-1", instance_id=instance_id, required_role="member", modules=None,
        status="active", granted_by_user_id=1,
        created_at=datetime.fromisoformat("2026-10-01T10:00:00+00:00"), revoked_at=None,
    )
    return SharedInstance(
        grant=grant,
        instance={"instance_id": instance_id, "display_name": name, "provider": "aws",
                  "last_probe_at": "2026-10-20T08:00:00+00:00"},
        readable_modules=["os"] * modules,
    )


class _Team:
    """A fake team service: what each team lists can change between calls."""

    def __init__(self, listings: Dict[str, List[SharedInstance]]) -> None:
        self.listings = listings
        self.calls: List[str] = []

    async def list_shared_instances(self, slug: str) -> List[SharedInstance]:
        self.calls.append(slug)
        return list(self.listings.get(slug, []))


def _host(tmp_path, team: _Team, *, rows=None, demo: bool = False):
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    reader = SharedMemoryReader(team, lambda: 0.0, teams_provider=AsyncMock(return_value=TEAMS))
    listed = [dict(SHARED_ROW)] if rows is None else rows

    class Host(App):
        CSS = ""
        memory_service = MemoryService(store=store, config=MemoryConfig(), probers=[])
        shared_memory_reader = reader
        demo_mode = False
        instances = listed
        fleet_service = None

        def compose(self) -> ComposeResult:
            yield SafeHeader()
            yield Footer()

        def on_mount(self) -> None:
            if demo:
                self.demo_mode = True
                self.redaction_service = MagicMock()
                self.redaction_service.redact_name = lambda n: "stand-in-name"
                self.redaction_service.redact_instance_id = lambda n: "i-stand-in"
                self.redaction_service.redact_provider = lambda n: "stand-in-provider"
            self.push_screen(FleetMemoryScreen())

    return Host(), reader


async def _wait_for(pilot, cond):
    for _ in range(200):
        await pilot.pause(0.05)
        if cond():
            return
    raise AssertionError("timed out")


def _table(app) -> DataTable:
    return app.screen.query_one("#fleet-memory-table", DataTable)


def _cells(app) -> List[list]:
    return [list(_table(app).get_row_at(i)) for i in range(_table(app).row_count)]


async def test_a_shared_server_with_no_local_record_shows_its_age_and_module_count(tmp_path):
    app, _ = _host(tmp_path, _Team({"team-a": [_shared()]}))
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and "team" in str(_cells(app)[0][3]))
        row = _cells(app)[0]
        assert "Shared" in str(row[4]) and str(row[5]) == "3" and row[7] != "—"
        status = str(app.screen.query_one("#fleet-memory-status", Static).render())
        assert "1 shared by a team" in status


async def test_a_team_that_lists_nothing_leaves_the_row_as_it_was(tmp_path):
    team = _Team({})
    app, _ = _host(tmp_path, team)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: team.calls)
        await pilot.pause(0.2)
        assert "Shared" not in str(_cells(app)[0][4])


async def test_two_teams_listing_one_server_make_one_row(tmp_path):
    team = _Team({"team-a": [_shared()], "team-b": [_shared()]})
    app, _ = _host(tmp_path, team)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: len(team.calls) >= 2)
        await pilot.pause(0.3)
        assert _table(app).row_count == 1


async def test_a_revoked_share_turns_the_row_back(tmp_path):
    team = _Team({"team-a": [_shared()]})
    app, reader = _host(tmp_path, team)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and "Shared" in str(_cells(app)[0][4]))
        team.listings = {"team-a": []}
        await reader.prefetch_all()
        app.screen._sync_shared_rows()
        await pilot.pause(0.1)
        row = _cells(app)[0]
        assert "Shared" not in str(row[4]) and str(row[5]) == "—"


async def test_changed_module_counts_reach_a_row_already_marked_shared(tmp_path):
    team = _Team({"team-a": [_shared(modules=3)]})
    app, reader = _host(tmp_path, team)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and str(_cells(app)[0][5]) == "3")
        team.listings = {"team-a": [_shared(modules=1)]}
        await reader.prefetch_all()
        app.screen._sync_shared_rows()
        await pilot.pause(0.1)
        assert str(_cells(app)[0][5]) == "1"


async def test_a_grant_with_no_server_row_still_gets_a_read_only_row(tmp_path):
    app, _ = _host(tmp_path, _Team({"team-a": [_shared(name="owner-web")]}), rows=[])
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count)
        row = _cells(app)[0]
        assert "owner-web" in str(row[0]) and "team" in str(row[3]) and str(row[5]) == "3"
        notes: list = []
        app.notify = lambda m, **kw: notes.append(str(m))
        app.screen.action_clear_selected()
        assert notes and "read-only" in notes[0].lower()


async def test_a_grant_for_a_listed_server_adds_no_second_row(tmp_path):
    app, _ = _host(tmp_path, _Team({"team-a": [_shared()]}))
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and "team" in str(_cells(app)[0][3]))
        await pilot.pause(0.3)
        assert _table(app).row_count == 1


async def test_demo_mode_shows_stand_ins_for_a_memory_only_row(tmp_path):
    app, _ = _host(tmp_path, _Team({"team-a": [_shared(name="owner-web")]}), rows=[], demo=True)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count)
        text = " ".join(str(c) for c in _cells(app)[0])
        assert "owner-web" not in text and "i-owner-1" not in text and "stand-in-name" in text


def _listing_for(instance_id: str, modules: int) -> SharedInstance:
    return _shared(instance_id=instance_id, modules=modules)


async def test_an_own_row_keeps_the_grant_that_covers_it(tmp_path):
    own = {"id": "i-owner-1", "name": "owner-web", "provider": "aws", "public_ip": "8.8.8.8"}
    app, _ = _host(tmp_path, _Team({"team-a": [_shared()]}), rows=[own])
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and app.screen._rows
                        and app.screen._rows[0].get("grant_candidates"))
        assert _table(app).row_count == 1
        row = app.screen._rows[0]
        assert [(c.team_slug, c.instance_id) for c in row["grant_candidates"]] == [("team-a", "i-owner-1")]


async def test_two_teams_for_one_server_keep_every_candidate(tmp_path):
    team = _Team({"team-a": [_shared(modules=0)], "team-b": [_shared(modules=1)]})
    app, _ = _host(tmp_path, team, rows=[])
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count)
        await pilot.pause(0.2)
        assert _table(app).row_count == 1
        row = app.screen._rows[0]
        assert sorted(c.team_slug for c in row["grant_candidates"]) == ["team-a", "team-b"]
        assert row["instance"]["grant_candidates"] == row["grant_candidates"]


async def test_a_warm_cache_refresh_still_turns_a_revoked_row_back(tmp_path):
    team = _Team({"team-a": [_shared()]})
    app, reader = _host(tmp_path, team)
    await reader.prefetch_all()  # the listing is cached before the screen opens
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and "Shared" in str(_cells(app)[0][4]))
        team.listings = {"team-a": []}
        await reader.prefetch_all()
        app.screen._sync_shared_rows()
        await pilot.pause(0.1)
        row = _cells(app)[0]
        assert "Shared" not in str(row[4]) and str(row[5]) == "—"
