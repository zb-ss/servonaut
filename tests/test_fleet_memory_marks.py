"""Fleet Memory: marking the user's own servers to share several at once."""

from __future__ import annotations

from datetime import datetime, timezone
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

# Captured at import: another suite replaces FleetMemoryScreen.app with a
# stand-in and never restores it.
_REAL_APP_PROPERTY = FleetMemoryScreen.__dict__["app"]


@pytest.fixture(autouse=True)
def _real_screen_app(monkeypatch):
    monkeypatch.setattr(FleetMemoryScreen, "app", _REAL_APP_PROPERTY)


OWN_ROWS: List[Dict[str, Any]] = [
    {"id": "web-1", "name": "web-1", "provider": "custom", "public_ip": "10.0.0.1"},
    {"id": "web-2", "name": "web-2", "provider": "custom", "public_ip": "10.0.0.2"},
    {"id": "vps-1.example.net", "name": "vps-1", "provider": "custom", "public_ip": "10.0.0.3"},
]
TEAM_ROW: Dict[str, Any] = {
    "id": "share-1", "name": "team-web", "provider": "Team Team A", "is_shared": True,
    "team_slug": "team-a", "team_name": "Team A", "instance_id": "i-owner-9",
    "public_ip": "9.9.9.9", "port": 22, "username": "deploy", "state": "shared",
}


def _probe(store: MemoryStore, instance_id: str) -> None:
    """Store one module for *instance_id*, as a probe would."""
    store.save_module(instance_id, "os", {
        "module": "os", "instance_id": instance_id,
        "probed_at": datetime.now(timezone.utc).isoformat(), "ttl_seconds": 86400,
        "sudo_used": False, "truncated": False, "partial": False,
        "observed": {"name": "Debian"}, "declared": {}, "raw_output": "",
    }, "custom")
    store.update_index(instance_id, instance_id, "custom", ["os"])


def _listing(instance_id: str) -> SharedInstance:
    grant = Grant(
        id="g-9", instance_id=instance_id, required_role="member", modules=None,
        status="active", granted_by_user_id=9,
        created_at=datetime.fromisoformat("2026-10-01T10:00:00+00:00"), revoked_at=None,
    )
    return SharedInstance(grant=grant, readable_modules=["os"], instance={
        "instance_id": instance_id, "display_name": "owner-only", "provider": "aws",
        "last_probe_at": "2026-10-20T08:00:00+00:00"})


class _Team:
    def __init__(self, listings: Dict[str, List[SharedInstance]]) -> None:
        self.listings = listings

    async def list_shared_instances(self, slug: str) -> List[SharedInstance]:
        return list(self.listings.get(slug, []))


def _host(tmp_path, *, rows=None, listings=None, entitled: bool = True, opt_out=()):
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    _probe(store, "web-1")
    config = MemoryConfig(per_server_overrides={i: {"memory_disabled": True} for i in opt_out})
    teams = [{"slug": "team-a", "name": "Team A"}]
    reader = SharedMemoryReader(_Team(listings or {}), lambda: 0.0,
                                teams_provider=AsyncMock(return_value=teams))
    listed = [dict(r) for r in (OWN_ROWS if rows is None else rows)]
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=entitled)
    auth.list_teams = AsyncMock(return_value=[])

    class Host(App):
        CSS = ""
        memory_service = MemoryService(store=store, config=config, probers=[])
        shared_memory_reader = reader
        demo_mode = False
        instances = listed
        fleet_service = None
        auth_service = auth
        team_memory_service = None

        def compose(self) -> ComposeResult:
            yield SafeHeader()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen(FleetMemoryScreen())

    app = Host()
    app.notes = []  # type: ignore[attr-defined]
    app.notify = lambda m, **kw: app.notes.append(str(m))  # type: ignore[method-assign]
    return app


# Keys are pressed one at a time: Textual runs a batch's bound keys after its
# printable ones, which would reorder "space" and "S".
async def _wait_for(pilot, cond, what: str = "state"):
    for _ in range(200):
        await pilot.pause(0.05)
        if cond():
            return
    raise AssertionError(f"timed out waiting for {what}")


def _table(app) -> DataTable:
    return app.screen.query_one("#fleet-memory-table", DataTable)


def _names(app) -> List[str]:
    return [str(_table(app).get_row_at(i)[0]) for i in range(_table(app).row_count)]


def _status(app) -> str:
    return str(app.screen.query_one("#fleet-memory-status", Static).render())


async def _ready(app, pilot, rows: int = 3) -> FleetMemoryScreen:
    await _wait_for(pilot, lambda: isinstance(app.screen, FleetMemoryScreen)
                    and _table(app).row_count == rows, "the fleet rows")
    _table(app).focus()
    await pilot.pause()
    return app.screen


async def test_space_marks_a_row_and_moves_to_the_next(tmp_path):
    app = _host(tmp_path)
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot)
        await pilot.press("space")
        assert screen.marked_ids() == ["web-1"]
        assert "✓" in _names(app)[0]
        assert _table(app).cursor_row == 1
        assert "1 marked" in _status(app)


async def test_space_on_a_marked_row_unmarks_it(tmp_path):
    app = _host(tmp_path)
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot)
        await pilot.press("space")
        await pilot.press("up")
        await pilot.press("space")
        assert screen.marked_ids() == []
        assert not "✓" in _names(app)[0]
        assert "marked" not in _status(app)


async def test_a_team_server_in_the_list_cannot_be_marked(tmp_path):
    app = _host(tmp_path, rows=[TEAM_ROW, *OWN_ROWS])
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot, rows=4)
        await pilot.press("space")
        assert screen.marked_ids() == []
        assert any("read-only" in n for n in app.notes)
        assert _table(app).cursor_row == 0


async def test_a_server_only_a_team_shares_cannot_be_marked(tmp_path):
    app = _host(tmp_path, rows=[], listings={"team-a": [_listing("i-owner-9")]})
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot, rows=1)
        await pilot.press("space")
        assert screen.marked_ids() == []
        assert any("read-only" in n for n in app.notes)


async def test_mark_all_marks_every_own_server_and_again_clears(tmp_path):
    app = _host(tmp_path, rows=[TEAM_ROW, *OWN_ROWS])
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot, rows=4)
        await pilot.press("m")
        assert screen.marked_ids() == ["web-1", "web-2", "vps-1.example.net"]
        assert "3 marked" in _status(app)
        assert not "✓" in _names(app)[0]  # the team's server
        await pilot.press("m")
        assert screen.marked_ids() == []


async def test_marks_survive_a_refresh_of_the_view(tmp_path):
    app = _host(tmp_path)
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot)
        await pilot.press("down")
        await pilot.press("space")
        await pilot.press("r")
        await _wait_for(pilot, lambda: _table(app).row_count == 3, "the refreshed rows")
        await pilot.pause(0.1)
        assert screen.marked_ids() == ["web-2"]
        assert "✓" in _names(app)[1]


async def test_share_with_marks_opens_the_bulk_form_for_the_marked_servers(tmp_path):
    from servonaut.screens.memory_bulk_share import BulkShareScreen

    app = _host(tmp_path, opt_out=("web-2",))
    async with app.run_test(headless=True) as pilot:
        await _ready(app, pilot)
        await pilot.press("m")
        await pilot.press("S")
        await _wait_for(pilot, lambda: isinstance(app.screen, BulkShareScreen), "the bulk form")
        targets = app.screen.targets
        assert [t.instance_id for t in targets] == ["web-1", "web-2", "vps-1.example.net"]
        assert [t.label for t in targets] == ["web-1", "web-2", "vps-1"]
        assert [t.probed for t in targets] == [True, False, False]
        assert [t.memory_off for t in targets] == [False, True, False]


async def test_share_without_marks_keeps_the_single_server_form(tmp_path):
    from servonaut.screens.memory_share import ShareInstanceScreen

    app = _host(tmp_path)
    async with app.run_test(headless=True) as pilot:
        await _ready(app, pilot)
        await pilot.press("S")
        await _wait_for(pilot, lambda: isinstance(app.screen, ShareInstanceScreen), "the share form")


async def test_share_with_marks_needs_the_team_share_plan(tmp_path):
    from servonaut.widgets.upsell_modal import UpsellModal

    app = _host(tmp_path, entitled=False)
    async with app.run_test(headless=True) as pilot:
        await _ready(app, pilot)
        await pilot.press("m")
        await pilot.press("S")
        await _wait_for(pilot, lambda: isinstance(app.screen, UpsellModal), "the upsell")


async def test_marks_are_cleared_once_the_batch_ran(tmp_path):
    from servonaut.screens.memory_bulk_share import BulkShareScreen

    app = _host(tmp_path)
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot)
        await pilot.press("m")
        await pilot.press("S")
        await _wait_for(pilot, lambda: isinstance(app.screen, BulkShareScreen), "the bulk form")
        app.screen.dismiss(True)
        await _wait_for(pilot, lambda: app.screen is screen, "the fleet again")
        assert screen.marked_ids() == []


async def test_marks_stay_when_the_bulk_form_is_cancelled(tmp_path):
    from servonaut.screens.memory_bulk_share import BulkShareScreen

    app = _host(tmp_path)
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot)
        await pilot.press("space")
        await pilot.press("S")
        await _wait_for(pilot, lambda: isinstance(app.screen, BulkShareScreen), "the bulk form")
        await pilot.press("escape")
        await _wait_for(pilot, lambda: app.screen is screen, "the fleet again")
        assert screen.marked_ids() == ["web-1"]


async def test_marks_survive_a_demo_toggle(tmp_path):
    app = _host(tmp_path)
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot)
        await pilot.press("space")  # marks web-1
        # Demo mode redacts the listed rows in place; the app maps stand-ins back.
        stand_ins = {f"fake-{row['id']}": row["id"] for row in OWN_ROWS}
        app.real_instance_id = lambda i: stand_ins.get(i, i)
        app.instances[:] = [{**row, "id": f"fake-{row['id']}", "name": "stand-in"} for row in OWN_ROWS]
        screen.refresh_after_demo_toggle()
        await _wait_for(pilot, lambda: "fake-web-1" in str(_table(app).get_row_at(0)[1]), "the redacted rows")
        assert screen.marked_ids() == ["web-1"]
        assert "✓" in _names(app)[0]


async def test_a_row_scanned_while_shown_as_a_teams_copy_counts_as_probed(tmp_path):
    from servonaut.services.memory.status import STATUS_FRESH, STATUS_NONE
    from servonaut.screens.fleet_memory import STATUS_SHARED

    app = _host(tmp_path)
    async with app.run_test(headless=True) as pilot:
        screen = await _ready(app, pilot)
        row = dict(screen._rows[1])
        # Shown as the team's copy, then probed here: the live scan writes the
        # row's status, while the status underneath the decoration is older.
        row.update(status=STATUS_FRESH, _before_share={"status": STATUS_NONE})
        assert screen._share_target(row).probed is True
        row.update(status=STATUS_SHARED)
        assert screen._share_target(row).probed is False
