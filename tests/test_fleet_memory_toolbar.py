"""Fleet Memory: the compact action row and the empty state, with the real stylesheet."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer

from servonaut.config.schema import MemoryConfig
from servonaut.screens.fleet_memory import FleetMemoryScreen
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.styles import CSS_FILES
from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.safe_header import SafeHeader

pytestmark = pytest.mark.asyncio

_REAL_APP_PROPERTY = FleetMemoryScreen.__dict__["app"]

ROWS: List[Dict[str, Any]] = [
    {"id": "web-1", "name": "web-1", "provider": "custom", "public_ip": "10.0.0.1"},
    {"id": "web-2", "name": "web-2", "provider": "custom", "public_ip": "10.0.0.2"},
    {"id": "web-3", "name": "web-3", "provider": "custom", "public_ip": "10.0.0.3"},
]
BUTTONS = (
    "btn_scan_all", "btn_refresh_stale", "btn_toggle_auto_scan", "btn_refresh_view",
    "btn_open", "btn_share", "btn_clear",
)


@pytest.fixture(autouse=True)
def _real_screen_app(monkeypatch):
    monkeypatch.setattr(FleetMemoryScreen, "app", _REAL_APP_PROPERTY)


def _probe(store: MemoryStore, instance_id: str) -> None:
    """Store one module for *instance_id*, as a probe would."""
    store.save_module(instance_id, "os", {
        "module": "os", "instance_id": instance_id,
        "probed_at": datetime.now(timezone.utc).isoformat(), "ttl_seconds": 86400,
        "sudo_used": False, "truncated": False, "partial": False,
        "observed": {"name": "Debian"}, "declared": {}, "raw_output": "",
    }, "custom")
    store.update_index(instance_id, instance_id, "custom", ["os"])


def _host(tmp_path, rows=None, opt_out=(), demo: bool = False, probed=("web-1",)):
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    for instance_id in probed:
        _probe(store, instance_id)
    config = MemoryConfig(per_server_overrides={i: {"memory_disabled": True} for i in opt_out})
    listed = [dict(r) for r in (ROWS if rows is None else rows)]

    class Host(App):
        CSS_PATH = CSS_FILES
        memory_service = MemoryService(store=store, config=config, probers=[])
        demo_mode = demo
        instances = listed
        fleet_service = None
        auth_service = MagicMock()
        redaction_service = None

        def compose(self) -> ComposeResult:
            yield SafeHeader()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen(FleetMemoryScreen())

    app = Host()
    app.notify = lambda *a, **k: None  # type: ignore[method-assign]
    return app


async def _ready(pilot) -> FleetMemoryScreen:
    await pilot.pause()
    screen = pilot.app.screen
    assert isinstance(screen, FleetMemoryScreen)
    await pilot.pause()
    return screen


def _label(screen: FleetMemoryScreen, selector: str) -> str:
    return str(screen.query_one(selector, ActionButton).label)


async def test_scan_button_shows_how_many_servers_a_scan_probes(tmp_path):
    app = _host(tmp_path, opt_out=("web-3",))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert "(2)" in _label(screen, "#btn_scan_all")


async def test_no_servers_shows_the_card_without_a_scan_button(tmp_path):
    app = _host(tmp_path, rows=[])
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert screen.query_one("#fleet-memory-empty").display is True
        assert screen.query_one("#fleet-memory-table", DataTable).display is False
        assert screen.query_one("#btn_empty_scan").display is False
        assert "Add a server" in str(screen.query_one("#fleet-empty-text").render())


async def test_servers_without_any_memory_show_the_card_with_the_scan(tmp_path):
    app = _host(tmp_path, probed=())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert screen.query_one("#fleet-memory-empty").display is True
        assert screen.query_one("#fleet-memory-table", DataTable).display is False
        button = screen.query_one("#btn_empty_scan", ActionButton)
        assert button.display is True
        assert "Scan all 3 servers now" in str(button.label)
        assert "cached" in str(screen.query_one("#fleet-empty-text").render())


async def test_cached_memory_hides_the_card_and_shows_the_table(tmp_path):
    app = _host(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert screen.query_one("#fleet-memory-empty").display is False
        table = screen.query_one("#fleet-memory-table", DataTable)
        assert table.display is True and table.row_count == 3


async def test_servers_that_all_opted_out_keep_their_table(tmp_path):
    app = _host(tmp_path, probed=(), opt_out=("web-1", "web-2", "web-3"))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert screen.query_one("#fleet-memory-empty").display is False
        assert screen.query_one("#fleet-memory-table", DataTable).display is True


async def test_nothing_is_shown_as_empty_before_the_first_load(tmp_path):
    app = _host(tmp_path, probed=())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        screen._loaded = False
        screen._sync_chrome()
        assert screen.query_one("#fleet-memory-empty").display is False


async def test_demo_mode_keeps_the_count_and_hides_the_card(tmp_path):
    app = _host(tmp_path, demo=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert "(3)" in _label(screen, "#btn_scan_all")
        assert screen.query_one("#fleet-memory-empty").display is False


@pytest.mark.parametrize("button_id, action", [
    ("btn_scan_all", "action_scan_all"),
    ("btn_refresh_stale", "action_refresh_stale"),
    ("btn_toggle_auto_scan", "action_toggle_auto_scan"),
    ("btn_refresh_view", "action_refresh_view"),
    ("btn_open", "action_open_selected"),
    ("btn_share", "action_share_selected"),
    ("btn_clear", "action_clear_selected"),
])
async def test_every_action_runs_when_its_button_is_clicked(tmp_path, monkeypatch, button_id, action):
    app = _host(tmp_path)
    called: List[str] = []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        monkeypatch.setattr(screen, action, lambda: called.append(action))
        await pilot.click(f"#{button_id}")
        await pilot.pause()
    assert called == [action]


async def test_the_empty_state_scan_button_runs_the_scan(tmp_path, monkeypatch):
    app = _host(tmp_path, probed=())
    called: List[str] = []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        monkeypatch.setattr(screen, "action_scan_all", lambda: called.append("scan"))
        await pilot.click("#btn_empty_scan")
        await pilot.pause()
    assert called == ["scan"]


@pytest.mark.parametrize("key, action", [
    ("s", "action_scan_all"), ("f", "action_refresh_stale"), ("a", "action_toggle_auto_scan"),
    ("r", "action_refresh_view"), ("S", "action_share_selected"), ("x", "action_clear_selected"),
])
async def test_every_action_runs_from_its_key(tmp_path, monkeypatch, key, action):
    app = _host(tmp_path)
    called: List[str] = []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        monkeypatch.setattr(screen, action, lambda: called.append(action))
        await pilot.press(key)
        await pilot.pause()
    assert called == [action]


async def test_the_toolbar_is_short_and_the_table_gets_the_space(tmp_path):
    app = _host(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        toolbar = screen.query_one("#memory-actions", ActionRow)
        table = screen.query_one("#fleet-memory-table", DataTable)
        assert toolbar.size.height <= 3
        assert table.size.height >= 20
        assert table.region.y >= toolbar.region.bottom


@pytest.mark.parametrize("width", [80, 100, 120, 140, 160])
async def test_no_button_is_clipped_at_any_width(tmp_path, width):
    app = _host(tmp_path)
    async with app.run_test(size=(width, 40)) as pilot:
        screen = await _ready(pilot)
        await pilot.pause()
        toolbar = screen.query_one("#memory-actions", ActionRow)
        for button_id in BUTTONS:
            button = screen.query_one(f"#{button_id}", ActionButton)
            assert button.region.width > 0, button_id
            assert toolbar.region.contains_region(button.region), (width, button_id)


async def test_the_auto_scan_button_says_whether_it_is_on(tmp_path):
    app = _host(tmp_path)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert "off" in _label(screen, "#btn_toggle_auto_scan")
