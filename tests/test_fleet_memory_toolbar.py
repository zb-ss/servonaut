"""Fleet Memory: the compact action row and the empty state, with the real stylesheet."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer

from servonaut.config.schema import MemoryConfig
from servonaut.screens.fleet_memory import FleetMemoryScreen
from servonaut.services.memory.fleet_service import FleetService
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.styles import CSS_FILES
from servonaut.screens.memory import SimpleConfirmModal
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


class _Gated(FleetService):
    """The real fleet service, held at the start of a load until released."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.release = asyncio.Event()

    async def get_merged_fleet(self, hidden_ids=()):
        await self.release.wait()
        return await super().get_merged_fleet(hidden_ids)


def _host(tmp_path, rows=None, opt_out=(), demo: bool = False, probed=("web-1",),
          production: bool = False, noted=(), gated: bool = False):
    """*production* lists servers through the real FleetService (only those with memory)."""
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    for instance_id in probed:
        _probe(store, instance_id)
    for instance_id in noted:
        store.update_index(instance_id, instance_id, "custom", [])
    config = MemoryConfig(per_server_overrides={i: {"memory_disabled": True} for i in opt_out})
    listed = [dict(r) for r in (ROWS if rows is None else rows)]
    memory = MemoryService(store=store, config=config, probers=[])
    api = MagicMock()
    api.get = AsyncMock(side_effect=RuntimeError("offline"))
    fleet = (_Gated if gated else FleetService)(api, memory) if (production or gated) else None

    class Host(App):
        CSS_PATH = CSS_FILES
        memory_service = memory
        demo_mode = demo
        instances = listed
        fleet_service = fleet
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


def _shown(screen: FleetMemoryScreen) -> Dict[str, bool]:
    return {
        "card": screen.query_one("#fleet-memory-empty").display,
        "banner": screen.query_one("#fleet-memory-banner").display,
        "table": screen.query_one("#fleet-memory-table", DataTable).display,
    }


async def test_no_rows_shows_the_card_and_focuses_its_button(tmp_path):
    app = _host(tmp_path, probed=(), production=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert _shown(screen) == {"card": True, "banner": False, "table": False}
        assert screen.query_one("#btn_empty_scan", ActionButton).display is True
        assert screen.focused is screen.query_one("#btn_empty_scan")


async def test_no_rows_disables_the_row_actions_with_a_reason(tmp_path):
    app = _host(tmp_path, probed=(), production=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        for button_id in ("btn_open", "btn_share", "btn_clear"):
            button = screen.query_one(f"#{button_id}", ActionButton)
            assert button.disabled is True and button.tooltip, button_id
        for action in ("open_selected", "share_selected", "clear_selected", "toggle_mark", "mark_all"):
            assert screen.check_action(action, ()) is False, action


async def test_no_servers_card_has_no_scan_button(tmp_path):
    app = _host(tmp_path, rows=[], probed=(), production=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert screen.query_one("#fleet-memory-empty").display is True
        assert screen.query_one("#btn_empty_scan").display is False
        assert "Add a server" in str(screen.query_one("#fleet-empty-text").render())


@pytest.mark.parametrize("noted", [("web-2",)])
async def test_a_row_with_notes_but_no_probe_keeps_the_table_and_a_banner(tmp_path, noted):
    app = _host(tmp_path, probed=(), noted=noted, production=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert screen.query_one("#fleet-memory-table", DataTable).row_count == 1
        assert _shown(screen) == {"card": False, "banner": True, "table": True}


async def test_the_fallback_list_of_unprobed_servers_gets_a_banner_over_its_table(tmp_path):
    app = _host(tmp_path, probed=())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert screen.query_one("#fleet-memory-table", DataTable).row_count == 3
        assert _shown(screen) == {"card": False, "banner": True, "table": True}
        assert screen.query_one("#btn_open", ActionButton).disabled is False


async def test_cached_memory_shows_neither_card_nor_banner(tmp_path):
    app = _host(tmp_path, production=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert _shown(screen) == {"card": False, "banner": False, "table": True}


async def test_servers_that_all_opted_out_keep_their_table(tmp_path):
    app = _host(tmp_path, probed=(), opt_out=("web-1", "web-2", "web-3"))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert _shown(screen) == {"card": False, "banner": False, "table": True}


async def test_the_banner_stays_through_a_scan_with_progress_and_goes_after(tmp_path):
    app = _host(tmp_path, probed=())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        screen._scanning = True
        screen._set_progress("[b]Scanning 3 / 7[/b]", note="Scanning 3 of 7…")
        _probe(app.memory_service._store, "web-1")
        screen._populate_table()
        await pilot.pause()
        assert screen.query_one("#fleet-memory-banner").display is True
        assert "Scanning 3 of 7" in str(screen.query_one("#fleet-banner-text").render())
        screen._scanning = False
        screen._set_progress("")
        screen._sync_chrome()
        assert screen.query_one("#fleet-memory-banner").display is False


async def test_the_card_and_banner_are_composed_hidden_until_the_fleet_has_loaded(tmp_path):
    app = _host(tmp_path, probed=(), gated=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert _shown(screen)["card"] is False and _shown(screen)["banner"] is False
        app.fleet_service.release.set()
        await pilot.pause()
        await pilot.pause()
        assert _shown(screen)["card"] is True


async def test_onboarding_buttons_name_no_count(tmp_path):
    app = _host(tmp_path, probed=())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        label = str(screen.query_one("#btn_banner_scan", ActionButton).label)
        assert "Scan all servers now" in label and not any(c.isdigit() for c in label)


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


@pytest.mark.parametrize("button_id, production", [
    ("btn_empty_scan", True), ("btn_banner_scan", False),
])
async def test_the_onboarding_scan_buttons_run_the_scan(tmp_path, monkeypatch, button_id, production):
    app = _host(tmp_path, probed=(), production=production)
    called: List[str] = []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        monkeypatch.setattr(screen, "action_scan_all", lambda: called.append("scan"))
        await pilot.click(f"#{button_id}")
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


MANY = [{"id": f"web-{n}", "name": f"web-{n}", "provider": "custom", "public_ip": "10.0.0.9"}
        for n in range(1, 13)]


@pytest.mark.parametrize("width", [80, 90, 99, 100, 110, 120, 140, 160])
async def test_no_button_is_clipped_or_ellipsised_at_any_width(tmp_path, width):
    app = _host(tmp_path, rows=MANY)
    async with app.run_test(size=(width, 40)) as pilot:
        screen = await _ready(pilot)
        await pilot.pause()
        toolbar = screen.query_one("#memory-actions", ActionRow)
        for button_id in BUTTONS:
            button = screen.query_one(f"#{button_id}", ActionButton)
            assert toolbar.region.contains_region(button.region), (width, button_id)
            assert button.content_size.width >= button.label.cell_length, (
                width, button_id, button.label.plain)


async def test_clear_is_last_and_in_the_error_role(tmp_path):
    app = _host(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _ready(pilot)
        last = list(screen.query_one("#memory-actions", ActionRow).query(ActionButton))[-1]
        assert last.id == "btn_clear" and last.has_class("-error")
        assert "x" in last.label.plain


async def test_clear_asks_first_and_names_the_server(tmp_path):
    app = _host(tmp_path, production=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        store = app.memory_service._store
        await pilot.press("x")
        await pilot.pause()
        assert isinstance(app.screen, SimpleConfirmModal)
        assert "web-1" in app.screen._message.plain
        assert store.get_all_modules("web-1", "custom")
        await pilot.click("#confirm_no_btn")
        await pilot.pause()
        assert store.get_all_modules("web-1", "custom")
        await pilot.press("x")
        await pilot.pause()
        await pilot.click("#confirm_yes_btn")
        await pilot.pause()
        assert not store.get_all_modules("web-1", "custom")


async def test_clear_does_nothing_without_a_selection(tmp_path):
    app = _host(tmp_path, probed=(), production=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        screen.action_clear_selected()
        await pilot.pause()
        assert not isinstance(app.screen, SimpleConfirmModal)


async def test_growing_a_label_refits_the_row_so_clear_stays_on_it(tmp_path):
    app = _host(tmp_path, rows=MANY[:9])
    async with app.run_test(size=(107, 40)) as pilot:
        screen = await _ready(pilot)
        app.instances.extend(dict(r) for r in MANY[9:] + [
            {"id": f"web-{n}", "name": f"web-{n}", "provider": "custom"} for n in range(13, 120)])
        screen._sync_chrome()
        screen._refresh_auto_scan_status()
        await pilot.pause()
        await pilot.pause()
        toolbar = screen.query_one("#memory-actions", ActionRow)
        for button_id in BUTTONS:
            button = screen.query_one(f"#{button_id}", ActionButton)
            assert toolbar.region.contains_region(button.region), button_id
            assert button.content_size.width >= button.label.cell_length, button_id


async def test_the_onboarding_buttons_are_disabled_while_a_scan_runs(tmp_path):
    app = _host(tmp_path, probed=())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert screen.query_one("#btn_banner_scan").disabled is False
        screen._scanning = True
        screen._sync_chrome()
        assert screen.query_one("#btn_banner_scan").disabled is True
        screen._scanning = False
        screen._sync_chrome()
        assert screen.query_one("#btn_banner_scan").disabled is False


async def test_the_card_notices_servers_that_arrive_later(tmp_path):
    app = _host(tmp_path, rows=[], probed=(), production=True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(pilot)
        assert "Add a server" in str(screen.query_one("#fleet-empty-text").render())
        app.instances.append(dict(ROWS[0]))
        screen._recheck_card()
        await pilot.pause()
        assert "Add a server" not in str(screen.query_one("#fleet-empty-text").render())
        assert screen.query_one("#btn_empty_scan").display is True


async def test_the_banner_is_one_line_in_a_narrow_terminal(tmp_path):
    app = _host(tmp_path, probed=())
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _ready(pilot)
        await pilot.pause()
        banner = screen.query_one("#fleet-memory-banner")
        assert banner.region.height <= 3
        assert "No memory cached yet" in str(screen.query_one("#fleet-banner-text").render())
        assert screen.query_one("#fleet-memory-table", DataTable).size.height >= 8
