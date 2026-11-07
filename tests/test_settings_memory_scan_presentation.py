"""Memory scalars and native Scan cards retain reachable controls and state."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.cells import cell_len
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input, Static

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, ScanRule
from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor
from servonaut.services.memory import passphrase_store
from tests._async_bounds import wait_until
from tests.test_settings_presentation import _Host, _ready


SIZES = [(160, 50), (100, 30)]
MEMORY_SCALARS = [
    ("memory_enabled", "Memory enabled"),
    ("memory_sync_encryption", "Sync encryption enabled"),
    ("memory_redaction_enabled", "Redaction enabled"),
    ("memory_snapshot_stale", "Snapshot stale (seconds)"),
    ("memory_first_connect_reprompt", "First-connect reprompt (seconds)"),
    ("memory_auto_scan_enabled", "Background fleet auto-scan"),
    ("memory_auto_scan_interval", "Auto-scan interval (seconds)"),
    ("memory_findings_sync", "Findings sync enabled"),
    ("memory_findings_confidence", "Confidence threshold (0–1)"),
    ("memory_findings_index_char_cap", "Findings index char cap"),
]


@pytest.fixture(autouse=True)
def no_real_keychain(monkeypatch):
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: False)
    for name in ("get_passphrase", "store_passphrase", "clear_passphrase"):
        monkeypatch.setattr(passphrase_store, name, Mock(side_effect=AssertionError("Settings must not access passphrase storage")))
    yield
    for name in ("get_passphrase", "store_passphrase", "clear_passphrase"):
        getattr(passphrase_store, name).assert_not_called()


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = AppConfig()
    config.memory = replace(config.memory,
        disabled_modules=["example-module"], default_ttl_overrides={"services": 1800},
        per_server_overrides={"example-1": {"memory_disabled": True}},
        auto_scan_enabled=False, sync_remember_device=True,
    )
    config.default_scan_paths = ["/var/log/base.log"]
    config.scan_rules = [
        ScanRule("first-rule", {"name_contains": "web"}, ["/var/log/first.log"], ["echo first"]),
        ScanRule("second-rule", {"name_contains": "api"}, ["/var/log/second.log"], ["echo second"]),
    ]
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(config)
    manager.load()
    return manager


class _MemoryScanHost(_Host):
    def __init__(self, manager: ConfigManager, panel_id: str, navigation: bool) -> None:
        super().__init__(manager, panel_id, navigation_visible=navigation)
        self.cache_service = SimpleNamespace(is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [])
        self.scan_service = SimpleNamespace(scan_server=Mock(side_effect=AssertionError("Editing Settings must not scan a server")))
        self.fleet_refreshes = 0
        self.notes: list[str] = []

    def provider_inventory(self, provider: str) -> None:
        return None

    def _refresh_fleet_auto_scan_loop(self) -> None:
        self.fleet_refreshes += 1

    def notify(self, message: str, **kwargs) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)


def _exposed(app: _MemoryScanHost, widget: Widget) -> bool:
    hit, _ = app.get_widget_at(*widget.region.center)
    return widget.region.width > 0 and widget.region.height > 0 and app.screen.region.contains_region(widget.region) and (hit is widget or widget in hit.ancestors)


async def _click(app: _MemoryScanHost, pilot: Pilot, widget: Widget) -> None:
    if isinstance(widget, Button):
        await wait_until(lambda: not widget.has_class("-active"))
    widget.scroll_visible(animate=False)
    await pilot.pause()
    await wait_until(lambda: _exposed(app, widget))
    assert await pilot.click(widget)


async def _tab_to(app: _MemoryScanHost, pilot: Pilot, widget: Widget) -> None:
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is widget:
            assert _exposed(app, widget)
            return
        await pilot.press("tab")
    pytest.fail(f"Tab did not reach {widget.id}")


def _paint(app: _MemoryScanHost, widget: Widget) -> str:
    region = widget.content_region
    body = app.screen.query_one(".panel-body")
    assert region.width > 0 and region.height > 0
    assert app.screen.region.contains_region(widget.region)
    assert body.scrollable_content_region.contains_region(widget.region)
    strips = app.screen._compositor.render_strips()
    rows = []
    for y in range(region.y, region.bottom):
        text = strips[y].crop(region.x, region.right).text
        rows.append(text)
        column = region.x
        for glyph in text:
            width = cell_len(glyph)
            if not glyph.isspace():
                for x in range(column, column + width):
                    hit = app.get_widget_at(x, y)[0]
                    assert hit is widget or widget in hit.ancestors
            column += width
    return "\n".join(rows)


def _compact(value: str) -> str:
    return "".join(value.split())


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("keychain_available", [False, True])
async def test_memory_scalar_labels_compound_status_and_editors_remain_painted_and_reachable(
    monkeypatch, manager, size, navigation, keychain_available,
) -> None:
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: keychain_available)
    app = _MemoryScanHost(manager, "memory", navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        for field_id, label in MEMORY_SCALARS:
            field = panel.query_one(f"#{field_id}")
            field.parent.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert _exposed(app, field)
            label_widget = field.parent.query_one(".label", Static)
            assert label_widget.render().plain == label
            assert _compact(label) == _compact(_paint(app, label_widget))
        status = panel.query_one("#memory_device_auto_unlock_status", Static)
        status.parent.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert status.render().plain
        assert _compact(status.render().plain) == _compact(_paint(app, status))
        assert _exposed(app, panel.query_one("#memory_manage_device_auto_unlock", Button))
        body = panel.query_one(".panel-body")
        for editor_id, selector in (("memory_disabled_modules", ".list-add"), ("memory_ttl_overrides", ".kv-add")):
            editor = panel.query_one(f"#{editor_id}")
            editor.scroll_visible(animate=False)
            await pilot.pause()
            assert editor.region.x == body.scrollable_content_region.x
            assert editor.region.right == body.scrollable_content_region.right
            await _tab_to(app, pilot, editor.query_one(selector, Button))
        await _tab_to(app, pilot, panel.query_one("#save_memory", Button))
        assert not panel.is_dirty()
        assert app.fleet_refreshes == 0
        app.scan_service.scan_server.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_scan_native_remove_then_add_cards_roundtrip_order_and_compound_editors(
    manager, size, navigation,
) -> None:
    app = _MemoryScanHost(manager, "scan", navigation)
    original_memory = manager.get().memory
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        await wait_until(lambda: bool(panel.query("#scan_rule_name_1")))
        await _click(app, pilot, panel.query_one("#scan_rule_remove_0", Button))
        await wait_until(lambda: not panel.query("#scan_rule_card_0"))
        panel.query_one("#scan_new_rule_name", Input).value = "third-rule"
        await _click(app, pilot, panel.query_one("#scan_btn_add_rule", Button))
        await wait_until(lambda: bool(panel.query("#scan_rule_name_2")))
        panel.query_one("#scan_rule_name_1", Input).value = "second-edited"
        paths = panel.query_one("#scan_rule_paths_2", StringListEditor)
        paths.query_one(".list-new", Input).value = "/var/log/new.log"
        await _click(app, pilot, paths.query_one(".list-add", Button))
        commands = panel.query_one("#scan_rule_commands_2", StringListEditor)
        commands.query_one(".list-new", Input).value = "echo fixture"
        await _click(app, pilot, commands.query_one(".list-add", Button))
        conditions = panel.query_one("#scan_rule_conditions_2", KeyValueEditor)
        conditions.query_one(".kv-new-key", Input).value = "name_contains"
        conditions.query_one(".kv-new-value", Input).value = "db"
        await _click(app, pilot, conditions.query_one(".kv-add", Button))
        defaults = panel.query_one("#scan_default_paths_editor", StringListEditor)
        defaults.query_one(".list-new", Input).value = "/var/log/extra.log"
        await _click(app, pilot, defaults.query_one(".list-add", Button))
        await pilot.pause()
        assert panel.is_dirty()
        await _click(app, pilot, panel.query_one("#save_scan", Button))
        await wait_until(lambda: "Saved" in app.notes and not panel._settling)
        saved = ConfigManager(config_path=manager._config_path).load()
        assert saved.default_scan_paths == ["/var/log/base.log", "/var/log/extra.log"]
        assert saved.scan_rules == [
            ScanRule("second-edited", {"name_contains": "api"}, ["/var/log/second.log"], ["echo second"]),
            ScanRule("third-rule", {"name_contains": "db"}, ["/var/log/new.log"], ["echo fixture"]),
        ]
        assert saved.memory == original_memory
        assert not panel.is_dirty()
        app.scan_service.scan_server.assert_not_called()
        assert app.fleet_refreshes == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_scan_blank_surviving_rule_focuses_real_field_after_middle_id_gap(
    manager, size, navigation,
) -> None:
    app = _MemoryScanHost(manager, "scan", navigation)
    before = manager._config_path.read_bytes()
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        await wait_until(lambda: bool(panel.query("#scan_rule_name_1")))
        await _click(app, pilot, panel.query_one("#scan_rule_remove_0", Button))
        await wait_until(lambda: not panel.query("#scan_rule_name_0"))
        survivor = panel.query_one("#scan_rule_name_1", Input)
        survivor.value = ""
        await pilot.pause()
        await _click(app, pilot, panel.query_one("#save_scan", Button))
        await wait_until(lambda: app.focused is survivor)
        assert _exposed(app, survivor)
        assert manager._config_path.read_bytes() == before
        assert "Saved" not in app.notes
        app.scan_service.scan_server.assert_not_called()
