"""Fieldless Settings launchers retain visible routes and clean return state."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Static

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, CustomServer
from servonaut.screens.backup_restore import BackupRestoreScreen
from servonaut.screens.custom_servers import CustomServersScreen
from servonaut.screens.key_management import KeyManagementScreen
from servonaut.screens.settings.shell import SettingsScreen
from servonaut.screens.snapshot_manager import SnapshotManagerScreen
from tests._async_bounds import wait_until
from tests.test_settings_presentation import _Host, _ready

pytestmark = pytest.mark.usefixtures("navigation_open")


ROUTES = [
    ("custom_servers", "open_custom_servers", CustomServersScreen),
    ("ssh_keys", "ssh_keys_open", KeyManagementScreen),
    ("backups", "backups_open_snapshots", SnapshotManagerScreen),
    ("backups", "backups_open_restore", BackupRestoreScreen),
]


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(AppConfig(
        custom_servers=[CustomServer("web-1", "192.0.2.10")],
        instance_keys={"example-1": "example-key-path"},
    ))
    manager.load()
    return manager


class _LauncherHost(_Host):
    def __init__(self, manager: ConfigManager, panel_id: str, navigation: bool, *, snapshots: bool = True) -> None:
        super().__init__(manager, panel_id, navigation_visible=navigation)
        self.custom_server_service = SimpleNamespace(list_servers=lambda: manager.get().custom_servers)
        self.ssh_service = SimpleNamespace(
            check_ssh_agent=Mock(return_value=True),
            start_ssh_agent=Mock(side_effect=AssertionError("No real agent may start")),
            list_available_keys=Mock(return_value=[]),
        )
        self.config_sync_service = SimpleNamespace(list_snapshots=AsyncMock(return_value=[])) if snapshots else None
        self.cache_service = SimpleNamespace(is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [])
        self.notes: list[str] = []

    def provider_inventory(self, provider: str) -> None:
        return None

    def notify(self, message: str, **kwargs) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)


async def _click_launcher(app: _LauncherHost, pilot: Pilot, button: Button) -> None:
    button.scroll_visible(animate=False)
    await pilot.pause()
    assert app.screen.region.contains_region(button.region)
    assert app.get_widget_at(*button.region.center)[0] is button
    painted = "".join(strip.text for strip in button.render_lines(button.region.size.region))
    assert button.label.plain in painted
    assert await pilot.click(button)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("panel_id,button_id,destination", ROUTES)
async def test_launcher_pointer_opens_real_route_and_returns_to_clean_cached_panel(
    monkeypatch, manager, size, navigation, panel_id, button_id, destination,
) -> None:
    app = _LauncherHost(manager, panel_id, navigation)
    before = manager._config_path.read_bytes()
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        settings = app.screen
        assert not panel.query_one(f"#panel_save_dock_{panel_id}").display
        assert not panel.is_dirty()
        await _click_launcher(app, pilot, panel.query_one(f"#{button_id}", Button))
        await wait_until(lambda: isinstance(app.screen, destination))
        await pilot.pause()
        if destination is CustomServersScreen:
            assert app.screen.query_one("#custom_servers_table", DataTable).row_count == 1
        elif destination is KeyManagementScreen:
            app.ssh_service.check_ssh_agent.assert_called_once()
            app.ssh_service.list_available_keys.assert_called_once()
            app.ssh_service.start_ssh_agent.assert_not_called()
            # The destination's edit owner has changed the in-memory config;
            # only the launcher's real dismissal callback must repaint count.
            changed = replace(manager.get(), instance_keys={"example-1": "first", "example-2": "second"})
            monkeypatch.setattr(manager, "get", lambda: changed)
        elif destination is SnapshotManagerScreen:
            await wait_until(lambda: not app.screen._loading)
            app.config_sync_service.list_snapshots.assert_awaited_once()
        await pilot.press("escape")
        await wait_until(lambda: app.screen is settings)
        assert isinstance(app.screen, SettingsScreen)
        assert settings._current_panel() is panel
        assert not panel.is_dirty()
        if destination is KeyManagementScreen:
            assert panel.query_one("#ssh_keys_count", Static).render().plain == "Per-instance key overrides: 2 overrides configured"
        assert manager._config_path.read_bytes() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation", [True, False])
async def test_snapshot_launcher_without_service_stays_in_settings_with_existing_warning(
    manager, size, navigation,
) -> None:
    app = _LauncherHost(manager, "backups", navigation, snapshots=False)
    before = manager._config_path.read_bytes()
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        settings = app.screen
        button = panel.query_one("#backups_open_snapshots", Button)
        await _click_launcher(app, pilot, button)
        await wait_until(lambda: "Config sync is not available on this plan." in app.notes)
        assert app.screen is settings
        assert not panel.is_dirty()
        assert not panel.query_one("#panel_save_dock_backups").display
        assert manager._config_path.read_bytes() == before
