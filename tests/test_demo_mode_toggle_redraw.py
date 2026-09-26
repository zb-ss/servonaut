"""Switching demo mode redraws every open screen, and switching it off restores.

Runs the real app over temp storage (no outbound calls), with a config that
names a custom server, SSH keys and an OVH project, and checks what each
screen actually shows before, during and after demo mode.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable, List

import pytest
from textual.widgets import DataTable, Input, Static

from servonaut.app import ServonautApp
from servonaut.runtime import RuntimeEvidence, resolve_runtime

# Fixture identifiers: every one of them must disappear in demo mode.
SERVER_NAME = "acme-files"
SERVER_HOST = "files.acme-corp.example"
SERVER_USER = "acmeops"
SERVER_KEY = "~/.ssh/acme_files_key"
DEFAULT_KEY = "~/.ssh/acme_default_key"
MAPPED_ID = "i-0acme00000000001"
MAPPED_KEY = "~/.ssh/acme_mapped_key"
OVH_PROJECT = "0acme000000000000000000000000001"
REAL_VALUES = (
    SERVER_NAME, SERVER_HOST, SERVER_USER, "acme_files_key",
    "acme_default_key", MAPPED_ID, "acme_mapped_key", OVH_PROJECT,
)


def _runtime(tmp_path: Path):
    executable = Path(sys.executable)
    return resolve_runtime(RuntimeEvidence(
        executable=executable,
        executable_root=executable.parent,
        resource_root=tmp_path / "resources",
        home=tmp_path,
        is_frozen=False,
        package_version="2.27.0",
        package_is_installed=False,
        source_install_path=None,
        path_console=None,
        pipx_executable=None,
        pipx_contains_servonaut=False,
        marker=None,
    ))


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ServonautApp:
    from servonaut.services.cache_service import CacheService

    runtime = _runtime(tmp_path)
    root = runtime.data_root
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "version": 6,
        "default_key": DEFAULT_KEY,
        "instance_keys": {MAPPED_ID: MAPPED_KEY},
        "custom_servers": [{
            "name": SERVER_NAME, "host": SERVER_HOST, "username": SERVER_USER,
            "ssh_key": SERVER_KEY, "port": 22,
        }],
        "ovh": {"enabled": False, "cloud_project_ids": [OVH_PROJECT]},
        "memory": {"enabled": False},
        "relay": {
            "base_url": "https://loopback.invalid",
            "mercure_url": "https://loopback.invalid/.well-known/mercure",
        },
    }), encoding="utf-8")

    monkeypatch.setattr("servonaut.config.manager.CONFIG_DIR", root)
    monkeypatch.setattr("servonaut.config.manager.CONFIG_PATH", config_path)
    monkeypatch.setattr("servonaut.config.manager.BACKUP_DIR", root / "backups")
    monkeypatch.setattr("servonaut.config.manager._LEGACY_CONFIG", tmp_path / "legacy.json")
    monkeypatch.setattr("servonaut.config.manager._LEGACY_EC2SSH_DIR", tmp_path / "legacy-dir")
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", root / "auth.json")
    monkeypatch.setattr("servonaut.services.memory.store.MEMORY_ROOT", root / "memory")
    monkeypatch.setattr(CacheService, "CACHE_PATH", root / "cache.json")
    monkeypatch.setattr("servonaut.utils.ephemeral_key.cleanup_stale_bw_keys", lambda: None)
    monkeypatch.setattr(
        "servonaut.services.update_service.UpdateService.check_for_update", lambda _self: None
    )

    async def no_instances(_self, *, force_refresh: bool = False) -> list:
        return []

    monkeypatch.setattr(
        "servonaut.services.aws_service.AWSService.fetch_instances_cached", no_instances
    )
    return ServonautApp(config_path=config_path, runtime_layout=runtime)


def _shown(screen) -> str:
    """Everything the screen draws: statics, table cells and form fields."""
    parts: List[str] = []
    for static in screen.query(Static):
        if static.display:
            parts.append(str(static.render()))
    for table in screen.query(DataTable):
        for row_key in table.rows:
            parts.extend(str(cell) for cell in table.get_row(row_key))
    for field in screen.query(Input):
        if not field.password:
            parts.append(field.value)
    return "\n".join(parts)


def _visible(text: str, values: Iterable[str]) -> List[str]:
    return [value for value in values if value in text]


async def _settle(pilot) -> None:
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


async def _open(pilot, nav_id: str, screen_name: str):
    from servonaut.widgets.sidebar import Sidebar

    pilot.app.post_message(Sidebar.NavigationRequested(nav_id))
    for _ in range(50):
        await pilot.pause()
        if type(pilot.app.screen).__name__ == screen_name:
            break
    await _settle(pilot)
    assert type(pilot.app.screen).__name__ == screen_name
    return pilot.app.screen


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("nav_id", "screen_name", "expected"),
    [
        ("nav_custom_servers", "CustomServersScreen",
         (SERVER_NAME, SERVER_HOST, SERVER_USER, "acme_files_key")),
        ("nav_keys", "KeyManagementScreen",
         ("acme_default_key", MAPPED_ID, "acme_mapped_key")),
        ("nav_settings", "SettingsScreen", ("acme_default_key",)),
    ],
)
async def test_toggle_redraws_the_open_screen_and_restores_it(
    tmp_path, monkeypatch, nav_id, screen_name, expected
) -> None:
    app = _app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(200, 60)) as pilot:
        await _settle(pilot)
        screen = await _open(pilot, nav_id, screen_name)
        assert _visible(_shown(screen), expected) == list(expected)

        app.action_toggle_demo()
        await _settle(pilot)
        assert app.screen is screen, "the toggle must redraw, not navigate"
        assert _visible(_shown(screen), REAL_VALUES) == []

        app.action_toggle_demo()
        await _settle(pilot)
        assert _visible(_shown(screen), expected) == list(expected)


@pytest.mark.asyncio
async def test_settings_panels_hide_identifiers_and_save_the_real_values(
    tmp_path, monkeypatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(200, 60)) as pilot:
        await _settle(pilot)
        app.action_toggle_demo()
        await _settle(pilot)
        screen = await _open(pilot, "nav_settings", "SettingsScreen")
        general = screen._panels["general"]
        ovh = screen._ensure_content("ovh")
        await _settle(pilot)

        shown = _shown(general) + _shown(ovh)
        assert _visible(shown, ("acme_default_key", OVH_PROJECT)) == []
        assert not general.is_dirty() and not ovh.is_dirty()

        # Saving in demo mode writes the real values back, not the stand-ins.
        general.persist()
        ovh.persist()
        saved = app.config_manager.get()
        assert saved.default_key == DEFAULT_KEY
        assert saved.ovh.cloud_project_ids == [OVH_PROJECT]


@pytest.mark.asyncio
async def test_toggle_redraws_screens_below_the_top_one(tmp_path, monkeypatch) -> None:
    from servonaut.screens.instance_list import InstanceListScreen
    from servonaut.screens.server_actions import ServerActionsScreen

    app = _app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(200, 60)) as pilot:
        await _settle(pilot)
        fleet = app.screen
        assert isinstance(fleet, InstanceListScreen)
        row = next(i for i in app.instances if i.get("name") == SERVER_NAME)
        app.push_screen(ServerActionsScreen(row))
        await _settle(pilot)
        actions = app.screen
        assert SERVER_HOST in _shown(actions)

        app.action_toggle_demo()
        await _settle(pilot)
        assert _visible(_shown(actions), REAL_VALUES) == []
        assert _visible(_shown(fleet), REAL_VALUES) == []

        app.action_toggle_demo()
        await _settle(pilot)
        assert SERVER_HOST in _shown(actions)
        assert SERVER_NAME in _shown(fleet)


@pytest.mark.asyncio
async def test_toggle_shows_and_hides_the_demo_badge(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(200, 60)) as pilot:
        await _settle(pilot)
        assert "DEMO" not in _shown(app.screen)

        app.action_toggle_demo()
        await _settle(pilot)
        assert "DEMO" in _shown(app.screen)

        app.action_toggle_demo()
        await _settle(pilot)
        assert "DEMO" not in _shown(app.screen)


@pytest.mark.asyncio
async def test_a_server_fetched_before_demo_mode_keeps_its_real_record(
    tmp_path, monkeypatch
) -> None:
    """Fetched with demo mode off, acted on with it on, intact once it is off."""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from servonaut.screens.hetzner_create import HetznerCreateScreen
    from servonaut.screens.ip_ban import IPBanScreen
    from servonaut.screens.server_actions import ServerActionsScreen

    real = {
        "id": "48151623", "name": "acme-cache", "public_ip": "1.1.1.1",
        "is_hetzner": True, "provider": "hetzner", "state": "running",
    }
    app = _app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(200, 60)) as pilot:
        await _settle(pilot)
        # A server created (and fetched) while demo mode is off.
        app.hetzner_service = SimpleNamespace(
            fetch_instances_cached=AsyncMock(return_value=[dict(real)]),
            get_cached_instances=lambda: [dict(real)],
        )
        await HetznerCreateScreen()._refresh_instances_after_create()
        row = next(i for i in app.instances if i.get("is_hetzner"))
        app.push_screen(ServerActionsScreen(row))
        await _settle(pilot)
        actions = app.screen

        app.action_toggle_demo()
        await _settle(pilot)
        assert row["name"] != real["name"] and row["public_ip"] != real["public_ip"]
        target = app.connection_instance(row)
        assert (target["id"], target["public_ip"]) == (real["id"], real["public_ip"])
        actions.action_action_8()
        await _settle(pilot)
        ban = app.screen
        assert isinstance(ban, IPBanScreen)
        assert ban._prefill_real_ip == real["public_ip"]
        app.pop_screen()
        await _settle(pilot)

        app.action_toggle_demo()
        await _settle(pilot)
        assert row in app.instances, "the row must survive switching demo mode off"
        assert row["name"] == real["name"] and row["public_ip"] == real["public_ip"]
        assert real["name"] in _shown(actions)


@pytest.mark.asyncio
async def test_provider_errors_quoting_a_real_name_are_redacted(tmp_path, monkeypatch) -> None:
    """Actions now send real ids, so provider errors quote them back."""
    from textual.app import App

    vps = {
        "id": "vps-acme01.vps.ovh.net", "name": "acme-mail", "public_ip": "9.9.9.9",
        "is_ovh": True, "provider_type": "vps", "provider": "ovh",
    }
    app = _app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(200, 60)) as pilot:
        await _settle(pilot)
        app.replace_instances("ovh", [vps])
        app.action_toggle_demo()
        await _settle(pilot)
        sent = []
        monkeypatch.setattr(
            App, "notify",
            lambda self, message, **kw: sent.append((message, kw.get("markup"))),
        )
        app.notify(
            "Reinstall failed: serviceName = vps-acme01.vps.ovh.net (acme-mail) "
            "does not exist",
            severity="error", markup=False,
        )
        message, markup = sent[-1]
        assert "vps-acme01" not in message and "acme-mail" not in message
        assert app.redaction_service.redact_instance_id(vps["id"]) in message
        assert markup is False
