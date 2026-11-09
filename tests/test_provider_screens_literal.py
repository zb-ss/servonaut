"""Names chosen in a provider account are drawn literally on the provider screens."""
from __future__ import annotations

import importlib
from unittest.mock import AsyncMock

import pytest
from textual.widgets import DataTable

from servonaut.app import ServonautApp
from tests._literal_probe import PAYLOADS, assert_literal, no_backstop  # noqa: F401 - fixture
from tests.test_cloud_screens_multi_account import (
    Host, _config, _registry, _wait_for,
)


class LiteralHost(Host):
    CSS_PATH = ServonautApp.CSS_PATH

    def action_pwn(self) -> None:  # an action a hostile name could name
        raise AssertionError("an action named by a provider name must not run")


def _hetzner_keys(accounts, name):
    async def keys():
        return [{"name": name, "id": 7, "fingerprint": "aa:bb"}]

    for fake in accounts.hetzner.values():
        fake.list_ssh_keys = keys


def _hetzner_servers(accounts, name):
    for fake in accounts.hetzner.values():
        for row in fake.rows:
            row["name"] = name


def _ovh_servers(accounts, name):
    for fake in accounts.ovh.values():
        for row in fake.rows:
            row["name"] = name


def _ovh_volumes(accounts, name):
    for bundle in accounts.bundles.values():
        bundle.storage.list_volumes = AsyncMock(return_value=[{"id": "v1", "name": name, "size": 10}])


def _ovh_reverse_dns(accounts, name):
    for bundle in accounts.bundles.values():
        bundle.ip.list_ips = AsyncMock(
            return_value=[{"ip": "10.0.0.1/32", "type": "failover", "reverse": name}],
        )


def _ovh_keys(accounts, name):
    for bundle in accounts.bundles.values():
        bundle.cloud.list_ssh_keys = AsyncMock(return_value=[{"id": "k1", "name": name}])


def _ovh_domains(accounts, name):
    for bundle in accounts.bundles.values():
        bundle.dns.list_domains = AsyncMock(return_value=[name])


SCREENS = {
    "hetzner_ssh_keys": ("servonaut.screens.hetzner_ssh_keys", "HetznerSSHKeysScreen", _hetzner_keys),
    "hetzner_manager": ("servonaut.screens.hetzner_manager", "HetznerManagerScreen", _hetzner_servers),
    "ovh_manager": ("servonaut.screens.ovh_manager", "OVHManagerScreen", _ovh_servers),
    "ovh_storage": ("servonaut.screens.ovh_storage", "OVHStorageScreen", _ovh_volumes),
    "ovh_ip_reverse_dns": ("servonaut.screens.ovh_ip_management", "OVHIPManagementScreen", _ovh_reverse_dns),
    "ovh_ssh_keys": ("servonaut.screens.ovh_ssh_keys", "OVHSSHKeysScreen", _ovh_keys),
    "ovh_dns_zones": ("servonaut.screens.ovh_dns", "OVHDNSScreen", _ovh_domains),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("screen_name", list(SCREENS))
@pytest.mark.parametrize("kind", list(PAYLOADS))
async def test_provider_names_are_drawn_literally(no_backstop, screen_name, kind) -> None:  # noqa: F811
    module, class_name, inject = SCREENS[screen_name]
    screen_class = getattr(importlib.import_module(module), class_name)
    config = _config(hetzner_extra=False, ovh_extra=False)
    accounts = _registry(config)
    payload = PAYLOADS[kind]
    inject(accounts, payload)
    app = LiteralHost(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = screen_class()
        await app.push_screen(screen)
        await _wait_for(pilot, lambda: any(t.row_count for t in screen.query(DataTable)), "rows")
        await pilot.pause(0.1)
        assert_literal(app, payload)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", list(PAYLOADS))
async def test_snapshot_names_state_and_title_are_drawn_literally(no_backstop, kind) -> None:  # noqa: F811
    from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen

    payload = PAYLOADS[kind]
    config = _config(hetzner_extra=False, ovh_extra=False)
    accounts = _registry(config)
    for bundle in accounts.bundles.values():
        bundle.snapshot.list_vps_snapshots = AsyncMock(return_value=[
            {"name": payload, "creationDate": "2026-11-01", "description": payload},
        ])
        bundle.snapshot.get_vps_backup_options = AsyncMock(
            return_value={"state": payload, "schedule": payload},
        )
    app = LiteralHost(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = OVHSnapshotsScreen({"id": "vps-1.example", "name": payload, "provider_type": "vps"})
        await app.push_screen(screen)
        await _wait_for(pilot, lambda: any(t.row_count for t in screen.query(DataTable)), "rows")
        await pilot.pause(0.2)
        assert_literal(app, payload)
        status = str(screen.query_one("#backup_status").render())
        assert payload in status
