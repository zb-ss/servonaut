"""Screenshot tests: Hetzner and OVH screens with two accounts each.

The seeded home gets a second Hetzner project ("archive") and a second OVH
account ("ovh-ca"), each serving pinned rows without calling a provider.
The Hetzner manager lists both projects' servers, one name in both; the
OVH SSH keys screen shows its account picker, switched to the second
account. With a single account these screens look exactly as before.
"""

from __future__ import annotations

from typing import Any, List

import pytest

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import HetznerAccount, OVHAccount

from . import _harness

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))

OVH_CA_ROWS: List[dict] = [
    {
        "id": "0e0e0000000000000000000000000002/web-0001",
        "name": "web-2",
        "type": "d2-4",
        "state": "running",
        "public_ip": "9.9.9.13",
        "private_ip": "",
        "region": "BHS5",
        "key_name": "",
        "provider": "OVH",
        "provider_type": "cloud",
        "is_ovh": True,
    },
]

# Project ids of the two OVH accounts (the SSH keys screen shows the first).
_PROJECTS = {"": "0e0e0000000000000000000000000001", "ovh-ca": "0e0e0000000000000000000000000002"}

_FLEET_SIZE = (
    len(_harness.FLEET_NAMES) + len(_harness.HETZNER_ARCHIVE_ROWS) + len(OVH_CA_ROWS)
)


class CloudAccountsSnapshotApp(_harness.SnapshotApp):
    """Every provider read through the account registry, as the real app does."""

    def provider_inventory(self, provider: str):
        return ServonautApp.provider_inventory(self, provider)


@pytest.fixture(autouse=True)
def two_accounts_each(snapshot_state: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """A second Hetzner project and OVH account, with fixed rows and keys."""
    from servonaut.services.hetzner_service import HetznerService
    from servonaut.services.ovh_cloud_service import OVHCloudService
    from servonaut.services.ovh_service import OVHService

    manager = ConfigManager()
    config = manager.get()
    config.hetzner.enabled = True
    config.hetzner.api_token = "primary-project-token"
    config.hetzner.accounts = [HetznerAccount(label="archive", api_token="archive-token")]
    config.ovh.enabled = True
    config.ovh.application_key = "app-key"
    config.ovh.cloud_project_ids = [_PROJECTS[""]]
    config.ovh.accounts = [OVHAccount(
        label="ovh-ca", endpoint="ovh-ca", client_id="id", client_secret="secret",
        cloud_project_ids=[_PROJECTS["ovh-ca"]],
    )]
    manager.save(config)

    def hetzner_rows(self: HetznerService) -> List[dict]:
        extra = self._config.label == "archive"
        rows = _harness.HETZNER_ARCHIVE_ROWS if extra else _harness.HETZNER_ROWS
        return [dict(r) for r in rows]

    def ovh_rows(self: OVHService) -> List[dict]:
        extra = self._config.label == "ovh-ca"
        return [dict(r) for r in (OVH_CA_ROWS if extra else _harness.OVH_ROWS)]

    for service, rows in ((HetznerService, hetzner_rows), (OVHService, ovh_rows)):
        async def fetch(self: Any, force_refresh: bool = False, _rows=rows) -> List[dict]:
            del force_refresh
            return _rows(self)

        monkeypatch.setattr(service, "fetch_instances_cached", fetch)
        monkeypatch.setattr(service, "get_cached_instances", rows)
        monkeypatch.setattr(service, "is_cache_fresh", lambda self: True)

    async def ssh_keys(self: OVHCloudService, project_id: str) -> List[dict]:
        suffix = "ca" if project_id == _PROJECTS["ovh-ca"] else "eu"
        return [
            {"id": f"key-{suffix}-1", "name": f"deploy-{suffix}", "fingerprint": "",
             "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixedKeyForScreens"},
        ]

    monkeypatch.setattr(OVHCloudService, "list_ssh_keys", ssh_keys)


def _run(scenario):
    async def run_before(pilot: Any) -> None:
        from servonaut.widgets.instance_table import InstanceTable

        await _harness.wait_for_screen(pilot, "InstanceListScreen")
        table = pilot.app.screen.query_one(InstanceTable)
        await _harness.wait_until(
            pilot, lambda: table.row_count == _FLEET_SIZE, "every account in the fleet"
        )
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    return run_before


def _capture(screen_snapshot: Any, size: str, scenario: Any) -> None:
    screen_snapshot(CloudAccountsSnapshotApp(), _harness.SIZES[size], _run(scenario))


async def _hetzner_manager(pilot: Any) -> None:
    from textual.widgets import DataTable

    from servonaut.screens.hetzner_manager import HetznerManagerScreen

    pilot.app.push_screen(HetznerManagerScreen())
    screen = await _harness.wait_for_screen(pilot, "HetznerManagerScreen")
    table = screen.query_one("#hetzner_mgr_table", DataTable)
    expected = len(_harness.HETZNER_ROWS) + len(_harness.HETZNER_ARCHIVE_ROWS)
    await _harness.wait_until(pilot, lambda: table.row_count == expected, "both projects")
    table.focus()
    pilot.app.clear_notifications()


async def _ovh_ssh_keys(pilot: Any) -> None:
    from textual.widgets import DataTable, Select

    from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen

    pilot.app.push_screen(OVHSSHKeysScreen())
    screen = await _harness.wait_for_screen(pilot, "OVHSSHKeysScreen")
    table = screen.query_one("#ssh_keys_table", DataTable)
    await _harness.wait_until(pilot, lambda: table.row_count == 1, "the first account's keys")
    screen.query_one("#ovh_ssh_keys_account_select", Select).value = "ovh-ca"
    await _harness.wait_until(
        pilot,
        lambda: table.row_count == 1 and str(table.get_row_at(0)[0]) == "deploy-ca",
        "the second account's keys",
    )
    table.focus()
    pilot.app.clear_notifications()


@sizes
def test_hetzner_manager_two_projects(screen_snapshot, size: str) -> None:
    """Servers of both projects, named ``project/name``."""
    _capture(screen_snapshot, size, _hetzner_manager)


@sizes
def test_ovh_ssh_keys_two_accounts(screen_snapshot, size: str) -> None:
    """The account picker leads the OVH SSH keys screen, second account chosen."""
    _capture(screen_snapshot, size, _ovh_ssh_keys)
