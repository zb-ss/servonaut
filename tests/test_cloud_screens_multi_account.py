"""Hetzner and OVH screens with several accounts per provider.

A real :class:`AccountRegistry` holds two Hetzner projects and two OVH
accounts whose services are swapped for recording fakes, so each test can
tell which account a screen listed, created in or acted on.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from textual.app import App
from textual.widgets import DataTable, Select

from servonaut.config.schema import AppConfig, HetznerAccount, OVHAccount
from servonaut.services.accounts import AccountRegistry, OVHAccountServices
from servonaut.widgets.account_picker import AccountPicker

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

HETZNER_ROWS = {
    "hetzner": [{"id": "11", "name": "web-1", "type": "cx22", "state": "stopped",
                 "public_ip": "9.9.9.9", "region": "fsn1", "is_hetzner": True}],
    "staging": [{"id": "22", "name": "web-1", "type": "cx22", "state": "stopped",
                 "public_ip": "1.1.1.1", "region": "nbg1", "is_hetzner": True}],
}
OVH_ROWS = {
    "ovh": [{"id": "vps-1.example", "name": "mail-1", "type": "vps", "state": "stopped",
             "provider_type": "vps", "public_ip": "9.9.9.9", "region": "GRA", "is_ovh": True}],
    "ca": [{"id": "proj-ca/inst-1", "name": "mail-1", "type": "d2-2", "state": "stopped",
            "provider_type": "cloud", "public_ip": "1.1.1.1", "region": "BHS5", "is_ovh": True}],
}


class FakeHetzner:
    """One Hetzner project: records every call, serves canned lists."""

    def __init__(self, label: str, config, rows: List[dict]) -> None:
        self.label = label
        self._config = config
        self.rows = [dict(r) for r in rows]
        self.calls: List[tuple] = []
        self.last_fetch_error: Optional[str] = None

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        return [dict(r) for r in self.rows]

    def get_cached_instances(self) -> List[dict]:
        return [dict(r) for r in self.rows]

    def is_cache_fresh(self) -> bool:
        return True

    async def power_on(self, identifier: str) -> bool:
        self.calls.append(("power_on", identifier))
        return True

    async def delete_server(self, identifier: str) -> bool:
        self.calls.append(("delete_server", identifier))
        return True

    async def list_server_types(self) -> List[dict]:
        return [{"name": f"{self.label}-type", "cores": 2, "memory_gb": 4,
                 "disk_gb": 40, "architecture": "x86"}]

    async def list_images(self) -> List[dict]:
        return [{"name": f"{self.label}-image", "architecture": "x86"}]

    async def list_locations(self) -> List[dict]:
        return [{"name": f"{self.label}-dc", "city": "", "country": "DE"}]

    async def list_ssh_keys(self) -> List[dict]:
        return [
            {"name": f"{self.label}-other", "id": 1, "fingerprint": "aa"},
            {"name": f"{self.label}-key", "id": 2, "fingerprint": "bb"},
        ]

    async def create_ssh_key(self, name: str, public_key: str) -> dict:
        self.calls.append(("create_ssh_key", name))
        return {"name": name}

    async def create_server(self, **kwargs) -> dict:
        self.calls.append(("create_server", kwargs))
        self.rows.append({"id": "99", "name": kwargs["name"], "is_hetzner": True})
        return {"id": "99"}


class FakeOVH:
    """One OVH account's API service."""

    def __init__(self, label: str, config, rows: List[dict]) -> None:
        self.label = label
        self._config = config
        self.rows = [dict(r) for r in rows]
        self.calls: List[tuple] = []
        self.last_fetch_error: Optional[str] = None
        self.last_fetch_partial = False
        self.credential_error: Optional[str] = None

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        return [dict(r) for r in self.rows]

    def get_cached_instances(self) -> List[dict]:
        return [dict(r) for r in self.rows]

    def is_cache_fresh(self) -> bool:
        return True

    async def check_credentials(self) -> Optional[str]:
        return self.credential_error

    async def start_instance(self, identifier: str, provider_type: str) -> bool:
        self.calls.append(("start_instance", identifier, provider_type))
        return True


def _ovh_bundle(ovh: FakeOVH) -> OVHAccountServices:
    label = ovh.label
    cloud = SimpleNamespace(
        list_regions=AsyncMock(return_value=["GRA7"]),
        list_flavors=AsyncMock(return_value=[
            {"id": f"{label}-flavor", "name": "d2-2", "region": "GRA7", "available": True},
        ]),
        list_images=AsyncMock(return_value=[
            {"id": f"{label}-image", "name": "Debian 12", "region": "GRA7"},
        ]),
        list_ssh_keys=AsyncMock(return_value=[{"id": f"{label}-key", "name": f"{label}-key"}]),
        add_ssh_key=AsyncMock(return_value={}),
        delete_ssh_key=AsyncMock(return_value=True),
        create_instance=AsyncMock(return_value={"id": "new"}),
        delete_instance=AsyncMock(return_value=True),
    )
    return OVHAccountServices(
        ovh=ovh,
        cloud=cloud,
        billing=SimpleNamespace(
            get_current_usage=AsyncMock(return_value={}),
            get_monthly_spend_history=AsyncMock(return_value=[]),
            get_invoices=AsyncMock(return_value=[{"billId": f"{label}-bill", "date": "2026-09-01"}]),
            get_service_list=AsyncMock(return_value=[]),
        ),
        storage=SimpleNamespace(list_volumes=AsyncMock(return_value=[
            {"id": f"{label}-vol", "name": f"{label}-vol", "size": 10},
        ])),
        dns=SimpleNamespace(
            list_domains=AsyncMock(return_value=[f"{label}.example"]),
            list_records=AsyncMock(return_value=[]),
        ),
        ip=SimpleNamespace(
            list_ips=AsyncMock(return_value=[{"ip": "10.0.0.1/32", "type": "failover"}]),
            list_reverse_dns=AsyncMock(return_value=[]),
            get_firewall=AsyncMock(return_value={"enabled": False}),
            list_firewall_rules=AsyncMock(return_value=[]),
        ),
        vps=SimpleNamespace(
            list_images=AsyncMock(return_value=[{"id": f"{label}-os", "name": "debian-12"}]),
            list_upgrade_models=AsyncMock(return_value=[]),
            get_reverse_dns=AsyncMock(return_value=f"{label}.rdns.example"),
        ),
        snapshot=SimpleNamespace(
            list_vps_snapshots=AsyncMock(return_value=[]),
            list_cloud_snapshots=AsyncMock(return_value=[]),
        ),
    )


# ---------------------------------------------------------------------------
# Registry and host
# ---------------------------------------------------------------------------


def _config(
    *, hetzner_extra: bool = True, ovh_extra: bool = True,
    hetzner_label: str = "staging", ovh_label: str = "ca",
) -> AppConfig:
    config = AppConfig()
    config.hetzner.enabled = True
    config.hetzner.api_token = "primary-token"
    config.hetzner.default_hetzner_ssh_key = "hetzner-key"
    if hetzner_extra:
        config.hetzner.accounts = [HetznerAccount(
            label=hetzner_label, api_token="extra-token",
            default_hetzner_ssh_key=f"{hetzner_label}-key",
        )]
    config.ovh.enabled = True
    config.ovh.application_key = "k"
    config.ovh.cloud_project_ids = ["proj-eu"]
    if ovh_extra:
        config.ovh.accounts = [OVHAccount(
            label=ovh_label, client_id="c", client_secret="s", cloud_project_ids=["proj-ca"],
        )]
    return config


class Accounts(SimpleNamespace):
    """The registry plus the fake behind every account, by label."""


def _registry(config: AppConfig) -> Accounts:
    registry = AccountRegistry(config)
    hetzner: Dict[str, FakeHetzner] = {}
    for ref in registry.accounts("hetzner"):
        real = registry.service("hetzner", ref.label)
        rows = HETZNER_ROWS["hetzner" if ref.primary else "staging"]
        hetzner[ref.label] = FakeHetzner(ref.label, real._config, rows)
        registry._providers["hetzner"].services[ref.key] = hetzner[ref.label]
    ovh: Dict[str, FakeOVH] = {}
    bundles: Dict[str, OVHAccountServices] = {}
    for ref in registry.accounts("ovh"):
        real = registry.service("ovh", ref.label)
        rows = OVH_ROWS["ovh" if ref.primary else "ca"]
        ovh[ref.label] = FakeOVH(ref.label, real._config, rows)
        registry._providers["ovh"].services[ref.key] = ovh[ref.label]
        bundles[ref.label] = _ovh_bundle(ovh[ref.label])
        registry._ovh_bundles[ref.key] = bundles[ref.label]
    return Accounts(registry=registry, hetzner=hetzner, ovh=ovh, bundles=bundles)


class Host(App):
    """The attributes the provider screens read from the real app."""

    demo_mode = False
    redaction_service = None
    ovh_audit = None

    def __init__(self, accounts: Accounts, config: AppConfig) -> None:
        super().__init__()
        self.accounts = accounts.registry
        self.config_manager = SimpleNamespace(get=lambda: config)
        self.instances: List[dict] = []
        self.hetzner_service = accounts.registry.default_service("hetzner")
        self.ovh_service = accounts.registry.default_service("ovh")
        self.ovh_cloud_service = accounts.registry.ovh_services().cloud

    def provider_inventory(self, provider: str):
        return self.accounts.fleet(provider)


@pytest.fixture
def config() -> AppConfig:
    return _config()


@pytest.fixture
def accounts(config) -> Accounts:
    return _registry(config)


async def _wait_for(pilot, predicate: Callable[[], bool], what: str) -> None:
    for _ in range(1000):
        if predicate():
            return
        await pilot.pause(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def _names(screen, table_id: str) -> List[str]:
    table = screen.query_one(f"#{table_id}", DataTable)
    return [str(table.get_row_at(i)[0]) for i in range(table.row_count)]


def _column(screen, table_id: str, column: int) -> List[str]:
    table = screen.query_one(f"#{table_id}", DataTable)
    return [str(table.get_row_at(i)[column]) for i in range(table.row_count)]


async def _pick(pilot, screen, picker_id: str, label: str) -> None:
    picker = screen.query_one(f"#{picker_id}", AccountPicker)
    assert picker.display, "the account picker is shown with several accounts"
    screen.query_one(f"#{picker_id}_select", Select).value = label
    await _wait_for(pilot, lambda: picker.account == label, f"account {label}")


# ---------------------------------------------------------------------------
# Hetzner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hetzner_manager_lists_every_project_and_acts_in_the_owning_one(accounts, config):
    from servonaut.screens.hetzner_manager import HetznerManagerScreen

    app = Host(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = HetznerManagerScreen()
        await app.push_screen(screen)
        table = screen.query_one("#hetzner_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 2, "both projects' servers")
        # Two servers share a name: each is shown under its project.
        assert _column(screen, "hetzner_mgr_table", 1) == ["hetzner/web-1", "staging/web-1"]

        table.focus()
        table.move_cursor(row=1)
        await pilot.pause()
        screen.action_power_on()
        await _wait_for(pilot, lambda: accounts.hetzner["staging"].calls, "the start")
        assert accounts.hetzner["staging"].calls == [("power_on", "22")]
        assert accounts.hetzner["hetzner"].calls == []


@pytest.mark.asyncio
async def test_hetzner_manager_deletes_in_the_owning_project(accounts, config):
    from servonaut.screens.hetzner_manager import HetznerManagerScreen

    app = Host(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = HetznerManagerScreen()
        await app.push_screen(screen)
        table = screen.query_one("#hetzner_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 2, "both projects' servers")
        with patch.object(type(app), "push_screen_wait", AsyncMock(return_value=True)):
            await screen._do_delete(screen._instances[1])
    assert accounts.hetzner["staging"].calls == [("delete_server", "22")]
    assert accounts.hetzner["hetzner"].calls == []


@pytest.mark.asyncio
async def test_hetzner_create_uses_the_chosen_project(accounts, config):
    from servonaut.screens.hetzner_create import HetznerCreateScreen
    from textual.widgets import Input

    app = Host(accounts, config)
    async with app.run_test(size=(160, 60)) as pilot:
        screen = HetznerCreateScreen()
        await app.push_screen(screen)
        keys = screen.query_one("#hetzner_keys_table", DataTable)
        await _wait_for(pilot, lambda: keys.row_count == 2, "the default project's keys")
        assert _names(screen, "hetzner_types_table") == ["hetzner-type"]

        await _pick(pilot, screen, "hetzner_create_account", "staging")
        await _wait_for(
            pilot, lambda: _names(screen, "hetzner_types_table") == ["staging-type"]
            and keys.row_count == 2, "the staging project's lists",
        )
        assert _names(screen, "hetzner_locations_table") == ["staging-dc"]
        assert _names(screen, "hetzner_keys_table") == ["staging-other", "staging-key"]
        # The default Hetzner-side key is the chosen project's own.
        assert keys.cursor_row == 1

        screen.query_one("#hetzner_input_name", Input).value = "db-1"
        with patch.object(type(app), "push_screen_wait", AsyncMock(return_value=True)) as ask:
            await screen._on_create()
        assert "in project [bold]staging[/bold]" in ask.call_args.args[0]._description

    created = [c for c in accounts.hetzner["staging"].calls if c[0] == "create_server"]
    assert created and created[0][1]["ssh_keys"] == ["staging-key"]
    assert created[0][1]["server_type"] == "staging-type"
    assert accounts.hetzner["hetzner"].calls == []
    # The fleet got every project's servers, the new one under its project.
    listed = {(row["account"], row["id"]) for row in app.instances}
    assert listed == {("hetzner", "11"), ("staging", "22"), ("staging", "99")}


@pytest.mark.asyncio
async def test_hetzner_ssh_keys_follow_the_chosen_project(accounts, config):
    from servonaut.screens.hetzner_ssh_keys import HetznerSSHKeysScreen
    from textual.widgets import Input

    app = Host(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = HetznerSSHKeysScreen()
        await app.push_screen(screen)
        await _wait_for(
            pilot, lambda: _names(screen, "hetzner_ssh_keys_table") == ["hetzner-other", "hetzner-key"],
            "the default project's keys",
        )
        await _pick(pilot, screen, "hetzner_ssh_keys_account", "staging")
        await _wait_for(
            pilot, lambda: _names(screen, "hetzner_ssh_keys_table") == ["staging-other", "staging-key"],
            "the staging project's keys",
        )
        screen.action_add_key()
        screen.query_one("#hetzner_ssh_input_name", Input).value = "laptop"
        screen.query_one("#hetzner_ssh_input_public_key", Input).value = "ssh-ed25519 AAAA test"
        screen._save_key()
        await _wait_for(pilot, lambda: accounts.hetzner["staging"].calls, "the key upload")
    assert accounts.hetzner["staging"].calls == [("create_ssh_key", "laptop")]
    assert accounts.hetzner["hetzner"].calls == []


# ---------------------------------------------------------------------------
# OVH
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ovh_manager_lists_every_account_and_acts_in_the_owning_one(accounts, config):
    from servonaut.screens.ovh_manager import OVHManagerScreen

    app = Host(accounts, config)
    async with app.run_test(size=(200, 48)) as pilot:
        screen = OVHManagerScreen()
        await app.push_screen(screen)
        table = screen.query_one("#ovh_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 2, "both accounts' instances")
        assert _column(screen, "ovh_mgr_table", 1) == ["ovh/mail-1", "ca/mail-1"]

        table.focus()
        table.move_cursor(row=1)
        await pilot.pause()
        screen.action_start()
        await _wait_for(pilot, lambda: accounts.ovh["ca"].calls, "the start")
        assert accounts.ovh["ca"].calls == [("start_instance", "proj-ca/inst-1", "cloud")]
        assert accounts.ovh["ovh"].calls == []

        with patch.object(type(app), "push_screen_wait", AsyncMock(return_value=True)):
            await screen._do_delete(screen._instances[1])
    accounts.bundles["ca"].cloud.delete_instance.assert_awaited_once_with("proj-ca", "inst-1")
    accounts.bundles["ovh"].cloud.delete_instance.assert_not_awaited()


@pytest.mark.asyncio
async def test_ovh_manager_names_the_account_whose_credentials_fail(accounts, config):
    from servonaut.screens.ovh_manager import OVHManagerScreen

    for fake in accounts.ovh.values():
        fake.rows = []
    accounts.ovh["ca"].credential_error = "Authentication failed."
    app = Host(accounts, config)
    async with app.run_test(size=(200, 48)) as pilot:
        screen = OVHManagerScreen()
        await app.push_screen(screen)
        status = screen.query_one("#ovh_mgr_status")
        await _wait_for(pilot, lambda: "ca: Authentication failed." in str(status.content), "the error")


@pytest.mark.asyncio
async def test_ovh_cloud_create_uses_the_chosen_accounts_project(accounts, config):
    from servonaut.screens.ovh_cloud_create import OVHCloudCreateScreen
    from textual.widgets import Input

    app = Host(accounts, config)
    async with app.run_test(size=(160, 60)) as pilot:
        screen = OVHCloudCreateScreen()
        await app.push_screen(screen)
        flavors = screen.query_one("#flavors_table", DataTable)
        await _wait_for(pilot, lambda: flavors.row_count == 1, "the default account's flavors")
        accounts.bundles["ovh"].cloud.list_regions.assert_awaited_with("proj-eu")

        await _pick(pilot, screen, "cloud_create_account", "ca")
        await _wait_for(
            pilot, lambda: accounts.bundles["ca"].cloud.list_flavors.await_count >= 2
            and flavors.row_count == 1
            and screen.query_one("#keys_table", DataTable).row_count == 1,
            "the ca account's lists",
        )
        accounts.bundles["ca"].cloud.list_regions.assert_awaited_with("proj-ca")
        accounts.bundles["ca"].cloud.list_ssh_keys.assert_awaited_with("proj-ca")
        assert screen._flavors[0]["id"] == "ca-flavor"

        screen.query_one("#input_name", Input).value = "batch-1"
        with patch.object(type(app), "push_screen_wait", AsyncMock(return_value=True)) as ask:
            await screen._on_create()
        assert "in account [bold]ca[/bold]" in ask.call_args.args[0]._description

    create = accounts.bundles["ca"].cloud.create_instance
    create.assert_awaited_once()
    assert create.call_args.kwargs["project_id"] == "proj-ca"
    assert create.call_args.kwargs["flavor_id"] == "ca-flavor"
    accounts.bundles["ovh"].cloud.create_instance.assert_not_awaited()
    assert {row["account"] for row in app.instances} == {"ovh", "ca"}


@pytest.mark.asyncio
async def test_ovh_cloud_create_says_when_the_chosen_account_has_no_project(config):
    config.ovh.accounts[0].cloud_project_ids = []
    accounts = _registry(config)
    app = Host(accounts, config)
    async with app.run_test(size=(160, 60)) as pilot:
        from servonaut.screens.ovh_cloud_create import OVHCloudCreateScreen

        screen = OVHCloudCreateScreen()
        await app.push_screen(screen)
        flavors = screen.query_one("#flavors_table", DataTable)
        await _wait_for(pilot, lambda: flavors.row_count == 1, "the default account's flavors")

        await _pick(pilot, screen, "cloud_create_account", "ca")
        await _wait_for(pilot, lambda: len(screen.query("#no_project_error")) == 1, "the notice")
        assert flavors.row_count == 0 and screen._project_id == ""

        await _pick(pilot, screen, "cloud_create_account", "ovh")
        await _wait_for(
            pilot, lambda: flavors.row_count == 1 and not screen.query("#no_project_error"),
            "the default account's project again",
        )
        assert screen._project_id == "proj-eu"
    accounts.bundles["ca"].cloud.list_regions.assert_not_awaited()


@pytest.mark.asyncio
async def test_ovh_ssh_keys_follow_the_chosen_account(accounts, config):
    from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen

    app = Host(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = OVHSSHKeysScreen()
        await app.push_screen(screen)
        await _wait_for(pilot, lambda: _names(screen, "ssh_keys_table") == ["ovh-key"], "keys")
        await _pick(pilot, screen, "ovh_ssh_keys_account", "ca")
        await _wait_for(pilot, lambda: _names(screen, "ssh_keys_table") == ["ca-key"], "ca keys")
        assert screen._project_id == "proj-ca"
        await screen._do_add("laptop", "ssh-ed25519 AAAA test")
    accounts.bundles["ca"].cloud.add_ssh_key.assert_awaited_once_with("proj-ca", "laptop", "ssh-ed25519 AAAA test")
    accounts.bundles["ovh"].cloud.add_ssh_key.assert_not_awaited()


@pytest.mark.asyncio
async def test_ovh_storage_lists_the_chosen_accounts_volumes(accounts, config):
    from servonaut.screens.ovh_storage import OVHStorageScreen

    app = Host(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = OVHStorageScreen()
        await app.push_screen(screen)
        await _wait_for(pilot, lambda: _names(screen, "volumes_table") == ["ovh-vol"], "volumes")
        await _pick(pilot, screen, "storage_account", "ca")
        await _wait_for(pilot, lambda: _names(screen, "volumes_table") == ["ca-vol"], "ca volumes")
    accounts.bundles["ca"].storage.list_volumes.assert_awaited_once_with("proj-ca")
    accounts.bundles["ovh"].storage.list_volumes.assert_awaited_once_with("proj-eu")


@pytest.mark.asyncio
async def test_ovh_billing_shows_the_chosen_account(accounts, config):
    from servonaut.screens.ovh_billing import OVHBillingScreen

    app = Host(accounts, config)
    async with app.run_test(size=(160, 60)) as pilot:
        screen = OVHBillingScreen()
        await app.push_screen(screen)
        await _wait_for(pilot, lambda: _column(screen, "invoices_table", 1) == ["ovh-bill"], "invoices")
        await _pick(pilot, screen, "billing_account", "ca")
        await _wait_for(pilot, lambda: _column(screen, "invoices_table", 1) == ["ca-bill"], "ca invoices")
    accounts.bundles["ca"].billing.get_current_usage.assert_awaited_once()
    accounts.bundles["ovh"].billing.get_invoices.assert_awaited_once()


@pytest.mark.asyncio
async def test_ovh_dns_shows_the_chosen_accounts_zones(accounts, config):
    from servonaut.screens.ovh_dns import OVHDNSScreen

    app = Host(accounts, config)
    async with app.run_test(size=(160, 60)) as pilot:
        screen = OVHDNSScreen()
        await app.push_screen(screen)
        await _wait_for(pilot, lambda: _names(screen, "domains_table") == ["ovh.example"], "zones")
        await _pick(pilot, screen, "dns_account", "ca")
        await _wait_for(pilot, lambda: _names(screen, "domains_table") == ["ca.example"], "ca zones")
    accounts.bundles["ca"].ip.list_ips.assert_awaited_once()


@pytest.mark.asyncio
async def test_ovh_dns_drops_a_load_that_outlives_an_account_switch(accounts, config):
    from servonaut.screens.ovh_dns import OVHDNSScreen

    release = asyncio.Event()

    async def slow_domains():
        await release.wait()
        return ["ovh.example"]

    accounts.bundles["ovh"].dns.list_domains = slow_domains
    app = Host(accounts, config)
    async with app.run_test(size=(160, 60)) as pilot:
        screen = OVHDNSScreen()
        await app.push_screen(screen)
        await pilot.pause()
        await _pick(pilot, screen, "dns_account", "ca")
        await _wait_for(pilot, lambda: _names(screen, "domains_table") == ["ca.example"], "ca zones")
        release.set()
        await pilot.pause(0.05)
        assert _names(screen, "domains_table") == ["ca.example"]


@pytest.mark.asyncio
async def test_ovh_ip_management_lists_the_chosen_accounts_ips(accounts, config):
    from servonaut.screens.ovh_ip_management import OVHIPManagementScreen

    app = Host(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = OVHIPManagementScreen()
        await app.push_screen(screen)
        await _wait_for(pilot, lambda: accounts.bundles["ovh"].ip.list_ips.await_count == 1, "ips")
        await _pick(pilot, screen, "ip_mgmt_account", "ca")
        await _wait_for(pilot, lambda: accounts.bundles["ca"].ip.list_ips.await_count == 1, "ca ips")


# ---------------------------------------------------------------------------
# Per-server screens: the server's own account
# ---------------------------------------------------------------------------


def _ca_row() -> dict:
    return dict(OVH_ROWS["ca"][0], account="ca", account_qualified=True)


@pytest.mark.parametrize(("module", "cls", "kind"), [
    ("servonaut.screens.ovh_reinstall", "OVHReinstallScreen", "vps"),
    ("servonaut.screens.ovh_resize", "OVHResizeScreen", "vps"),
    ("servonaut.screens.ovh_snapshots", "OVHSnapshotsScreen", "snapshot"),
    ("servonaut.screens.ovh_firewall", "OVHFirewallScreen", "ip"),
    ("servonaut.screens.server_actions", "ServerActionsScreen", "vps"),
])
def test_per_server_screens_use_the_servers_account(accounts, config, module, cls, kind):
    import importlib

    screen_cls = getattr(importlib.import_module(module), cls)
    screen = screen_cls(_ca_row())
    app = SimpleNamespace(accounts=accounts.registry)
    with patch.object(screen_cls, "app", new_callable=PropertyMock, return_value=app):
        assert screen._ovh_service(kind) is getattr(accounts.bundles["ca"], kind)


def test_reinstall_lists_images_of_the_servers_account(accounts, config):
    from servonaut.screens.ovh_reinstall import OVHReinstallScreen

    row = dict(OVH_ROWS["ovh"][0], account="ovh", account_qualified=True)
    screen = OVHReinstallScreen(row)
    app = SimpleNamespace(accounts=accounts.registry, demo_mode=False)
    with (
        patch.object(OVHReinstallScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=MagicMock()),
    ):
        asyncio.run(screen._load_images())
    accounts.bundles["ovh"].vps.list_images.assert_awaited_once_with("vps-1.example")
    accounts.bundles["ca"].vps.list_images.assert_not_awaited()


@pytest.mark.asyncio
async def test_server_actions_reverse_dns_asks_the_servers_account(accounts, config):
    from servonaut.screens.server_actions import ServerActionsScreen

    row = dict(OVH_ROWS["ovh"][0], account="ovh", account_qualified=True)
    screen = ServerActionsScreen(row)
    app = SimpleNamespace(accounts=accounts.registry)
    with (
        patch.object(ServerActionsScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_render_server_info"),
    ):
        await screen._fetch_rdns()
    accounts.bundles["ovh"].vps.get_reverse_dns.assert_awaited_once_with("vps-1.example", "9.9.9.9")
    accounts.bundles["ca"].vps.get_reverse_dns.assert_not_awaited()
    assert screen._reverse_dns == "ovh.rdns.example"


def test_a_row_of_a_removed_account_is_refused_with_a_message(accounts, config):
    from servonaut.screens.ovh_reinstall import OVHReinstallScreen

    screen = OVHReinstallScreen(dict(_ca_row(), account="gone"))
    app = SimpleNamespace(accounts=accounts.registry, demo_mode=False)
    with (
        patch.object(OVHReinstallScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "notify") as notify,
        patch.object(screen, "query_one", return_value=MagicMock()),
    ):
        asyncio.run(screen._load_images())
    first = notify.call_args_list[0]
    assert "No OVH account named 'gone'" in first.args[0]
    assert first.kwargs["markup"] is False
    for bundle in accounts.bundles.values():
        bundle.vps.list_images.assert_not_awaited()


@pytest.mark.asyncio
async def test_manager_refuses_a_row_of_a_removed_account(accounts, config):
    from servonaut.screens.hetzner_manager import HetznerManagerScreen

    app = Host(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = HetznerManagerScreen()
        await app.push_screen(screen)
        table = screen.query_one("#hetzner_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 2, "both projects' servers")
        # The project was removed from the settings after the list loaded.
        screen._raw_instances[1]["account"] = "gone"
        table.focus()
        table.move_cursor(row=1)
        await pilot.pause()
        with patch.object(screen, "notify") as notify:
            screen.action_power_on()
            await pilot.pause()
        assert "No Hetzner account named 'gone'" in notify.call_args.args[0]
        assert notify.call_args.kwargs["markup"] is False
    for fake in accounts.hetzner.values():
        assert fake.calls == []


def test_an_unavailable_account_says_why(monkeypatch):
    from servonaut.screens._provider_accounts import UnknownAccountError, account_service

    monkeypatch.delenv("SERVONAUT_TEST_UNSET_TOKEN", raising=False)
    config = _config()
    config.hetzner.accounts.append(
        HetznerAccount(label="dev", api_token="$SERVONAUT_TEST_UNSET_TOKEN")
    )
    app = SimpleNamespace(accounts=AccountRegistry(config))
    with pytest.raises(UnknownAccountError, match="account 'dev' is not available"):
        account_service(app, "hetzner", "dev")


# ---------------------------------------------------------------------------
# One account per provider: nothing changes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("module", "cls", "picker_id"), [
    ("servonaut.screens.hetzner_create", "HetznerCreateScreen", "hetzner_create_account"),
    ("servonaut.screens.hetzner_ssh_keys", "HetznerSSHKeysScreen", "hetzner_ssh_keys_account"),
    ("servonaut.screens.ovh_cloud_create", "OVHCloudCreateScreen", "cloud_create_account"),
    ("servonaut.screens.ovh_ssh_keys", "OVHSSHKeysScreen", "ovh_ssh_keys_account"),
    ("servonaut.screens.ovh_storage", "OVHStorageScreen", "storage_account"),
    ("servonaut.screens.ovh_billing", "OVHBillingScreen", "billing_account"),
    ("servonaut.screens.ovh_dns", "OVHDNSScreen", "dns_account"),
    ("servonaut.screens.ovh_ip_management", "OVHIPManagementScreen", "ip_mgmt_account"),
])
@pytest.mark.asyncio
async def test_single_account_screens_hide_the_picker(module, cls, picker_id):
    import importlib

    config = _config(hetzner_extra=False, ovh_extra=False)
    accounts = _registry(config)
    app = Host(accounts, config)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = getattr(importlib.import_module(module), cls)()
        await app.push_screen(screen)
        await pilot.pause()
        picker = screen.query_one(f"#{picker_id}", AccountPicker)
        assert not picker.display
        assert picker.region.height == 0


@pytest.mark.asyncio
async def test_single_account_managers_show_plain_names():
    from servonaut.screens.hetzner_manager import HetznerManagerScreen
    from servonaut.screens.ovh_manager import OVHManagerScreen

    config = _config(hetzner_extra=False, ovh_extra=False)
    accounts = _registry(config)
    app = Host(accounts, config)
    async with app.run_test(size=(200, 48)) as pilot:
        hetzner = HetznerManagerScreen()
        await app.push_screen(hetzner)
        table = hetzner.query_one("#hetzner_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 1, "the server")
        assert _column(hetzner, "hetzner_mgr_table", 1) == ["web-1"]
        app.pop_screen()
        ovh = OVHManagerScreen()
        await app.push_screen(ovh)
        table = ovh.query_one("#ovh_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 1, "the instance")
        assert _column(ovh, "ovh_mgr_table", 1) == ["mail-1"]


# ---------------------------------------------------------------------------
# Findings remediation: the finding's server in its own account
# ---------------------------------------------------------------------------


def _aws_registry() -> AccountRegistry:
    from servonaut.config.schema import AWSAccount

    config = AppConfig()
    config.aws.accounts = [AWSAccount(label="prod", profile="prod")]
    return AccountRegistry(config)


def _ban_configs():
    from servonaut.config.schema import IPBanConfig

    return [
        IPBanConfig(name="edge", method="waf", account=""),
        IPBanConfig(name="prod-sg", method="security_group", account="prod"),
    ]


def _resolve_method(finding: dict, app) -> tuple:
    from servonaut.screens.findings import FindingDetailScreen

    screen = FindingDetailScreen(finding)
    with patch.object(FindingDetailScreen, "app", new_callable=PropertyMock, return_value=app):
        return asyncio.run(screen._resolve_block_ip_method())


@pytest.mark.parametrize(("account", "method"), [("aws", "waf"), ("prod", "security_group")])
def test_block_ip_uses_a_ban_plane_of_the_servers_aws_account(account, method):
    app = SimpleNamespace(
        accounts=_aws_registry(),
        ip_ban_service=SimpleNamespace(get_configs=_ban_configs),
        instances=[{"id": "i-0abc", "name": "web-1", "account": account, "account_qualified": True}],
    )
    assert _resolve_method({"instance_id": "i-0abc"}, app) == (method, None)


def test_block_ip_refuses_when_no_ban_plane_covers_the_servers_account():
    from servonaut.config.schema import IPBanConfig

    app = SimpleNamespace(
        accounts=_aws_registry(),
        ip_ban_service=SimpleNamespace(
            get_configs=lambda: [IPBanConfig(name="edge", method="waf")],
        ),
        instances=[{"id": "i-0abc", "name": "web-1", "account": "prod", "account_qualified": True}],
    )
    method, error = _resolve_method({"instance_id": "i-0abc"}, app)
    assert method is None
    assert "AWS account 'prod'" in error


def test_block_ip_with_one_aws_account_offers_every_ban_plane():
    app = SimpleNamespace(
        accounts=AccountRegistry(AppConfig()),
        ip_ban_service=SimpleNamespace(get_configs=_ban_configs),
        instances=[{"id": "i-0abc", "name": "web-1", "account": "aws"}],
    )
    # Unchanged single-account rule: the first plane alphabetically.
    assert _resolve_method({"instance_id": "i-0abc"}, app) == ("security_group", None)


def test_block_ip_refuses_a_name_shared_by_several_servers():
    app = SimpleNamespace(
        accounts=_aws_registry(),
        ip_ban_service=SimpleNamespace(get_configs=_ban_configs),
        instances=[
            {"id": "i-0abc", "name": "web-1", "account": "aws", "account_qualified": True},
            {"id": "i-0def", "name": "web-1", "account": "prod", "account_qualified": True},
        ],
    )
    method, error = _resolve_method({"instance_id": "web-1"}, app)
    assert method is None
    assert "aws/web-1" in error and "prod/web-1" in error


def test_onbox_ban_detects_the_firewall_of_the_servers_own_id():
    tools = SimpleNamespace(detect_onbox_firewall=AsyncMock(return_value="ufw"))
    app = SimpleNamespace(
        servonaut_tools=tools,
        instances=[{"id": "22", "name": "web-2", "is_hetzner": True, "account": "staging"}],
    )
    assert _resolve_method({"instance_id": "web-2"}, app) == ("ufw", None)
    tools.detect_onbox_firewall.assert_awaited_once_with("22")


# ---------------------------------------------------------------------------
# Demo mode: drawn rows and labels are stand-ins, actions stay real
# ---------------------------------------------------------------------------

# Not a generic word, so demo mode swaps it for a stand-in.
_NAMED = "north"


def _demo(app) -> None:
    from servonaut.services.redaction_service import RedactionService

    app.demo_mode = True
    app.redaction_service = RedactionService()


@pytest.mark.asyncio
async def test_demo_mode_manager_shows_stand_ins_and_acts_in_the_real_project():
    from servonaut.screens.hetzner_manager import HetznerManagerScreen

    config = _config(hetzner_label=_NAMED)
    accounts = _registry(config)
    app = Host(accounts, config)
    _demo(app)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = HetznerManagerScreen()
        await app.push_screen(screen)
        table = screen.query_one("#hetzner_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 2, "both projects' servers")
        shown = _column(screen, "hetzner_mgr_table", 1)[1]
        assert _NAMED not in shown and "web-1" not in shown

        table.focus()
        table.move_cursor(row=1)
        await pilot.pause()
        screen.action_power_on()
        await _wait_for(pilot, lambda: accounts.hetzner[_NAMED].calls, "the start")
    assert accounts.hetzner[_NAMED].calls == [("power_on", "22")]
    assert accounts.hetzner["hetzner"].calls == []


@pytest.mark.asyncio
async def test_demo_mode_picker_shows_stand_ins_and_keeps_real_values():
    from servonaut.screens.hetzner_ssh_keys import HetznerSSHKeysScreen

    config = _config(hetzner_label=_NAMED)
    accounts = _registry(config)
    app = Host(accounts, config)
    _demo(app)
    async with app.run_test(size=(160, 48)) as pilot:
        screen = HetznerSSHKeysScreen()
        await app.push_screen(screen)
        await pilot.pause()
        select = screen.query_one("#hetzner_ssh_keys_account_select", Select)
        shown = [str(prompt) for prompt, _ in select._options]
        assert _NAMED not in shown
        assert "hetzner" in shown  # a provider's default label is public
        assert {value for _, value in select._options} == {"hetzner", _NAMED}

        await _pick(pilot, screen, "hetzner_ssh_keys_account", _NAMED)
        await _wait_for(
            pilot, lambda: len(screen._keys) == 2 and screen._keys[0]["name"] == f"{_NAMED}-other",
            "the other project's keys",
        )

        # Turning demo mode off draws the real labels again.
        app.demo_mode = False
        screen.refresh_after_demo_toggle()
        assert _NAMED in [str(prompt) for prompt, _ in select._options]
        assert select.value == _NAMED


def test_demo_mode_per_server_screen_uses_the_real_account(accounts):
    from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen

    real = _ca_row()
    drawn = dict(real, id="fake-id", name="fake-name", account="stand-in")
    app = SimpleNamespace(
        accounts=accounts.registry,
        connection_instance=lambda row: real if row is drawn else row,
    )
    screen = OVHSnapshotsScreen(drawn)
    with patch.object(OVHSnapshotsScreen, "app", new_callable=PropertyMock, return_value=app):
        assert screen._ovh_service("snapshot") is accounts.bundles["ca"].snapshot


def test_demo_mode_finding_is_matched_against_the_real_records():
    real = {"id": "i-0abc", "name": "web-1", "account": "prod", "account_qualified": True}
    drawn = dict(real, id="i-fake", name="fake-name", account="stand-in")
    app = SimpleNamespace(
        accounts=_aws_registry(),
        ip_ban_service=SimpleNamespace(get_configs=_ban_configs),
        instances=[drawn],
        connection_instance=lambda row: real if row is drawn else row,
    )
    assert _resolve_method({"instance_id": "i-0abc"}, app) == ("security_group", None)
