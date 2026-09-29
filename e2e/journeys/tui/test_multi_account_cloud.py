"""Journey: Hetzner and OVH screens act in the account a server belongs to.

Each provider has a second account ("staging" for Hetzner, "backup" for
OVH), and both accounts of a provider hold a server named web-1. The
managers list both accounts' servers by ``account/name``; powering off,
rebooting or creating a server goes to the account the server is (or is
created) in, with that account's credentials, and never to the other one.
Screens that work on one account at a time (Hetzner SSH keys, OVH billing
and SSH keys) offer an account picker, and switching it shows the other
account's data. A per-server OVH action reaches the server's own account.

The provider stand-ins log the account each request reached, so every
assertion is about where a request went, not only what the screen says.
"""

from __future__ import annotations

import re

import pytest

from e2e.harness import fleet
from e2e.harness.controls import choose
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.fake_providers import ovh as fake_ovh
from e2e.harness.fake_providers.ovh import SeedBill
from e2e.journeys.tui.ovh_ui import confirm_typed, plain, press, select_row

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

HETZNER = fake_hetzner.PRIMARY_LABEL
OVH = fake_ovh.PRIMARY_LABEL
STAGING = fleet.HETZNER_SECOND_ACCOUNT
BACKUP = fleet.OVH_SECOND_ACCOUNT
WEB_1 = fleet.SHARED_NAME

HZ_TABLE = "#hetzner_mgr_table"
OVH_TABLE = "#ovh_mgr_table"
HETZNER_ROWS = {
    *(f"{HETZNER}/{host.name}" for host in (*fleet.HETZNER_FLEET, fleet.HZ_WEB_1)),
    *(f"{STAGING}/{host.name}" for host in fleet.HETZNER_SECOND_FLEET),
}

# Fabricated public keys: the right shape, no real key material.
_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2E{}keyonly0000000000000000 {}"
PRIMARY_KEY = ("e2e-deploy", _KEY.format("primary", "deploy"))
STAGING_KEY = ("e2e-staging", _KEY.format("staging", "staging"))
LAPTOP_KEY = ("e2e-laptop", _KEY.format("laptop", "laptop"))
NEW_SERVER = "web-2"


def _names(t, selector: str, column: int = 1) -> list[str]:
    return [plain(row[column]) for row in t.table_rows(selector)]


def _seed_hetzner(seed, providers):
    """Both Hetzner projects, each with one SSH key; returns the second project."""
    fleet.seed_provider_fleet(providers, ovh=False)
    staging, _ = fleet.seed_second_accounts(providers, ovh=False)
    providers.hetzner.seed_ssh_key(*PRIMARY_KEY)
    staging.seed_ssh_key(*STAGING_KEY)
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    seed.config(hetzner=seed.hetzner_config(accounts=[seed.hetzner_account(STAGING)]))
    return staging


def _seed_ovh(seed, providers):
    """Both OVH accounts; returns the second account."""
    fleet.seed_provider_fleet(providers, hetzner=False)
    _, backup = fleet.seed_second_accounts(providers, hetzner=False)
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    seed.config(ovh=seed.ovh_config(accounts=[seed.ovh_account(BACKUP)]))
    return backup


def _states(t, selector: str) -> dict[str, str]:
    """Manager rows: the shown name and the state, without colour."""
    return {plain(row[1]): plain(row[4]) for row in t.table_rows(selector)}


def _mutations(providers, provider: str, account: str) -> list[tuple[str, str]]:
    return [
        (entry["method"], entry["api_path"])
        for entry in providers.mutations(provider)
        if entry["account"] == account
    ]


async def _open_hetzner_manager(t) -> None:
    await t.nav("nav_hetzner_manage")
    await t.wait_for_screen("HetznerManagerScreen")
    await t.wait_until(
        lambda: set(_names(t, HZ_TABLE)) == HETZNER_ROWS, desc="both projects in the manager"
    )


async def _answer_power_prompt(t, back_to: str) -> None:
    await t.wait_for_screen("PowerActionConfirmModal")
    await t.wait_until(lambda: t.focused_id() == "btn_power_confirm_no", desc="No focused")
    await t.click("#btn_power_confirm_yes")
    await t.wait_for_screen(back_to)


# ---------------------------------------------------------------------------
# Hetzner
# ---------------------------------------------------------------------------


async def test_power_off_reaches_the_servers_own_project(tui, seed, providers):
    staging = _seed_hetzner(seed, providers)
    target, twin = fleet.HZ_SECOND_WEB_1, fleet.HZ_WEB_1

    async with tui() as t:
        await _open_hetzner_manager(t)
        await select_row(t, HZ_TABLE, 1, f"{STAGING}/{WEB_1}")
        await press(t, "#btn_hetzner_mgr_power_off")
        await _answer_power_prompt(t, "HetznerManagerScreen")
        await t.wait_for_toast(rf"^Server {target.server_id}: powered off\.$")
        await t.wait_until(
            lambda: _states(t, HZ_TABLE)[f"{STAGING}/{WEB_1}"] == "stopped",
            desc="staging/web-1 stopped",
        )
        # The server of the same name in the other project is untouched.
        assert _states(t, HZ_TABLE)[f"{HETZNER}/{WEB_1}"] == "running"

    action = f"/servers/{target.server_id}/actions/poweroff"
    assert _mutations(providers, "hetzner", STAGING) == [("POST", action)]
    assert _mutations(providers, "hetzner", HETZNER) == []
    assert staging.server(target.server_id)["status"] == "off"
    assert providers.hetzner.server(twin.server_id)["status"] == "running"


async def test_create_a_server_in_the_second_project(tui, seed, providers):
    staging = _seed_hetzner(seed, providers)

    async with tui() as t:
        await _open_hetzner_manager(t)
        await press(t, "#btn_hetzner_mgr_new")
        await t.wait_for_screen("HetznerCreateScreen")
        await t.wait_until(
            lambda: _names(t, "#hetzner_keys_table", 0) == [PRIMARY_KEY[0]],
            desc="the default project's keys",
        )

        # Picking the other project reloads the wizard with its keys.
        await choose(t, "#hetzner_create_account_select", STAGING)
        await t.wait_until(
            lambda: _names(t, "#hetzner_keys_table", 0) == [STAGING_KEY[0]]
            and t.table_rows("#hetzner_types_table")
            and t.table_rows("#hetzner_images_table")
            and t.table_rows("#hetzner_locations_table"),
            desc="the staging project's lists",
        )
        await select_row(t, "#hetzner_keys_table", 0, STAGING_KEY[0])
        await t.fill("#hetzner_input_name", NEW_SERVER)
        await press(t, "#btn_hetzner_create_submit")
        # The confirmation says which project is billed.
        await t.wait_for_screen("ConfirmActionScreen")
        await t.wait_for_text(NEW_SERVER, f"in project {STAGING}", screen_only=True)
        await confirm_typed(t, "create")
        await t.wait_for_toast(rf"^Server '{NEW_SERVER}' created \(ID: \d+\)")

        # Back in the manager, the new server is listed under its project.
        await t.wait_for_screen("HetznerManagerScreen")
        await t.wait_until(
            lambda: f"{STAGING}/{NEW_SERVER}" in _names(t, HZ_TABLE), desc="staging/web-2 listed"
        )

    creates = providers.requests("hetzner", method="POST", path="/servers")
    assert [entry["account"] for entry in creates] == [STAGING]
    assert creates[0]["body"]["ssh_keys"] == [staging.key_named(STAGING_KEY[0])["id"]]
    assert staging.server_named(NEW_SERVER) is not None
    assert providers.hetzner.server_named(NEW_SERVER) is None


async def test_ssh_keys_are_managed_per_project(tui, seed, providers):
    staging = _seed_hetzner(seed, providers)
    table = "#hetzner_ssh_keys_table"

    async with tui() as t:
        await t.nav("nav_hetzner_ssh_keys")
        await t.wait_for_screen("HetznerSSHKeysScreen")
        await t.wait_until(lambda: _names(t, table, 0) == [PRIMARY_KEY[0]], desc="primary keys")

        await choose(t, "#hetzner_ssh_keys_account_select", STAGING)
        await t.wait_until(lambda: _names(t, table, 0) == [STAGING_KEY[0]], desc="staging keys")

        await press(t, "#btn_hetzner_ssh_add")
        await t.fill("#hetzner_ssh_input_name", LAPTOP_KEY[0])
        await t.fill("#hetzner_ssh_input_public_key", LAPTOP_KEY[1])
        await press(t, "#btn_hetzner_ssh_save")
        await t.wait_for_toast(rf"^SSH key '{LAPTOP_KEY[0]}' registered\.$")
        await t.wait_until(
            lambda: sorted(_names(t, table, 0)) == sorted([STAGING_KEY[0], LAPTOP_KEY[0]]),
            desc="the new key in the staging project",
        )

    assert _mutations(providers, "hetzner", STAGING) == [("POST", "/ssh_keys")]
    assert _mutations(providers, "hetzner", HETZNER) == []
    assert staging.key_named(LAPTOP_KEY[0]) is not None
    assert providers.hetzner.key_named(LAPTOP_KEY[0]) is None


# ---------------------------------------------------------------------------
# OVH
# ---------------------------------------------------------------------------


async def test_ovh_manager_reboots_in_the_servers_own_account(tui, seed, providers):
    _seed_ovh(seed, providers)
    target = fleet.OVH_SECOND_VPS_WEB_1

    async with tui() as t:
        await t.nav("nav_ovh_manage")
        await t.wait_for_screen("OVHManagerScreen")
        await t.wait_until(
            lambda: {f"{OVH}/{WEB_1}", f"{BACKUP}/{WEB_1}"} <= set(_names(t, OVH_TABLE)),
            desc="both accounts' web-1",
        )
        await select_row(t, OVH_TABLE, 1, f"{BACKUP}/{WEB_1}")
        await press(t, "#btn_ovh_mgr_reboot")
        await _answer_power_prompt(t, "OVHManagerScreen")
        await t.wait_for_toast(rf"OVH vps {re.escape(target.service_name)}: reboot sent")

    assert _mutations(providers, "ovh", BACKUP) == [("POST", f"/vps/{target.service_name}/reboot")]
    assert _mutations(providers, "ovh", OVH) == []


async def test_ovh_billing_follows_the_account_picker(tui, seed, providers):
    backup = _seed_ovh(seed, providers)
    providers.ovh.seed_bills([SeedBill("FR00000001", "2026-08-01", 21.0)])
    backup.seed_bills([SeedBill("CA00000011", "2026-08-01", 12.5)])

    async with tui() as t:
        await t.nav("nav_ovh_billing")
        await t.wait_for_screen("OVHBillingScreen")
        await t.wait_until(
            lambda: _names(t, "#invoices_table") == ["FR00000001"], desc="primary invoices"
        )
        await choose(t, "#billing_account_select", BACKUP)
        await t.wait_until(
            lambda: _names(t, "#invoices_table") == ["CA00000011"], desc="backup invoices"
        )
        assert t.table_rows("#invoices_table")[0][2] == "12.5 EUR"

    assert providers.requests("ovh", method="GET", path="/me/bill", account=BACKUP)
    assert providers.mutations("ovh") == []


async def test_ovh_ssh_keys_follow_the_account_picker(tui, seed, providers):
    backup = _seed_ovh(seed, providers)
    providers.ovh.seed_project_ssh_key(
        fleet.OVH_PROJECT_ID, "deploy-eu", "ssh-ed25519 AAAAE2EEU e2e"
    )
    backup.seed_project_ssh_key(
        fleet.OVH_SECOND_PROJECT_ID, "deploy-backup", "ssh-ed25519 AAAAE2EBACKUP e2e"
    )
    table = "#ssh_keys_table"

    async with tui() as t:
        await t.nav("nav_ovh_ssh_keys")
        await t.wait_for_screen("OVHSSHKeysScreen")
        await t.wait_until(lambda: _names(t, table, 0) == ["deploy-eu"], desc="primary keys")
        await choose(t, "#ovh_ssh_keys_account_select", BACKUP)
        await t.wait_until(lambda: _names(t, table, 0) == ["deploy-backup"], desc="backup keys")
        await t.wait_for_text(fleet.OVH_SECOND_PROJECT_ID)

    keys_path = f"/cloud/project/{fleet.OVH_SECOND_PROJECT_ID}/sshkey"
    assert providers.requests("ovh", method="GET", path=keys_path, account=BACKUP)
    assert providers.mutations("ovh") == []


async def _select_fleet_row(t, shown: str) -> None:
    """Move the fleet table's cursor to the row showing *shown*, by keyboard."""
    table = await t.focus_instance_table()
    names = [row[1] for row in t.table_rows("InstanceTable")]
    target = names.index(shown)
    for _ in range(len(names) + 1):
        if table.cursor_row == target:
            break
        await t.press("down" if table.cursor_row < target else "up")
    await t.wait_until(lambda: table.cursor_row == target, desc=f"cursor on {shown}")


async def test_ovh_server_action_uses_the_servers_own_account(tui, seed, providers):
    _seed_ovh(seed, providers)
    target = fleet.OVH_SECOND_VPS_WEB_1
    shown = f"{BACKUP}/{WEB_1}"
    vps_path = f"/vps/{target.service_name}"

    async with tui() as t:
        await t.wait_until(
            lambda: shown in [row[1] for row in t.table_rows("InstanceTable")], desc=f"{shown} row"
        )
        await _select_fleet_row(t, shown)
        await t.press("enter")
        await t.wait_for_screen("ServerActionsScreen")
        await t.wait_for_text("Account:", BACKUP, target.ips[0])
        await t.wait_until(lambda: t.find("#btn_ovh_snapshots"), desc="OVH actions mounted")
        await press(t, "#btn_ovh_snapshots")
        await t.wait_for_screen("OVHSnapshotsScreen")
        await press(t, "#btn_create")
        await t.wait_for_toast("Snapshot creation has been queued")

    # The reverse DNS lookup and the snapshot both went to the server's account.
    assert providers.requests("ovh", method="GET", path=f"{vps_path}/ips/.+", account=BACKUP)
    assert _mutations(providers, "ovh", BACKUP) == [("POST", f"{vps_path}/createSnapshot")]
    assert _mutations(providers, "ovh", OVH) == []
    assert not providers.requests("ovh", path=f"{vps_path}(/.*)?", account=OVH)
