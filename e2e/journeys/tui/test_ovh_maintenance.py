"""Journey: OVH maintenance screens — snapshots, firewall, reinstall, resize,
SSH keys, IPs, block storage and billing.

Snapshots, the network firewall, reinstall and resize are opened from an OVH
server's action screen. Restoring a snapshot, reinstalling or resizing asks
for the server's name, deleting a snapshot for the snapshot's name, and
every firewall change for the word ``confirm``; each confirmed step sends
exactly one request and is audited, and backing out sends nothing. The SSH
Keys screen registers and removes keys on the Public Cloud project, IP
Management moves a failover IP and Block Storage deletes a volume, each after
the name or address is typed back. The Billing dashboard lists invoices and
services without changing anything.
"""

from __future__ import annotations

import asyncio
import re

import pytest

from e2e.harness import fleet
from e2e.harness.fake_providers.ovh import SeedBill, SeedFirewallRule
from e2e.harness.known_bugs import ProductBug
from e2e.journeys.tui.ovh_ui import (
    cancel_confirmation,
    confirm_typed,
    mutations,
    ovh_audit,
    plain,
    press,
    select_row,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

PROJECT = fleet.OVH_PROJECT_ID
MAIL = fleet.OVH_VPS_MAIL_1
PROXY = fleet.OVH_VPS_PROXY_1
MAIL_IP = MAIL.ips[0]
FAILOVER = "9.9.9.11/32"


class FirewallPromptShowsTemplate(ProductBug):
    """The firewall toggle confirmation prints a raw Python expression."""


class VpsActionsCrashOnReverseDns(ProductBug):
    """Opening a VPS whose address has reverse DNS crashes the whole app."""


def _audit(seed) -> list[tuple[str, bool]]:
    return [(row["action"], row["confirmed"]) for row in ovh_audit(seed)]


def _seed(seed, providers) -> None:
    seed.config(ovh=seed.ovh_config())
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    fleet.seed_provider_fleet(providers, hetzner=False)


async def _open_server_action(t, name: str, button: str, screen: str) -> None:
    await t.wait_until(
        lambda: name in [row[1] for row in t.table_rows("InstanceTable")], desc=f"{name} row"
    )
    await t.select_instance(name)
    await t.press("enter")
    await t.wait_for_screen("ServerActionsScreen")
    await t.wait_until(lambda: t.find(f"#{button}"), desc=f"{button} mounted")
    await press(t, f"#{button}")
    await t.wait_for_screen(screen)


async def test_vps_actions_show_the_reverse_dns(tui, seed, providers):
    from textual.worker import WorkerFailed

    _seed(seed, providers)
    # Every OVH VPS address has a reverse DNS name by default.
    providers.ovh.seed_vps_reverse(MAIL.service_name, MAIL_IP, "mail-1.e2e.test")
    crash = ""
    try:
        async with tui() as t:
            await t.wait_until(
                lambda: MAIL.display_name in [r[1] for r in t.table_rows("InstanceTable")],
                desc="mail-1 row",
            )
            await t.select_instance(MAIL.display_name)
            try:
                # A crash mid-keypress leaves the key press waiting forever.
                await asyncio.wait_for(t.press("enter"), timeout=8)
                await t.wait_for_screen("ServerActionsScreen")
                await t.wait_until(
                    lambda: "mail-1.e2e.test" in t.rendered_text(),
                    timeout=8,
                    desc="reverse DNS shown",
                )
            except (TimeoutError, AttributeError):
                crash = t.state()["exception"]
                if "renderable" not in crash:
                    raise
    except WorkerFailed as exc:
        # Leaving the session re-raises the error that ended the app.
        crash = crash or repr(exc)
    if crash:
        raise VpsActionsCrashOnReverseDns(crash)


async def test_vps_snapshot_restore_delete_and_create(tui, seed, providers):
    _seed(seed, providers)
    snapshot_id = providers.ovh.seed_vps_snapshot(MAIL.service_name, "before-upgrade")
    vps_path = f"/vps/{MAIL.service_name}"

    async with tui() as t:
        await _open_server_action(t, MAIL.display_name, "btn_ovh_snapshots", "OVHSnapshotsScreen")
        # The action screen looked up the address's reverse DNS on the way.
        assert providers.requests("ovh", method="GET", path=f"{vps_path}/ips/{MAIL_IP}")
        await t.wait_until(
            lambda: [plain(r[0]) for r in t.table_rows("#snapshots_table")] == [snapshot_id],
            desc="snapshot listed",
        )
        assert "before-upgrade" in t.table_rows("#snapshots_table")[0][2]

        # Restore needs the server's name; backing out sends nothing.
        await press(t, "#btn_restore")
        await cancel_confirmation(t, "OVHSnapshotsScreen")
        await press(t, "#btn_restore")
        await confirm_typed(t, MAIL.display_name, wrong=MAIL.service_name)
        await t.wait_for_toast("Snapshot restore has been queued")

        # Delete needs the snapshot's name (here its id, as the table shows it).
        await press(t, "#btn_delete")
        await confirm_typed(t, snapshot_id, wrong="before-upgrade")
        await t.wait_for_toast("Snapshot deleted successfully")
        await t.wait_until(lambda: not t.table_rows("#snapshots_table"), desc="table empty")

        # Taking a new snapshot is not destructive and asks nothing.
        await press(t, "#btn_create")
        await t.wait_for_toast("Snapshot creation has been queued")
        await t.wait_until(lambda: len(t.table_rows("#snapshots_table")) == 1, desc="new one")

    assert mutations(providers) == [
        ("POST", f"{vps_path}/snapshot/{snapshot_id}/revert"),
        ("DELETE", f"{vps_path}/snapshot"),
        ("POST", f"{vps_path}/createSnapshot"),
    ]
    assert providers.ovh.vps_snapshot(MAIL.service_name) is not None
    assert _audit(seed) == [
        ("snapshot_restore", False), ("snapshot_restore", True), ("snapshot_delete", True),
    ]


async def test_firewall_toggle_add_and_delete_rules(tui, seed, providers):
    _seed(seed, providers)
    providers.ovh.seed_firewall(
        MAIL_IP, enabled=True, rules=[SeedFirewallRule(0, "permit", "tcp", "22", "10.0.0.0/8")]
    )
    rule_path = f"/ip/{MAIL_IP}/firewall/{MAIL_IP}/rule"

    async with tui() as t:
        await _open_server_action(t, MAIL.display_name, "btn_ovh_firewall", "OVHFirewallScreen")
        await t.wait_until(lambda: len(t.table_rows("#rules_table")) == 1, desc="rules listed")
        await t.wait_for_text("Firewall: Enabled")
        assert plain(t.table_rows("#rules_table")[0][1]) == "permit"

        # Disable: backing out first, then the typed word.
        await press(t, "#btn_toggle")
        await cancel_confirmation(t, "OVHFirewallScreen")
        await press(t, "#btn_toggle")
        await confirm_typed(t, "confirm", wrong="Confirm")
        await t.wait_for_toast(rf"Firewall disabled for {re.escape(MAIL_IP)}")

        # Add a rule: invalid input is refused before any prompt.
        await press(t, "#btn_add_rule")
        await t.fill("#input_action", "block")
        await t.fill("#input_protocol", "tcp")
        await press(t, "#btn_save_rule")
        await t.wait_for_toast("Action must be 'permit' or 'deny'", severity="warning")
        await t.fill("#input_action", "deny")
        await t.fill("#input_port", "3306")
        await t.fill("#input_source", "9.9.9.9/32")
        await t.fill("#input_sequence", "1")
        await press(t, "#btn_save_rule")
        await confirm_typed(t, "confirm")
        await t.wait_for_toast("Firewall rule added")
        await t.wait_until(lambda: len(t.table_rows("#rules_table")) == 2, desc="two rules")

        await select_row(t, "#rules_table", 0, "0")
        await press(t, "#btn_delete_rule")
        await confirm_typed(t, "confirm")
        await t.wait_for_toast("Firewall rule #0 deleted")
        await t.wait_until(lambda: len(t.table_rows("#rules_table")) == 1, desc="one rule left")

    sent = providers.mutations("ovh")
    assert mutations(providers) == [
        ("PUT", f"/ip/{MAIL_IP}/firewall/{MAIL_IP}"),
        ("POST", rule_path),
        ("DELETE", f"{rule_path}/0"),
    ]
    assert sent[0]["body"] == {"enabled": False}
    assert sent[1]["body"] == {
        "action": "deny", "protocol": "tcp", "sequence": 1,
        "destinationPort": "3306", "source": "9.9.9.9/32",
    }
    firewall = providers.ovh.firewall(MAIL_IP)
    assert firewall["enabled"] is False and sorted(firewall["rules"]) == [1]
    assert _audit(seed) == [
        ("firewall_toggle", False), ("firewall_toggle", True),
        ("firewall_add_rule", True), ("firewall_delete_rule", True),
    ]


async def test_firewall_toggle_prompt_describes_the_effect(tui, seed, providers):
    _seed(seed, providers)
    providers.ovh.seed_firewall(MAIL_IP, enabled=True)

    async with tui() as t:
        await _open_server_action(t, MAIL.display_name, "btn_ovh_firewall", "OVHFirewallScreen")
        await t.wait_until(lambda: "Firewall: Enabled" in t.rendered_text(), desc="state")
        await press(t, "#btn_toggle")
        await t.wait_for_screen("ConfirmActionScreen")
        text = t.rendered_text()
        if "{'take effect'" in text or "new_state" in text:
            raise FirewallPromptShowsTemplate("the prompt shows the raw template expression")
        assert "rules will be suspended" in text


async def test_project_ssh_keys_add_and_delete(tui, seed, providers):
    _seed(seed, providers)
    providers.ovh.seed_project_ssh_key(PROJECT, "deploy-key", "ssh-ed25519 AAAAE2EDEPLOY e2e")
    keys_path = f"/cloud/project/{PROJECT}/sshkey"

    async with tui() as t:
        await t.nav("nav_ovh_ssh_keys")
        await t.wait_for_screen("OVHSSHKeysScreen")
        await t.wait_until(
            lambda: [r[0] for r in t.table_rows("#ssh_keys_table")] == ["deploy-key"],
            desc="project keys",
        )

        await press(t, "#btn_add_key")
        await t.fill("#input_key_name", "laptop-2")
        await press(t, "#btn_save_key")
        await t.wait_for_toast("Public key is required", severity="warning")
        await t.fill("#input_public_key", "ssh-ed25519 AAAAE2ELAPTOP e2e")
        await press(t, "#btn_save_key")
        await t.wait_for_toast(r"SSH key 'laptop-2' registered with project")
        await t.wait_until(lambda: len(t.table_rows("#ssh_keys_table")) == 2, desc="two keys")

        await select_row(t, "#ssh_keys_table", 0, "deploy-key")
        await press(t, "#btn_delete_key")
        await cancel_confirmation(t, "OVHSSHKeysScreen")
        assert len(mutations(providers)) == 1
        await press(t, "#btn_delete_key")
        await confirm_typed(t, "deploy-key", wrong="laptop-2")
        await t.wait_for_toast(r"SSH key 'deploy-key' deleted from project")
        await t.wait_until(
            lambda: [r[0] for r in t.table_rows("#ssh_keys_table")] == ["laptop-2"],
            desc="deleted key gone",
        )

    deploy_id = next(
        r["api_path"].rsplit("/", 1)[1]
        for r in providers.mutations("ovh")
        if r["method"] == "DELETE"
    )
    assert mutations(providers) == [("POST", keys_path), ("DELETE", f"{keys_path}/{deploy_id}")]
    assert providers.mutations("ovh")[0]["body"] == {
        "name": "laptop-2", "publicKey": "ssh-ed25519 AAAAE2ELAPTOP e2e",
    }
    assert [k["name"] for k in providers.ovh.project_ssh_keys(PROJECT)] == ["laptop-2"]


async def test_move_a_failover_ip(tui, seed, providers):
    _seed(seed, providers)
    providers.ovh.seed_ip_block(f"{MAIL_IP}/32", ip_type="vps", routed_to=MAIL.service_name)
    providers.ovh.seed_ip_block(FAILOVER, ip_type="failover", routed_to=PROXY.service_name)

    async with tui() as t:
        await t.nav("nav_ovh_ips")
        await t.wait_for_screen("OVHIPManagementScreen")
        await t.wait_until(lambda: len(t.table_rows("#ip_table")) == 2, desc="IP blocks listed")
        assert [row[:3] for row in t.table_rows("#ip_table")] == [
            [f"{MAIL_IP}/32", "vps", MAIL.service_name],
            [FAILOVER, "failover", PROXY.service_name],
        ]

        await select_row(t, "#ip_table", 0, FAILOVER)
        await t.press("enter")
        await press(t, "#btn_move")
        await t.fill("#input_move_target", MAIL.service_name)
        await press(t, "#btn_move_confirm")
        await cancel_confirmation(t, "OVHIPManagementScreen")
        assert mutations(providers) == []

        await press(t, "#btn_move_confirm")
        await confirm_typed(t, FAILOVER, wrong=FAILOVER.split("/")[0])
        await t.wait_for_toast(rf"IP {re.escape(FAILOVER)} is being moved to")
        await t.wait_until(
            lambda: t.table_rows("#ip_table")[1][2] == MAIL.service_name, desc="new route shown"
        )

    assert mutations(providers) == [("POST", f"/ip/{FAILOVER}/move")]
    assert providers.mutations("ovh")[0]["body"] == {"to": MAIL.service_name}
    assert _audit(seed) == [("ip_move", False), ("ip_move", True)]


async def test_billing_dashboard_is_read_only(tui, seed, providers):
    _seed(seed, providers)
    providers.ovh.seed_bills([
        SeedBill("FR00000001", "2026-07-01", 18.5),
        SeedBill("FR00000002", "2026-08-01", 21.0),
    ])
    providers.ovh.set_usage(current=12.0, forecast=20.0)

    async with tui() as t:
        await t.nav("nav_ovh_billing")
        await t.wait_for_screen("OVHBillingScreen")
        await t.wait_until(lambda: len(t.table_rows("#invoices_table")) == 2, desc="invoices")
        invoices = t.table_rows("#invoices_table")
        assert [row[1] for row in invoices] == ["FR00000002", "FR00000001"]  # newest first
        assert invoices[0][2] == "21.0 EUR"
        await t.wait_until(lambda: len(t.table_rows("#services_table")) == 3, desc="services")
        services = {plain(row[0]): plain(row[1]) for row in t.table_rows("#services_table")}
        assert services == {
            MAIL.service_name: "VPS", PROXY.service_name: "VPS",
            fleet.OVH_DEDICATED_STORAGE_1.service_name: "Dedicated",
        }
        await t.wait_until(lambda: "2026-08" in t.rendered_text(), desc="spend history")

    assert providers.mutations("ovh") == []


class ReinstallCrashesTheApp(ProductBug):
    """Pressing Reinstall ends the app before any confirmation is shown."""


async def test_reinstall_a_vps_needs_the_server_name(tui, seed, providers):
    from textual.worker import NoActiveWorker

    _seed(seed, providers)
    crash = ""
    try:
        async with tui() as t:
            await _open_server_action(
                t, MAIL.display_name, "btn_ovh_reinstall", "OVHReinstallScreen"
            )
            await t.wait_until(lambda: len(t.table_rows("#images_table")) == 2, desc="images")
            await select_row(t, "#images_table", 0, "Debian 12")
            try:
                # A crash mid-click leaves the click waiting forever.
                await asyncio.wait_for(t.click("#btn_reinstall"), timeout=8)
                await t.wait_for_screen("ConfirmActionScreen", timeout=8)
            except (TimeoutError, NoActiveWorker):
                crash = t.state()["exception"]
                if "NoActiveWorker" not in crash:
                    raise
            else:
                await confirm_typed(t, MAIL.display_name, wrong=MAIL.service_name)
                await t.wait_for_toast("Reinstall")
    except NoActiveWorker as exc:
        crash = crash or repr(exc)
    if crash:
        raise ReinstallCrashesTheApp(crash)
    assert mutations(providers) == [("POST", f"/vps/{MAIL.service_name}/reinstall")]


async def test_resize_a_vps_needs_the_server_name(tui, seed, providers):
    _seed(seed, providers)

    async with tui() as t:
        await _open_server_action(t, MAIL.display_name, "btn_ovh_resize", "OVHResizeScreen")
        await t.wait_until(lambda: len(t.table_rows("#models_table")) == 1, desc="plans")
        await press(t, "#btn_upgrade")
        await cancel_confirmation(t, "OVHResizeScreen")
        assert mutations(providers) == []
        await press(t, "#btn_upgrade")
        await confirm_typed(t, MAIL.display_name, wrong=MAIL.service_name)
        await t.wait_for_toast(r"Upgrade of mail-1 to vps-value-2-4-80 has been queued")

    assert mutations(providers) == [("POST", f"/vps/{MAIL.service_name}/change")]
    assert providers.mutations("ovh")[0]["body"] == {"model": "vps-value-2-4-80"}
    assert _audit(seed) == [("vps_upgrade", False), ("vps_upgrade", True)]


async def test_delete_a_block_storage_volume(tui, seed, providers):
    _seed(seed, providers)
    data_id = providers.ovh.seed_volume(PROJECT, "data-1", 50)
    providers.ovh.seed_volume(PROJECT, "logs-1", 20, attached_to=[fleet.OVH_BATCH_1.instance_id])

    async with tui() as t:
        await t.nav("nav_ovh_storage")
        await t.wait_for_screen("OVHStorageScreen")
        await t.wait_until(lambda: len(t.table_rows("#volumes_table")) == 2, desc="volumes")
        rows = {row[0]: row for row in t.table_rows("#volumes_table")}
        assert rows["logs-1"][4] == fleet.OVH_BATCH_1.instance_id
        assert rows["data-1"][3] == "available"

        await select_row(t, "#volumes_table", 0, "data-1")
        await press(t, "#btn_delete")
        await cancel_confirmation(t, "OVHStorageScreen")
        await press(t, "#btn_delete")
        await confirm_typed(t, "data-1", wrong="logs-1")
        await t.wait_for_toast("Volume 'data-1' deleted")
        await t.wait_until(
            lambda: [row[0] for row in t.table_rows("#volumes_table")] == ["logs-1"],
            desc="data-1 gone",
        )

    assert mutations(providers) == [("DELETE", f"/cloud/project/{PROJECT}/volume/{data_id}")]
    assert _audit(seed) == [("volume_delete", True)]
