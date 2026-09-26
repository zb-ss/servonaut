"""Journey: manage OVHcloud servers from the OVH Manager screen.

The manager lists VPS, dedicated servers and Public Cloud instances. Each
row only offers the actions its kind supports: start and stop for VPS and
Cloud, reboot for all three, delete for Cloud only. Stop and reboot ask a
yes/no question first, with No selected: declining sends nothing and is
recorded in the audit log. Every action sends exactly one request to OVH
and the table then shows the new state.
Deleting a Cloud instance asks the user to type ``delete`` first; creating
one goes through a wizard (region, flavor, image, SSH key) and a typed
``create`` confirmation, since billing starts at once. Destructive steps
are written to the OVH audit log.
"""

from __future__ import annotations

import re

import pytest

from e2e.harness import fleet
from e2e.harness.fake_providers.ovh import flavor_id, image_id
from e2e.journeys.tui.ovh_ui import ovh_audit, plain, press, select_row

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

TABLE = "#ovh_mgr_table"
BUTTONS = ("start", "stop", "reboot", "delete")
PROJECT = fleet.OVH_PROJECT_ID
MAIL = fleet.OVH_VPS_MAIL_1
PROXY = fleet.OVH_VPS_PROXY_1
STORAGE = fleet.OVH_DEDICATED_STORAGE_1
BATCH_1 = fleet.OVH_BATCH_1
BATCH_2 = fleet.OVH_BATCH_2
# Rows as the manager names them: VPS by display name, dedicated by reverse.
ROW_NAMES = {MAIL.display_name, PROXY.display_name, STORAGE.reverse, BATCH_1.name, BATCH_2.name}


def _rows(t) -> dict[str, list[str]]:
    return {row[1]: [plain(cell) for cell in row] for row in t.table_rows(TABLE)}


def _state(t, name: str) -> str:
    return _rows(t)[name][4]


def _enabled(t) -> dict[str, bool]:
    return {
        name: not t.on_screen(f"#btn_ovh_mgr_{name}").disabled for name in BUTTONS
    }


async def _open_manager(t) -> None:
    await t.nav("nav_ovh_manage")
    await t.wait_for_screen("OVHManagerScreen")
    await t.wait_until(lambda: set(_rows(t)) == ROW_NAMES, desc="OVH manager rows")


async def _answer_power_prompt(t, *, confirm: bool) -> None:
    """Answer the stop/reboot question; No has the focus, so Enter declines."""
    await t.wait_for_screen("PowerActionConfirmModal")
    await t.wait_until(
        lambda: t.focused_id() == "btn_power_confirm_no", desc="No focused"
    )
    if confirm:
        await t.click("#btn_power_confirm_yes")
    else:
        await t.press("enter")
    await t.wait_for_screen("OVHManagerScreen")


async def _act(t, button: str, toast: str, *, asks: bool = False) -> None:
    assert _enabled(t)[button], f"{button} should be enabled here: {_enabled(t)}"
    await press(t, f"#btn_ovh_mgr_{button}")
    if asks:
        await _answer_power_prompt(t, confirm=True)
    await t.wait_for_toast(toast)


def _seed(seed, providers) -> None:
    seed.config(ovh=seed.ovh_config())
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    fleet.seed_provider_fleet(providers, hetzner=False)


async def test_power_actions_reach_ovh_once_each(tui, seed, providers):
    _seed(seed, providers)
    cloud_path = f"/cloud/project/{PROJECT}/instance"

    async with tui() as t:
        await _open_manager(t)

        # Dedicated: reboot only.
        await select_row(t, TABLE, 1, STORAGE.reverse)
        assert _enabled(t) == {"start": False, "stop": False, "reboot": True, "delete": False}
        await _act(
            t, "reboot", rf"OVH dedicated {re.escape(STORAGE.service_name)}: reboot sent", asks=True
        )

        # A stopped VPS can be started, nothing else.
        await select_row(t, TABLE, 1, PROXY.display_name)
        assert _enabled(t) == {"start": True, "stop": False, "reboot": False, "delete": False}
        await _act(t, "start", rf"OVH vps {re.escape(PROXY.service_name)}: started")
        await t.wait_until(lambda: _state(t, PROXY.display_name) == "running", desc="proxy-1 up")

        # A running VPS can be stopped or rebooted.
        await select_row(t, TABLE, 1, MAIL.display_name)
        assert _enabled(t) == {"start": False, "stop": True, "reboot": True, "delete": False}
        # Declining (Enter on the focused No) sends nothing.
        mutations = len(providers.mutations("ovh"))
        await press(t, "#btn_ovh_mgr_stop")
        await _answer_power_prompt(t, confirm=False)
        await t.settle()
        assert len(providers.mutations("ovh")) == mutations
        assert _state(t, MAIL.display_name) == "running"
        await _act(t, "stop", rf"OVH vps {re.escape(MAIL.service_name)}: stop sent", asks=True)
        await t.wait_until(lambda: _state(t, MAIL.display_name) == "stopped", desc="mail-1 down")

        # Cloud: a running instance reboots, a stopped one starts.
        await select_row(t, TABLE, 1, BATCH_1.name)
        assert _enabled(t) == {"start": False, "stop": True, "reboot": True, "delete": True}
        await _act(t, "reboot", r"OVH cloud .*: reboot sent", asks=True)
        await select_row(t, TABLE, 1, BATCH_2.name)
        assert _enabled(t) == {"start": True, "stop": False, "reboot": False, "delete": True}
        await _act(t, "start", r"OVH cloud .*: started")
        await t.wait_until(lambda: _state(t, BATCH_2.name) == "running", desc="batch-2 up")

    assert [(r["method"], r["api_path"], r["body"]) for r in providers.mutations("ovh")] == [
        ("POST", f"/dedicated/server/{STORAGE.service_name}/reboot", None),
        ("POST", f"/vps/{PROXY.service_name}/start", None),
        ("POST", f"/vps/{MAIL.service_name}/stop", None),
        ("POST", f"{cloud_path}/{BATCH_1.instance_id}/reboot", {"type": "soft"}),
        ("POST", f"{cloud_path}/{BATCH_2.instance_id}/start", None),
    ]
    assert providers.ovh.vps_state(PROXY.service_name) == "running"
    assert providers.ovh.vps_state(MAIL.service_name) == "stopped"
    audited = [
        (row["action"], row["target"], row["details"]["success"], row["confirmed"])
        for row in ovh_audit(seed)
    ]
    assert audited == [
        ("reboot_instance", STORAGE.service_name, True, True),
        ("start_instance", PROXY.service_name, True, True),
        ("stop_instance", MAIL.service_name, False, False),
        ("stop_instance", MAIL.service_name, True, True),
        ("reboot_instance", fleet.ovh_cloud_id(BATCH_1), True, True),
        ("start_instance", fleet.ovh_cloud_id(BATCH_2), True, True),
    ]


async def test_deleting_a_cloud_instance_needs_the_typed_confirmation(tui, seed, providers):
    _seed(seed, providers)
    delete_path = f"/cloud/project/{PROJECT}/instance/{BATCH_1.instance_id}"

    async with tui() as t:
        await _open_manager(t)

        # VPS cannot be deleted from here: the key only explains why.
        await select_row(t, TABLE, 1, MAIL.display_name)
        await t.press("d")
        await t.wait_for_toast("Delete is not supported for OVH vps instances")

        await select_row(t, TABLE, 1, BATCH_1.name)
        # Cancelled: nothing is deleted.
        await press(t, "#btn_ovh_mgr_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.wait_for_text("Delete OVH Cloud Instance", screen_only=True)
        await press(t, "#btn_cancel")
        await t.wait_for_screen("OVHManagerScreen")
        assert providers.mutations("ovh") == []

        # Only the exact word enables the button.
        await press(t, "#btn_ovh_mgr_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        confirm = t.on_screen("#btn_confirm")
        await t.fill("#confirm_input", "Delete")
        await t.settle()
        assert confirm.disabled
        await t.fill("#confirm_input", "delete")
        await t.wait_until(lambda: not confirm.disabled, desc="confirm enabled")
        await press(t, confirm)
        await t.wait_for_toast(r"OVH instance .* deleted\.")
        await t.wait_until(lambda: BATCH_1.name not in _rows(t), desc="batch-1 row gone")

    assert [(r["method"], r["api_path"]) for r in providers.mutations("ovh")] == [
        ("DELETE", delete_path)
    ]
    assert providers.ovh.cloud_instance(PROJECT, BATCH_1.instance_id) is None
    target = fleet.ovh_cloud_id(BATCH_1)
    audited = [
        (row["action"], row["target"], row["confirmed"], row["details"]["success"])
        for row in ovh_audit(seed)
    ]
    assert audited == [
        ("cloud_delete", target, False, False),  # the cancelled attempt
        ("cloud_delete", target, True, False),  # confirmed, before the call
        ("cloud_delete", target, True, True),  # the call succeeded
    ]


async def test_create_a_cloud_instance_through_the_wizard(tui, seed, providers):
    _seed(seed, providers)
    key_id = providers.ovh.seed_project_ssh_key(PROJECT, "deploy-key", "ssh-ed25519 AAAAE2E e2e")

    async with tui() as t:
        await _open_manager(t)
        await press(t, "#btn_ovh_mgr_new")
        await t.wait_for_screen("OVHCloudCreateScreen")
        region = t.on_screen("#input_region")
        await t.wait_until(lambda: region.value == "GRA7", desc="region picked")
        await t.wait_until(
            lambda: len(t.table_rows("#flavors_table")) == 2
            and len(t.table_rows("#images_table")) == 2
            and len(t.table_rows("#keys_table")) == 1,
            desc="flavors, images and keys loaded",
        )
        assert [row[0] for row in t.table_rows("#keys_table")] == ["deploy-key"]

        await t.fill("#input_name", "batch-3")
        await select_row(t, "#flavors_table", 0, "d2-2")
        await select_row(t, "#images_table", 0, "Debian 12")

        # The confirmation names the choice and the cost; escape backs out.
        await press(t, "#btn_create")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.wait_for_text("batch-3", "GRA7", "d2-2", "5.00 EUR", screen_only=True)
        await t.press("escape")
        await t.wait_for_screen("OVHCloudCreateScreen")
        assert providers.mutations("ovh") == []

        await press(t, "#btn_create")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.fill("#confirm_input", "create")
        await press(t, "#btn_confirm")
        await t.wait_for_toast(r"Instance 'batch-3' created successfully")
        await t.wait_for_screen("OVHManagerScreen")

    posts = providers.mutations("ovh")
    assert [(r["method"], r["api_path"]) for r in posts] == [
        ("POST", f"/cloud/project/{PROJECT}/instance")
    ]
    assert posts[0]["body"] == {
        "name": "batch-3",
        "flavorId": flavor_id("d2-2"),
        "imageId": image_id("Debian 12"),
        "region": "GRA7",
        "sshKeyId": key_id,
    }
    creates = [row for row in ovh_audit(seed) if row["action"] == "cloud_create"]
    assert [row["confirmed"] for row in creates] == [False, True]
