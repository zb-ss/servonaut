"""Journey: create Hetzner servers and manage the project's SSH keys.

The create wizard (``n`` on the Hetzner Manager) loads server types, images,
locations and the project's SSH keys from the Hetzner API. The user picks a
row in each table and names the server; creating it asks for the word
"create" (it starts billing) and then sends exactly one create request with
exactly the chosen values. Without any SSH key, or with an ARM server type
and an x86 image, the wizard explains the problem and sends nothing.

The SSH Keys screen lists the project's keys, registers a pasted public key
with one request, and deletes a key only after the word "delete" is typed.

The Hetzner setup screen, opened from Settings, tests a token against the
API, fills its dropdowns from the project, and saves the provider as enabled.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.known_bugs import ProductBug, known_bug
from e2e.harness.pilot import JourneyTimeout

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

# Fabricated public keys: the right shape, no real key material.
DEPLOY_KEY = ("e2e-deploy", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Edeploykeyonly00000000000000000 deploy")
LAPTOP_KEY = ("e2e-laptop", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Elaptopkeyonly00000000000000000 laptop")
CI_KEY = ("e2e-ci", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Ecikeyonly0000000000000000000000 ci")
NEW_SERVER = "web-2"


class ManagerNotRefreshedAfterCreate(ProductBug):
    """The manager still lists the old servers after the wizard created one."""


def _seed(seed, providers, *, keys=(DEPLOY_KEY,), **hetzner) -> None:
    seed.config(hetzner=seed.hetzner_config(**hetzner))
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    providers.hetzner.seed_servers(fleet.HETZNER_FLEET)
    for name, public_key in keys:
        providers.hetzner.seed_ssh_key(name, public_key)


def _names(t, selector: str) -> list[str]:
    return [row[0] for row in t.table_rows(selector)]


async def _pick(t, selector: str, name: str) -> None:
    """Move a table's cursor to the row whose first cell is *name*."""
    table = t.on_screen(selector)
    await t.click(table)
    await t.wait_until(lambda: table.has_focus, desc=f"focus on {selector}")
    target = _names(t, selector).index(name)
    for _ in range(table.row_count + 1):
        if table.cursor_row == target:
            break
        await t.press("down" if table.cursor_row < target else "up")
    await t.wait_until(lambda: table.cursor_row == target, desc=f"{selector} on {name}")


async def _open_wizard(t, *, keys: int) -> None:
    await t.nav("nav_hetzner_manage")
    await t.wait_for_screen("HetznerManagerScreen")
    await t.wait_until(lambda: t.table_rows("#hetzner_mgr_table"), desc="manager rows")
    await t.click("#btn_hetzner_mgr_new")
    await t.wait_for_screen("HetznerCreateScreen")
    await t.wait_until(
        lambda: len(_names(t, "#hetzner_types_table")) == 3
        and len(_names(t, "#hetzner_images_table")) == 3
        and len(_names(t, "#hetzner_locations_table")) == 3
        and len(_names(t, "#hetzner_keys_table")) == keys,
        desc="wizard tables loaded",
    )


def _creates(providers) -> list[dict]:
    return providers.requests("hetzner", method="POST", path="/servers")


async def _create_web_2(t, providers) -> None:
    """Fill the wizard for web-2 (cx32 / debian-12 / nbg1) and confirm."""
    await _pick(t, "#hetzner_types_table", "cx32")
    await _pick(t, "#hetzner_images_table", "debian-12")
    await _pick(t, "#hetzner_locations_table", "nbg1")
    await _pick(t, "#hetzner_keys_table", DEPLOY_KEY[0])
    await t.fill("#hetzner_input_name", NEW_SERVER)
    await t.click("#btn_hetzner_create_submit")
    await t.wait_for_screen("ConfirmActionScreen")
    text = t.rendered_text()
    for part in (NEW_SERVER, "nbg1", "cx32", "debian-12", DEPLOY_KEY[0], "6.80"):
        assert part in text, part
    assert t.on_screen("#btn_confirm").disabled
    await t.fill("#confirm_input", "create")
    await t.wait_until(lambda: not t.on_screen("#btn_confirm").disabled, desc="confirm enabled")
    await t.click("#btn_confirm")
    await t.wait_for_toast(rf"^Server '{NEW_SERVER}' created \(ID: \d+\)")
    await t.wait_for_screen("HetznerManagerScreen")


async def test_create_a_server_with_the_wizard(tui, seed, providers):
    _seed(seed, providers)

    async with tui() as t:
        await _open_wizard(t, keys=1)
        # The configured defaults are preselected.
        assert t.on_screen("#hetzner_types_table").cursor_row == 0  # cx23
        assert t.on_screen("#hetzner_images_table").cursor_row == 0  # ubuntu-22.04

        # Backing out of the confirmation creates nothing.
        await t.fill("#hetzner_input_name", NEW_SERVER)
        await t.click("#btn_hetzner_create_submit")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.press("escape")
        await t.wait_for_screen("HetznerCreateScreen")
        await t.settle()
        assert _creates(providers) == []

        await _create_web_2(t, providers)

        # The manager lists the new server once refreshed.
        await t.click("#btn_hetzner_mgr_refresh")
        await t.wait_until(
            lambda: NEW_SERVER in [row[1] for row in t.table_rows("#hetzner_mgr_table")],
            desc="new server in the manager",
        )

    creates = _creates(providers)
    assert len(creates) == 1
    key_id = providers.hetzner.key_named(DEPLOY_KEY[0])["id"]
    body = creates[0]["body"]
    assert {k: body[k] for k in ("name", "server_type", "image", "location", "ssh_keys")} == {
        "name": NEW_SERVER,
        "server_type": "cx32",
        "image": "debian-12",
        "location": "nbg1",
        "ssh_keys": [key_id],
    }
    assert body["start_after_create"] is True
    created = providers.hetzner.server_named(NEW_SERVER)
    assert created is not None and created["server_type"]["name"] == "cx32"
    assert providers.requests("hetzner", method="DELETE") == []


@known_bug(
    "After the create wizard returns to the Hetzner Manager, the manager keeps "
    "its old list: the new server only shows after a manual refresh",
    raises=ManagerNotRefreshedAfterCreate,
)
async def test_manager_lists_the_new_server_after_create(tui, seed, providers):
    _seed(seed, providers)

    async with tui() as t:
        await _open_wizard(t, keys=1)
        await _create_web_2(t, providers)
        try:
            await t.wait_until(
                lambda: NEW_SERVER in [row[1] for row in t.table_rows("#hetzner_mgr_table")],
                timeout=5,
                desc="new server in the manager",
            )
        except JourneyTimeout as exc:
            assert providers.hetzner.server_named(NEW_SERVER) is not None
            raise ManagerNotRefreshedAfterCreate("manager rows unchanged") from exc


async def test_wizard_refuses_what_hetzner_would_reject(tui, seed, providers):
    # No key in the project and none configured as the default.
    _seed(seed, providers, keys=())

    async with tui() as t:
        await _open_wizard(t, keys=0)
        await t.fill("#hetzner_input_name", NEW_SERVER)
        await t.click("#btn_hetzner_create_submit")
        await t.wait_for_toast(r"No SSH keys are registered with Hetzner Cloud yet", severity="error")
        assert t.screen_name() == "HetznerCreateScreen"

        # An ARM server type cannot boot the x86 image.
        providers.hetzner.seed_ssh_key(*DEPLOY_KEY)
        await t.press("escape")
        await t.wait_for_screen("HetznerManagerScreen")
        await t.click("#btn_hetzner_mgr_new")
        await t.wait_for_screen("HetznerCreateScreen")
        await t.wait_until(lambda: len(_names(t, "#hetzner_keys_table")) == 1, desc="key row")
        await t.wait_until(lambda: len(_names(t, "#hetzner_types_table")) == 3, desc="types")
        await t.wait_until(lambda: len(_names(t, "#hetzner_images_table")) == 3, desc="images")
        await _pick(t, "#hetzner_types_table", "cax11")
        await t.fill("#hetzner_input_name", NEW_SERVER)
        await t.click("#btn_hetzner_create_submit")
        await t.wait_for_toast(r"^Architecture mismatch: server type 'cax11' is arm", severity="error")
        assert t.screen_name() == "HetznerCreateScreen"

    assert _creates(providers) == []
    assert providers.mutations("hetzner") == []


async def test_ssh_keys_add_and_delete(tui, seed, providers):
    _seed(seed, providers, keys=(LAPTOP_KEY,))

    async with tui() as t:
        await t.nav("nav_hetzner_ssh_keys")
        await t.wait_for_screen("HetznerSSHKeysScreen")
        await t.wait_until(
            lambda: _names(t, "#hetzner_ssh_keys_table") == [LAPTOP_KEY[0]], desc="key list"
        )

        # Register a pasted key.
        await t.click("#btn_hetzner_ssh_add")
        await t.wait_until(lambda: t.on_screen("#hetzner_ssh_input_name").display, desc="form")
        await t.fill("#hetzner_ssh_input_name", CI_KEY[0])
        await t.fill("#hetzner_ssh_input_public_key", CI_KEY[1])
        await t.click("#btn_hetzner_ssh_save")
        await t.wait_for_toast(rf"^SSH key '{CI_KEY[0]}' registered\.$")
        await t.wait_until(
            lambda: _names(t, "#hetzner_ssh_keys_table") == [LAPTOP_KEY[0], CI_KEY[0]],
            desc="new key listed",
        )
        added = providers.requests("hetzner", method="POST", path="/ssh_keys")
        assert [(e["body"]["name"], e["body"]["public_key"]) for e in added] == [CI_KEY]

        # Deleting asks for the word "delete"; backing out sends nothing.
        await _pick(t, "#hetzner_ssh_keys_table", CI_KEY[0])
        await t.click("#btn_hetzner_ssh_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        assert CI_KEY[0] in t.rendered_text()
        await t.press("escape")
        await t.wait_for_screen("HetznerSSHKeysScreen")
        await t.settle()
        assert providers.requests("hetzner", method="DELETE") == []

        await t.click("#btn_hetzner_ssh_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.fill("#confirm_input", "delete")
        await t.wait_until(lambda: not t.on_screen("#btn_confirm").disabled, desc="confirm enabled")
        await t.click("#btn_confirm")
        await t.wait_for_toast(r"^SSH key '\d+' deleted\.$")
        await t.wait_until(
            lambda: _names(t, "#hetzner_ssh_keys_table") == [LAPTOP_KEY[0]], desc="key removed"
        )

    assert added[0]["status"] == 201
    deletes = providers.requests("hetzner", method="DELETE")
    assert len(deletes) == 1 and deletes[0]["status"] == 204
    assert providers.hetzner.key_named(CI_KEY[0]) is None
    assert providers.hetzner.key_named(LAPTOP_KEY[0]) is not None


async def test_setup_screen_tests_and_saves_a_token(tui, seed, providers):
    # Hetzner is not configured yet.
    seed.config()
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    providers.hetzner.seed_servers(fleet.HETZNER_FLEET)
    providers.hetzner.seed_ssh_key(*DEPLOY_KEY)

    async with tui() as t:
        assert not t.nav_reachable("nav_hetzner_manage")
        await t.nav("nav_settings")
        await t.wait_for_screen("SettingsScreen")
        # Provider panels sit in a collapsed "Cloud Providers" group.
        await t.nav("navbtn_hetzner")
        status = t.on_screen("#hetzner_status_label")
        await t.wait_until(lambda: "Not configured" in str(status.render()), desc="panel status")
        await t.click("#btn_hetzner_setup")
        await t.wait_for_screen("HetznerSetupScreen")

        # Testing without a token asks for one and calls nothing.
        await t.click("#btn_hetzner_test")
        await t.wait_for_toast(r"Enter an API token", severity="warning")
        assert providers.requests("hetzner") == []

        await t.fill("#hetzner_input_token", "hz-fake-token")
        await t.click("#btn_hetzner_test")
        await t.wait_for_toast(r"^Hetzner connection OK\.$")
        result = t.on_screen("#hetzner_test_result")
        assert "Connected. 2 server(s) in project." in str(result.render())
        # The key dropdown now offers the project's key and selects it.
        key_select = t.on_screen("#hetzner_select_remote_ssh_key")
        await t.wait_until(lambda: key_select.value == DEPLOY_KEY[0], desc="key dropdown filled")

        await t.click("#btn_hetzner_save")
        await t.wait_for_toast(r"^Hetzner configuration saved\.$")
        await t.wait_for_toast(r"Hetzner enabled — 2 server\(s\) loaded\.")

    saved = seed.read_config()["hetzner"]
    assert saved["enabled"] is True
    assert saved["api_token"] == "hz-fake-token"
    assert saved["default_server_type"] == "cx23"
    assert saved["default_hetzner_ssh_key"] == DEPLOY_KEY[0]
    assert providers.mutations("hetzner") == []
