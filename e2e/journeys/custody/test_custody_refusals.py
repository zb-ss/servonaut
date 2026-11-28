"""Journey: what the user reads when the service refuses a vault-custody step.

Each refusal the service can give is read in the client's own plain wording
(never the service's text, never a raw code), leaves nothing half done, and
leaves the previous state alone:

* ``feature_disabled`` (the custody switch off): set-up stops, no vault item and
  no key row are left;
* ``memory_key_custody_vault`` (the passphrase switch off, an account with no
  vault): set-up tells the user to set up their vault;
* ``vault_not_ready`` at set-up: the new item is removed again, no key row;
* ``forbidden_entitlement`` on a Free account: the upgrade prompt;
* moving a passphrase key to the vault: ``fingerprint_mismatch`` and
  ``vault_not_ready`` leave the passphrase key as it was;
* config sync: ``config_key_not_ready`` on a push, ``no_vault_snapshot`` on a move
  (the old passphrase copies are kept).

Not reachable from a screen, so not here: ``memory_key_in_use`` (an item the
vault screens never offer to delete; the rotation journey covers the "kept"
note) and ``item_type_exists`` (covered in its rotation wording by the rotation
journey).
"""

from __future__ import annotations

import base64
import os

import pytest

from e2e.harness.fake_cloud.routes_configs import ENCRYPTION
from e2e.harness.memory_sync import ACTIVE, open_memory_sync, status, sync_all, unlock, use_passphrase
from e2e.harness.vault_custody import setup_vault
from e2e.journeys.custody.wi12b_support import (
    live_memory_items, seed_probed_memory, settle_card,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio, pytest.mark.xdist_group("custody-refusals")]

FEATURE_DISABLED = (
    "Keeping Memory Sync keys in the vault is not available on this Servonaut "
    "service yet. Nothing was changed. Try again later."
)
CUSTODY_VAULT = (
    "Memory Sync keeps its key in your vault. Set up or unlock your vault on this "
    "device, then try again."
)
VAULT_NOT_READY = (
    "Your vault is not ready for this. Unlock your vault on this device, confirm "
    "your vault identity, and try again."
)
FINGERPRINT_MISMATCH = (
    "Your Memory Sync key changed on another device. Nothing was moved. Open "
    "Memory Sync and try again."
)
CONFIG_KEY_NOT_READY = (
    "Your config sync key is not in your vault yet. Unlock your vault and try again."
)
NO_VAULT_SNAPSHOT = (
    "Your config was not uploaded with the vault key yet, so the old copies were "
    "kept. Nothing was deleted."
)
# The service's own wording, which must never reach the user.
SERVICE_WORDING = (
    "Vault custody for Memory Sync keys is not available yet.",
    "Update Servonaut to set up Memory Sync.",
    "Store your Memory Sync key in your personal vault first.",
    "The fingerprint does not match your active Memory Sync key.",
    "Store your config sync key in your personal vault first.",
    "Upload your config under the vault key before removing the old copies.",
    "Your plan does not include Memory Sync.",
)


def _texts(t) -> str:
    return " | ".join(message for _, message in t.toasts())


def _assert_only_client_wording(t) -> None:
    shown = _texts(t) + " " + t.rendered_text()
    for wording in SERVICE_WORDING:
        assert wording not in shown, wording


async def _press_setup(t) -> None:
    await open_memory_sync(t)
    await t.wait_until(lambda: status(t) == "⚪ Not set up yet", desc="not set up")
    await settle_card(t, "#msync_btn_setup")
    await t.click("#msync_btn_setup")


async def _setup_refused(t, text: str, *, severity: str = "error") -> None:
    await _press_setup(t)
    await t.wait_for_toast(text, severity=severity)
    await t.wait_until(lambda: status(t).startswith("✗"), desc="the refusal on the status line")
    _assert_only_client_wording(t)


def _nothing_left(fake_cloud) -> None:
    assert fake_cloud.memory.enrolled_key() is None
    assert live_memory_items(fake_cloud) == []


@pytest.fixture
def vault_account(journey, fake_cloud, seed, servonaut_cmd, custody_device, signed_in_home, monkeypatch):
    signed_in_home()
    seed_probed_memory(seed)
    _, recovery_key = setup_vault(journey, journey.ctx.sandbox, servonaut_cmd)
    return recovery_key


async def test_set_up_with_the_custody_switch_off_leaves_nothing(tui, fake_cloud, vault_account):
    fake_cloud.memory.set_vault_custody(False)
    async with tui() as t:
        await _setup_refused(t, f"^{FEATURE_DISABLED}$")
    _nothing_left(fake_cloud)


async def test_set_up_with_the_passphrase_switch_off_and_no_vault(
    tui, fake_cloud, seed, signed_in_home, monkeypatch,
):
    signed_in_home()
    use_passphrase(monkeypatch)
    fake_cloud.memory.set_passphrase_custody(False)
    async with tui() as t:
        await _setup_refused(t, f"^{CUSTODY_VAULT}$")
    assert fake_cloud.memory.enrolled_key() is None


async def test_set_up_when_the_service_says_the_vault_is_not_ready(tui, fake_cloud, vault_account, monkeypatch):
    monkeypatch.setattr(fake_cloud.memory, "_vault_ready", lambda user_id, fingerprint: False)
    async with tui() as t:
        await _setup_refused(t, f"^{VAULT_NOT_READY}$")
    _nothing_left(fake_cloud)  # the item made for the key was removed again


async def test_a_free_account_is_sent_to_the_upgrade_prompt(tui, fake_cloud, vault_account):
    async with tui() as t:
        await open_memory_sync(t)
        await t.wait_until(lambda: status(t) == "⚪ Not set up yet", desc="not set up")
        await settle_card(t, "#msync_btn_setup")
        # The plan lapses after the app signed in: the service refuses the key write.
        fake_cloud.configure(plan="free")
        await t.click("#msync_btn_setup")
        await t.wait_until(
            lambda: any("plan" in m.lower() or "upgrade" in m.lower() for _, m in t.toasts()
                        if "relay" not in m),
            desc="the upgrade prompt",
        )
        _assert_only_client_wording(t)
    _nothing_left(fake_cloud)


# ---------------------------------------------------------------------------
# Moving a passphrase key to the vault
# ---------------------------------------------------------------------------


async def _passphrase_account_with_a_vault(
    tui, journey, fake_cloud, seed, servonaut_cmd, signed_in_home, monkeypatch,
) -> str:
    """A key enrolled with a passphrase, then a vault set up for the account."""
    signed_in_home()
    seed_probed_memory(seed)
    use_passphrase(monkeypatch)
    async with tui() as t:
        await open_memory_sync(t)
        await unlock(t)
        await sync_all(t)
    assert fake_cloud.memory.enrolled_key()["custody"] == "passphrase"
    _, recovery_key = setup_vault(journey, journey.ctx.sandbox, servonaut_cmd)
    return recovery_key


async def _start_move(t, recovery_key: str) -> None:
    await open_memory_sync(t)
    await unlock(t)
    await settle_card(t, "#msync_btn_move_to_vault")
    await t.click("#msync_btn_move_to_vault")
    await t.wait_for_screen("ConfirmModal")
    await t.click("#btn_confirm_yes")
    await t.wait_for_screen("VaultSecretPromptModal")
    await t.fill("#vault_secret_input", recovery_key)
    await t.click("#vault_secret_continue")


@pytest.mark.parametrize("refusal", ["fingerprint_mismatch", "vault_not_ready"])
async def test_a_refused_move_leaves_the_passphrase_key_alone(
    tui, fake_cloud, journey, seed, servonaut_cmd, custody_device, signed_in_home, monkeypatch, refusal,
):
    recovery_key = await _passphrase_account_with_a_vault(
        tui, journey, fake_cloud, seed, servonaut_cmd, signed_in_home, monkeypatch,
    )
    before = fake_cloud.memory.enrolled_key()
    if refusal == "fingerprint_mismatch":
        original = fake_cloud.memory.switch_custody
        monkeypatch.setattr(
            fake_cloud.memory, "switch_custody", lambda body: original({**body, "fingerprint": "0" * 64}),
        )
        expected_text = FINGERPRINT_MISMATCH
    else:
        # Restored after the journey: the fake outlives it.
        monkeypatch.setattr(fake_cloud.memory, "_vault_ready", lambda user_id, fingerprint: False)
        expected_text = VAULT_NOT_READY

    async with tui() as t:
        await _start_move(t, recovery_key)
        await t.wait_for_toast(f"^{expected_text}$", severity="error")
        _assert_only_client_wording(t)

    after = fake_cloud.memory.enrolled_key()
    assert after["id"] == before["id"] and after["custody"] == "passphrase"
    assert after["wrapped_private_key"] == before["wrapped_private_key"]


# ---------------------------------------------------------------------------
# Config sync
# ---------------------------------------------------------------------------


async def _open_snapshots(t) -> None:
    await t.nav("nav_sync_config")
    await t.wait_for_screen("SnapshotManagerScreen")


def _passphrase_snapshot(fake_cloud) -> None:
    """A snapshot another device pushed under a passphrase."""
    b64 = lambda size: base64.b64encode(os.urandom(size)).decode()  # noqa: E731
    status_code, _ = fake_cloud.configs.push({
        "name": "default", "label": "old laptop", "hash": "0" * 64, "encryption": ENCRYPTION,
        "data": b64(48), "iv": b64(12), "tag": b64(16), "salt": b64(16),
    })
    assert status_code == 201


async def test_a_config_push_without_the_key_item_reads_as_not_ready(tui, fake_cloud, vault_account, monkeypatch):
    # The service finds no live config sync key item.
    monkeypatch.setattr(fake_cloud.configs, "vault_key_ids", lambda: [])
    async with tui() as t:
        await _open_snapshots(t)
        await t.wait_until(lambda: "No snapshots yet" in t.rendered_text(), desc="empty list")
        await t.press("p")
        await t.wait_for_screen("LabelInputModal")
        await t.fill("#label_input", "journey-laptop")
        await t.click("#btn_label_save")
        shown = await t.wait_for_toast(r"config sync key", severity="error")
        assert shown == CONFIG_KEY_NOT_READY
        _assert_only_client_wording(t)
    assert fake_cloud.configs.all() == []


async def test_a_config_move_the_service_cannot_verify_keeps_the_old_copies(
    tui, fake_cloud, vault_account, monkeypatch,
):
    _passphrase_snapshot(fake_cloud)
    push = fake_cloud.configs.push

    def push_without_keeping_vault_copies(body):
        result = push(body)
        with fake_cloud.configs._lock:
            fake_cloud.configs._snapshots = [
                s for s in fake_cloud.configs._snapshots if s["key_custody"] != "vault"
            ]
        return result

    monkeypatch.setattr(fake_cloud.configs, "push", push_without_keeping_vault_copies)
    async with tui() as t:
        await _open_snapshots(t)
        await settle_card(t, "#snap_btn_move_to_vault")
        await t.click("#snap_btn_move_to_vault")
        await t.wait_for_screen("ConfirmModal")
        await t.click("#btn_confirm_yes")
        await t.wait_for_screen("VaultSecretPromptModal")
        await t.fill("#vault_secret_input", vault_account)
        await t.click("#vault_secret_continue")
        await t.wait_for_toast(f"^{NO_VAULT_SNAPSHOT}$", severity="error")
        _assert_only_client_wording(t)
    assert [s["key_custody"] for s in fake_cloud.configs.all()] == ["passphrase"]


async def test_set_up_is_not_stalled_by_the_keys_me_budget(
    tui, fake_cloud, seed, servonaut_cmd, journey, custody_device, signed_in_home,
):
    """With the client's real 3-per-hour budget for the key lookup, set-up still finishes."""
    signed_in_home()
    setup_vault(journey, journey.ctx.sandbox, servonaut_cmd)
    async with tui() as t:
        await _press_setup(t)
        await t.wait_for_toast(r"^Memory Sync is now active\.$")
    assert len(fake_cloud.requests("/api/v1/memory/keys/me", "GET")) <= 3
