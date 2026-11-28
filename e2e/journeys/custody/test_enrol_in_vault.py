"""Journey: Memory Sync set up with the key kept in the vault.

A signed-in user with a vault (set up with the real CLI on a real pty) opens
Memory Sync. The card says the key will be kept in the vault and offers one
button: no passphrase is asked for, in a dialog or anywhere else. Pressing it
makes the keypair, stores it as a ``memory_key`` item in the personal vault,
reads it back and registers the public half with the service in the vault
shape: the service ends up with one vault-custody row (no wrapped private key)
and the vault with exactly one ``memory_key`` item for it. No ``keys.json``
is written and nothing readable crosses the wire.

After a restart the store unlocks by itself from the vault: Memory Sync is
active as soon as the screen opens, with no passphrase dialog, no
``keys.json`` and no new key.
"""

from __future__ import annotations

import pytest

from e2e.harness.fake_cloud.routes_memory import KEYS_PATH
from e2e.harness.memory_sync import ACTIVE, open_memory_sync, plain, status
from e2e.harness.vault_custody import setup_vault
from e2e.journeys.custody.conftest import wait_for_active_toast

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio, pytest.mark.xdist_group("custody-enrol")]

# Screens a passphrase flow would open; none may appear.
PASSPHRASE_DIALOGS = ("PassphraseEnrolModal", "PassphraseUnlockModal", "PassphraseModal")


def _keys_json(home) -> bool:
    return (home / ".servonaut" / "memory" / "keys.json").exists()


def _vault_card(t) -> str:
    return plain(t.on_screen("#msync_vault_body").render())


def _asked_for_a_passphrase(t) -> list[str]:
    return [name for name in t.opened_screens() if "Passphrase" in name]


async def test_memory_sync_is_set_up_and_unlocked_from_the_vault(
    tui, seed, fake_cloud, journey, servonaut_cmd, custody_device, signed_in_home,
):
    signed_in_home()
    setup_vault(journey, journey.ctx.sandbox, servonaut_cmd)
    user_id = fake_cloud.entitlements()["user_id"]

    async with tui() as t:
        await open_memory_sync(t)
        await t.wait_until(lambda: status(t) == "⚪ Not set up yet", desc="not set up yet")
        await t.wait_for_text("Your key will be kept in your vault. No passphrase needed.")
        assert t.find("#msync_btn_setup")

        await t.click("#msync_btn_setup")
        await wait_for_active_toast(t)
        await t.wait_until(lambda: status(t) == ACTIVE, desc="Memory Sync active")
        await t.wait_for_text("kept in your vault")
        assert _asked_for_a_passphrase(t) == []

    # One vault-custody row, no wrapped key; one live item for the same key.
    key = fake_cloud.memory.enrolled_key()
    assert key["custody"] == "vault" and key["wrapped_private_key"] is None
    assert fake_cloud.vault.app_key_fingerprints(user_id, "memory_key") == [key["fingerprint"]]
    posts = fake_cloud.requests(KEYS_PATH, "POST")
    assert [(r["status"], r["body"]["custody"]) for r in posts] == [(201, "vault")]
    assert not _keys_json(seed.home)

    # A restart finds the key in the vault: active with no dialog and no new key.
    row_id = key["id"]
    async with tui() as t:
        await open_memory_sync(t)
        await t.wait_until(lambda: status(t) == ACTIVE, desc="unlocked from the vault")
        assert _asked_for_a_passphrase(t) == []
        assert not t.find("#msync_btn_setup")
    assert not _keys_json(seed.home)
    assert fake_cloud.memory.enrolled_key()["id"] == row_id
    assert fake_cloud.requests(KEYS_PATH, "POST") == posts
