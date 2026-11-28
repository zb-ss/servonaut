"""Journey: a second device with no vault, for an account whose key is in the vault.

The account's Memory Sync key is in vault custody (the vault was set up on a
first device). On a second device that is signed in but not added to the
vault, Memory Sync cannot be unlocked, and the app says so instead of
offering a way that would not work: no passphrase dialog opens, on the Memory
Sync screen or on Fleet Memory, no new key is registered (no ``POST`` to the
key route, so the account's key is untouched) and the screen points to the
vault with an "Open vault" button, which opens the Vault screen.
"""

from __future__ import annotations

import pytest

from e2e.harness.fake_cloud.routes_memory import KEYS_PATH
from e2e.harness.memory_sync import open_memory_sync, plain, status
from e2e.harness.vault_custody import setup_vault

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio, pytest.mark.xdist_group("custody-second-device")]

# Either card tells the user the vault is the way in; both carry the button.
GUIDANCE = (
    "Add this device to your vault first",  # no marker yet: asked the service, the account has a vault
    "Unlock or add this device to your vault",  # the service already said the key is in the vault
)


def _passphrase_screens(t) -> list[str]:
    return [name for name in t.opened_screens() if "Passphrase" in name]


def _guidance_shown(t) -> bool:
    text = t.rendered_text()
    return any(line in text for line in GUIDANCE)


async def test_a_device_without_the_vault_is_pointed_to_the_vault_not_to_a_passphrase(
    tui, seed, fake_cloud, journey, account_home, servonaut_cmd, custody_device, signed_in_home,
):
    # The first device: it owns the vault, and the account's key is kept there.
    setup_vault(journey, account_home("first-device"), servonaut_cmd)
    key = fake_cloud.memory.seed_vault_custody_key()
    posts_before = len(fake_cloud.requests(KEYS_PATH, "POST"))

    # The second device: signed in, no vault identity of its own.
    signed_in_home()

    async with tui() as t:
        await open_memory_sync(t)
        await t.wait_until(lambda: _guidance_shown(t), desc="the vault guidance")
        assert status(t) in ("⚪ Not set up yet", "⚪ Locked")
        button = t.on_screen("#msync_btn_open_vault")
        assert plain(button.label) == "Open vault"
        # No way to set up or unlock with a passphrase is offered.
        assert not t.find("#msync_btn_setup")
        assert not t.find("#msync_btn_remember")
        assert _passphrase_screens(t) == []

        # Fleet Memory is the other place that used to ask for the passphrase.
        await t.nav("nav_memory")
        await t.wait_for_screen("FleetMemoryScreen")
        await t.settle(10)
        assert _passphrase_screens(t) == []

        await t.nav("nav_memory_sync")
        await t.wait_for_screen("MemorySyncSetupScreen")
        await t.wait_until(lambda: _guidance_shown(t), desc="the vault guidance again")
        await t.click("#msync_btn_open_vault")
        await t.wait_for_screen("VaultScreen")
        assert _passphrase_screens(t) == []

    # The account's key was never touched: no registration was attempted.
    assert len(fake_cloud.requests(KEYS_PATH, "POST")) == posts_before == 0
    assert fake_cloud.memory.enrolled_key()["id"] == key["id"]
    assert fake_cloud.memory.enrolled_key()["custody"] == "vault"
    assert not (seed.home / ".servonaut" / "memory" / "keys.json").exists()
