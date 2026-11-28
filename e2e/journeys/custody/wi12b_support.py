"""Steps shared by the TUI and MCP vault-custody journeys (rotation, refusals, summaries).

The account lives in the suite's own sandbox home, which the in-process app and
a child process can both use; the fixtures of ``conftest.py`` sign it in and
give it the test vault custody.
"""

from __future__ import annotations

from typing import Any

from e2e.harness import fleet
from e2e.harness.memory_seed import seed_memory
from e2e.harness.memory_sync import ACTIVE, open_memory_sync, status, sync_all

HOST = fleet.APP_1
OS_MODULE = {"distro": "Ubuntu 24.04 LTS", "kernel": "6.8.0-e2e"}
SERVICES_MODULE = {"nginx": "1.24.0", "php-fpm": "8.3"}
NOT_SET_UP = "⚪ Not set up yet"


def seed_probed_memory(seed: Any) -> None:
    """Two modules of app-1 probed on this device before Memory Sync is set up."""
    seed_memory(seed.home, HOST, {"os": OS_MODULE, "services": SERVICES_MODULE})


async def settle_card(t: Any, button: str) -> None:
    """Wait until the Memory Sync card shows *button* (the cards are rebuilt after each step)."""
    await t.wait_until(lambda: _reachable(t, button), desc=f"{button} on the card")


def _reachable(t: Any, button: str) -> bool:
    try:
        widget = t.on_screen(button)
    except Exception:
        return False
    return t.is_reachable(widget) and not widget.disabled


async def set_up_in_vault(t: Any) -> None:
    """Open Memory Sync and press Set up: no passphrase dialog, a vault key."""
    await open_memory_sync(t)
    await t.wait_until(lambda: status(t) == NOT_SET_UP, desc="not set up")
    await settle_card(t, "#msync_btn_setup")
    await t.click("#msync_btn_setup")
    await t.wait_for_toast(r"^Memory Sync is now active\.$")
    await t.wait_until(lambda: status(t) == ACTIVE, desc="Memory Sync active")
    await settle_card(t, "#msync_btn_sync_now")


async def synced(t: Any) -> str:
    return await sync_all(t)


def live_memory_items(fake_cloud: Any) -> list[str]:
    """Fingerprints of the account's live ``memory_key`` vault items on the fake."""
    user_id = fake_cloud.entitlements()["user_id"]
    return fake_cloud.vault.app_key_fingerprints(user_id, "memory_key")

