"""Journey: share straight after start-up, while Memory Sync is still unlocking.

The owner set up Memory Sync on this computer and keeps it unlocked: the
passphrase is in the OS keychain. On the next start the app unlocks Memory
Sync by itself. It loads the key, then registers every server with the
service, which takes a while on a slow connection. The owner goes straight
to Fleet Memory and shares app-1 with the team while that is still running.

Opening Fleet Memory starts its own unlock, which replaces the one from
start-up. Sharing still works: the key reaches it the moment it is loaded,
and the start-up unlock finishes in the background.
"""

from __future__ import annotations

import re

import pytest

from e2e.harness.memory_sync import PASSPHRASE
from e2e.journeys.tui.test_team_memory_share import (
    FIRST_SYNC,
    HOST,
    TEAM,
    _confirm_share,
    _fleet_rows,
    _seed,
    _synced,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

# Long enough that Fleet Memory opens while the start-up unlock is still
# registering servers (it waits once per request).
SLOW_SECONDS = 3.0


def _keep_unlocked(seed, monkeypatch) -> None:
    """The device remembers the passphrase, as "Keep unlocked" does."""
    from servonaut.config.manager import ConfigManager
    import servonaut.services.memory.passphrase_store as passphrase_store

    manager = ConfigManager(config_path=seed.config_path)
    config = manager.get()
    config.memory.sync_remember_device = True
    manager.save(config)
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: True)
    monkeypatch.setattr(passphrase_store, "get_passphrase", lambda: PASSPHRASE)


async def test_share_while_the_start_up_unlock_is_still_running(
    tui, seed, fake_cloud, monkeypatch
):
    _seed(seed, fake_cloud, monkeypatch)
    async with tui() as t:
        await _synced(t)
    _keep_unlocked(seed, monkeypatch)

    fake_cloud.slow_down(SLOW_SECONDS)
    async with tui() as t:
        sync = t.app.memory_sync_service
        await t.wait_until(lambda: sync.is_configured, desc="the key loaded at start-up")
        await t.nav("nav_memory")
        await t.wait_for_screen("FleetMemoryScreen")
        fake_cloud.slow_down(0)

        await t.wait_until(
            lambda: _fleet_rows(t) == [[HOST.name, HOST.instance_id, "synced", "● Fresh"]],
            desc="app-1 probed here and synced",
        )
        await t.press("S")
        await t.wait_for_screen("ShareInstanceScreen")
        select = t.on_screen("#share-team-select")
        await t.wait_until(lambda: select.value == TEAM, desc="team loaded")
        await _confirm_share(t)
        await t.wait_for_toast(rf"^Shared {re.escape(HOST.name)} with team Ops\.$")

    (grant,) = fake_cloud.memory.grants(TEAM)
    assert (grant["instance_id"], grant["status"]) == (HOST.instance_id, "active")
    fake_cloud.assert_no_unexpected_errors(*FIRST_SYNC)
