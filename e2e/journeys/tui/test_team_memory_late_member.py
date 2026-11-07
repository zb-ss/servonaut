"""Journey: a teammate who sets up Memory Sync after the share.

The owner shares app-1 while the teammate has no memory key yet, so the
grant holds no wrap for them and they cannot read it. Once they set up
Memory Sync:

* Fleet Memory names the team in its "Shared with" column;
* the server's Share form says the teammate cannot read it yet, and "Share
  with them too" seals the latest snapshots for them without stopping or
  changing the share;
* or the bulk share, with "Update existing shares to these settings" ticked
  and the share's own settings, keeps the share and opens it to them.

Either way the teammate then opens every shared module with their own key.
"""

from __future__ import annotations

import re

import pytest

from e2e.harness import fleet
from e2e.harness.memory_seed import seed_memory
from e2e.harness.memory_sync import plain, use_passphrase
from e2e.harness.session_seed import seed_session
from e2e.journeys.tui.test_team_memory_bulk_share import (
    _mark,
    _open_bulk_form,
    _open_fleet_memory,
    _press,
    _share,
)
from e2e.journeys.tui.test_team_memory_share import (
    FIRST_SYNC,
    GRANT_PATH,
    HOST,
    MODULES,
    TEAM,
    TEAMMATE,
    _confirm_share,
    _open_share,
    _synced,
    _teammate,
    _teammate_opens,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

NAME = f"member {TEAMMATE}"
SHARED_WITH = 5  # Fleet Memory's "Shared with" column


def _seed_without_teammate(seed, fake_cloud, monkeypatch) -> None:
    """The share journey's seed, before the teammate set up Memory Sync."""
    fake_cloud.configure(plan="teams", mcp_connections=0)
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    seed_memory(seed.home, HOST, MODULES)
    use_passphrase(monkeypatch)


async def _share_alone(t, fake_cloud) -> dict:
    """Share app-1 while nobody else can read it; return the grant."""
    await _synced(t)
    await _open_share(t)
    readers = t.on_screen("#share-readers")
    await t.wait_until(lambda: "Members who set up Memory Sync later" in plain(readers.render()),
                       desc="the readers listed")
    assert NAME not in plain(readers.render())  # no memory key yet
    await _confirm_share(t)
    await t.wait_for_toast(rf"^Shared {re.escape(HOST.name)} with team Ops\.$")
    await t.wait_for_screen("FleetMemoryScreen")
    (grant,) = fake_cloud.memory.grants(TEAM)
    assert not any(w["recipient_user_id"] == TEAMMATE for w in grant["wraps"])
    return grant


def _untouched(fake_cloud, grant: dict) -> dict:
    """The same live share: never revoked, never sent again."""
    (live,) = fake_cloud.memory.grants(TEAM)
    assert (live["id"], live["status"]) == (grant["id"], "active")
    assert not fake_cloud.requests(f"{GRANT_PATH}/{grant['id']}", "DELETE")
    assert len(fake_cloud.requests(GRANT_PATH, "POST")) == 1
    return live


async def test_share_with_a_teammate_who_set_up_memory_sync_later(
    tui, seed, fake_cloud, monkeypatch,
):
    _seed_without_teammate(seed, fake_cloud, monkeypatch)
    async with tui() as t:
        grant = await _share_alone(t, fake_cloud)
        # Fleet Memory names the team the owner shares app-1 with.
        await t.wait_until(
            lambda: plain(t.table_rows("#fleet-memory-table")[0][SHARED_WITH]) == "Ops",
            desc="the Shared with column",
        )

        teammate = _teammate(fake_cloud)  # sets up Memory Sync now
        await t.press("S")
        await t.wait_for_screen("ShareInstanceScreen")
        line = t.on_screen("#share-existing-text")
        await t.wait_until(lambda: f"Cannot read it yet: {NAME}." in plain(line.render()),
                           desc="the teammate named")
        await _press(t, "#share-btn-add")
        await t.wait_for_toast(rf"^The latest snapshots are shared with {NAME} now\.$")
        await t.wait_until(
            lambda: "Cannot read it yet" not in plain(t.on_screen("#share-existing-text").render()),
            desc="the line gone",
        )
        assert not t.on_screen("#share-btn-add").display

    live = _untouched(fake_cloud, grant)
    assert _teammate_opens(fake_cloud, live, teammate) == MODULES
    fake_cloud.assert_no_unexpected_errors(*FIRST_SYNC)


async def test_the_bulk_update_opens_an_unchanged_share_to_a_late_teammate(
    tui, seed, fake_cloud, monkeypatch,
):
    _seed_without_teammate(seed, fake_cloud, monkeypatch)
    async with tui() as t:
        grant = await _share_alone(t, fake_cloud)
        teammate = _teammate(fake_cloud)

        table = await _open_fleet_memory(t, {HOST.name})
        await _mark(t, table, HOST.name)
        await _open_bulk_form(t, 1)
        # The single share's settings: the role (viewer) and the modules it holds.
        modules = t.on_screen("#bulk-modules-list")
        for index in range(modules.option_count):
            value = modules.get_option_at_index(index).value
            if (value in grant["modules"]) != (value in modules.selected):
                modules.toggle(value)
        await t.wait_until(lambda: set(modules.selected) == set(grant["modules"]),
                           desc="the share's modules chosen")
        update = t.on_screen("#bulk-update-existing")
        await t.click(update)
        await t.wait_until(lambda: update.value, desc="update existing shares ticked")

        status, summary = await _share(t)
        assert "1 opened to more members" in status
        assert "Already shared, opened to members who could not read it yet (1)" in summary
        assert f"{HOST.name} — now also {NAME}" in summary

    live = _untouched(fake_cloud, grant)
    assert _teammate_opens(fake_cloud, live, teammate) == MODULES
    fake_cloud.assert_no_unexpected_errors(*FIRST_SYNC)
