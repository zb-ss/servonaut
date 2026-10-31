"""Journey: a team member reads the memory the owner shared, including later snapshots.

Two people, each with a home and a sign-in of their own, run the real TUI
one after the other against the hermetic FakeCloud:

* the member enrols a Memory Sync key; the owner shares app-1's memory with
  the team; the member, who does not list app-1 among their own servers,
  finds it in Fleet Memory (a read-only row) and its Memory screen shows the
  team's ``os`` module, labelled "Shared by Ops";
* a member who enrols their key AFTER the share is not left out: the next
  snapshot the owner uploads comes with wraps for them (the service names
  them in ``missing_team_wraps`` and the owner's app seals the data key for
  them), and they can open it.

Before this change a member had no screen or tool that read a team's copy,
and a member who enrolled after the share could never be added.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from e2e.harness import fleet
from e2e.harness.bootstrap import Sandbox
from e2e.harness.memory_seed import seed_memory
from e2e.harness.memory_sync import PASSPHRASE, open_memory_sync, plain, unlock, use_passphrase
from e2e.harness.seed import HomeSeeder
from e2e.harness.session_seed import seed_relay_config, seed_session
from e2e.journeys.tui.test_team_memory_share import (
    HOST,
    MODULES,
    TEAM,
    _confirm_share,
    _open_share,
    _synced,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

MEMBER_ID = 5252
MEMBER_EMAIL = "member@example.com"


def _teams(fake_cloud) -> None:
    """The "ops" team is managed, and the member belongs to it."""
    fake_cloud.configure(plan="teams", mcp_connections=0)
    owner = fake_cloud.entitlements()["user_id"]
    fake_cloud.add_user(MEMBER_ID, email=MEMBER_EMAIL, name="Member")
    fake_cloud.account.create_team(name="Ops", slug=TEAM, owner_user_id=owner)
    fake_cloud.account.join_team(TEAM, user_id=MEMBER_ID, role="member", email=MEMBER_EMAIL,
                                 name="Member")


class People:
    """Two people taking turns on the one in-process home.

    Servonaut binds its paths under the home at import, so the TUI cannot
    be pointed at another home. Each person's ``~/.servonaut`` (sign-in,
    config, memory) is kept aside and put in place when it is their turn.
    """

    def __init__(self, home: Path, stash: Path, current: str) -> None:
        self.home, self.stash, self.current = home, stash, current
        stash.mkdir(parents=True, exist_ok=True)

    def add(self, name: str, data_dir: Path) -> None:
        shutil.move(str(data_dir), str(self.stash / name))

    def become(self, name: str) -> None:
        if name == self.current:
            return
        live = self.home / ".servonaut"
        shutil.move(str(live), str(self.stash / self.current))
        shutil.move(str(self.stash / name), str(live))
        self.current = name


def _member_data(journey, fake_cloud) -> Path:
    """The member's own ``.servonaut``: signed in as themselves, listing no server."""
    sandbox = Sandbox(journey.ctx.root / f"m{journey.directory.name[:4]}").create()
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    seeder.config()
    seed_relay_config(seeder)
    seeder.cache([], fresh=True)
    seed_session(sandbox.home, fake_cloud, user_id=MEMBER_ID)
    return sandbox.home / ".servonaut"


def _owner_session(seed, fake_cloud, monkeypatch) -> None:
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    seed_memory(seed.home, HOST, MODULES)
    use_passphrase(monkeypatch)


async def _member_enrols(tui, people: People, fake_cloud) -> None:
    """The member unlocks Memory Sync (a key is enrolled) and the team learns the key."""
    people.become("member")
    async with tui() as t:
        await open_memory_sync(t)
        await unlock(t)
    key = fake_cloud.memory.enrolled_key(MEMBER_ID)
    assert key is not None, [(r["method"], r["path"], r.get("user_id"), r["status"]) for r in fake_cloud.requests()][-15:]
    fake_cloud.memory.add_team_member(TEAM, MEMBER_ID, key["public_key"], role="member")


async def _member_opens_shared_server(tui, people: People) -> list:
    people.become("member")
    async with tui() as t:
        await open_memory_sync(t)
        await unlock(t)
        await t.nav("nav_memory")
        await t.wait_for_screen("FleetMemoryScreen")
        await t.wait_until(
            lambda: any(HOST.name in plain(r[0]) for r in t.table_rows("#fleet-memory-table")),
            desc="the shared server listed",
        )
        row = next(r for r in t.table_rows("#fleet-memory-table") if HOST.name in plain(r[0]))
        assert "team" in plain(row[3]) and "Shared" in plain(row[4])
        await t.press("enter")
        await t.wait_for_screen("MemoryScreen")
        await t.wait_until(
            lambda: any(plain(r[0]) == "os" for r in t.table_rows("#memory-table")),
            desc="the team's os module",
        )
        rows = [[plain(c) for c in r] for r in t.table_rows("#memory-table")]
        label = plain(t.on_screen("#memory-shared-source").render())
        assert label.startswith("Shared by Ops")
        return rows


async def test_a_member_reads_the_shared_servers_memory(tui, seed, fake_cloud, monkeypatch, journey):
    _teams(fake_cloud)
    _owner_session(seed, fake_cloud, monkeypatch)
    people = People(seed.home, journey.directory / "people", "owner")
    people.add("member", _member_data(journey, fake_cloud))
    await _member_enrols(tui, people, fake_cloud)

    people.become("owner")
    async with tui() as t:
        await _synced(t)
        await _open_share(t)
        await _confirm_share(t)
        await t.wait_for_screen("FleetMemoryScreen")
    assert any(w["recipient_user_id"] == MEMBER_ID
               for w in fake_cloud.memory.grants(TEAM)[-1]["wraps"])

    rows = await _member_opens_shared_server(tui, people)
    assert any(r[:3] == ["os", "distro", "Debian 12"] for r in rows)


async def test_a_member_who_enrols_after_the_share_reads_the_next_snapshot(
    tui, seed, fake_cloud, monkeypatch, journey,
):
    _teams(fake_cloud)
    _owner_session(seed, fake_cloud, monkeypatch)
    people = People(seed.home, journey.directory / "people", "owner")
    people.add("member", _member_data(journey, fake_cloud))

    async with tui() as t:  # shared before the member has a key
        await _synced(t)
        await _open_share(t)
        await _confirm_share(t)
        await t.wait_for_screen("FleetMemoryScreen")
    assert not any(w["recipient_user_id"] == MEMBER_ID
                   for w in fake_cloud.memory.grants(TEAM)[-1]["wraps"])

    await _member_enrols(tui, people, fake_cloud)

    people.become("owner")
    async with tui() as t:  # the owner's next sync uploads a new snapshot
        await open_memory_sync(t)
        await unlock(t)
        await t.click("#msync_btn_sync_now")
        await t.wait_until(
            lambda: any(w["recipient_user_id"] == MEMBER_ID
                        for w in fake_cloud.memory.grants(TEAM)[-1]["wraps"]),
            desc="the member's wraps stored",
        )

    rows = await _member_opens_shared_server(tui, people)
    assert any(r[:3] == ["os", "distro", "Debian 12"] for r in rows)
