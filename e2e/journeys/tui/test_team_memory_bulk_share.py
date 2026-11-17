"""Journey: share several servers' memory with a team in one go.

On a Teams plan, with app-1 and edge-1 synced through Memory Sync, the owner
opens Fleet Memory and marks servers with space. A third server, filed under
an id with dots (as a host name), has memory on this computer only: Memory
Sync cannot store it. ``S`` opens one form for every marked server; it
lists the members who will read them, once. Share sends one grant per
server, each carrying the teammate's wraps, and the summary lists every
server: shared, already shared, skipped with the reason.

* Run again, a server already shared is reported as already shared and no
  grant is posted for it; with "Update existing shares to these settings"
  ticked and another role chosen, it is shared again with that role (the
  old grant revoked first).
* A member who reads a team's copy of a server cannot mark it: shared rows
  are read-only.
"""

from __future__ import annotations

import pytest
from textual.widgets import DataTable

from e2e.harness import fleet
from e2e.harness.controls import choose, click_row
from e2e.harness.fleet import AwsHost
from e2e.harness.memory_seed import seed_memory
from e2e.harness.memory_sync import open_memory_sync, plain, sync_all, unlock
from e2e.journeys.tui.test_team_memory_share import (
    FIRST_SYNC,
    GRANT_PATH,
    HOST,
    MODULES,
    TEAM,
    TEAMMATE,
    _seed,
)
from e2e.journeys.tui.test_team_memory_share_member import (
    MEMBER_ID,
    People,
    _member_data,
    _member_enrols,
    _owner_session,
    _teams,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

SECOND = fleet.EDGE_1
# Memory Sync ids are letters, digits, "-" and "_": this one is not accepted.
DOTTED = AwsHost("vps-1", "vps-1.e2e.test", "running", "t3.micro", "us-east-1", "10.0.4.10")
TABLE = "#fleet-memory-table"
MARK = "✓ "


def _names(t) -> list[str]:
    """The Name column of Fleet Memory, without the mark."""
    return [plain(row[0]).removeprefix(MARK) for row in t.table_rows(TABLE)]


def _marked(t) -> list[str]:
    return [plain(row[0]).removeprefix(MARK) for row in t.table_rows(TABLE)
            if plain(row[0]).startswith(MARK)]


def _status(t) -> str:
    return plain(t.on_screen("#fleet-memory-status").render())


def _posted(fake_cloud) -> list[str]:
    """The server of every grant request, oldest first."""
    return [r["body"]["instance_id"] for r in fake_cloud.requests(GRANT_PATH, "POST")]


def _live(fake_cloud) -> dict[str, dict]:
    return {g["instance_id"]: g for g in fake_cloud.memory.grants(TEAM) if g["status"] == "active"}


async def _synced_both(t) -> None:
    await open_memory_sync(t)
    await unlock(t)
    assert await sync_all(t) == "Synced 4 envelope(s)."


async def _open_fleet_memory(t, names: set[str]) -> DataTable:
    await t.nav("nav_memory")
    await t.wait_for_screen("FleetMemoryScreen")
    await t.wait_until(lambda: set(_names(t)) == names, desc=f"Fleet Memory listing {sorted(names)}")
    return t.on_screen(TABLE, DataTable)


async def _focus_table(t, table: DataTable) -> None:
    """Give the table focus with the mouse, without opening a row.

    A click on the highlighted row opens it, so another row is clicked; a
    one-row table is clicked below its row.
    """
    if table.has_focus:
        return
    if table.row_count > 1:
        await click_row(t, table, 1 if table.cursor_row == 0 else 0)
    else:
        await t.click(table)
    await t.wait_until(lambda: table.has_focus, desc="the table focused")


async def _mark(t, table: DataTable, name: str) -> None:
    """Move to *name*'s row with the arrow keys and mark it with space."""
    await _focus_table(t, table)
    index = _names(t).index(name)
    for _ in range(table.row_count + 1):
        if table.cursor_row == index:
            break
        await t.press("down" if table.cursor_row < index else "up")
    assert table.cursor_row == index, (table.cursor_row, index)
    await t.press("space")
    await t.wait_until(lambda: name in _marked(t), desc=f"{name} marked")


async def _press(t, selector: str, *, tabs: int = 40) -> None:
    """Tab to a button and press Enter (toasts may cover the button's corner)."""
    button = t.on_screen(selector)
    await t.wait_until(lambda: not button.disabled, desc=f"{selector} enabled")
    for _ in range(tabs):
        if button.has_focus:
            break
        await t.press("tab")
    assert button.has_focus, t.focused_id()
    await t.press("enter")


async def _open_bulk_form(t, count: int, reader: str = f"member {TEAMMATE}") -> None:
    await t.press("S")
    await t.wait_for_screen("BulkShareScreen")
    await t.wait_until(lambda: t.on_screen("#bulk-team-select").value == TEAM, desc="team loaded")
    readers = t.on_screen("#bulk-readers")
    await t.wait_until(lambda: "Will be able to read them" in plain(readers.render()),
                       desc="the readers listed")
    assert reader in plain(readers.render())
    servers = f"{count} server" if count == 1 else f"{count} servers"
    assert plain(t.on_screen("#bulk-title").render()) == f"Share memory: {servers}"


async def _share(t) -> tuple[str, str]:
    """Press Share; return the status and summary once the batch is done."""
    await _press(t, "#bulk-btn-confirm")
    status = t.on_screen("#bulk-status")
    await t.wait_until(lambda: plain(status.render()).startswith("Done"), desc="the batch done")
    return plain(status.render()), plain(t.on_screen("#bulk-summary").render())


async def _close_form(t) -> None:
    await t.press("escape")
    await t.wait_for_screen("FleetMemoryScreen")
    await t.wait_until(lambda: not _marked(t), desc="the marks cleared after the batch")


def _seed_two(seed, fake_cloud, monkeypatch) -> None:
    """app-1 (the share journey's own seed) and edge-1, both probed here."""
    _seed(seed, fake_cloud, monkeypatch)
    seed_memory(seed.home, SECOND, MODULES)


async def test_share_two_servers_and_skip_one_memory_sync_cannot_store(
    tui, seed, fake_cloud, monkeypatch,
):
    _seed_two(seed, fake_cloud, monkeypatch)
    async with tui() as t:
        await _synced_both(t)
        # Probed on this computer since: memory only here, under a dotted id.
        seed_memory(seed.home, DOTTED, MODULES)
        table = await _open_fleet_memory(t, {HOST.name, SECOND.name, DOTTED.name})
        for name in (HOST.name, SECOND.name, DOTTED.name):
            await _mark(t, table, name)
        assert _status(t).startswith("3 marked")

        await _open_bulk_form(t, 3)
        status, summary = await _share(t)
        assert "2 shared, 1 skipped" in status
        assert "Shared (2)" in summary and "Skipped (1)" in summary
        assert f"{DOTTED.name} — Memory Sync does not accept this server's id" in summary
        await t.wait_for_toast(r"^Shared with team Ops: 2 shared, 1 skipped\.$")

        # One grant per server; the dotted id never reached the service.
        assert sorted(_posted(fake_cloud)) == sorted([HOST.instance_id, SECOND.instance_id])
        live = _live(fake_cloud)
        assert set(live) == {HOST.instance_id, SECOND.instance_id}
        for grant in live.values():
            assert grant["required_role"] == "viewer"
            assert any(w["recipient_user_id"] == TEAMMATE for w in grant["wraps"])
        assert not any(DOTTED.instance_id in r["path"] for r in fake_cloud.requests())

        await _close_form(t)
    fake_cloud.assert_no_unexpected_errors(*FIRST_SYNC)


async def test_a_second_run_leaves_existing_shares_unless_asked_to_update_them(
    tui, seed, fake_cloud, monkeypatch,
):
    _seed_two(seed, fake_cloud, monkeypatch)
    async with tui() as t:
        await _synced_both(t)
        table = await _open_fleet_memory(t, {HOST.name, SECOND.name})
        await _mark(t, table, HOST.name)
        await _open_bulk_form(t, 1)
        await _share(t)
        await _close_form(t)
        first = _live(fake_cloud)[HOST.instance_id]

        # Again, with edge-1: app-1 is reported as shared and gets no request.
        await _mark(t, table, HOST.name)
        await _mark(t, table, SECOND.name)
        await _open_bulk_form(t, 2)
        status, summary = await _share(t)
        assert "1 shared, 1 already shared" in status
        assert "Already shared, left as it was (1)" in summary and HOST.name in summary
        assert "Update existing shares to these settings" in summary  # the hint
        assert _posted(fake_cloud) == [HOST.instance_id, SECOND.instance_id]
        await _close_form(t)

        # Asked to update, with another role: revoked, then shared with it.
        await _mark(t, table, HOST.name)
        await _open_bulk_form(t, 1)
        await choose(t, "#bulk-role-select", "Member")
        update = t.on_screen("#bulk-update-existing")
        await t.click(update)
        await t.wait_until(lambda: update.value, desc="update existing shares ticked")
        status, summary = await _share(t)
        assert "1 updated" in status
        assert "Already shared, updated to these settings (1)" in summary
        deletes = [r["path"] for r in fake_cloud.requests(method="DELETE")
                   if r["path"].startswith(GRANT_PATH)]
        assert deletes == [f"{GRANT_PATH}/{first['id']}"]
        assert _posted(fake_cloud) == [HOST.instance_id, SECOND.instance_id, HOST.instance_id]
        renewed = _live(fake_cloud)[HOST.instance_id]
        assert renewed["id"] != first["id"] and renewed["required_role"] == "member"
        assert any(w["recipient_user_id"] == TEAMMATE for w in renewed["wraps"])
    fake_cloud.assert_no_unexpected_errors(*FIRST_SYNC)


async def test_a_member_cannot_mark_a_teams_copy(tui, seed, fake_cloud, monkeypatch, journey):
    _teams(fake_cloud)
    _owner_session(seed, fake_cloud, monkeypatch)
    people = People(seed.home, journey.directory / "people", "owner")
    people.add("member", _member_data(journey, fake_cloud))
    await _member_enrols(tui, people, fake_cloud)

    people.become("owner")
    async with tui() as t:  # the owner shares app-1 through the bulk form
        await open_memory_sync(t)
        await unlock(t)
        assert await sync_all(t) == "Synced 2 envelope(s)."
        table = await _open_fleet_memory(t, {HOST.name})
        await _mark(t, table, HOST.name)
        await _open_bulk_form(t, 1, reader=f"member {MEMBER_ID}")
        status, _summary = await _share(t)
        assert "1 shared" in status

    people.become("member")
    async with tui() as t:
        await open_memory_sync(t)
        await unlock(t)
        table = await _open_fleet_memory(t, {HOST.name})
        await t.wait_until(lambda: "Shared" in plain(t.table_rows(TABLE)[0][4]),
                           desc="the team's copy listed")
        await _focus_table(t, table)
        await t.press("space")
        await t.wait_for_toast(r"read-only")
        await t.press("m")
        await t.wait_for_toast(r"^There is no server of your own to mark\.$")
        assert not _marked(t) and "marked" not in _status(t)
