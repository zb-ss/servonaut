"""Journey: an MCP client sees a team's copy of a server's memory merged into the own record.

Signed in as a member of the team Ops, which shares the user's own app-1 as
``app-1-team``, the module and note the team filed under its own copy of that
server are merged into the own app-1 record the first time a memory tool
touches it, so ``get_server_memory`` returns them and ``list_server_memories``
lists the server once. Signed out, nothing is merged.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet
from e2e.harness.team_agent_rules import SLUG, TEAM_ID, TEAM_NAME
from e2e.harness.team_copy_memory import (
    SHARED_APP_1, TEAM_NOTE, marker, own_notes, seed_team_copy,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

TEAM = {"id": TEAM_ID, "slug": SLUG, "name": TEAM_NAME, "role": "member", "member_count": 2}


def _share_app_1(fake_cloud) -> None:
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[TEAM], shared_servers={SLUG: [dict(SHARED_APP_1)]})


async def test_get_server_memory_returns_the_merged_team_copy(mcp, fake_cloud, account_home):
    _share_app_1(fake_cloud)
    home = account_home("mcp-team-copy")
    copy = seed_team_copy(home.home)
    async with mcp(home) as session:
        result = await session.call("get_server_memory", {"instance_id": fleet.APP_1.name})
        listing = await session.call("list_server_memories", {})

    assert TEAM_NOTE in result and "- os:" in result  # the note and the probed module
    assert TEAM_NOTE in own_notes(home.home)
    assert marker(copy)["target_id"] == fleet.APP_1.instance_id
    assert "app-1-team" not in listing
    assert listing.count(fleet.APP_1.instance_id) == 1


async def test_a_note_deleted_meanwhile_does_not_come_back_on_the_next_session(
    mcp, fake_cloud, account_home,
):
    _share_app_1(fake_cloud)
    home = account_home("mcp-team-copy-again")
    seed_team_copy(home.home)
    async with mcp(home) as session:
        await session.call("get_server_memory", {"instance_id": fleet.APP_1.name})
    notes = home.home / ".servonaut" / "memory" / "aws" / fleet.APP_1.instance_id / "annotations.md"
    notes.write_text("", encoding="utf-8")

    async with mcp(home) as session:
        result = await session.call("get_server_memory", {"instance_id": fleet.APP_1.name})

    assert TEAM_NOTE not in result and own_notes(home.home) == ""


async def test_signed_out_merges_nothing(mcp, fake_cloud, account_home):
    _share_app_1(fake_cloud)
    home = account_home("mcp-team-copy-out", signed_in=False)
    seed_team_copy(home.home)
    async with mcp(home) as session:
        await session.call("get_server_memory", {"instance_id": fleet.APP_1.name})

    assert own_notes(home.home) == ""
