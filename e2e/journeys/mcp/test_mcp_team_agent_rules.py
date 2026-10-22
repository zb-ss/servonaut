"""Journey: a team's agent rules decide what a member's MCP agent may do on its servers.

Signed in as a member of the team Ops, an agent works through ``servonaut
--mcp`` on Ops's server-1 (``ops/server-1``). The rules Ops's owners and
admins set come signed from the service; Servonaut verifies and applies them:

* a pattern the team blocks refuses a command there and says so, while other
  commands still run, and the member's own servers keep their own rules;
* an admin tightening the rules on the website reaches the running agent at
  Servonaut's next scheduled refresh, without a restart;
* rules that cannot be trusted leave the team's servers read-only for every
  role, owners included, and the refusal says why: no signed rules, a copy
  changed on the way, a key this Servonaut does not know, an older copy
  replayed after this device had a newer one, or rules that expired while
  the service could not be reached;
* a user in no team is not affected at all.

``list_instances`` names the level agents run at on each team server and who
set it, which is how the journeys see a change land in a running agent.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import time

import pytest

from servonaut.config.schema import MCPConfig

from e2e.harness import fleet
from e2e.harness.fake_cloud import routes_agent_rules as served
from e2e.harness.team_agent_rules import (
    ADMIN_ID,
    ENV_FILES,
    SERVER_1,
    SERVER_1_REF,
    SLUG,
    audit_rows,
    member_of_ops,
    ops_with_people,
    save_policy,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

UPTIME = " 10:00:00 up 3 days,  1 user,  load average: 0.01, 0.02, 0.00\n"
READ_ENV = "cat /srv/app/.env"
TEAM_SECTION = "Agents on team shared servers"
NO_COMMANDS = "running commands is not available there"
# How long a journey waits for a change made elsewhere to reach the agent.
_CHANGE_SECONDS = 15.0
_POLL_SECONDS = 0.1


def _blocked(level: str, setter: str, what: str, server: str = "") -> str:
    """A team refusal; *server* when the team set the level for that server alone."""
    where = f"shared server {server}" if server else "shared servers"
    return (
        f"Blocked: on team Ops's {where} your agents run at the {level} level "
        f"({setter}), and {what}."
    )


def _level_line(level: str, setter: str) -> str:
    """The line ``list_instances`` gives server-1."""
    return f"  {SERVER_1_REF}: {level} ({setter})"


async def _listing_until(session, text: str, *, desc: str) -> str:
    """``list_instances``, asked again until it shows *text* (a change made elsewhere)."""
    deadline = time.monotonic() + _CHANGE_SECONDS
    while True:
        listing = await session.call("list_instances", {})
        if text in listing:
            return listing
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {desc}; the listing ends:\n{listing[-600:]}")
        await asyncio.sleep(_POLL_SECONDS)


def _team_refusals(home) -> list[dict]:
    return [row for row in audit_rows(home.home, "run_command") if row.get("reason") == "team_rule"]


async def test_a_pattern_the_team_blocks_is_refused_there_and_only_there(
    mcp, journey, fake_cloud, account_home,
):
    member_of_ops(fake_cloud)
    fake_cloud.agent_rules.set_rules(SLUG, {"command_blocklist": [ENV_FILES]})
    journey.shims.when("ssh", r"server-1\.example\.com.*uptime", stdout=UPTIME)
    edge_1 = fleet.EDGE_1.public_ip.replace(".", r"\.")
    journey.shims.when("ssh", rf"{edge_1}.*\.env", stdout="APP_ENV=production\n")
    home = account_home("mcp-team-pattern")
    async with mcp(home) as session:
        refused = await session.call("run_command", {"instance_id": SERVER_1_REF, "command": READ_ENV})
        uptime = await session.call("run_command", {"instance_id": SERVER_1_REF, "command": "uptime"})
        own = await session.call("run_command", {"instance_id": fleet.EDGE_1.name, "command": READ_ENV})
        listing = await session.call("list_instances", {})

    assert refused == _blocked(
        "standard", "set by the team",
        rf"'{READ_ENV}' is refused there: it matches the blocked pattern {ENV_FILES}",
    )
    assert UPTIME.strip() in uptime
    # The member's own server keeps the member's own rules.
    assert "APP_ENV=production" in own
    assert _level_line("standard", "set by the team") in listing
    ran = [call.joined for call in journey.shims.calls("ssh")]
    assert len(ran) == 2 and not any("server-1" in line and ".env" in line for line in ran)
    (row,) = _team_refusals(home)
    assert row["args"]["command"] == READ_ENV


async def test_an_admin_tightening_the_rules_reaches_a_running_agent(
    mcp, journey, fake_cloud, account_home,
):
    ops_with_people(fake_cloud)
    # Each signed copy is valid for 4 s, so Servonaut refreshes it every 2 s.
    fake_cloud.agent_rules.set_rules(SLUG, None, version=0, lifetime=dt.timedelta(seconds=4))
    journey.shims.when("ssh", r"server-1\.example\.com.*uptime", stdout=UPTIME)
    uptime = {"instance_id": SERVER_1_REF, "command": "uptime"}
    home = account_home("mcp-team-tightened")
    async with mcp(home) as session:
        assert UPTIME.strip() in await session.call("run_command", uptime)

        # On the website, an admin makes server-1 read-only for members.
        saved = save_policy(fake_cloud, {"agent_rules": {
            "servers": {SERVER_1["id"]: {"role_levels": {"member": "readonly"}}},
        }}, user_id=ADMIN_ID)
        assert saved.status_code == 200
        version = fake_cloud.agent_rules.version(SLUG)
        await _listing_until(
            session, _level_line("readonly", "set by the team"), desc="the admin's change",
        )
        refused = await session.call("run_command", uptime)

    # The override holds on server-1 alone, so the refusal names it.
    assert refused == _blocked("readonly", "set by the team", NO_COMMANDS, server="server-1")
    assert len(journey.shims.calls("ssh")) == 1
    # The same process fetched the new version on its own schedule.
    assert {"version": version, "serving": served.SIGNED, "status": 200} in fake_cloud.agent_rules.served(SLUG)
    assert len(_team_refusals(home)) == 1


UNTRUSTED = {
    served.UNSIGNED: "the team service sent no signed agent rules",
    served.TAMPERED: "the team's agent rules could not be verified",
    served.UNKNOWN_KEY: "this Servonaut cannot verify the team's agent rules; update Servonaut",
}


@pytest.mark.parametrize("how", sorted(UNTRUSTED))
async def test_rules_that_cannot_be_trusted_leave_the_team_servers_read_only(
    mcp, journey, fake_cloud, account_home, how,
):
    # Owners included: what the rules would allow is not known.
    member_of_ops(fake_cloud, role="owner")
    fake_cloud.agent_rules.serve(SLUG, how)
    home = account_home(f"mcp-team-{how}")
    async with mcp(home) as session:
        listing = await session.call("list_instances", {})
        refused = await session.call("run_command", {"instance_id": SERVER_1_REF, "command": "uptime"})

    because = f"because {UNTRUSTED[how]}"
    assert _level_line("readonly", because) in listing
    assert refused == _blocked("readonly", because, NO_COMMANDS)
    assert journey.shims.calls("ssh") == []
    assert len(_team_refusals(home)) == 1


async def test_an_older_copy_replayed_after_a_newer_one_is_refused(
    mcp, journey, fake_cloud, account_home,
):
    member_of_ops(fake_cloud)
    home = account_home("mcp-team-replay")
    read_env = {"instance_id": SERVER_1_REF, "command": READ_ENV}
    fake_cloud.agent_rules.set_rules(SLUG, None, version=1)
    async with mcp(home) as session:
        assert _level_line("standard", "set by the team") in await session.call("list_instances", {})

    fake_cloud.agent_rules.set_rules(SLUG, {"command_blocklist": [ENV_FILES]}, version=2)
    async with mcp(home) as session:
        tightened = await session.call("run_command", read_env)
    assert "it matches the blocked pattern" in tightened

    # The looser version 1 comes back, validly signed, to a device that had version 2.
    fake_cloud.agent_rules.replay(SLUG, 1)
    async with mcp(home) as session:
        listing = await session.call("list_instances", {})
        refused = await session.call("run_command", read_env)

    because = "because the team service sent older agent rules than this device already has"
    assert _level_line("readonly", because) in listing
    assert refused == _blocked("readonly", because, NO_COMMANDS)
    assert journey.shims.calls("ssh") == []
    assert {"version": 1, "serving": served.REPLAYED, "status": 200} in fake_cloud.agent_rules.served(SLUG)


async def test_rules_that_expire_while_the_service_is_unreachable_fall_back_to_read_only(
    mcp, journey, fake_cloud, account_home,
):
    member_of_ops(fake_cloud)
    fake_cloud.agent_rules.set_rules(SLUG, None, version=0, lifetime=dt.timedelta(seconds=3))
    home = account_home("mcp-team-expired")
    async with mcp(home) as session:
        assert _level_line("standard", "set by the team") in await session.call("list_instances", {})
        fake_cloud.agent_rules.serve(SLUG, served.UNAVAILABLE)
        because = (
            "because the team's agent rules expired and could not be refreshed; "
            "check that you are online and signed in"
        )
        await _listing_until(session, _level_line("readonly", because), desc="the rules to expire")
        refused = await session.call("run_command", {"instance_id": SERVER_1_REF, "command": "uptime"})

    assert refused == _blocked("readonly", because, NO_COMMANDS)
    assert journey.shims.calls("ssh") == []
    # Servonaut tried to refresh them before they expired.
    assert any(row["status"] == 503 for row in fake_cloud.agent_rules.served(SLUG))


async def test_a_user_in_no_team_keeps_their_own_rules(mcp, journey, fake_cloud, account_home):
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[], shared_servers={})
    edge_1 = fleet.EDGE_1.public_ip.replace(".", r"\.")
    journey.shims.when("ssh", rf"{edge_1}.*systemctl status nginx", stdout="Active: active (running)\n")
    home = account_home("mcp-no-team", mcp=MCPConfig(guard_level="dangerous"))
    async with mcp(home) as session:
        listing = await session.call("list_instances", {})
        ran = await session.call(
            "run_command", {"instance_id": fleet.EDGE_1.name, "command": "systemctl status nginx"},
        )

    assert "Active: active (running)" in ran
    assert TEAM_SECTION not in listing
    assert not [entry for entry in fake_cloud.requests() if entry["path"].endswith("/policy")]
    assert not (home.home / ".servonaut" / "team_policy.json").exists()
