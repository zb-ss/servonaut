"""Journey: an MCP client sees and reaches the team's shared servers.

Signed in as a member of the team Ops, ``list_instances`` lists the team's
server-1 by its team reference (``ops/server-1``) beside the user's own
servers; the team's copy of the user's own app-1 is listed once, as app-1.
``run_command`` on ``ops/server-1`` connects to the team's host as the
team's login. Signed out, only the user's own servers are listed.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

TEAM = {"slug": "ops", "name": "Ops", "role": "member", "member_count": 2}
SERVER_1 = {
    "id": "srv-1", "name": "server-1", "hostname": "server-1.example.com", "port": 22,
    "login_user": "deploy", "username": "deploy", "status": "active",
}
APP_1_SHARED = {
    "id": "srv-2", "name": "app-1-team", "hostname": "app-1.example.com", "port": 22,
    "instance_id": fleet.APP_1.instance_id, "status": "active",
}
UPTIME = " 10:00:00 up 3 days,  1 user,  load average: 0.01, 0.02, 0.00\n"


def _team(fake_cloud) -> None:
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[TEAM], shared_servers={"ops": [SERVER_1, APP_1_SHARED]})


async def test_list_instances_names_the_team_servers(mcp, fake_cloud, account_home):
    _team(fake_cloud)
    home = account_home("mcp-shared")
    async with mcp(home) as session:
        result = await session.call("list_instances", {})

    assert "ops/server-1" in result
    assert "server-1.example.com" in result
    assert "app-1-team" not in result
    assert result.count(fleet.APP_1.instance_id) == 1
    for host in fleet.AWS_FLEET:
        assert host.name in result


async def test_run_command_reaches_a_team_server_by_its_reference(
    mcp, journey, fake_cloud, account_home,
):
    _team(fake_cloud)
    journey.shims.when("ssh", r"server-1\.example\.com.*uptime", stdout=UPTIME)
    home = account_home("mcp-shared-run")
    async with mcp(home) as session:
        result = await session.call(
            "run_command", {"instance_id": "ops/server-1", "command": "uptime"},
        )

    assert UPTIME.strip() in result
    (connect,) = journey.shims.calls("ssh")
    login, host = SERVER_1["username"], SERVER_1["hostname"]
    assert f"{login}@{host}" in connect.argv


async def test_signed_out_lists_only_the_own_servers(mcp, fake_cloud, account_home):
    _team(fake_cloud)
    home = account_home("mcp-shared-out", signed_in=False)
    async with mcp(home) as session:
        result = await session.call("list_instances", {})

    assert "server-1" not in result
    assert fleet.APP_1.name in result
