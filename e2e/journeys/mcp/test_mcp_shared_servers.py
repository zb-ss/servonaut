"""Journey: an MCP client sees and reaches the team's shared servers.

Signed in as a member of the team Ops, ``list_instances`` lists the team's
server-1 by its team reference (``ops/server-1``) beside the user's own
servers; the team's copy of the user's own app-1 is listed once, as app-1.
``run_command`` on ``ops/server-1`` connects to the team's host as the
team's login. Signed out, only the user's own servers are listed.

The team's rule decides what an agent may do on its servers: a member whose
own MCP settings say ``dangerous`` still runs at the team's standard level
there, so a command outside the standard allowlist is refused (and audited
as ``team_rule``) on ``ops/server-1`` while it runs on the user's own edge-1.
"""

from __future__ import annotations

import json

import pytest

from servonaut.config.schema import MCPConfig

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


NOT_ALLOWLISTED = "systemctl status nginx"
NGINX_STATUS = "nginx.service - A high performance web server\n   Active: active (running)\n"


def _audit(home) -> list[dict]:
    path = home / ".servonaut" / "mcp_audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


async def test_the_team_rule_refuses_what_local_dangerous_settings_would_allow(
    mcp, journey, fake_cloud, account_home,
):
    _team(fake_cloud)
    journey.shims.when("ssh", r"server-1\.example\.com", stdout=NGINX_STATUS)
    home = account_home("mcp-team-rule", mcp=MCPConfig(guard_level="dangerous"))
    async with mcp(home) as session:
        result = await session.call(
            "run_command", {"instance_id": "ops/server-1", "command": NOT_ALLOWLISTED},
        )

    assert result == (
        "Blocked: on team Ops's shared servers your agents run at the standard "
        f"level (set by the team), and '{NOT_ALLOWLISTED}' is not an allowed command there."
    )
    assert journey.shims.calls("ssh") == []
    (row,) = [entry for entry in _audit(home.home) if entry.get("tool") == "run_command"]
    assert row["reason"] == "team_rule"


async def test_the_same_command_runs_on_an_own_server(
    mcp, journey, fake_cloud, account_home,
):
    _team(fake_cloud)
    host = fleet.EDGE_1.public_ip.replace(".", r"\.")
    journey.shims.when("ssh", rf"{host}.*systemctl status nginx", stdout=NGINX_STATUS)
    home = account_home("mcp-team-rule-own", mcp=MCPConfig(guard_level="dangerous"))
    async with mcp(home) as session:
        result = await session.call(
            "run_command", {"instance_id": fleet.EDGE_1.name, "command": NOT_ALLOWLISTED},
        )

    assert "Active: active (running)" in result
    (connect,) = journey.shims.calls("ssh")
    assert fleet.EDGE_1.public_ip in connect.joined
