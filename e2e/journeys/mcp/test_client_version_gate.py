"""Journey: client-version gate behavior in ``servonaut --mcp``.

Under ``mode="enforce"`` with a server minimum newer than the running client:
- ``api_request`` on a gated API route returns a structured
  ``client_update_required`` error naming the required version;
- account, entitlements, relay status, hosted tools, and local tools work.

Under ``mode="log"`` with the same minimum, ``api_request`` and
``mcp_tool_call`` succeed with zero HTTP 426 responses.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet
from servonaut.services.version_policy import parse_client_signal

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

MINIMUM_VERSION = "99.0.0"
TEAM_PATH = "/api/v1/teams/ops"


async def _json(session, tool, arguments=None, **kwargs):
    return json.loads(await session.call(tool, arguments, **kwargs))


async def test_mcp_cloud_tools_return_client_update_required_while_local_and_exempt_work(
    mcp, journey, fake_cloud, account_home,
):
    fake_cloud.configure(plan="teams")
    fake_cloud.set_client_version_policy(mode="enforce", minimum_version=MINIMUM_VERSION)
    home = account_home("mcp-version-gate-enforce")

    async with mcp(home) as session:
        # Local session status keeps working.
        who = await _json(session, "whoami")
        assert who["logged_in"] is True

        # Local fleet tool works unaffected by the server version floor.
        instances_text = await session.call("list_instances")
        assert fleet.APP_1.name in instances_text

        # Exempt /api/entitlements passes through api_request.
        ents = await _json(session, "api_request", {"method": "GET", "path": "/api/entitlements"})
        assert ents["status"] == 200
        assert ents["body"]["client_version_policy"]["mode"] == "enforce"

        me = await _json(session, "api_request", {"method": "GET", "path": "/api/v1/me"})
        assert me["status"] == 200
        assert fake_cloud.statuses("/api/v1/me") == [200]

        team = await _json(session, "api_request", {"method": "GET", "path": TEAM_PATH})
        assert team["error"]["code"] == "client_update_required", team
        assert MINIMUM_VERSION in team["error"]["message"]
        assert "update your source checkout and reinstall" in team["error"]["message"]
        (team_request,) = fake_cloud.requests(TEAM_PATH)
        assert team_request["status"] == 426
        assert parse_client_signal(team_request["client_header"])[2] == "mcp"

        hosted = await _json(session, "mcp_tool_call", {"name": "fleet_summary"})
        assert hosted["status"] == 200
        assert hosted["response"]["result"]["isError"] is False
        mcp_reqs = fake_cloud.requests("/mcp")
        assert any(request["status"] == 200 for request in mcp_reqs)
        assert all(parse_client_signal(request["client_header"])[2] == "mcp" for request in mcp_reqs)

        status = await _json(session, "relay_status")
        assert status["connected"] is False
        assert fake_cloud.statuses("/api/cli/status") == [200]

    assert session.protocol_errors == []


async def test_mcp_log_mode_allows_hosted_and_api_tools(
    mcp, journey, fake_cloud, account_home,
):
    fake_cloud.configure(plan="teams")
    fake_cloud.set_client_version_policy(mode="log", minimum_version=MINIMUM_VERSION)
    home = account_home("mcp-version-gate-log")

    async with mcp(home) as session:
        me = await _json(session, "api_request", {"method": "GET", "path": "/api/v1/me"})
        assert me["status"] == 200
        team = await _json(session, "api_request", {"method": "GET", "path": TEAM_PATH})
        assert team["status"] == 200
        assert team["body"]["name"] == "Ops"
        hosted = await _json(session, "mcp_tool_call", {"name": "fleet_summary"})
        assert hosted["status"] == 200
        assert hosted["response"]["result"]["isError"] is False

    (team_request,) = fake_cloud.requests(TEAM_PATH)
    assert team_request["below_minimum"] is True
    assert parse_client_signal(team_request["client_header"])[2] == "mcp"
    assert all(
        "below_minimum" not in request
        for path in ("/api/v1/me", "/mcp")
        for request in fake_cloud.requests(path)
    )
    assert not any(req["status"] == 426 for req in fake_cloud.requests())
    assert session.protocol_errors == []
