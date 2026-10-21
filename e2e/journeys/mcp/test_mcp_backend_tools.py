"""Journey: an MCP client uses the account and relay tools of ``servonaut --mcp``.

Against the (fake) service, signed in: ``whoami`` describes the session
without revealing the token; ``api_request`` calls the API with the CLI's
session and recovers from an expired access token by refreshing it;
``mcp_tool_call`` runs a tool on the hosted MCP server over Streamable HTTP
(ending the session after each call, which frees its connection slot at
once), passes the server's answer for an unknown tool through, returns its
JSON-RPC errors (a capacity refusal) as answers and refreshes an expired
access token refused on the session's first request. Against a server whose
host redirects ``/mcp`` elsewhere it takes the event stream instead, without
following the redirect, and, when called right after another call, waits
for the server to free the closed stream's connection slot instead of
failing;
``relay_status`` reports the service's view of the relay; and
``relay_reconnect`` starts a background listener when the service does not
see one, without writing anything to the protocol stream, then leaves a
healthy listener alone.

At the read-only level ``relay_status`` still works; signed out, every tool
answers "not logged in" without calling the service.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness.session_seed import read_session
from e2e.harness.waits import wait_for, wait_for_async

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


async def _json(session, tool, arguments=None, **kwargs):
    return json.loads(await session.call(tool, arguments, **kwargs))


async def test_account_and_relay_tools_signed_in(mcp, journey, fake_cloud, account_home, relay):
    home = account_home("mcp-signed-in")
    listener = relay(home)  # stops whatever relay_reconnect starts in this home
    user_id = fake_cloud.entitlements()["user_id"]

    async with mcp(home) as session:
        who = await _json(session, "whoami")
        assert who["logged_in"] is True
        assert who["plan"] == "solo" and who["base_url"] == fake_cloud.url
        assert who["token_expires_in_seconds"] > 0
        assert fake_cloud.tokens()[0] not in json.dumps(who)

        me = await _json(session, "api_request", {"method": "GET", "path": "/api/v1/me"})
        assert me["status"] == 200 and me["body"] == {"user_id": user_id}
        assert "authorization" not in {k.lower() for k in me["headers"]}

        # An expired access token is refreshed and the request retried.
        fake_cloud.expire_access_token()
        ents = await _json(session, "api_request", {"method": "GET", "path": "/api/entitlements"})
        assert ents["status"] == 200 and ents["body"]["plan"] == "solo"
        assert fake_cloud.statuses("/api/entitlements") == [401, 200]
        assert fake_cloud.statuses("/api/oauth/refresh") == [200]
        assert read_session(home.home)["refresh_token"] == fake_cloud.tokens()[1]

        hosted = await _json(
            session, "mcp_tool_call",
            {"name": "fleet_summary", "arguments": {"region": "us-east-1"}},
        )
        assert hosted == {"status": 200, "response": {"result": {
            "content": [{"type": "text", "text": "hosted fleet_summary: 1 argument(s)"}],
            "isError": False,
        }}}
        first = fake_cloud.hosted_mcp.streams()[0]
        assert first["transport"] == "streamable-http"
        assert [m["method"] for m in first["messages"]] == [
            "initialize", "notifications/initialized", "tools/call",
        ]
        assert first["messages"][-1]["params"] == {
            "name": "fleet_summary", "arguments": {"region": "us-east-1"}
        }
        unknown = await _json(session, "mcp_tool_call", {"name": "no_such_tool"})
        assert unknown["response"] == {"result": {
            "content": [{"type": "text", "text": "Unknown tool: no_such_tool"}], "isError": True,
        }}
        fake_cloud.hosted_mcp.refuse()  # the service's capacity refusal
        refused = await _json(session, "mcp_tool_call", {"name": "fleet_summary"})
        assert refused["response"]["error"]["code"] == -32050

        # The session's first request refuses an expired access token; the
        # call refreshes it.
        fake_cloud.expire_access_token()
        again = await _json(session, "mcp_tool_call", {"name": "fleet_summary"})
        assert again["response"]["result"]["isError"] is False
        assert fake_cloud.statuses("/api/oauth/refresh") == [200, 200]
        assert 401 in fake_cloud.statuses("/mcp")

        # Each call ends its session with a DELETE, which frees the slot at
        # once: calls made right after one another are not refused, even
        # where a closed event stream would keep its slot for a while.
        fake_cloud.hosted_mcp.hold_slots(2.0)
        refused_before = fake_cloud.hosted_mcp.refused_streams()
        for _ in range(2):
            quick = await _json(session, "mcp_tool_call", {"name": "fleet_summary"})
            assert quick["response"]["result"]["isError"] is False, quick
        assert fake_cloud.hosted_mcp.refused_streams() == refused_before
        assert [e["status"] for e in fake_cloud.requests("/mcp", "DELETE")] == [204] * 6
        assert fake_cloud.requests("/mcp/sse") == []

        # A host without the endpoint redirects /mcp to another origin: the
        # call takes the event stream instead and never follows the redirect.
        # The service frees a closed stream's slot about two seconds after
        # the client left, so a call made right after another one waits.
        fake_cloud.hosted_mcp.serve_streamable_http(False)
        for _ in range(2):
            fallback = await _json(session, "mcp_tool_call", {"name": "fleet_summary"})
            assert fallback["response"]["result"]["isError"] is False, fallback
        assert fake_cloud.statuses("/mcp")[-1] == 308
        assert fake_cloud.hosted_mcp.refused_streams() > refused_before
        assert 429 in fake_cloud.statuses("/mcp/sse")
        # Every call closed its session or stream: the service caps the open ones.
        await wait_for_async(
            lambda: all(s["closed"] for s in fake_cloud.hosted_mcp.streams()),
            desc="hosted MCP sessions closed",
        )
        assert [s["transport"] for s in fake_cloud.hosted_mcp.streams()] == (
            ["streamable-http"] * 6 + ["sse"] * 2
        )
        assert set(fake_cloud.statuses("/mcp")) <= {200, 202, 204, 308, 401, 405}
        assert all(r["bearer_ok"] for r in fake_cloud.requests("/mcp/message"))
        assert set(fake_cloud.statuses("/mcp/message")) == {200}

        status = await _json(session, "relay_status")
        assert status == {"connected": False, "last_heartbeat_at": None, "client_ids": []}

        # Nothing is connected, so relay_reconnect starts a background listener.
        restarted = await _json(session, "relay_reconnect", timeout=60)
        assert restarted["action"] == "restarted", restarted
        assert restarted["backend_connected_before"] is False
        assert any("started in background" in line for line in restarted["details"])
        await wait_for_async(lambda: fake_cloud.relay.heartbeats(), desc="listener heartbeat")
        pid = listener.background_pid()
        assert pid is not None and listener.lock_owner() == {"pid": pid, "mode": "bg"}

        # Its progress messages went into the result, not onto the protocol
        # stream: the session keeps working and saw no stray output.
        assert (await _json(session, "whoami"))["logged_in"] is True
        assert session.protocol_errors == []

        status = await _json(session, "relay_status")
        assert status["connected"] is True
        assert status["client_ids"] == [fake_cloud.relay.heartbeats()[0]["client_id"]]
        healthy = await _json(session, "relay_reconnect")
        assert healthy["action"] == "none"
        assert listener.background_pid() == pid

    assert session.protocol_errors == []


async def test_relay_status_works_read_only(mcp, journey, fake_cloud, account_home, relay):
    from servonaut.config.schema import MCPConfig

    home = account_home("mcp-readonly", mcp=MCPConfig(guard_level="readonly"))
    listener = relay(home).start()
    wait_for(lambda: fake_cloud.relay.heartbeats(), desc="listener heartbeat")

    async with mcp(home) as session:
        status = await _json(session, "relay_status")
        assert status["connected"] is True
        assert status["client_ids"] == [fake_cloud.relay.heartbeats()[0]["client_id"]]
        assert (await _json(session, "whoami"))["logged_in"] is True
        refused = await _json(session, "relay_reconnect")
        assert refused["error"]["code"] == "guard_denied"
    assert listener.running  # the refused call left the listener alone


async def test_backend_tools_signed_out(mcp, journey, fake_cloud, account_home):
    home = account_home("mcp-signed-out", signed_in=False)
    async with mcp(home) as session:
        assert await _json(session, "whoami") == {"logged_in": False}
        for tool, arguments in (
            ("relay_status", {}),
            ("api_request", {"method": "GET", "path": "/api/v1/me"}),
            ("mcp_tool_call", {"name": "fleet_summary"}),
        ):
            answer = await _json(session, tool, arguments)
            assert answer["error"]["code"] == "not_logged_in", (tool, answer)
    assert fake_cloud.requests() == []
