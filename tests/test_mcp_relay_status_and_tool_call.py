"""Tests for the ``relay_status`` and ``mcp_tool_call`` MCP tools."""
from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

httpx = pytest.importorskip("httpx")

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools


API_BASE = "https://api.staging.servonaut.dev"
MCP_BASE = "https://mcp.staging.servonaut.dev"


def _run(coro):
    return asyncio.run(coro)


def _make_tools(auth_service):
    config = AppConfig(mcp=MCPConfig(guard_level=GuardLevel.STANDARD))
    cm = MagicMock()
    cm.get.return_value = config
    audit = MagicMock()
    audit.log = MagicMock()
    return ServonautTools(
        config_manager=cm,
        aws_service=MagicMock(),
        custom_server_service=MagicMock(),
        cache_service=MagicMock(),
        ssh_service=MagicMock(),
        connection_service=MagicMock(),
        scp_service=MagicMock(),
        guard=CommandGuard(config.mcp),
        audit=audit,
        auth_service=auth_service,
    ), audit


def _authed_stub():
    svc = MagicMock()
    svc.is_authenticated = True
    svc.access_token = "tok"
    svc.plan = "solo"
    svc._token = SimpleNamespace(
        access_token="tok", refresh_token="r",
        expires_at=time.time() + 3600, email="a@b.c", plan="solo",
    )
    svc.refresh_token = AsyncMock(return_value=True)
    return svc


def _install_transport(monkeypatch, handler):
    real = httpx.AsyncClient

    class _Patched(real):
        def __init__(self, *a, **kw):
            kw.pop("transport", None)
            super().__init__(*a, transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _Patched)


@pytest.fixture(autouse=True)
def _bases(monkeypatch):
    monkeypatch.setenv("SERVONAUT_API_URL", API_BASE)
    monkeypatch.setenv("SERVONAUT_MCP_URL", MCP_BASE)


# ---------------------------------------------------------------------------
# relay_status
# ---------------------------------------------------------------------------

class TestRelayStatus:
    def test_unwraps_backend_body(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/cli/status"
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"connected": True, "client_ids": ["host-ab"]},
            )
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.relay_status()))
        assert result == {"connected": True, "client_ids": ["host-ab"]}

    def test_backend_error_propagates_envelope(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("dns boom", request=request)
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.relay_status()))
        assert result["error"]["code"] == "network_error"

    def test_non_object_body_returns_structured_error(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json=[1, 2, 3],
            )
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.relay_status()))
        assert result["error"]["code"] == "unexpected_response"


# ---------------------------------------------------------------------------
# mcp_tool_call
# ---------------------------------------------------------------------------

class TestMcpToolCall:
    def test_posts_json_rpc_envelope_to_mcp_host(self, monkeypatch):
        captured = {"url": None, "body": None, "auth": None}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["body"] = json.loads(request.content)
            captured["auth"] = request.headers.get("authorization")
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"jsonrpc": "2.0", "id": captured["body"]["id"],
                      "result": {"content": [{"type": "text", "text": "ok"}]}},
            )
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("cost_report", {"scope": "month"})))

        assert captured["url"] == f"{MCP_BASE}/mcp/message"
        assert captured["auth"] == "Bearer tok"
        assert captured["body"]["jsonrpc"] == "2.0"
        assert captured["body"]["method"] == "tools/call"
        assert captured["body"]["params"] == {"name": "cost_report",
                                              "arguments": {"scope": "month"}}
        assert isinstance(captured["body"]["id"], str) and captured["body"]["id"]

        assert result["status"] == 200
        assert result["response"]["result"] == {"content": [{"type": "text", "text": "ok"}]}

    def test_none_arguments_becomes_empty_object(self, monkeypatch):
        captured = {"body": None}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"jsonrpc": "2.0", "id": captured["body"]["id"], "result": {}},
            )
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())

        _run(tools.mcp_tool_call("list_tools"))
        assert captured["body"]["params"]["arguments"] == {}

    def test_401_triggers_refresh_and_retry(self, monkeypatch):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(
                    401, headers={"Content-Type": "application/json"},
                    json={"error": "expired"},
                )
            assert request.headers["authorization"] == "Bearer REFRESHED"
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"jsonrpc": "2.0", "id": "x", "result": {}},
            )
        _install_transport(monkeypatch, handler)

        svc = _authed_stub()
        async def _refresh():
            svc.access_token = "REFRESHED"
            return True
        svc.refresh_token = AsyncMock(side_effect=_refresh)

        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.mcp_tool_call("ping")))
        assert calls["n"] == 2
        assert result["status"] == 200
        svc.refresh_token.assert_awaited_once()

    def test_not_logged_in(self):
        svc = MagicMock()
        svc.is_authenticated = False
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.mcp_tool_call("deploy")))
        assert result["error"]["code"] == "not_logged_in"

    def test_timeout_returns_structured_error(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("too slow", request=request)
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())
        result = json.loads(_run(tools.mcp_tool_call("slow")))
        assert result["error"]["code"] == "timeout"

    def test_audit_entry_recorded(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"jsonrpc": "2.0", "id": "x", "result": {}},
            )
        _install_transport(monkeypatch, handler)
        tools, audit = _make_tools(auth_service=_authed_stub())
        _run(tools.mcp_tool_call("cost_report"))
        audit.log.assert_called_once()
        args = audit.log.call_args.args
        assert args[0] == "mcp_tool_call"
        assert args[1]["name"] == "cost_report"
        assert args[1]["has_arguments"] is False
        assert args[1]["status"] == 200
        assert args[3] is True
