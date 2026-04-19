"""Tests for the MCP relay_reconnect tool.

The tool consults ``/api/cli/status`` (through ``api_request``) before touching
the local listener, so we mock both the backend via httpx MockTransport and
the ``_relay_reconnect`` helper in ``servonaut.main``.
"""
from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

httpx = pytest.importorskip("httpx")

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools


BASE_URL = "https://staging.servonaut.dev"


def _run(coro):
    return asyncio.run(coro)


def _make_tools(auth_service):
    config = AppConfig(mcp=MCPConfig(guard_level=GuardLevel.STANDARD))
    cm = MagicMock()
    cm.get.return_value = config
    audit = MagicMock()
    audit.log = MagicMock()
    tools = ServonautTools(
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
    )
    return tools, audit


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
def _base_url(monkeypatch):
    monkeypatch.setenv("SERVONAUT_API_URL", BASE_URL)


class TestHealthyNoop:
    def test_backend_reports_connected_no_restart(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"connected": True, "client_ids": ["host-ab"]},
            )
        _install_transport(monkeypatch, handler)

        tools, audit = _make_tools(auth_service=_authed_stub())
        with patch("servonaut.main._relay_reconnect") as reconnect:
            result = json.loads(_run(tools.relay_reconnect()))
        reconnect.assert_not_called()
        assert result["action"] == "none"
        assert result["backend"]["connected"] is True
        assert audit.log.call_args.args[0] == "relay_reconnect"


class TestForceRestart:
    def test_force_skips_backend_check(self, monkeypatch):
        called = {"status_hits": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            called["status_hits"] += 1
            return httpx.Response(200, json={"connected": True})
        _install_transport(monkeypatch, handler)

        tools, _ = _make_tools(auth_service=_authed_stub())
        with patch("servonaut.main._relay_reconnect") as reconnect:
            result = json.loads(_run(tools.relay_reconnect(force=True)))
        reconnect.assert_called_once_with()
        assert result["action"] == "restarted"
        assert called["status_hits"] == 0


class TestStaleRestart:
    def test_backend_disconnected_triggers_restart(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"connected": False, "client_ids": []},
            )
        _install_transport(monkeypatch, handler)

        tools, _ = _make_tools(auth_service=_authed_stub())
        with patch("servonaut.main._relay_reconnect") as reconnect:
            result = json.loads(_run(tools.relay_reconnect()))
        reconnect.assert_called_once_with()
        assert result["action"] == "restarted"
        assert result["backend_connected_before"] is False


class TestFailures:
    def test_reconnect_helper_raising_is_returned_as_error(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"connected": False})
        _install_transport(monkeypatch, handler)

        tools, audit = _make_tools(auth_service=_authed_stub())
        with patch("servonaut.main._relay_reconnect",
                   side_effect=RuntimeError("boom")):
            result = json.loads(_run(tools.relay_reconnect()))
        assert result["error"]["code"] == "reconnect_failed"
        # Audit must record the failure.
        assert audit.log.call_args.args[3] is False

    def test_status_check_auth_error_still_restarts_on_force(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "nope"})
        _install_transport(monkeypatch, handler)

        tools, _ = _make_tools(auth_service=_authed_stub())
        # Without force: status call returns 401, body dict lacks `connected`,
        # so the tool treats it as "unknown" and proceeds to restart.
        with patch("servonaut.main._relay_reconnect") as reconnect:
            result = json.loads(_run(tools.relay_reconnect()))
        reconnect.assert_called_once_with()
        assert result["action"] == "restarted"
        assert result["backend_connected_before"] is None
