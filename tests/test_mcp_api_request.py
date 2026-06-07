"""Tests for the MCP api_request tool.

Covers the safety envelope that protects the OAuth bearer when external
agents invoke backend endpoints through the CLI:

* happy-path GET/POST with JSON;
* rejection of non-relative paths and unsupported methods;
* stripping of user-supplied Authorization headers;
* response size cap;
* one-shot 401 → refresh → retry;
* CLI-side sliding-window rate limit.
"""
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
from servonaut.mcp import tools as tools_module
from servonaut.mcp.tools import ServonautTools


BASE_URL = "https://staging.example.com"


def _run(coro):
    return asyncio.run(coro)


def _make_tools(auth_service):
    config = AppConfig(mcp=MCPConfig(guard_level=GuardLevel.STANDARD))
    config_manager = MagicMock()
    config_manager.get.return_value = config
    audit = MagicMock()
    audit.log = MagicMock()
    tools = ServonautTools(
        config_manager=config_manager,
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


def _authed_stub(access_token: str = "bearer-token-abc", refresh_ok: bool = True):
    svc = MagicMock()
    svc.is_authenticated = True
    svc.access_token = access_token
    svc.plan = "solo"
    svc._token = SimpleNamespace(
        access_token=access_token, refresh_token="r",
        expires_at=time.time() + 3600, email="a@b.c", plan="solo",
    )
    svc.refresh_token = AsyncMock(return_value=refresh_ok)
    return svc


class _Capture:
    """Collects the last httpx.Request observed by the mock transport."""
    def __init__(self):
        self.requests: list[httpx.Request] = []


def _install_transport(monkeypatch, handler):
    """Replace httpx.AsyncClient with one backed by a MockTransport."""
    real_client = httpx.AsyncClient

    class _PatchedClient(real_client):
        def __init__(self, *args, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(*args, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _PatchedClient)


@pytest.fixture(autouse=True)
def _base_url(monkeypatch):
    monkeypatch.setenv("SERVONAUT_API_URL", BASE_URL)


class TestHappyPath:
    def test_get_returns_status_headers_and_parsed_body(self, monkeypatch):
        captured = _Capture()

        def handler(request: httpx.Request) -> httpx.Response:
            captured.requests.append(request)
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"connected": True, "client_ids": ["host-abc"]},
            )
        _install_transport(monkeypatch, handler)

        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)

        raw = _run(tools.api_request("GET", "/api/cli/status"))
        result = json.loads(raw)

        assert result["status"] == 200
        assert result["body"] == {"connected": True, "client_ids": ["host-abc"]}
        assert "authorization" not in {k.lower() for k in result["headers"]}
        # The real request carried the bearer.
        req = captured.requests[-1]
        assert req.headers["authorization"] == "Bearer bearer-token-abc"
        assert req.url.path == "/api/cli/status"

    def test_post_encodes_body_as_json(self, monkeypatch):
        captured = _Capture()

        def handler(request: httpx.Request) -> httpx.Response:
            captured.requests.append(request)
            return httpx.Response(204, headers={"Content-Type": "application/json"})
        _install_transport(monkeypatch, handler)

        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)

        _run(tools.api_request(
            "POST", "/api/cli/heartbeat",
            body={"client_id": "host-abc-ef01"},
        ))
        req = captured.requests[-1]
        assert req.method == "POST"
        assert json.loads(req.content) == {"client_id": "host-abc-ef01"}
        assert req.headers["content-type"].startswith("application/json")


class TestValidation:
    def test_reject_absolute_url(self):
        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(
            tools.api_request("GET", "https://evil.example.com/leak")
        ))
        assert result["error"]["code"] == "invalid_path"

    def test_reject_missing_leading_slash(self):
        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("GET", "api/cli/status")))
        assert result["error"]["code"] == "invalid_path"

    def test_reject_unknown_method(self):
        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("TRACE", "/api/x")))
        assert result["error"]["code"] == "invalid_method"

    def test_reject_when_not_logged_in(self):
        svc = MagicMock()
        svc.is_authenticated = False
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("GET", "/api/cli/status")))
        assert result["error"]["code"] == "not_logged_in"


class TestHeaderHandling:
    def test_user_supplied_authorization_is_dropped(self, monkeypatch):
        captured = _Capture()

        def handler(request: httpx.Request) -> httpx.Response:
            captured.requests.append(request)
            return httpx.Response(200, headers={"Content-Type": "application/json"}, json={})
        _install_transport(monkeypatch, handler)

        svc = _authed_stub(access_token="REAL-TOKEN")
        tools, _ = _make_tools(auth_service=svc)
        _run(tools.api_request(
            "GET", "/api/cli/status",
            headers={
                "Authorization": "Bearer FAKE-ATTACKER-TOKEN",
                "X-Evil": "please-log-me",
                "Cookie": "session=abc",
                "Accept-Language": "en-CA",
            },
        ))
        req = captured.requests[-1]
        assert req.headers["authorization"] == "Bearer REAL-TOKEN"
        assert "x-evil" not in {k.lower() for k in req.headers}
        assert "cookie" not in {k.lower() for k in req.headers}
        assert req.headers.get("accept-language") == "en-CA"

    def test_response_sensitive_headers_stripped(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers=[
                    ("Content-Type", "application/json"),
                    ("Set-Cookie", "leak=yep"),
                    ("WWW-Authenticate", "Bearer realm=api"),
                ],
                json={},
            )
        _install_transport(monkeypatch, handler)
        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("GET", "/api/cli/status")))
        lowered = {k.lower() for k in result["headers"]}
        assert "set-cookie" not in lowered
        assert "www-authenticate" not in lowered


class TestResponseSizeCap:
    def test_response_over_one_mib_rejected(self, monkeypatch):
        big_body = "x" * (tools_module._MAX_RESPONSE_BYTES + 1)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                content=big_body.encode("utf-8"),
            )
        _install_transport(monkeypatch, handler)
        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("GET", "/api/huge")))
        assert result["error"]["code"] == "response_too_large"


class TestRefreshOn401:
    def test_401_triggers_single_refresh_and_retry(self, monkeypatch):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            if calls["count"] == 1:
                return httpx.Response(
                    401, headers={"Content-Type": "application/json"},
                    json={"error": "expired"},
                )
            assert request.headers["authorization"] == "Bearer REFRESHED"
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"ok": True},
            )
        _install_transport(monkeypatch, handler)

        svc = _authed_stub(access_token="STALE")
        async def _refresh():
            svc.access_token = "REFRESHED"
            return True
        svc.refresh_token = AsyncMock(side_effect=_refresh)

        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("GET", "/api/cli/status")))

        assert calls["count"] == 2
        assert result["status"] == 200
        assert result["body"] == {"ok": True}
        svc.refresh_token.assert_awaited_once()

    def test_401_without_refresh_returned_as_is(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401, headers={"Content-Type": "application/json"},
                json={"error": "nope"},
            )
        _install_transport(monkeypatch, handler)

        svc = _authed_stub()
        svc.refresh_token = AsyncMock(return_value=False)
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("GET", "/api/cli/status")))
        assert result["status"] == 401
        assert result["body"] == {"error": "nope"}

    def test_401_on_oauth_endpoint_skips_refresh_loop(self, monkeypatch):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(
                401, headers={"Content-Type": "application/json"},
                json={"error": "bad_grant"},
            )
        _install_transport(monkeypatch, handler)

        svc = _authed_stub()
        svc.refresh_token = AsyncMock(return_value=True)
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("POST", "/api/oauth/token", body={})))
        assert result["status"] == 401
        assert calls["count"] == 1
        svc.refresh_token.assert_not_awaited()


class TestTransportErrors:
    def test_timeout_returns_structured_error(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("too slow", request=request)
        _install_transport(monkeypatch, handler)
        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("GET", "/api/slow")))
        assert result["error"]["code"] == "timeout"

    def test_network_error_returns_structured_error(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("dns boom", request=request)
        _install_transport(monkeypatch, handler)
        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.api_request("GET", "/api/boom")))
        assert result["error"]["code"] == "network_error"


class TestRateLimit:
    def test_rate_limit_kicks_in_after_30_calls(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json={},
            )
        _install_transport(monkeypatch, handler)

        svc = _authed_stub()
        tools, _ = _make_tools(auth_service=svc)
        # Burn through the full window.
        for _ in range(tools_module._API_REQUEST_MAX_PER_WINDOW):
            result = json.loads(_run(tools.api_request("GET", "/api/cli/status")))
            assert result["status"] == 200
        # 31st call within the same window must be rejected client-side.
        blocked = json.loads(_run(tools.api_request("GET", "/api/cli/status")))
        assert blocked["error"]["code"] == "cli_rate_limited"


class TestAudit:
    def test_audit_entry_written_on_success(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, json={},
            )
        _install_transport(monkeypatch, handler)
        svc = _authed_stub()
        tools, audit = _make_tools(auth_service=svc)
        _run(tools.api_request("GET", "/api/cli/status"))
        audit.log.assert_called_once()
        call = audit.log.call_args
        args = call.args
        assert args[0] == "api_request"
        assert args[1]["method"] == "GET"
        assert args[1]["path"] == "/api/cli/status"
        assert args[1]["status"] == 200
        assert args[3] is True

    def test_audit_entry_written_on_error(self):
        svc = _authed_stub()
        tools, audit = _make_tools(auth_service=svc)
        _run(tools.api_request("GET", "bad-path"))
        audit.log.assert_called_once()
        args = audit.log.call_args.args
        assert args[0] == "api_request"
        assert args[1]["error_code"] == "invalid_path"
        assert args[3] is False
