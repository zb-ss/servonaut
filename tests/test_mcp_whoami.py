"""Tests for the MCP whoami tool.

Key invariants:
* the OAuth access token is NEVER present in the returned payload;
* logged-out CLI returns a clean ``{"logged_in": false}`` without raising;
* expired tokens still return, so agents can observe the state and decide
  whether to trigger a refresh via ``api_request``.
"""
from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools


def _run(coro):
    return asyncio.run(coro)


def _make_tools(auth_service):
    config = AppConfig(mcp=MCPConfig(guard_level=GuardLevel.READONLY))
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


def _authenticated_stub(
    *,
    email: str = "user@example.com",
    plan: str = "solo",
    expires_at: float,
    access_token: str = "SECRET-ACCESS-TOKEN",
):
    token = SimpleNamespace(
        access_token=access_token,
        refresh_token="refresh",
        expires_at=expires_at,
        plan=plan,
        email=email,
    )
    svc = MagicMock()
    svc.is_authenticated = True
    svc.plan = plan
    svc.access_token = access_token
    svc._token = token
    return svc


class TestWhoamiLoggedOut:
    def test_returns_logged_in_false_when_auth_service_missing(self, monkeypatch):
        tools, _ = _make_tools(auth_service=None)
        result = json.loads(_run(tools.whoami()))
        assert result == {"logged_in": False}

    def test_returns_logged_in_false_when_not_authenticated(self):
        svc = MagicMock()
        svc.is_authenticated = False
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.whoami()))
        assert result == {"logged_in": False}


class TestWhoamiLoggedIn:
    def test_returns_expected_fields_without_leaking_token(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_API_URL", "https://staging.servonaut.dev")
        expires = time.time() + 3600
        svc = _authenticated_stub(
            email="zashboy@gmail.com", plan="solo", expires_at=expires
        )
        tools, _ = _make_tools(auth_service=svc)

        raw = _run(tools.whoami())
        result = json.loads(raw)

        assert result["logged_in"] is True
        assert result["email"] == "zashboy@gmail.com"
        assert result["plan"] == "solo"
        assert result["base_url"] == "https://staging.servonaut.dev"
        assert result["token_expires_in_seconds"] > 3500
        assert result["token_expires_at"].startswith(
            time.strftime("%Y", time.gmtime(expires))
        )
        # Bearer leak guard — neither key nor value should surface.
        assert "access_token" not in result
        assert "SECRET-ACCESS-TOKEN" not in raw

    def test_expired_token_returns_negative_expires_in(self, monkeypatch):
        monkeypatch.setenv("SERVONAUT_API_URL", "https://staging.servonaut.dev")
        expires = time.time() - 600
        svc = _authenticated_stub(
            email="expired@example.com", plan="free", expires_at=expires
        )
        # Even though the token is "expired" from the CLI's view, an agent
        # should still be able to read the state so it can trigger a refresh
        # via api_request. Force is_authenticated=True to simulate that the
        # agent asked mid-lifetime.
        tools, _ = _make_tools(auth_service=svc)

        result = json.loads(_run(tools.whoami()))
        assert result["logged_in"] is True
        assert result["token_expires_in_seconds"] < 0

    def test_audit_entry_recorded_on_success(self):
        svc = _authenticated_stub(
            email="a@b.c", plan="solo", expires_at=time.time() + 60
        )
        tools, audit = _make_tools(auth_service=svc)
        _run(tools.whoami())
        audit.log.assert_called_once()
        args, _kwargs = audit.log.call_args
        # (tool, args, result, allowed) positional form used elsewhere.
        assert args[0] == "whoami"
        assert args[3] is True

    def test_audit_entry_recorded_when_logged_out(self):
        tools, audit = _make_tools(auth_service=None)
        _run(tools.whoami())
        audit.log.assert_called_once()
        args, _kwargs = audit.log.call_args
        assert args[0] == "whoami"
        assert args[3] is True  # not an error, just a state report
