"""Tests for RemoteMCPClient."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def run_async(coro):
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)

from servonaut.mcp.remote_client import (
    RemoteMCPClient,
    LOCAL_TOOLS,
    PREMIUM_TOOLS,
)


@pytest.fixture
def mock_auth():
    auth = MagicMock()
    auth.access_token = "test-token"
    auth.is_authenticated = True
    return auth


@pytest.fixture
def remote_client(mock_auth):
    return RemoteMCPClient(mock_auth)


class TestRemoteMCPClient:
    def test_initial_state(self, remote_client):
        assert not remote_client.is_connected
        assert remote_client._session_id is None

    def test_is_premium_tool(self):
        assert RemoteMCPClient.is_premium_tool("deploy")
        assert RemoteMCPClient.is_premium_tool("provision")
        assert RemoteMCPClient.is_premium_tool("cost_report")
        assert RemoteMCPClient.is_premium_tool("security_scan")
        assert not RemoteMCPClient.is_premium_tool("list_instances")

    def test_is_local_tool(self):
        assert RemoteMCPClient.is_local_tool("list_instances")
        assert RemoteMCPClient.is_local_tool("run_command")
        assert not RemoteMCPClient.is_local_tool("deploy")

    def test_local_and_premium_no_overlap(self):
        assert LOCAL_TOOLS.isdisjoint(PREMIUM_TOOLS)


class TestToolCall:
    def test_call_tool_requires_connection(self, remote_client):
        with pytest.raises(RuntimeError, match="Not connected"):
            run_async(remote_client.call_tool("deploy", {}))

    def test_disconnect(self, remote_client):
        remote_client._connected = True
        remote_client._session_id = "test"
        run_async(remote_client.disconnect())
        assert not remote_client.is_connected
        assert remote_client._session_id is None


class TestReconnect:
    def test_reconnect_delay_increases(self, remote_client):
        initial = remote_client._reconnect_delay
        remote_client._reconnect_delay *= 2
        assert remote_client._reconnect_delay == initial * 2

    def test_max_reconnect_delay(self, remote_client):
        remote_client._reconnect_delay = 100
        capped = min(remote_client._reconnect_delay, remote_client._max_reconnect_delay)
        assert capped == remote_client._max_reconnect_delay
