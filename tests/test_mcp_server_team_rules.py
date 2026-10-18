"""The MCP server fetches the teams' agent rules at start and keeps them fresh."""
from __future__ import annotations

import asyncio
import contextlib
from types import SimpleNamespace

import pytest


def test_the_rules_are_fetched_at_start_and_the_schedule_stops_at_exit(monkeypatch):
    pytest.importorskip("mcp")
    from servonaut.mcp import server as mcp_server

    events = []

    class Refresher:
        async def refresh(self, teams=None):
            events.append("refresh")
            return []

        def close(self):
            events.append("close")

    class Server:
        servonaut_tools = SimpleNamespace(team_policy=Refresher(), _vault_runtime=None)

        def create_initialization_options(self):
            return None

        async def run(self, read_stream, write_stream, options):
            await asyncio.sleep(0)  # the first fetch starts meanwhile
            events.append("served")

    @contextlib.asynccontextmanager
    async def stdio_server():
        yield None, None

    monkeypatch.setattr(mcp_server, "create_mcp_server", Server)
    monkeypatch.setattr("mcp.server.stdio.stdio_server", stdio_server)
    asyncio.run(mcp_server.run_server())

    assert events == ["refresh", "served", "close"]
