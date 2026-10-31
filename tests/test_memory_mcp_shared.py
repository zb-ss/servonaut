"""get_server_memory falls back to what a team shares with the user."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

from servonaut.services.memory.shared_view import SharedMemory
from tests.test_memory_mcp_tools import _make_memory_service, _make_tools

SHARED_ROW = {
    "id": "share-1", "name": "web-1", "provider": "Team Team A", "is_shared": True,
    "team_slug": "team-a", "team_name": "Team A", "instance_id": "i-owner-1",
    "public_ip": "9.9.9.9", "port": 22, "state": "shared",
}


def _shared() -> SharedMemory:
    return SharedMemory("team-a", "Team A", {
        "os": {"observed": {"distro": "Debian 12"}, "declared": {},
               "probed_at": "2026-10-20T08:00:00+00:00"},
    })


def _tools(reader, *, local=None):
    service = _make_memory_service(get_all_modules_return=local if local is not None else {})
    tools = _make_tools(memory_service=service, instance_to_find=dict(SHARED_ROW))
    tools._shared_memory_reader = reader
    tools._shared_server_rows = AsyncMock(return_value=[dict(SHARED_ROW)])
    tools._memory_target = AsyncMock(side_effect=lambda row: row)
    return tools


def test_a_member_gets_the_shared_os_module_with_its_source():
    reader = MagicMock()
    reader.read = AsyncMock(return_value=_shared())
    out = asyncio.run(_tools(reader).get_server_memory("web-1", format="full"))
    data = json.loads(out)
    assert data["modules"]["os"]["observed"] == {"distro": "Debian 12"}
    assert data["source"] == "Shared by Team A, probed 2026-10-20 08:00"
    reader.read.assert_awaited_once_with("team-a", "Team A", "i-owner-1")


def test_the_summary_says_where_it_comes_from():
    reader = MagicMock()
    reader.read = AsyncMock(return_value=_shared())
    out = asyncio.run(_tools(reader).get_server_memory("web-1"))
    assert "Shared by Team A" in out and "distro: Debian 12" in out


def test_without_a_grant_the_answer_is_the_usual_missing_error():
    reader = MagicMock()
    reader.read = AsyncMock(return_value=None)
    out = asyncio.run(_tools(reader).get_server_memory("web-1"))
    assert json.loads(out)["error"]["code"] == "missing"


def test_a_failing_read_is_nothing_shared():
    reader = MagicMock()
    reader.read = AsyncMock(side_effect=RuntimeError("offline"))
    out = asyncio.run(_tools(reader).get_server_memory("web-1"))
    assert json.loads(out)["error"]["code"] == "missing"


def test_a_newer_local_module_keeps_the_local_answer():
    reader = MagicMock()
    reader.read = AsyncMock(return_value=_shared())
    local = {"os": {"observed": {"distro": "Local 13"}, "probed_at": "2030-01-01T00:00:00+00:00"}}
    out = asyncio.run(_tools(reader, local=local).get_server_memory("web-1", format="full"))
    assert json.loads(out)["modules"]["os"]["observed"] == {"distro": "Local 13"}
