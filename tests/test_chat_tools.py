"""Tests for the ChatToolExecutor adapter.

The adapter delegates to ``ServonautTools``; ServonautTools' own behaviour
(instance merging, SSH dispatch, OVH lookup, etc.) is covered separately in
``test_mcp_tools.py``. These tests focus on the adapter itself:

* tool-definition filtering (chat_exposed + guard_level);
* dispatch to the underlying tools instance;
* CommandGuard enforcement at both tool and command level;
* chat-specific output truncation;
* exception capture.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.services.chat_tools import (
    CHAT_TOOLS,
    MAX_OUTPUT_CHARS,
    MAX_OUTPUT_LINES,
    ChatToolExecutor,
    _truncate_for_chat,
)
from servonaut.mcp.tool_schemas import TOOL_SCHEMAS


def _run(coro):
    return asyncio.run(coro)


def _fake_tools():
    """Build a stand-in ServonautTools with async methods that record calls."""
    cm = MagicMock()
    cm.get.return_value = AppConfig(mcp=MCPConfig())
    tools = MagicMock()
    tools.config_manager = cm
    # Every chat-exposed tool name gets an AsyncMock so execute() can dispatch.
    for name, spec in TOOL_SCHEMAS.items():
        if spec.get("chat_exposed"):
            setattr(tools, name, AsyncMock(return_value=f"{name}: ok"))
    return tools


def _make_executor(guard_level: str = "standard", tools=None):
    return ChatToolExecutor(tools=tools or _fake_tools(), guard_level=guard_level)


# ---------------------------------------------------------------------------
# CHAT_TOOLS definitions
# ---------------------------------------------------------------------------

class TestToolDefinitions:
    def test_only_chat_exposed_tools_surfaced(self):
        chat_names = {t["name"] for t in CHAT_TOOLS}
        expected = {n for n, spec in TOOL_SCHEMAS.items() if spec.get("chat_exposed")}
        assert chat_names == expected

    def test_every_tool_has_required_fields(self):
        for tool in CHAT_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "parameters" in tool
            assert tool["parameters"].get("type") == "object"

    def test_standard_guard_lets_list_and_readonly_tools_through(self):
        executor = _make_executor("standard")
        names = [t["name"] for t in executor.get_tool_definitions()]
        assert "list_instances" in names
        assert "check_status" in names
        assert "run_command" in names
        assert "get_logs" in names
        assert "whoami" in names

    def test_readonly_guard_excludes_run_and_logs(self):
        executor = _make_executor("readonly")
        names = [t["name"] for t in executor.get_tool_definitions()]
        assert "list_instances" in names
        assert "check_status" in names
        assert "run_command" not in names
        assert "get_logs" not in names


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

class TestDispatch:
    def test_execute_delegates_to_tools_method(self):
        tools = _fake_tools()
        executor = _make_executor(tools=tools)
        result = _run(executor.execute("list_instances", {"region": "us-east-1"}))
        tools.list_instances.assert_awaited_once_with(region="us-east-1")
        assert result == "list_instances: ok"

    def test_execute_unknown_tool_rejected(self):
        tools = _fake_tools()
        executor = _make_executor(tools=tools)
        result = _run(executor.execute("definitely_not_a_tool", {}))
        assert "Unknown tool" in result

    def test_execute_not_chat_exposed_tool_rejected_even_if_method_exists(self):
        """``transfer_file`` exists on ServonautTools but is chat_exposed=False.
        The adapter must refuse to dispatch it even though the method exists.
        """
        tools = _fake_tools()
        tools.transfer_file = AsyncMock(return_value="should not be reached")
        executor = _make_executor(tools=tools)
        result = _run(executor.execute("transfer_file", {
            "instance_id": "x", "local_path": "/a",
            "remote_path": "/b", "direction": "upload",
        }))
        assert "Unknown tool" in result
        tools.transfer_file.assert_not_awaited()

    def test_handler_exception_returned_as_string(self):
        tools = _fake_tools()
        tools.run_command = AsyncMock(side_effect=RuntimeError("kaboom"))
        executor = _make_executor(tools=tools)
        result = _run(executor.execute("run_command", {
            "instance_id": "i-1", "command": "ls",
        }))
        assert "Error executing run_command" in result
        assert "kaboom" in result


# ---------------------------------------------------------------------------
# Guard enforcement
# ---------------------------------------------------------------------------

class TestGuardEnforcement:
    def test_readonly_blocks_run_command(self):
        tools = _fake_tools()
        executor = _make_executor("readonly", tools=tools)
        result = _run(executor.execute("run_command", {
            "instance_id": "i-1", "command": "ls",
        }))
        assert "Blocked" in result
        tools.run_command.assert_not_awaited()

    def test_standard_blocks_blocklisted_command(self):
        tools = _fake_tools()
        executor = _make_executor("standard", tools=tools)
        result = _run(executor.execute("run_command", {
            "instance_id": "i-1", "command": "rm -rf /",
        }))
        assert "Blocked" in result
        tools.run_command.assert_not_awaited()

    def test_standard_allows_whitelisted_command(self):
        tools = _fake_tools()
        tools.run_command = AsyncMock(return_value="total 0\ndrwxr-xr-x 2 .")
        executor = _make_executor("standard", tools=tools)
        result = _run(executor.execute("run_command", {
            "instance_id": "i-1", "command": "ls -la",
        }))
        tools.run_command.assert_awaited_once_with(instance_id="i-1", command="ls -la")
        assert "drwxr-xr-x" in result


# ---------------------------------------------------------------------------
# Output truncation (chat-specific)
# ---------------------------------------------------------------------------

class TestTruncation:
    def test_long_output_line_capped(self):
        tools = _fake_tools()
        big = "\n".join(f"line {i}" for i in range(500))
        tools.run_command = AsyncMock(return_value=big)
        executor = _make_executor("standard", tools=tools)
        result = _run(executor.execute("run_command", {
            "instance_id": "i-1", "command": "ls",
        }))
        assert "truncated, 500 total lines" in result
        assert result.count("\n") <= MAX_OUTPUT_LINES + 2

    def test_long_output_char_capped(self):
        tools = _fake_tools()
        tools.run_command = AsyncMock(return_value="x" * (MAX_OUTPUT_CHARS + 500))
        executor = _make_executor("standard", tools=tools)
        result = _run(executor.execute("run_command", {
            "instance_id": "i-1", "command": "ls",
        }))
        assert "truncated at character limit" in result
        assert len(result) <= MAX_OUTPUT_CHARS + 100

    def test_short_output_untouched(self):
        assert _truncate_for_chat("hello") == "hello"
        assert _truncate_for_chat("") == ""


# ---------------------------------------------------------------------------
# Back-compat constructor (legacy kwargs still build a ServonautTools)
# ---------------------------------------------------------------------------

class TestLegacyKwargs:
    def test_builds_servonauttools_from_services(self):
        """Older call sites passed aws_service/ssh_service/etc. directly.
        Keep that path working so nothing breaks during migration."""
        cm = MagicMock()
        cm.get.return_value = AppConfig(mcp=MCPConfig())
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        custom = MagicMock()
        custom.list_as_instances.return_value = []
        executor = ChatToolExecutor(
            config_manager=cm,
            aws_service=aws,
            cache_service=MagicMock(),
            ssh_service=MagicMock(),
            connection_service=MagicMock(),
            custom_server_service=custom,
            ovh_service=None,
        )
        names = [t["name"] for t in executor.get_tool_definitions()]
        assert "list_instances" in names
        # The real formatter produces a table with Name/ID/State headers.
        result = _run(executor.execute("list_instances", {}))
        assert "Name" in result and "State" in result

    def test_raises_when_neither_tools_nor_config_manager_given(self):
        with pytest.raises(ValueError, match="config_manager"):
            ChatToolExecutor()
