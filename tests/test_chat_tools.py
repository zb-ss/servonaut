"""Tests for ChatToolExecutor — tool definitions, guard enforcement, execution."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.services.chat_tools import CHAT_TOOLS, ChatToolExecutor


def _run(coro):
    return asyncio.run(coro)


def _make_executor(guard_level: str = "standard") -> ChatToolExecutor:
    """Build a ChatToolExecutor with mocked services."""
    mcp_config = MCPConfig()
    config = AppConfig(mcp=mcp_config)
    config_manager = MagicMock()
    config_manager.get.return_value = config

    aws_service = MagicMock()
    aws_service.fetch_instances_cached = AsyncMock(return_value=[
        {
            "id": "i-abc123",
            "name": "web-server-1",
            "type": "t3.micro",
            "state": "running",
            "public_ip": "1.2.3.4",
            "private_ip": "10.0.0.1",
            "region": "us-east-1",
            "key_name": "my-key",
        },
        {
            "id": "i-def456",
            "name": "db-server-1",
            "type": "t3.large",
            "state": "stopped",
            "public_ip": None,
            "private_ip": "10.0.0.2",
            "region": "us-west-2",
            "key_name": "db-key",
        },
    ])

    cache_service = MagicMock()
    ssh_service = MagicMock()
    ssh_service.get_key_path.return_value = "/home/user/.ssh/my-key.pem"
    ssh_service.discover_key.return_value = None
    ssh_service.build_ssh_command.return_value = ["ssh", "user@1.2.3.4", "uptime"]

    connection_service = MagicMock()
    connection_service.resolve_profile.return_value = None
    connection_service.get_target_host.return_value = "1.2.3.4"
    connection_service.get_proxy_args.return_value = []

    return ChatToolExecutor(
        config_manager=config_manager,
        aws_service=aws_service,
        cache_service=cache_service,
        ssh_service=ssh_service,
        connection_service=connection_service,
        guard_level=guard_level,
    )


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

class TestToolDefinitions:
    def test_chat_tools_count(self):
        assert len(CHAT_TOOLS) == 5

    def test_all_tools_have_required_fields(self):
        for tool in CHAT_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "parameters" in tool
            assert tool["parameters"]["type"] == "object"

    def test_tool_names(self):
        names = {t["name"] for t in CHAT_TOOLS}
        assert names == {
            "list_instances", "check_status", "get_server_info",
            "run_command", "get_logs",
        }


# ---------------------------------------------------------------------------
# Guard enforcement
# ---------------------------------------------------------------------------

class TestGuardEnforcement:
    def test_standard_mode_includes_readonly_and_standard_tools(self):
        executor = _make_executor("standard")
        tools = executor.get_tool_definitions()
        names = {t["name"] for t in tools}
        assert "list_instances" in names
        assert "check_status" in names
        assert "get_server_info" in names
        assert "run_command" in names
        assert "get_logs" in names

    def test_readonly_mode_excludes_run_and_logs(self):
        executor = _make_executor("readonly")
        tools = executor.get_tool_definitions()
        names = {t["name"] for t in tools}
        assert "list_instances" in names
        assert "check_status" in names
        assert "get_server_info" in names
        assert "run_command" not in names
        assert "get_logs" not in names

    def test_execute_blocked_tool_in_readonly(self):
        executor = _make_executor("readonly")
        result = _run(executor.execute("run_command", {"instance_id": "i-abc", "command": "ls"}))
        assert "Blocked" in result

    def test_execute_blocked_command_in_standard(self):
        executor = _make_executor("standard")
        result = _run(executor.execute("run_command", {
            "instance_id": "i-abc123",
            "command": "rm -rf /",
        }))
        assert "Blocked" in result

    def test_execute_allowed_command_in_standard(self):
        executor = _make_executor("standard")
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"file1.txt\nfile2.txt\n", b""))
            mock_exec.return_value = mock_proc

            result = _run(executor.execute("run_command", {
                "instance_id": "i-abc123",
                "command": "ls /tmp",
            }))
        assert "file1.txt" in result


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

class TestToolExecution:
    def test_list_instances(self):
        executor = _make_executor()
        result = _run(executor.execute("list_instances", {}))
        assert "web-server-1" in result
        assert "db-server-1" in result

    def test_list_instances_with_region_filter(self):
        executor = _make_executor()
        result = _run(executor.execute("list_instances", {"region": "us-east-1"}))
        assert "web-server-1" in result
        assert "db-server-1" not in result

    def test_list_instances_with_state_filter(self):
        executor = _make_executor()
        result = _run(executor.execute("list_instances", {"state": "stopped"}))
        assert "web-server-1" not in result
        assert "db-server-1" in result

    def test_check_status_by_id(self):
        executor = _make_executor()
        result = _run(executor.execute("check_status", {"instance_id": "i-abc123"}))
        assert "web-server-1" in result
        assert "running" in result
        assert "1.2.3.4" in result

    def test_check_status_by_name(self):
        executor = _make_executor()
        result = _run(executor.execute("check_status", {"instance_id": "web-server-1"}))
        assert "i-abc123" in result

    def test_check_status_not_found(self):
        executor = _make_executor()
        result = _run(executor.execute("check_status", {"instance_id": "nonexistent"}))
        assert "not found" in result.lower()

    def test_check_status_missing_id(self):
        executor = _make_executor()
        result = _run(executor.execute("check_status", {}))
        assert "required" in result.lower()

    def test_unknown_tool(self):
        executor = _make_executor()
        result = _run(executor.execute("unknown_tool", {}))
        assert "Blocked" in result or "Unknown tool" in result

    def test_get_server_info(self):
        executor = _make_executor()
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(
                b"web-server-1\n 10:30:00 up 5 days\n", b""
            ))
            mock_exec.return_value = mock_proc

            result = _run(executor.execute("get_server_info", {"instance_id": "i-abc123"}))
        assert "web-server-1" in result

    def test_get_logs(self):
        executor = _make_executor()
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(
                b"Mar  1 10:00 syslog message\n", b""
            ))
            mock_exec.return_value = mock_proc

            result = _run(executor.execute("get_logs", {
                "instance_id": "i-abc123",
                "log_path": "/var/log/syslog",
                "lines": 50,
            }))
        assert "syslog message" in result

    def test_status_callback_called(self):
        executor = _make_executor()
        callback = MagicMock()
        result = _run(executor.execute("list_instances", {}, status_callback=callback))
        callback.assert_called()

    def test_ssh_timeout_handled(self):
        executor = _make_executor()
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_exec.return_value = mock_proc

            result = _run(executor.execute("run_command", {
                "instance_id": "i-abc123",
                "command": "ls",
            }))
        assert "timed out" in result.lower()

    def test_output_truncation(self):
        executor = _make_executor()
        # Generate output with 300 lines (exceeds MAX_OUTPUT_LINES=200)
        long_output = "\n".join(f"line {i}" for i in range(300))
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(long_output.encode(), b""))
            mock_exec.return_value = mock_proc

            result = _run(executor.execute("run_command", {
                "instance_id": "i-abc123",
                "command": "cat /var/log/big.log",
            }))
        assert "truncated" in result
        assert "300 total lines" in result
