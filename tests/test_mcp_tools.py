"""Tests for MCP tool implementations."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools


SAMPLE_CUSTOM_INSTANCES = [
    {
        "id": "custom-ovh-web",
        "name": "ovh-web",
        "type": "custom",
        "state": "unknown",
        "public_ip": "51.195.151.208",
        "private_ip": "51.195.151.208",
        "region": "OVH",
        "key_name": "~/.ssh/ovh.pem",
        "ssh_key": "~/.ssh/ovh.pem",
        "provider": "OVH",
        "group": "",
        "tags": {},
        "port": 2222,
        "username": "ubuntu",
        "is_custom": True,
    },
]

SAMPLE_INSTANCES = [
    {
        "id": "i-abc123",
        "name": "web-server-prod",
        "type": "t3.medium",
        "state": "running",
        "public_ip": "54.123.45.67",
        "private_ip": "10.0.1.100",
        "region": "us-east-1",
        "key_name": "prod-key",
    },
    {
        "id": "i-def456",
        "name": "api-server-staging",
        "type": "t3.small",
        "state": "stopped",
        "public_ip": None,
        "private_ip": "10.0.2.200",
        "region": "us-west-2",
        "key_name": "staging-key",
    },
]


def make_tools(guard_level=GuardLevel.STANDARD, instances=None, custom_instances=None, max_output_lines=500):
    if instances is None:
        instances = SAMPLE_INSTANCES

    config = AppConfig(mcp=MCPConfig(guard_level=guard_level, max_output_lines=max_output_lines))
    config_manager = MagicMock()
    config_manager.get.return_value = config

    aws_service = MagicMock()
    aws_service.fetch_instances_cached = AsyncMock(return_value=instances)

    custom_server_service = MagicMock()
    custom_server_service.list_as_instances.return_value = custom_instances or []

    cache_service = MagicMock()

    ssh_service = MagicMock()
    ssh_service.get_key_path.return_value = "~/.ssh/test.pem"
    ssh_service.discover_key.return_value = None
    ssh_service.build_ssh_command.return_value = [
        "ssh", "-o", "StrictHostKeyChecking=no", "ec2-user@54.123.45.67", "ls"
    ]

    connection_service = MagicMock()
    connection_service.resolve_profile.return_value = None
    connection_service.get_target_host.return_value = "54.123.45.67"
    connection_service.get_proxy_args.return_value = []
    connection_service.get_proxy_jump_string.return_value = None

    scp_service = MagicMock()
    scp_service.execute_transfer = AsyncMock(return_value=(0, "", ""))
    scp_service.build_upload_command.return_value = ["scp", "local", "remote"]
    scp_service.build_download_command.return_value = ["scp", "remote", "local"]

    guard = CommandGuard(config.mcp)
    audit = MagicMock()
    audit.log = MagicMock()

    tools = ServonautTools(
        config_manager, aws_service, custom_server_service, cache_service,
        ssh_service, connection_service, scp_service,
        guard, audit,
    )
    return tools


def run(coro):
    return asyncio.run(coro)


class TestListInstances:
    def test_returns_formatted_table(self):
        tools = make_tools()
        result = run(tools.list_instances())
        assert "web-server-prod" in result
        assert "i-abc123" in result
        assert "running" in result
        assert "us-east-1" in result

    def test_filters_by_region(self):
        tools = make_tools()
        result = run(tools.list_instances(region="us-east-1"))
        assert "web-server-prod" in result
        assert "api-server-staging" not in result

    def test_filters_by_state(self):
        tools = make_tools()
        result = run(tools.list_instances(state="stopped"))
        assert "api-server-staging" in result
        assert "web-server-prod" not in result

    def test_allowed_in_readonly(self):
        tools = make_tools(guard_level=GuardLevel.READONLY)
        result = run(tools.list_instances())
        assert "web-server-prod" in result

    def test_audit_logged_on_success(self):
        tools = make_tools()
        run(tools.list_instances())
        tools._audit.log.assert_called_once()
        call_args = tools._audit.log.call_args
        assert call_args[0][0] == "list_instances"
        assert call_args[0][3] is True

    def test_public_ip_shown(self):
        tools = make_tools()
        result = run(tools.list_instances())
        assert "54.123.45.67" in result

    def test_no_public_ip_shows_dash(self):
        tools = make_tools()
        result = run(tools.list_instances())
        assert "-" in result


class TestCheckStatus:
    def test_returns_instance_details(self):
        tools = make_tools()
        result = run(tools.check_status("i-abc123"))
        assert "i-abc123" in result
        assert "web-server-prod" in result
        assert "running" in result
        assert "us-east-1" in result

    def test_find_by_name(self):
        tools = make_tools()
        result = run(tools.check_status("web-server-prod"))
        assert "i-abc123" in result

    def test_not_found(self):
        tools = make_tools()
        result = run(tools.check_status("i-nonexistent"))
        assert "not found" in result.lower()

    def test_allowed_in_readonly(self):
        tools = make_tools(guard_level=GuardLevel.READONLY)
        result = run(tools.check_status("i-abc123"))
        assert "Blocked" not in result


class TestRunCommand:
    def test_blocked_in_readonly(self):
        tools = make_tools(guard_level=GuardLevel.READONLY)
        result = run(tools.run_command("i-abc123", "ls"))
        assert "Blocked" in result
        assert "readonly" in result.lower()

    def test_blocked_non_allowlisted_standard(self):
        tools = make_tools(guard_level=GuardLevel.STANDARD)
        result = run(tools.run_command("i-abc123", "apt install nginx"))
        assert "Blocked" in result

    def test_instance_not_found(self):
        tools = make_tools(guard_level=GuardLevel.STANDARD)
        result = run(tools.run_command("i-doesnotexist", "ls"))
        assert "not found" in result.lower()

    def test_audit_logged_on_block(self):
        tools = make_tools(guard_level=GuardLevel.READONLY)
        run(tools.run_command("i-abc123", "ls"))
        tools._audit.log.assert_called_once()
        call_args = tools._audit.log.call_args
        assert call_args[0][3] is False

    def test_output_truncated_when_exceeds_max_lines(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, max_output_lines=5)
        long_output = "\n".join([f"line{i}" for i in range(100)])
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(long_output.encode(), b""))
            mock_exec.return_value = mock_process
            result = run(tools.run_command("i-abc123", "ls"))
        assert "truncated" in result

    def test_builds_ssh_command(self):
        tools = make_tools(guard_level=GuardLevel.STANDARD)
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"output", b""))
            mock_exec.return_value = mock_process
            run(tools.run_command("i-abc123", "ls"))
        tools._ssh_service.build_ssh_command.assert_called_once()


class TestGetLogs:
    def test_calls_run_command_with_tail(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        with patch.object(tools, "run_command", new=AsyncMock(return_value="log output")) as mock_rc:
            result = run(tools.get_logs("i-abc123", "/var/log/syslog", 50))
        mock_rc.assert_called_once_with("i-abc123", "tail -n 50 /var/log/syslog")
        assert result == "log output"

    def test_default_log_path(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        with patch.object(tools, "run_command", new=AsyncMock(return_value="ok")) as mock_rc:
            run(tools.get_logs("i-abc123"))
        call_args = mock_rc.call_args
        assert "/var/log/syslog" in call_args[0][1]

    def test_default_lines(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        with patch.object(tools, "run_command", new=AsyncMock(return_value="ok")) as mock_rc:
            run(tools.get_logs("i-abc123"))
        call_args = mock_rc.call_args
        assert "tail -n 100" in call_args[0][1]


class TestGetServerInfo:
    def test_not_found(self):
        tools = make_tools()
        result = run(tools.get_server_info("i-xyz"))
        assert "not found" in result.lower()

    def test_blocked_if_tool_blocked(self):
        # get_server_info is in readonly_tools, so it should be allowed in readonly
        # Check it's NOT blocked in standard
        tools = make_tools(guard_level=GuardLevel.STANDARD)
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"hostname info", b""))
            mock_exec.return_value = mock_process
            result = run(tools.get_server_info("i-abc123"))
        assert "Blocked" not in result

    def test_audit_logged(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b"info", b""))
            mock_exec.return_value = mock_process
            run(tools.get_server_info("i-abc123"))
        tools._audit.log.assert_called_once()
        assert tools._audit.log.call_args[0][0] == "get_server_info"


class TestTransferFile:
    def test_blocked_in_standard(self):
        tools = make_tools(guard_level=GuardLevel.STANDARD)
        result = run(tools.transfer_file("i-abc123", "/local/path", "/remote/path", "upload"))
        assert "Blocked" in result
        assert "standard" in result.lower()

    def test_blocked_in_readonly(self):
        tools = make_tools(guard_level=GuardLevel.READONLY)
        result = run(tools.transfer_file("i-abc123", "/local/path", "/remote/path", "download"))
        assert "Blocked" in result

    def test_upload_uses_upload_command(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        run(tools.transfer_file("i-abc123", "/local/file.txt", "/remote/file.txt", "upload"))
        tools._scp_service.build_upload_command.assert_called_once()
        tools._scp_service.build_download_command.assert_not_called()

    def test_download_uses_download_command(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        run(tools.transfer_file("i-abc123", "/local/file.txt", "/remote/file.txt", "download"))
        tools._scp_service.build_download_command.assert_called_once()
        tools._scp_service.build_upload_command.assert_not_called()

    def test_instance_not_found(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        result = run(tools.transfer_file("i-xyz", "/l", "/r", "upload"))
        assert "not found" in result.lower()

    def test_success_message(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        tools._scp_service.execute_transfer = AsyncMock(return_value=(0, "", ""))
        result = run(tools.transfer_file("i-abc123", "/local", "/remote", "download"))
        assert "successful" in result.lower()

    def test_failure_message(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        tools._scp_service.execute_transfer = AsyncMock(return_value=(1, "", "Connection refused"))
        result = run(tools.transfer_file("i-abc123", "/local", "/remote", "download"))
        assert "failed" in result.lower()

    def test_audit_logged_on_block(self):
        tools = make_tools(guard_level=GuardLevel.STANDARD)
        run(tools.transfer_file("i-abc123", "/l", "/r", "upload"))
        tools._audit.log.assert_called_once()
        assert tools._audit.log.call_args[0][3] is False

    def test_audit_logged_on_success(self):
        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        run(tools.transfer_file("i-abc123", "/l", "/r", "download"))
        tools._audit.log.assert_called_once()
        assert tools._audit.log.call_args[0][0] == "transfer_file"


class TestCustomServerResolution:
    def test_find_by_custom_name(self):
        tools = make_tools(custom_instances=SAMPLE_CUSTOM_INSTANCES)
        result = run(tools.check_status("ovh-web"))
        assert "custom-ovh-web" in result
        assert "ovh-web" in result

    def test_find_by_custom_id(self):
        tools = make_tools(custom_instances=SAMPLE_CUSTOM_INSTANCES)
        result = run(tools.check_status("custom-ovh-web"))
        assert "custom-ovh-web" in result

    def test_find_case_insensitive(self):
        tools = make_tools(custom_instances=SAMPLE_CUSTOM_INSTANCES)
        result = run(tools.check_status("OVH-Web"))
        assert "custom-ovh-web" in result

    def test_custom_not_found(self):
        tools = make_tools(custom_instances=SAMPLE_CUSTOM_INSTANCES)
        result = run(tools.check_status("nonexistent-server"))
        assert "not found" in result.lower()

    def test_list_instances_includes_custom(self):
        tools = make_tools(custom_instances=SAMPLE_CUSTOM_INSTANCES)
        result = run(tools.list_instances())
        assert "ovh-web" in result
        assert "web-server-prod" in result

    def test_list_instances_filter_by_custom_region(self):
        tools = make_tools(custom_instances=SAMPLE_CUSTOM_INSTANCES)
        result = run(tools.list_instances(region="OVH"))
        assert "ovh-web" in result
        assert "web-server-prod" not in result

    def test_aws_takes_precedence_over_custom(self):
        """AWS instances are searched first; if names collide, AWS wins."""
        tools = make_tools(custom_instances=SAMPLE_CUSTOM_INSTANCES)
        result = run(tools.check_status("web-server-prod"))
        assert "i-abc123" in result
