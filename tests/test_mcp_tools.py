"""Tests for MCP tool implementations."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests._key_fixtures import OPENSSH_HEADER, openssh_armor
from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools


SAMPLE_CUSTOM_INSTANCES = [
    {
        "id": "custom-ovh-web",
        "name": "ovh-web",
        "type": "custom",
        "state": "unknown",
        "public_ip": "192.0.2.10",
        "private_ip": "192.0.2.10",
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


SAMPLE_OVH_VPS_INSTANCE = {
    "id": "vps-abc123.ovh.net",
    "name": "my-vps",
    "type": "vps2-ssd-1",
    "state": "running",
    "public_ip": "1.2.3.4",
    "private_ip": None,
    "region": "GRA",
    "key_name": None,
    "provider_type": "vps",
    "is_ovh": True,
}

SAMPLE_OVH_CLOUD_INSTANCE = {
    "id": "12345678-1234-1234-1234-123456789abc",
    "name": "my-cloud-vm",
    "type": "b2-7",
    "state": "ACTIVE",
    "public_ip": "5.6.7.8",
    "private_ip": None,
    "region": "GRA11",
    "key_name": None,
    "provider_type": "cloud",
    "project_id": "project-abc",
    "is_ovh": True,
}


def make_tools(guard_level=GuardLevel.STANDARD, instances=None, custom_instances=None, max_output_lines=500,
               ovh_instances=None, ovh_monitoring_service=None, ovh_ip_service=None,
               ovh_snapshot_service=None, ovh_dns_service=None, ovh_billing_service=None,
               ovh_service=None, aws_service=None, aws_object_storage_service=None,
               bw_ssh_config_service=None):
    if instances is None:
        instances = SAMPLE_INSTANCES

    config = AppConfig(mcp=MCPConfig(guard_level=guard_level, max_output_lines=max_output_lines))
    config_manager = MagicMock()
    config_manager.get.return_value = config

    if aws_service is None:
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

    # Build a mock ovh_service that merges ovh_instances into fetch_instances_cached
    _ovh_service = ovh_service
    if _ovh_service is None and ovh_instances is not None:
        _ovh_service = MagicMock()
        _ovh_service.fetch_instances_cached = AsyncMock(return_value=ovh_instances)
    elif _ovh_service is None:
        _ovh_service = MagicMock()
        _ovh_service.fetch_instances_cached = AsyncMock(return_value=[])

    guard = CommandGuard(config.mcp)
    audit = MagicMock()
    audit.log = MagicMock()

    tools = ServonautTools(
        config_manager, aws_service, custom_server_service, cache_service,
        ssh_service, connection_service, scp_service,
        guard, audit,
        ovh_service=_ovh_service,
        ovh_monitoring_service=ovh_monitoring_service,
        ovh_ip_service=ovh_ip_service,
        ovh_snapshot_service=ovh_snapshot_service,
        ovh_dns_service=ovh_dns_service,
        ovh_billing_service=ovh_billing_service,
        aws_object_storage_service=aws_object_storage_service,
        bw_ssh_config_service=bw_ssh_config_service,
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


class TestOVHMonitoring:
    def _make_monitoring_service(self, data):
        svc = MagicMock()
        svc.get_vps_monitoring = AsyncMock(return_value=data)
        svc.get_dedicated_monitoring = AsyncMock(return_value=data)
        svc.get_cloud_monitoring = AsyncMock(return_value=data)
        return svc

    def test_returns_error_when_service_none(self):
        tools = make_tools(ovh_instances=[SAMPLE_OVH_VPS_INSTANCE])
        result = run(tools.ovh_monitoring("vps-abc123.ovh.net"))
        assert "Error" in result
        assert "not available" in result

    def test_returns_not_found_for_unknown_instance(self):
        monitoring_svc = self._make_monitoring_service({})
        tools = make_tools(ovh_monitoring_service=monitoring_svc)
        result = run(tools.ovh_monitoring("nonexistent-vps"))
        assert "not found" in result.lower()

    def test_vps_monitoring_shows_metrics(self):
        data = {
            "cpu": [{"timestamp": 1700000000, "value": 23.5}],
            "ram": [{"timestamp": 1700000000, "value": 512.0}],
            "net_in": [],
            "net_out": [],
        }
        monitoring_svc = self._make_monitoring_service(data)
        tools = make_tools(
            ovh_instances=[SAMPLE_OVH_VPS_INSTANCE],
            ovh_monitoring_service=monitoring_svc,
        )
        result = run(tools.ovh_monitoring("vps-abc123.ovh.net"))
        assert "cpu" in result
        assert "23.5" in result
        assert "no data" in result  # net_in/net_out are empty

    def test_cloud_monitoring_requires_project_id(self):
        monitoring_svc = self._make_monitoring_service({"cpu": [], "net_in": [], "net_out": []})
        # Cloud instance without project_id
        cloud_instance_no_project = {**SAMPLE_OVH_CLOUD_INSTANCE, "project_id": ""}
        tools = make_tools(
            ovh_instances=[cloud_instance_no_project],
            ovh_monitoring_service=monitoring_svc,
        )
        result = run(tools.ovh_monitoring("my-cloud-vm"))
        assert "Error" in result
        assert "project_id" in result


class TestOVHListIPs:
    def test_returns_error_when_service_none(self):
        tools = make_tools()
        result = run(tools.ovh_list_ips())
        assert "Error" in result
        assert "not available" in result

    def test_returns_no_ips_message(self):
        ip_svc = MagicMock()
        ip_svc.list_ips = AsyncMock(return_value=[])
        tools = make_tools(ovh_ip_service=ip_svc)
        result = run(tools.ovh_list_ips())
        assert "No IPs" in result

    def test_formats_ip_table(self):
        ip_svc = MagicMock()
        ip_svc.list_ips = AsyncMock(return_value=[
            {"ip": "1.2.3.4/32", "type": "failover", "routedTo": {"serviceName": "vps-abc.ovh.net"}, "country": "FR"},
        ])
        tools = make_tools(ovh_ip_service=ip_svc)
        result = run(tools.ovh_list_ips())
        assert "1.2.3.4/32" in result
        assert "failover" in result
        assert "vps-abc.ovh.net" in result

    def test_null_column_values_do_not_crash_formatter(self):
        """Regression: OVH API returns JSON nulls for country / routedTo /
        type on some IPs. ``dict.get(k, '')`` does not default when the key
        is present with value None — it returns None — which then crashes
        the ``f"{None:<22}"`` column formatter with
        ``unsupported format string passed to NoneType.__format__``.
        """
        ip_svc = MagicMock()
        ip_svc.list_ips = AsyncMock(return_value=[
            {"ip": "1.2.3.4", "type": None, "routedTo": None, "country": None},
            {"ip": None, "type": "failover",
             "routedTo": {"serviceName": None}, "country": ""},
        ])
        tools = make_tools(ovh_ip_service=ip_svc)
        result = run(tools.ovh_list_ips())
        # Must not raise; must still produce two data rows.
        assert "1.2.3.4" in result
        assert "failover" in result


class TestOVHFirewallRules:
    def test_returns_error_when_service_none(self):
        tools = make_tools()
        result = run(tools.ovh_firewall_rules("1.2.3.4"))
        assert "Error" in result
        assert "not available" in result

    def test_returns_no_rules_message(self):
        ip_svc = MagicMock()
        ip_svc.list_firewall_rules = AsyncMock(return_value=[])
        tools = make_tools(ovh_ip_service=ip_svc)
        result = run(tools.ovh_firewall_rules("1.2.3.4"))
        assert "No firewall rules" in result

    def test_formats_rules_table(self):
        ip_svc = MagicMock()
        ip_svc.list_firewall_rules = AsyncMock(return_value=[
            {"sequence": 0, "action": "permit", "protocol": "tcp", "source": "0.0.0.0/0", "destinationPort": "80"},
        ])
        tools = make_tools(ovh_ip_service=ip_svc)
        result = run(tools.ovh_firewall_rules("1.2.3.4"))
        assert "permit" in result
        assert "tcp" in result
        assert "80" in result

    def test_handles_invalid_ip_error(self):
        ip_svc = MagicMock()
        ip_svc.list_firewall_rules = AsyncMock(side_effect=ValueError("Invalid ip format"))
        tools = make_tools(ovh_ip_service=ip_svc)
        result = run(tools.ovh_firewall_rules("not-an-ip"))
        assert "Error" in result


class TestOVHSSHKeys:
    def test_returns_error_when_service_none(self):
        tools = make_tools(ovh_service=None)
        # Force ovh_service to None by not providing one, and also ensure
        # the MagicMock from make_tools doesn't shadow this. Build manually.
        config = AppConfig(mcp=MCPConfig())
        config_manager = MagicMock()
        config_manager.get.return_value = config
        from servonaut.mcp.guards import CommandGuard
        guard = CommandGuard(config.mcp)
        audit = MagicMock()
        aws_service = MagicMock()
        aws_service.fetch_instances_cached = AsyncMock(return_value=[])
        custom_svc = MagicMock()
        custom_svc.list_as_instances.return_value = []
        from servonaut.mcp.tools import ServonautTools
        t = ServonautTools(
            config_manager, aws_service, custom_svc, MagicMock(),
            MagicMock(), MagicMock(), MagicMock(),
            guard, audit,
            ovh_service=None,
        )
        result = run(t.ovh_ssh_keys())
        assert "Error" in result
        assert "not available" in result

    def test_formats_key_list(self):
        import asyncio as _asyncio
        client_mock = MagicMock()
        client_mock.get = MagicMock(side_effect=lambda path, **kw: (
            ["mykey", "deploykey"] if path == "/me/sshKey" else
            {"key": "ssh-rsa AAAAB3Nza mykey", "default": True} if "mykey" in path else
            {"key": "ssh-ed25519 AAAAC3Nza deploykey", "default": False}
        ))
        ovh_svc = MagicMock()
        ovh_svc.client = client_mock
        tools = make_tools(ovh_service=ovh_svc)
        # ovh_ssh_keys uses asyncio.to_thread; patch it
        with patch("asyncio.to_thread", new=AsyncMock(side_effect=lambda fn, *args, **kw: fn(*args, **kw))):
            result = run(tools.ovh_ssh_keys())
        assert "mykey" in result
        assert "deploykey" in result


class TestOVHSnapshots:
    def test_returns_error_when_service_none(self):
        tools = make_tools(ovh_instances=[SAMPLE_OVH_VPS_INSTANCE])
        result = run(tools.ovh_snapshots("vps-abc123.ovh.net"))
        assert "Error" in result
        assert "not available" in result

    def test_returns_not_found_for_unknown_instance(self):
        snap_svc = MagicMock()
        snap_svc.list_vps_snapshots = AsyncMock(return_value=[])
        tools = make_tools(ovh_snapshot_service=snap_svc)
        result = run(tools.ovh_snapshots("nonexistent"))
        assert "not found" in result.lower()

    def test_formats_vps_snapshots(self):
        snap_svc = MagicMock()
        snap_svc.list_vps_snapshots = AsyncMock(return_value=[
            {"id": "snap-001", "name": "before-upgrade", "creationDate": "2026-01-15T10:00:00Z"},
        ])
        tools = make_tools(
            ovh_instances=[SAMPLE_OVH_VPS_INSTANCE],
            ovh_snapshot_service=snap_svc,
        )
        result = run(tools.ovh_snapshots("vps-abc123.ovh.net"))
        assert "snap-001" in result
        assert "before-upgrade" in result

    def test_no_snapshots_message(self):
        snap_svc = MagicMock()
        snap_svc.list_vps_snapshots = AsyncMock(return_value=[])
        tools = make_tools(
            ovh_instances=[SAMPLE_OVH_VPS_INSTANCE],
            ovh_snapshot_service=snap_svc,
        )
        result = run(tools.ovh_snapshots("vps-abc123.ovh.net"))
        assert "No snapshots" in result

    def test_formatter_handles_non_dict_item_defensively(self):
        """If the service ever returns a bare string (legacy API shape),
        the formatter must not crash with AttributeError on ``.get()``.
        """
        snap_svc = MagicMock()
        snap_svc.list_vps_snapshots = AsyncMock(return_value=["plain-id-only"])
        tools = make_tools(
            ovh_instances=[SAMPLE_OVH_VPS_INSTANCE],
            ovh_snapshot_service=snap_svc,
        )
        result = run(tools.ovh_snapshots("vps-abc123.ovh.net"))
        assert "plain-id-only" in result


class TestOVHDNSRecords:
    def test_returns_error_when_service_none(self):
        tools = make_tools()
        result = run(tools.ovh_dns_records("example.com"))
        assert "Error" in result
        assert "not available" in result

    def test_returns_no_records_message(self):
        dns_svc = MagicMock()
        dns_svc.list_records = AsyncMock(return_value=[])
        tools = make_tools(ovh_dns_service=dns_svc)
        result = run(tools.ovh_dns_records("example.com"))
        assert "No DNS records" in result

    def test_formats_records_table(self):
        dns_svc = MagicMock()
        dns_svc.list_records = AsyncMock(return_value=[
            {"fieldType": "A", "subDomain": "www", "ttl": 3600, "target": "1.2.3.4"},
            {"fieldType": "MX", "subDomain": "", "ttl": 3600, "target": "mail.example.com"},
        ])
        tools = make_tools(ovh_dns_service=dns_svc)
        result = run(tools.ovh_dns_records("example.com"))
        assert "A" in result
        assert "www" in result
        assert "1.2.3.4" in result
        assert "MX" in result

    def test_passes_record_type_filter(self):
        dns_svc = MagicMock()
        dns_svc.list_records = AsyncMock(return_value=[])
        tools = make_tools(ovh_dns_service=dns_svc)
        run(tools.ovh_dns_records("example.com", record_type="A"))
        dns_svc.list_records.assert_called_once_with("example.com", field_type="A")

    def test_handles_invalid_zone_error(self):
        dns_svc = MagicMock()
        dns_svc.list_records = AsyncMock(side_effect=ValueError("Invalid zone_name"))
        tools = make_tools(ovh_dns_service=dns_svc)
        result = run(tools.ovh_dns_records("bad zone!"))
        assert "Error" in result


class TestOVHBilling:
    def test_returns_error_when_service_none(self):
        tools = make_tools()
        result = run(tools.ovh_billing())
        assert "Error" in result
        assert "not available" in result

    def test_formats_billing_summary(self):
        billing_svc = MagicMock()
        billing_svc.get_current_usage = AsyncMock(return_value={
            "provider": "ovh",
            "current_spend": {"totalPrice": 42.50, "currency": "EUR"},
            "forecast": {"totalPrice": 85.00},
        })
        tools = make_tools(ovh_billing_service=billing_svc)
        result = run(tools.ovh_billing())
        assert "Billing Summary" in result
        assert "Current Spend" in result
        assert "Forecast" in result

    def test_handles_empty_data_gracefully(self):
        billing_svc = MagicMock()
        billing_svc.get_current_usage = AsyncMock(return_value={
            "provider": "ovh",
            "current_spend": {},
            "forecast": {},
        })
        tools = make_tools(ovh_billing_service=billing_svc)
        result = run(tools.ovh_billing())
        assert "no data" in result


class TestOVHInvoices:
    def test_returns_error_when_service_none(self):
        tools = make_tools()
        result = run(tools.ovh_invoices())
        assert "Error" in result
        assert "not available" in result

    def test_returns_no_invoices_message(self):
        billing_svc = MagicMock()
        billing_svc.get_invoices = AsyncMock(return_value=[])
        tools = make_tools(ovh_billing_service=billing_svc)
        result = run(tools.ovh_invoices())
        assert "No invoices" in result

    def test_formats_invoice_table(self):
        billing_svc = MagicMock()
        billing_svc.get_invoices = AsyncMock(return_value=[
            {
                "billId": "BILL-001",
                "date": "2026-03-01T00:00:00Z",
                "priceWithTax": {"value": 29.99, "currencyCode": "EUR"},
                "status": "paid",
            },
        ])
        tools = make_tools(ovh_billing_service=billing_svc)
        result = run(tools.ovh_invoices())
        assert "BILL-001" in result
        assert "29.99" in result
        assert "EUR" in result

    def test_passes_limit_to_service(self):
        billing_svc = MagicMock()
        billing_svc.get_invoices = AsyncMock(return_value=[])
        tools = make_tools(ovh_billing_service=billing_svc)
        run(tools.ovh_invoices(limit=3))
        billing_svc.get_invoices.assert_called_once_with(limit=3)


class TestSchemaRenderParity:
    """Catch dict-key mismatches between service responses and tool rendering.

    The original aws_list_key_pairs bug shipped because no happy-path test
    rendered a non-empty mock response — the render loop's k.get('name')
    silently produced empty cells against the service's actual 'key_name' key.
    """

    def test_every_new_schema_has_tool_method(self):
        # exists schema-side, must exist on the handler — catches future schema drift
        from servonaut.mcp.tool_schemas import TOOL_SCHEMAS
        from servonaut.mcp.tools import ServonautTools
        orphans = [n for n in TOOL_SCHEMAS if not hasattr(ServonautTools, n)]
        assert not orphans, f"schemas without handlers: {orphans}"

    def test_tool_schema_count_tripwire(self):
        """Count tripwire: catch accidental schema removals.

        Use >= so adding more tools later doesn't break this test.
        Update the floor when removing tools intentionally.
        """
        from servonaut.mcp.tool_schemas import TOOL_SCHEMAS
        assert len(TOOL_SCHEMAS) >= 60, (
            f"Expected at least 60 tool schemas; found {len(TOOL_SCHEMAS)}. "
            "If you intentionally removed a tool, lower this floor and justify in the PR."
        )

    def test_aws_list_amis_renders_all_fields(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_amis = AsyncMock(return_value=[{
            'image_id': 'ami-0abc1234', 'name': 'amzn2-ami-kernel-5.10',
            'description': 'Amazon Linux 2', 'creation_date': '2024-01-15',
            'architecture': 'x86_64', 'virtualization_type': 'hvm',
        }])
        tools = make_tools(aws_service=svc)
        result = run(tools.aws_list_amis(region='us-east-1'))
        assert 'ami-0abc1234' in result
        assert 'amzn2-ami-kernel-5.10' in result
        assert 'x86_64' in result
        assert '2024-01-15' in result

    def test_aws_list_instance_types_renders_all_fields(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_instance_types = AsyncMock(return_value=[{
            'instance_type': 't3.medium', 'vcpus': 2, 'memory_mib': 4096,
        }])
        tools = make_tools(aws_service=svc)
        result = run(tools.aws_list_instance_types(region='us-east-1'))
        assert 't3.medium' in result
        assert '2' in result
        assert '4096' in result

    def test_aws_list_key_pairs_renders_all_fields(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_key_pairs = AsyncMock(return_value=[{
            'key_name': 'prod-key', 'key_pair_id': 'key-0abc123', 'fingerprint': 'aa:bb:cc',
        }])
        tools = make_tools(aws_service=svc)
        result = run(tools.aws_list_key_pairs(region='us-east-1'))
        assert 'prod-key' in result
        assert 'key-0abc123' in result
        assert 'aa:bb:cc' in result

    def test_aws_list_subnets_renders_all_fields(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_subnets = AsyncMock(return_value=[{
            'subnet_id': 'subnet-0abc1234', 'vpc_id': 'vpc-0def5678',
            'availability_zone': 'us-east-1a', 'cidr_block': '10.0.1.0/24',
            'available_ip_count': 251,
        }])
        tools = make_tools(aws_service=svc)
        result = run(tools.aws_list_subnets(region='us-east-1'))
        assert 'subnet-0abc1234' in result
        assert 'vpc-0def5678' in result
        assert 'us-east-1a' in result
        assert '10.0.1.0/24' in result
        assert '251' in result

    def test_aws_list_security_groups_renders_all_fields(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_security_groups = AsyncMock(return_value=[{
            'group_id': 'sg-0abc1234', 'group_name': 'web-sg',
            'description': 'Web tier security group', 'vpc_id': 'vpc-0def5678',
        }])
        tools = make_tools(aws_service=svc)
        result = run(tools.aws_list_security_groups(region='us-east-1'))
        assert 'sg-0abc1234' in result
        assert 'web-sg' in result
        assert 'Web tier security group' in result
        assert 'vpc-0def5678' in result

    def test_s3_list_buckets_renders_all_fields(self):
        s3_svc = MagicMock()
        s3_svc.list_buckets = AsyncMock(return_value=[{
            'name': 'my-logs-bucket', 'creation_date': '2024-03-10T12:00:00+00:00',
        }])
        tools = make_tools(aws_object_storage_service=s3_svc)
        result = run(tools.s3_list_buckets(provider='aws'))
        assert 'my-logs-bucket' in result
        assert '2024-03-10' in result


class TestBwVaultKeyResolution:
    """SSH-backed tools resolve a stored Bitwarden personal ref when present,
    preferring the vault key over local discovery, with a strict per-call
    temp-key lifecycle. The vault tier must never break a local-key setup."""

    # Test fixture only — obviously non-functional key material.
    FAKE_KEY = openssh_armor("FAKE")
    ITEM_ID = "11111111-2222-3333-4444-555555555555"  # leak-guard:allow (fixture UUID)
    REF_PAYLOAD = {
        "ssh_credential_provider": "bitwarden_pm",
        "ssh_credential_ref": {"item_id": ITEM_ID},
    }

    def _bw_service(self, payload):
        from servonaut.services.bw_ssh_config_service import BwSshConfigService
        svc = MagicMock(spec=BwSshConfigService)
        svc.get_personal_instance_ref = AsyncMock(return_value=payload)
        return svc

    def _patch_home(self, monkeypatch, tmp_path):
        """Redirect ~ so temp keys land under pytest's tmp_path, never the
        real ~/.servonaut/tmp."""
        from pathlib import Path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

    def test_run_command_uses_vault_temp_key_and_removes_it(self, tmp_path, monkeypatch):
        import os
        import stat as stat_mod
        from pathlib import Path

        self._patch_home(monkeypatch, tmp_path)
        bw = self._bw_service(self.REF_PAYLOAD)
        tools = make_tools(guard_level=GuardLevel.STANDARD, bw_ssh_config_service=bw)
        observed = {}

        async def fake_subprocess(ssh_cmd, timeout=None):
            key_path = tools._ssh_service.build_ssh_command.call_args.kwargs["key_path"]
            observed["key_path"] = key_path
            observed["exists_during_ssh"] = os.path.exists(key_path)
            observed["mode"] = stat_mod.S_IMODE(os.stat(key_path).st_mode)
            observed["content"] = Path(key_path).read_text()
            return (b"ok", b"")

        with patch("servonaut.services.bw_resolver.BwResolver") as resolver_cls, \
                patch("servonaut.mcp.tools.run_ssh_subprocess", new=fake_subprocess):
            resolver_cls.return_value.resolve_ssh_key.return_value = self.FAKE_KEY
            result = run(tools.run_command("i-abc123", "ls"))

        assert "[transport_used: ssh]" in result
        # Provider defaults to "aws" for AWS instance dicts (no provider key).
        bw.get_personal_instance_ref.assert_awaited_once_with("aws", "i-abc123")
        resolver_cls.return_value.resolve_ssh_key.assert_called_once_with(self.ITEM_ID)
        # Temp key: existed with 0600 while the subprocess ran…
        assert observed["exists_during_ssh"] is True
        assert observed["mode"] == 0o600
        assert observed["content"].startswith(OPENSSH_HEADER)
        # …and is gone after the tool returns.
        assert not os.path.exists(observed["key_path"])

    def test_run_command_temp_key_removed_when_subprocess_raises(self, tmp_path, monkeypatch):
        import os

        self._patch_home(monkeypatch, tmp_path)
        bw = self._bw_service(self.REF_PAYLOAD)
        tools = make_tools(guard_level=GuardLevel.STANDARD, bw_ssh_config_service=bw)
        observed = {}

        async def raising_subprocess(ssh_cmd, timeout=None):
            observed["key_path"] = tools._ssh_service.build_ssh_command.call_args.kwargs["key_path"]
            raise RuntimeError("boom")

        with patch("servonaut.services.bw_resolver.BwResolver") as resolver_cls, \
                patch("servonaut.mcp.tools.run_ssh_subprocess", new=raising_subprocess):
            resolver_cls.return_value.resolve_ssh_key.return_value = self.FAKE_KEY
            result = run(tools.run_command("i-abc123", "ls"))

        # run_command swallows subprocess errors into an Error string…
        assert "Error" in result
        # …but the finally must still have removed the temp key.
        assert not os.path.exists(observed["key_path"])

    def test_run_command_audit_row_carries_key_source(self, tmp_path, monkeypatch):
        self._patch_home(monkeypatch, tmp_path)
        bw = self._bw_service(self.REF_PAYLOAD)
        tools = make_tools(guard_level=GuardLevel.STANDARD, bw_ssh_config_service=bw)

        async def fake_subprocess(ssh_cmd, timeout=None):
            return (b"ok", b"")

        with patch("servonaut.services.bw_resolver.BwResolver") as resolver_cls, \
                patch("servonaut.mcp.tools.run_ssh_subprocess", new=fake_subprocess):
            resolver_cls.return_value.resolve_ssh_key.return_value = self.FAKE_KEY
            run(tools.run_command("i-abc123", "ls"))

        call = tools._audit.log.call_args
        assert call[0][0] == "run_command"
        assert call[0][3] is True
        assert call.kwargs.get("key_source") == "bw_personal"
        # The fake key body must never appear in the audited args/result.
        assert "PRIVATE KEY" not in str(call)

    def test_bw_session_missing_falls_back_to_local_key(self, tmp_path, monkeypatch):
        from servonaut.services.bw_errors import BwSessionMissingError

        self._patch_home(monkeypatch, tmp_path)
        bw = self._bw_service(self.REF_PAYLOAD)
        tools = make_tools(guard_level=GuardLevel.STANDARD, bw_ssh_config_service=bw)

        async def fake_subprocess(ssh_cmd, timeout=None):
            return (b"ok", b"")

        with patch("servonaut.services.bw_resolver.BwResolver") as resolver_cls, \
                patch("servonaut.mcp.tools.run_ssh_subprocess", new=fake_subprocess):
            resolver_cls.return_value.resolve_ssh_key.side_effect = (
                BwSessionMissingError("vault locked")
            )
            result = run(tools.run_command("i-abc123", "ls"))

        # Tool still succeeds using the locally-resolved key.
        assert "[transport_used: ssh]" in result
        key_path = tools._ssh_service.build_ssh_command.call_args.kwargs["key_path"]
        assert key_path == "~/.ssh/test.pem"
        assert "key_source" not in tools._audit.log.call_args.kwargs

    def test_no_bw_service_injected_is_regression_identical(self):
        """Pin: without a BW service, behavior is byte-for-byte the old path —
        local key, plain audit row, no vault lookups."""
        tools = make_tools(guard_level=GuardLevel.STANDARD)

        async def fake_subprocess(ssh_cmd, timeout=None):
            return (b"ok", b"")

        with patch("servonaut.mcp.tools.run_ssh_subprocess", new=fake_subprocess):
            result = run(tools.run_command("i-abc123", "ls"))

        assert "[transport_used: ssh]" in result
        key_path = tools._ssh_service.build_ssh_command.call_args.kwargs["key_path"]
        assert key_path == "~/.ssh/test.pem"
        assert "key_source" not in tools._audit.log.call_args.kwargs

    def test_transfer_file_uses_vault_key_and_cleans_up(self, tmp_path, monkeypatch):
        import os

        self._patch_home(monkeypatch, tmp_path)
        bw = self._bw_service(self.REF_PAYLOAD)
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, bw_ssh_config_service=bw)
        observed = {}

        async def fake_transfer(cmd):
            key_path = tools._scp_service.build_download_command.call_args.kwargs["key_path"]
            observed["key_path"] = key_path
            observed["exists_during_scp"] = os.path.exists(key_path)
            return (0, "", "")

        tools._scp_service.execute_transfer = AsyncMock(side_effect=fake_transfer)

        with patch("servonaut.services.bw_resolver.BwResolver") as resolver_cls:
            resolver_cls.return_value.resolve_ssh_key.return_value = self.FAKE_KEY
            result = run(tools.transfer_file("i-abc123", "/l", "/r", "download"))

        assert "successful" in result.lower()
        assert observed["exists_during_scp"] is True
        assert not os.path.exists(observed["key_path"])
        assert tools._audit.log.call_args.kwargs.get("key_source") == "bw_personal"

    def test_transfer_file_temp_key_removed_when_transfer_raises(self, tmp_path, monkeypatch):
        import os

        self._patch_home(monkeypatch, tmp_path)
        bw = self._bw_service(self.REF_PAYLOAD)
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, bw_ssh_config_service=bw)
        observed = {}

        async def raising_transfer(cmd):
            observed["key_path"] = tools._scp_service.build_upload_command.call_args.kwargs["key_path"]
            raise RuntimeError("scp exploded")

        tools._scp_service.execute_transfer = AsyncMock(side_effect=raising_transfer)

        with patch("servonaut.services.bw_resolver.BwResolver") as resolver_cls:
            resolver_cls.return_value.resolve_ssh_key.return_value = self.FAKE_KEY
            with pytest.raises(RuntimeError):
                run(tools.transfer_file("i-abc123", "/l", "/r", "upload"))

        assert not os.path.exists(observed["key_path"])

    def test_set_bw_ssh_config_service_binds_late_and_clears_memo(self):
        """The TUI builds the shared tools instance BEFORE the authenticated
        APIClient exists, so the BW ref client is pushed in late via the
        setter (mirrors set_secret_provider). Rebinding must clear the
        ssh-ref memo so entries memoized under the previous binding
        (including negative ones) cannot bleed into the new one."""
        tools = make_tools(guard_level=GuardLevel.STANDARD)
        assert tools._bw_ssh_config_service is None
        # Simulate a negative memo entry from the unbound era.
        tools._bw_ref_memo[("aws", "i-abc123")] = (float("inf"), None)

        bw = self._bw_service(self.REF_PAYLOAD)
        tools.set_bw_ssh_config_service(bw)
        assert tools._bw_ssh_config_service is bw
        assert tools._bw_ref_memo == {}

        tools.set_bw_ssh_config_service(None)
        assert tools._bw_ssh_config_service is None

    def test_late_bound_bw_service_resolves_vault_key(self, tmp_path, monkeypatch):
        """A tools instance constructed WITHOUT the BW service (the TUI
        startup order) must resolve vault keys once the app pushes the
        service in — same behaviour as constructor injection."""
        self._patch_home(monkeypatch, tmp_path)
        tools = make_tools(guard_level=GuardLevel.STANDARD)
        bw = self._bw_service(self.REF_PAYLOAD)
        tools.set_bw_ssh_config_service(bw)

        async def fake_subprocess(ssh_cmd, timeout=None):
            return (b"ok", b"")

        with patch("servonaut.services.bw_resolver.BwResolver") as resolver_cls, \
                patch("servonaut.mcp.tools.run_ssh_subprocess", new=fake_subprocess):
            resolver_cls.return_value.resolve_ssh_key.return_value = self.FAKE_KEY
            result = run(tools.run_command("i-abc123", "ls"))

        assert "[transport_used: ssh]" in result
        bw.get_personal_instance_ref.assert_awaited_once_with("aws", "i-abc123")
        assert tools._audit.log.call_args.kwargs.get("key_source") == "bw_personal"

    def test_ref_without_item_id_keeps_local_key(self, tmp_path, monkeypatch):
        """Partial roll-up row (mirror miss on this device): ref exists but
        carries no item_id — nothing resolvable, local key is used."""
        self._patch_home(monkeypatch, tmp_path)
        bw = self._bw_service({
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": None,
        })
        tools = make_tools(guard_level=GuardLevel.STANDARD, bw_ssh_config_service=bw)

        async def fake_subprocess(ssh_cmd, timeout=None):
            return (b"ok", b"")

        with patch("servonaut.mcp.tools.run_ssh_subprocess", new=fake_subprocess):
            result = run(tools.run_command("i-abc123", "ls"))

        assert "[transport_used: ssh]" in result
        key_path = tools._ssh_service.build_ssh_command.call_args.kwargs["key_path"]
        assert key_path == "~/.ssh/test.pem"
