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
               ovh_service=None):
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
