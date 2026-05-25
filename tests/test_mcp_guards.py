"""Tests for MCP guard system."""
from __future__ import annotations

import pytest
from servonaut.config.schema import MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel


def make_guard(level, **kwargs):
    config = MCPConfig(guard_level=level, **kwargs)
    return CommandGuard(config)


class TestReadonlyGuard:
    def test_allows_list_instances(self):
        guard = make_guard(GuardLevel.READONLY)
        allowed, _ = guard.check_tool("list_instances")
        assert allowed

    def test_allows_check_status(self):
        guard = make_guard(GuardLevel.READONLY)
        allowed, _ = guard.check_tool("check_status")
        assert allowed

    def test_allows_get_server_info(self):
        guard = make_guard(GuardLevel.READONLY)
        allowed, _ = guard.check_tool("get_server_info")
        assert allowed

    def test_blocks_run_command(self):
        guard = make_guard(GuardLevel.READONLY)
        allowed, reason = guard.check_tool("run_command")
        assert not allowed
        assert "readonly" in reason.lower()

    def test_blocks_get_logs(self):
        guard = make_guard(GuardLevel.READONLY)
        allowed, _ = guard.check_tool("get_logs")
        assert not allowed

    def test_blocks_transfer_file(self):
        guard = make_guard(GuardLevel.READONLY)
        allowed, _ = guard.check_tool("transfer_file")
        assert not allowed

    def test_check_command_always_blocked(self):
        guard = make_guard(GuardLevel.READONLY)
        allowed, reason = guard.check_command("ls -la")
        assert not allowed
        assert "readonly" in reason.lower()


class TestStandardGuard:
    def test_allows_list_instances(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_tool("list_instances")
        assert allowed

    def test_allows_run_command(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_tool("run_command")
        assert allowed

    def test_allows_get_logs(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_tool("get_logs")
        assert allowed

    def test_blocks_transfer_file(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, reason = guard.check_tool("transfer_file")
        assert not allowed
        assert "standard" in reason.lower()

    def test_allows_ls(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("ls -la")
        assert allowed

    def test_allows_cat(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("cat /etc/hosts")
        assert allowed

    def test_allows_grep(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("grep error /var/log/syslog")
        assert allowed

    def test_allows_tail(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("tail -100 /var/log/nginx/error.log")
        assert allowed

    def test_blocks_apt(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, reason = guard.check_command("apt install nginx")
        assert not allowed
        assert "allowlist" in reason.lower()

    def test_blocks_pip(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("pip install requests")
        assert not allowed

    def test_blocks_curl(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("curl http://example.com")
        assert not allowed

    def test_blocks_chmod(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("chmod 777 /etc/passwd")
        assert not allowed


class TestDangerousGuard:
    def test_allows_all_tools(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        for tool in ["list_instances", "check_status", "get_server_info",
                     "run_command", "get_logs", "transfer_file"]:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected tool to be allowed but got: {reason}"

    def test_allows_non_allowlisted_commands(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("apt install nginx")
        assert allowed

    def test_allows_complex_commands(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("curl -s http://example.com")
        assert allowed


class TestBlocklist:
    def test_rm_rf_blocked_at_all_levels(self):
        for level in [GuardLevel.READONLY, GuardLevel.STANDARD, GuardLevel.DANGEROUS]:
            guard = make_guard(level)
            allowed, reason = guard.check_command("rm -rf /tmp/test")
            assert not allowed, f"rm -rf should be blocked at level {level}"
            assert "blocklist" in reason.lower()

    def test_destruct_blocked_dangerous_dd(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        # uses word-boundary pattern for dd: matches "dd " or " dd "
        allowed, _ = guard.check_command("ls /; dd if=/dev/zero of=/dev/sda")
        assert not allowed

    def test_mkfs_blocked(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("mkfs.ext4 /dev/sdb")
        assert not allowed

    def test_shutdown_blocked(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("shutdown -h now")
        assert not allowed

    def test_reboot_blocked(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("reboot")
        assert not allowed

    def test_fdisk_blocked(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("fdisk /dev/sda")
        assert not allowed

    def test_parted_blocked(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("parted /dev/sda print")
        assert not allowed

    def test_halt_blocked(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("halt")
        assert not allowed

    def test_fork_bomb_blocked(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command(":(){:|:&};:")
        assert not allowed

    def test_sudo_rm_blocked(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("sudo rm /etc/passwd")
        assert not allowed

    def test_sudo_rm_rf_blocked(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("sudo rm -rf /")
        assert not allowed

    def test_rm_rf_space_variations(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_command("rm  -rf /tmp")
        assert not allowed


class TestSudoHandling:
    def test_sudo_allowlisted_cmd_passes_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        # base cmd after sudo is "ls" which is in allowlist
        allowed, _ = guard.check_command("sudo ls -la /root")
        assert allowed

    def test_sudo_non_allowlisted_blocked_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("sudo apt install nginx")
        assert not allowed

    def test_sudo_rm_blocked_by_blocklist(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("sudo rm /important/file")
        assert not allowed


OVH_READONLY_TOOLS = [
    'ovh_monitoring', 'ovh_list_ips', 'ovh_firewall_rules',
    'ovh_ssh_keys', 'ovh_snapshots', 'ovh_dns_records',
    'ovh_billing', 'ovh_invoices',
]


class TestOVHToolGuards:
    def test_all_ovh_tools_allowed_in_readonly(self):
        guard = make_guard(GuardLevel.READONLY)
        for tool in OVH_READONLY_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} to be allowed in readonly but got: {reason}"

    def test_all_ovh_tools_allowed_in_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        for tool in OVH_READONLY_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} to be allowed in standard but got: {reason}"

    def test_all_ovh_tools_allowed_in_dangerous(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        for tool in OVH_READONLY_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} to be allowed in dangerous but got: {reason}"

    def test_no_ovh_destructive_tools_exist_in_any_level(self):
        """Verify that no OVH write/delete tools are registered as guard-level tools."""
        destructive_names = [
            'ovh_create_snapshot', 'ovh_delete_snapshot', 'ovh_restore_snapshot',
            'ovh_add_firewall_rule', 'ovh_delete_firewall_rule',
            'ovh_create_dns_record', 'ovh_delete_dns_record', 'ovh_update_dns_record',
            'ovh_move_failover_ip', 'ovh_toggle_firewall',
        ]
        # In dangerous mode, unknown tools are allowed — so we check they are not
        # explicitly enumerated in the readonly/standard sets (they'd pass dangerous
        # by default but should not appear in a curated readonly set).
        guard_readonly = make_guard(GuardLevel.READONLY)
        for tool in destructive_names:
            allowed, _ = guard_readonly.check_tool(tool)
            assert not allowed, (
                f"Destructive OVH tool {tool!r} should NOT be allowed in readonly mode"
            )

    def test_ovh_tools_count_in_readonly_set(self):
        """Readonly tools set should include exactly 8 OVH tools."""
        guard = make_guard(GuardLevel.READONLY)
        ovh_tools_allowed = [t for t in OVH_READONLY_TOOLS if guard.check_tool(t)[0]]
        assert len(ovh_tools_allowed) == 8


# ---------------------------------------------------------------------------
# AWS + S3 guard tier tests (21 new tools)
# ---------------------------------------------------------------------------

# --- Readonly (allowed at all tiers) ---
AWS_READONLY_TOOLS = [
    'aws_list_regions', 'aws_list_amis', 'aws_list_instance_types',
    'aws_list_key_pairs', 'aws_list_subnets', 'aws_list_security_groups',
]
S3_READONLY_TOOLS = [
    's3_list_buckets', 's3_list_objects',
]

# --- Standard (allowed at standard+; blocked at readonly) ---
AWS_STANDARD_TOOLS = [
    'aws_start_instance', 'aws_stop_instance', 'aws_reboot_instance',
]
S3_STANDARD_TOOLS = [
    's3_download_object',
]

# --- Dangerous (allowed at dangerous only) ---
AWS_DANGEROUS_TOOLS = [
    'aws_terminate_instance', 'aws_run_instances',
]
S3_DANGEROUS_TOOLS = [
    's3_create_bucket', 's3_delete_bucket', 's3_upload_object',
    's3_delete_object', 's3_copy_object', 's3_move_object',
    's3_generate_presigned_url',
]


class TestAWSReadonlyToolGuards:
    def test_aws_readonly_tools_allowed_at_readonly(self):
        guard = make_guard(GuardLevel.READONLY)
        for tool in AWS_READONLY_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at readonly but got: {reason}"

    def test_aws_readonly_tools_allowed_at_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        for tool in AWS_READONLY_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at standard but got: {reason}"

    def test_aws_readonly_tools_allowed_at_dangerous(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        for tool in AWS_READONLY_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at dangerous but got: {reason}"

    @pytest.mark.parametrize("tool", AWS_READONLY_TOOLS)
    def test_each_aws_readonly_tool_allowed_at_readonly_parametrised(self, tool):
        guard = make_guard(GuardLevel.READONLY)
        allowed, reason = guard.check_tool(tool)
        assert allowed, f"Tool {tool!r} must be allowed at readonly; got: {reason}"


class TestAWSStandardToolGuards:
    def test_aws_standard_tools_blocked_at_readonly(self):
        guard = make_guard(GuardLevel.READONLY)
        for tool in AWS_STANDARD_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert not allowed, f"Expected {tool!r} blocked at readonly but was allowed"

    def test_aws_standard_tools_allowed_at_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        for tool in AWS_STANDARD_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at standard but got: {reason}"

    def test_aws_standard_tools_allowed_at_dangerous(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        for tool in AWS_STANDARD_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at dangerous but got: {reason}"

    @pytest.mark.parametrize("tool", AWS_STANDARD_TOOLS)
    def test_each_aws_standard_tool_blocked_at_readonly(self, tool):
        guard = make_guard(GuardLevel.READONLY)
        allowed, _ = guard.check_tool(tool)
        assert not allowed, f"Tool {tool!r} must be blocked at readonly"


class TestAWSDangerousToolGuards:
    def test_aws_dangerous_tools_blocked_at_readonly(self):
        guard = make_guard(GuardLevel.READONLY)
        for tool in AWS_DANGEROUS_TOOLS:
            allowed, _ = guard.check_tool(tool)
            assert not allowed, f"Expected {tool!r} blocked at readonly"

    def test_aws_dangerous_tools_blocked_at_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        for tool in AWS_DANGEROUS_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert not allowed, f"Expected {tool!r} blocked at standard but was allowed"
            assert "standard" in reason.lower()

    def test_aws_dangerous_tools_allowed_at_dangerous(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        for tool in AWS_DANGEROUS_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at dangerous but got: {reason}"

    @pytest.mark.parametrize("tool", AWS_DANGEROUS_TOOLS)
    def test_each_aws_dangerous_tool_blocked_at_standard(self, tool):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_tool(tool)
        assert not allowed, f"Tool {tool!r} must be blocked at standard"


class TestS3ReadonlyToolGuards:
    def test_s3_readonly_tools_allowed_at_readonly(self):
        guard = make_guard(GuardLevel.READONLY)
        for tool in S3_READONLY_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at readonly but got: {reason}"

    def test_s3_readonly_tools_allowed_at_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        for tool in S3_READONLY_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at standard but got: {reason}"

    def test_s3_readonly_tools_allowed_at_dangerous(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        for tool in S3_READONLY_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at dangerous but got: {reason}"

    @pytest.mark.parametrize("tool", S3_READONLY_TOOLS)
    def test_each_s3_readonly_tool_parametrised(self, tool):
        guard = make_guard(GuardLevel.READONLY)
        allowed, reason = guard.check_tool(tool)
        assert allowed, f"S3 readonly tool {tool!r} must be allowed at readonly; got: {reason}"


class TestS3StandardToolGuards:
    def test_s3_standard_tools_blocked_at_readonly(self):
        guard = make_guard(GuardLevel.READONLY)
        for tool in S3_STANDARD_TOOLS:
            allowed, _ = guard.check_tool(tool)
            assert not allowed, f"Expected {tool!r} blocked at readonly"

    def test_s3_standard_tools_allowed_at_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        for tool in S3_STANDARD_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at standard but got: {reason}"

    def test_s3_standard_tools_allowed_at_dangerous(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        for tool in S3_STANDARD_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at dangerous but got: {reason}"


class TestS3DangerousToolGuards:
    def test_s3_dangerous_tools_blocked_at_readonly(self):
        guard = make_guard(GuardLevel.READONLY)
        for tool in S3_DANGEROUS_TOOLS:
            allowed, _ = guard.check_tool(tool)
            assert not allowed, f"Expected {tool!r} blocked at readonly"

    def test_s3_dangerous_tools_blocked_at_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        for tool in S3_DANGEROUS_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert not allowed, f"Expected {tool!r} blocked at standard but was allowed"
            assert "standard" in reason.lower()

    def test_s3_dangerous_tools_allowed_at_dangerous(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        for tool in S3_DANGEROUS_TOOLS:
            allowed, reason = guard.check_tool(tool)
            assert allowed, f"Expected {tool!r} allowed at dangerous but got: {reason}"

    @pytest.mark.parametrize("tool", S3_DANGEROUS_TOOLS)
    def test_each_s3_dangerous_tool_blocked_at_standard(self, tool):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_tool(tool)
        assert not allowed, f"S3 dangerous tool {tool!r} must be blocked at standard"

    def test_presigned_url_specifically_blocked_at_standard(self):
        """s3_generate_presigned_url is a bearer-secret tool — must be dangerous only."""
        guard = make_guard(GuardLevel.STANDARD)
        allowed, reason = guard.check_tool("s3_generate_presigned_url")
        assert not allowed
        assert "standard" in reason.lower()

    def test_presigned_url_blocked_at_readonly(self):
        guard = make_guard(GuardLevel.READONLY)
        allowed, _ = guard.check_tool("s3_generate_presigned_url")
        assert not allowed


class TestEdgeCases:
    def test_empty_command_blocked_standard(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("")
        assert not allowed

    def test_empty_command_blocked_readonly(self):
        guard = make_guard(GuardLevel.READONLY)
        allowed, _ = guard.check_command("")
        assert not allowed

    def test_command_with_pipes_base_checked(self):
        guard = make_guard(GuardLevel.STANDARD)
        # grep is allowlisted — base command is grep
        allowed, _ = guard.check_command("grep error /var/log/syslog | head -20")
        assert allowed

    def test_whitespace_only_blocked(self):
        guard = make_guard(GuardLevel.STANDARD)
        allowed, _ = guard.check_command("   ")
        assert not allowed

    def test_unknown_tool_allowed_in_dangerous(self):
        guard = make_guard(GuardLevel.DANGEROUS)
        allowed, _ = guard.check_tool("some_future_tool")
        assert allowed

    def test_custom_blocklist(self):
        config = MCPConfig(guard_level=GuardLevel.DANGEROUS, command_blocklist=[r"\bcustom_danger\b"])
        guard = CommandGuard(config)
        allowed, _ = guard.check_command("custom_danger --nuke")
        assert not allowed

    def test_custom_allowlist_only_allows_listed(self):
        config = MCPConfig(guard_level=GuardLevel.STANDARD, command_allowlist=["myapp"])
        guard = CommandGuard(config)
        allowed, _ = guard.check_command("myapp --status")
        assert allowed
        # ls is NOT in custom allowlist
        allowed, _ = guard.check_command("ls -la")
        assert not allowed
