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
