"""Tests for RelayExecutors: command dispatch, blocklist, input validation."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.models.relay_messages import CommandRequest, CommandResponse, CommandType
from servonaut.services.relay_executors import RelayExecutors, _TRANSFERS_DIR


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_executors(instances=None, custom_instances=None, extra_blocklist=None):
    """Construct a RelayExecutors with fully mocked services."""
    if instances is None:
        instances = [
            {
                "id": "i-abc123",
                "name": "web-server",
                "type": "t3.medium",
                "state": "running",
                "public_ip": "54.1.2.3",
                "private_ip": "10.0.0.1",
                "region": "us-east-1",
                "key_name": "prod-key",
            }
        ]
    if custom_instances is None:
        custom_instances = []

    mcp_cfg = MCPConfig()
    if extra_blocklist:
        mcp_cfg.command_blocklist = extra_blocklist
    else:
        mcp_cfg.command_blocklist = []

    config = AppConfig(mcp=mcp_cfg)

    config_manager = MagicMock()
    config_manager.get.return_value = config

    aws_service = MagicMock()
    aws_service.fetch_instances_cached = AsyncMock(return_value=instances)

    custom_server_service = MagicMock()
    custom_server_service.list_as_instances.return_value = custom_instances

    ssh_service = MagicMock()
    ssh_service.get_key_path.return_value = "~/.ssh/prod-key.pem"
    ssh_service.discover_key.return_value = None
    ssh_service.build_ssh_command.return_value = [
        "ssh", "-o", "StrictHostKeyChecking=no", "ec2-user@54.1.2.3", "ls"
    ]

    connection_service = MagicMock()
    connection_service.resolve_profile.return_value = None
    connection_service.get_target_host.return_value = "54.1.2.3"
    connection_service.get_proxy_args.return_value = []
    connection_service.get_proxy_jump_string.return_value = None

    scp_service = MagicMock()
    scp_service.execute_transfer = AsyncMock(return_value=(0, "", ""))
    scp_service.build_upload_command.return_value = ["scp", "/local", "user@host:/remote"]
    scp_service.build_download_command.return_value = ["scp", "user@host:/remote", "/local"]

    return RelayExecutors(
        config_manager=config_manager,
        aws_service=aws_service,
        custom_server_service=custom_server_service,
        ssh_service=ssh_service,
        connection_service=connection_service,
        scp_service=scp_service,
    )


def make_request(
    cmd_type=CommandType.RUN_COMMAND,
    target="i-abc123",
    payload=None,
    ttl=60,
    req_id="req-001",
    user_id="user-1",
):
    return CommandRequest(
        id=req_id,
        user_id=user_id,
        type=cmd_type,
        target_server_id=target,
        payload=payload or {},
        ttl_seconds=ttl,
    )


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Blocklist tests
# ---------------------------------------------------------------------------

class TestCheckBlocklist:
    def _make_simple_executors(self):
        return make_executors()

    # Blocked patterns
    def test_blocks_rm_rf_short(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("rm -rf /") is not None

    def test_blocks_rm_rf_flags(self):
        # The pattern requires r before f: -rf matches; -fr does not match
        ex = self._make_simple_executors()
        assert ex._check_blocklist("rm -rf /some/path") is not None

    def test_blocks_rm_recursive_long_flag(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("rm --recursive /some/path") is not None

    def test_rm_r_without_f_not_blocked(self):
        # The blocklist only blocks rm -rf / rm --recursive, not bare rm -r
        ex = self._make_simple_executors()
        assert ex._check_blocklist("rm -r /some/path") is None

    def test_rm_fr_order_not_blocked(self):
        # Pattern requires r before f (-[a-zA-Z]*r[a-zA-Z]*f) — rm -fr does NOT match
        ex = self._make_simple_executors()
        assert ex._check_blocklist("rm -fr /some/path") is None

    def test_blocks_mkfs(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("mkfs.ext4 /dev/sdb") is not None

    def test_blocks_dd_to_device(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("dd if=/dev/zero of=/dev/sda") is not None

    def test_blocks_shutdown(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("shutdown -h now") is not None

    def test_blocks_reboot(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("reboot") is not None

    def test_blocks_halt(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("halt") is not None

    def test_blocks_poweroff(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("poweroff") is not None

    def test_blocks_fork_bomb(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist(":(){ :|:& };:") is not None

    def test_blocks_write_to_block_device(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("cat image.bin > /dev/sda") is not None

    def test_blocks_chmod_recursive_777(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("chmod -R 777 /etc") is not None

    # Allowed commands
    def test_allows_ls(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("ls -la /var/log") is None

    def test_allows_tail(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("tail -n 100 /var/log/syslog") is None

    def test_allows_grep(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("grep -r ERROR /var/log") is None

    def test_allows_cat(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("cat /etc/hostname") is None

    def test_allows_ps(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("ps aux") is None

    def test_allows_df(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("df -h") is None

    def test_allows_uname(self):
        ex = self._make_simple_executors()
        assert ex._check_blocklist("uname -a") is None

    def test_extra_blocklist_from_config(self):
        ex = make_executors(extra_blocklist=[r"\bcurl\b"])
        assert ex._check_blocklist("curl http://evil.com") is not None

    def test_extra_blocklist_does_not_block_unrelated(self):
        ex = make_executors(extra_blocklist=[r"\bcurl\b"])
        assert ex._check_blocklist("ls -la") is None

    def test_returns_reason_string_on_block(self):
        ex = self._make_simple_executors()
        reason = ex._check_blocklist("rm -rf /")
        assert isinstance(reason, str)
        assert len(reason) > 0


# ---------------------------------------------------------------------------
# TTL clamping
# ---------------------------------------------------------------------------

class TestTTLClamping:
    def test_ttl_above_max_is_clamped_to_300(self):
        ex = make_executors()
        request = make_request(ttl=9999, payload={"command": "ls"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"output", b""))):
            run(ex.execute(request))
        assert request.ttl_seconds == 300

    def test_ttl_zero_is_clamped_to_1(self):
        ex = make_executors()
        request = make_request(ttl=0, payload={"command": "ls"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"output", b""))):
            run(ex.execute(request))
        assert request.ttl_seconds == 1

    def test_ttl_within_range_unchanged(self):
        ex = make_executors()
        request = make_request(ttl=120, payload={"command": "ls"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"output", b""))):
            run(ex.execute(request))
        assert request.ttl_seconds == 120

    def test_ttl_exactly_300_unchanged(self):
        ex = make_executors()
        request = make_request(ttl=300, payload={"command": "ls"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"output", b""))):
            run(ex.execute(request))
        assert request.ttl_seconds == 300


# ---------------------------------------------------------------------------
# _run_command tests
# ---------------------------------------------------------------------------

class TestRunCommand:
    def test_happy_path_returns_success(self):
        ex = make_executors()
        request = make_request(payload={"command": "ls -la"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"file1\nfile2", b""))):
            resp = run(ex.execute(request))
        assert resp.status == "success"
        assert "file1" in resp.output

    def test_happy_path_includes_stdout(self):
        ex = make_executors()
        request = make_request(payload={"command": "hostname"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"my-server", b""))):
            resp = run(ex.execute(request))
        assert "my-server" in resp.output

    def test_missing_command_key_returns_rejected(self):
        ex = make_executors()
        request = make_request(payload={})
        resp = run(ex.execute(request))
        assert resp.status == "rejected"
        assert "command" in resp.error_message.lower()

    def test_empty_command_returns_rejected(self):
        ex = make_executors()
        request = make_request(payload={"command": ""})
        resp = run(ex.execute(request))
        assert resp.status == "rejected"

    def test_instance_not_found_returns_error(self):
        ex = make_executors()
        request = make_request(target="i-nonexistent", payload={"command": "ls"})
        resp = run(ex.execute(request))
        assert resp.status == "error"
        assert "not found" in resp.error_message.lower()

    def test_ssh_timeout_returns_timeout(self):
        ex = make_executors()
        request = make_request(payload={"command": "sleep 999"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(side_effect=asyncio.TimeoutError())):
            resp = run(ex.execute(request))
        assert resp.status == "timeout"
        assert "timed out" in resp.error_message.lower()

    def test_blocked_command_returns_rejected(self):
        ex = make_executors()
        request = make_request(payload={"command": "rm -rf /"})
        resp = run(ex.execute(request))
        assert resp.status == "rejected"
        assert "blocklist" in resp.error_message.lower()

    def test_ssh_exception_returns_error(self):
        ex = make_executors()
        request = make_request(payload={"command": "ls"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(side_effect=OSError("connection refused"))):
            resp = run(ex.execute(request))
        assert resp.status == "error"
        assert "connection refused" in resp.error_message

    def test_stderr_appended_to_output(self):
        ex = make_executors()
        request = make_request(payload={"command": "ls /missing"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"", b"No such file"))):
            resp = run(ex.execute(request))
        assert "STDERR" in resp.output
        assert "No such file" in resp.output

    def test_long_output_truncated(self):
        ex = make_executors()
        request = make_request(payload={"command": "cat big-file"})
        # 501 lines triggers truncation at 500
        big_output = "\n".join(f"line{i}" for i in range(501)).encode()
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(big_output, b""))):
            resp = run(ex.execute(request))
        assert "truncated" in resp.output

    def test_output_within_limit_not_truncated(self):
        ex = make_executors()
        request = make_request(payload={"command": "ls"})
        output = "\n".join(f"line{i}" for i in range(10)).encode()
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(output, b""))):
            resp = run(ex.execute(request))
        assert "truncated" not in resp.output


# ---------------------------------------------------------------------------
# _get_logs tests
# ---------------------------------------------------------------------------

class TestGetLogs:
    def test_valid_log_path_passes(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.GET_LOGS,
            payload={"log_path": "/var/log/syslog", "lines": 50},
        )
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"log content", b""))):
            resp = run(ex.execute(request))
        assert resp.status == "success"

    def test_default_log_path_used_when_missing(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.GET_LOGS,
            payload={"lines": 10},
        )
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"output", b""))) as mock_ssh:
            run(ex.execute(request))
        # SSH command is built from ssh_service mock; verify the payload was used
        # (the command is passed to build_ssh_command via remote_command kwarg)
        call_kwargs = ex._ssh_service.build_ssh_command.call_args
        assert "/var/log/syslog" in call_kwargs[1].get("remote_command", "")

    def test_shell_metacharacters_in_path_rejected(self):
        ex = make_executors()
        for bad_path in [
            "/var/log/syslog; rm -rf /",
            "/var/log/$(whoami)",
            "/var/log/`id`",
            "/var/log/syslog|cat /etc/passwd",
        ]:
            request = make_request(
                cmd_type=CommandType.GET_LOGS,
                payload={"log_path": bad_path, "lines": 10},
            )
            resp = run(ex.execute(request))
            assert resp.status == "rejected", f"Expected rejected for path: {bad_path}"
            assert "invalid log path" in resp.error_message.lower()

    def test_space_in_path_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.GET_LOGS,
            payload={"log_path": "/var/log/my log", "lines": 10},
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"

    def test_invalid_lines_string_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.GET_LOGS,
            payload={"log_path": "/var/log/syslog", "lines": "abc"},
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"
        assert "invalid" in resp.error_message.lower()

    def test_lines_zero_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.GET_LOGS,
            payload={"log_path": "/var/log/syslog", "lines": 0},
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"

    def test_lines_above_10000_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.GET_LOGS,
            payload={"log_path": "/var/log/syslog", "lines": 10001},
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"

    def test_lines_none_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.GET_LOGS,
            payload={"log_path": "/var/log/syslog", "lines": None},
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"

    def test_lines_at_upper_boundary_accepted(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.GET_LOGS,
            payload={"log_path": "/var/log/syslog", "lines": 10000},
        )
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"many lines", b""))):
            resp = run(ex.execute(request))
        assert resp.status == "success"


# ---------------------------------------------------------------------------
# _transfer_file tests
# ---------------------------------------------------------------------------

class TestTransferFile:
    def _make_safe_local_path(self) -> str:
        """Return a local_path that resolves inside _TRANSFERS_DIR."""
        return str(_TRANSFERS_DIR / "file.tar.gz")

    def test_local_path_outside_transfers_dir_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={
                "local_path": "/etc/passwd",
                "remote_path": "/tmp/passwd",
                "direction": "download",
            },
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"
        assert "local_path" in resp.error_message.lower()

    def test_remote_path_with_dotdot_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={
                "local_path": self._make_safe_local_path(),
                "remote_path": "/var/www/../../../etc/passwd",
                "direction": "download",
            },
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"
        assert ".." in resp.error_message

    def test_missing_local_path_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={
                "remote_path": "/tmp/file",
                "direction": "upload",
            },
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"
        assert "local_path" in resp.error_message.lower()

    def test_missing_remote_path_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={
                "local_path": self._make_safe_local_path(),
                "direction": "upload",
            },
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"
        assert "remote_path" in resp.error_message.lower()

    def test_both_paths_missing_rejected(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={"direction": "upload"},
        )
        resp = run(ex.execute(request))
        assert resp.status == "rejected"

    def test_instance_not_found_returns_error(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            target="i-ghost",
            payload={
                "local_path": self._make_safe_local_path(),
                "remote_path": "/tmp/file",
                "direction": "upload",
            },
        )
        resp = run(ex.execute(request))
        assert resp.status == "error"
        assert "not found" in resp.error_message.lower()

    def test_upload_uses_build_upload_command(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={
                "local_path": self._make_safe_local_path(),
                "remote_path": "/tmp/file.tar.gz",
                "direction": "upload",
            },
        )
        run(ex.execute(request))
        ex._scp_service.build_upload_command.assert_called_once()
        ex._scp_service.build_download_command.assert_not_called()

    def test_download_uses_build_download_command(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={
                "local_path": self._make_safe_local_path(),
                "remote_path": "/tmp/file.tar.gz",
                "direction": "download",
            },
        )
        run(ex.execute(request))
        ex._scp_service.build_download_command.assert_called_once()
        ex._scp_service.build_upload_command.assert_not_called()

    def test_successful_transfer_returns_success(self):
        ex = make_executors()
        ex._scp_service.execute_transfer = AsyncMock(return_value=(0, "", ""))
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={
                "local_path": self._make_safe_local_path(),
                "remote_path": "/tmp/file.tar.gz",
                "direction": "download",
            },
        )
        resp = run(ex.execute(request))
        assert resp.status == "success"
        assert "successful" in resp.output.lower()

    def test_failed_transfer_returns_error(self):
        ex = make_executors()
        ex._scp_service.execute_transfer = AsyncMock(return_value=(1, "", "Permission denied"))
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={
                "local_path": self._make_safe_local_path(),
                "remote_path": "/tmp/file.tar.gz",
                "direction": "upload",
            },
        )
        resp = run(ex.execute(request))
        assert resp.status == "error"
        assert "failed" in resp.error_message.lower()


# ---------------------------------------------------------------------------
# execute() dispatch
# ---------------------------------------------------------------------------

class TestExecuteDispatch:
    def test_dispatch_run_command(self):
        ex = make_executors()
        request = make_request(cmd_type=CommandType.RUN_COMMAND, payload={"command": "ls"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"output", b""))):
            resp = run(ex.execute(request))
        assert resp.status == "success"

    def test_dispatch_get_logs(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.GET_LOGS,
            payload={"log_path": "/var/log/syslog", "lines": 10},
        )
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"log data", b""))):
            resp = run(ex.execute(request))
        assert resp.status == "success"

    def test_dispatch_deploy_falls_through_to_run_command(self):
        ex = make_executors()
        request = make_request(cmd_type=CommandType.DEPLOY, payload={"command": "helm upgrade app"})
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"deployed", b""))):
            resp = run(ex.execute(request))
        assert resp.status == "success"

    def test_dispatch_provision_plan_falls_through_to_run_command(self):
        ex = make_executors()
        request = make_request(
            cmd_type=CommandType.PROVISION_PLAN,
            payload={"command": "terraform plan"},
        )
        with patch("servonaut.services.relay_executors.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"plan output", b""))):
            resp = run(ex.execute(request))
        assert resp.status == "success"

    def test_dispatch_transfer_file(self):
        ex = make_executors()
        ex._scp_service.execute_transfer = AsyncMock(return_value=(0, "", ""))
        request = make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={
                "local_path": str(_TRANSFERS_DIR / "data.tar"),
                "remote_path": "/tmp/data.tar",
                "direction": "upload",
            },
        )
        resp = run(ex.execute(request))
        assert resp.status == "success"

    def test_unexpected_exception_returns_error(self):
        ex = make_executors()
        # Force an unexpected exception in _run_command by making find_instance raise
        ex._aws_service.fetch_instances_cached = AsyncMock(side_effect=RuntimeError("boom"))
        request = make_request(payload={"command": "ls"})
        resp = run(ex.execute(request))
        assert resp.status == "error"
        assert "boom" in resp.error_message
