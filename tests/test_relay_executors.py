"""Tests for RelayExecutors: command dispatch, blocklist, input validation."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.models.relay_messages import CommandRequest, CommandResponse, CommandType
from servonaut.services.relay_executors import RelayExecutors, _TRANSFERS_DIR
from tests._team_policy_fixtures import trust_signed_team_rules


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
    from_agent=False,
):
    return CommandRequest(
        id=req_id,
        user_id=user_id,
        type=cmd_type,
        target_server_id=target,
        payload=payload or {},
        ttl_seconds=ttl,
        from_agent=from_agent,
    )


def run(coro):
    return asyncio.run(coro)


class _VaultLease:
    identity_agent = "/tmp/servonaut-agent.sock"
    identity_file = "/tmp/servonaut-agent-key.pub"
    certificate_path = "/tmp/servonaut-cert.pub"
    known_hosts_path = "/tmp/servonaut-known-hosts"
    login_user = "vault-login"

    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class _VaultRuntime:
    def __init__(self, lease=None, target=None, error=None) -> None:
        self.lease = lease
        self.target = target
        self.error = error
        self.resolved = []

    async def resolve_ssh(self, instance):
        self.resolved.append(instance)
        if self.error is not None:
            raise self.error
        return self.lease

    async def resolve_relay_target(self, identifier):
        if self.target is None:
            return None
        assert identifier == self.target["id"]
        return self.target


class TestNativeVaultRelay:
    def test_native_lease_uses_strict_agent_options_and_closes_after_command(self):
        executor = make_executors()
        lease = _VaultLease()
        runtime = _VaultRuntime(lease=lease)
        executor.set_vault_runtime(runtime)
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            response = run(executor.execute(make_request(payload={"command": "id"})))

        assert response.status == "success"
        call = executor._ssh_service.build_ssh_command.call_args.kwargs
        assert call["username"] == "vault-login"
        assert call["key_path"] is None
        assert call["identity_agent"] == "/tmp/servonaut-agent.sock"
        assert call["identity_file"] == "/tmp/servonaut-agent-key.pub"
        assert call["certificate_file"] == "/tmp/servonaut-cert.pub"
        assert call["known_hosts_file"] == "/tmp/servonaut-known-hosts"
        assert call["extra_options"] == ["BatchMode=yes"]
        assert lease.closed == 1

    def test_native_runtime_failure_never_falls_back_to_local_key(self):
        executor = make_executors()
        executor.set_vault_runtime(_VaultRuntime(error=ValueError("binding signature invalid")))

        response = run(executor.execute(make_request(payload={"command": "id"})))

        assert response.status == "error"
        assert "binding signature invalid" in response.error_message
        executor._ssh_service.build_ssh_command.assert_not_called()

    def test_native_binding_without_runtime_never_uses_local_key(self):
        executor = make_executors(instances=[{
            "id": "i-native", "name": "native", "hostname": "native.example.test",
            "credential_binding": {"source": "servonaut_vault"},
        }])

        response = run(executor.execute(make_request(
            target="i-native", payload={"command": "id"},
        )))

        assert response.status == "error"
        assert "no active vault runtime" in response.error_message
        executor._ssh_service.build_ssh_command.assert_not_called()

    def test_native_binding_without_lease_never_uses_local_key(self):
        executor = make_executors(instances=[{
            "id": "i-native", "name": "native", "hostname": "native.example.test",
            "credential_binding": {"source": "servonaut_vault"},
        }])
        executor.set_vault_runtime(_VaultRuntime())

        response = run(executor.execute(make_request(
            target="i-native", payload={"command": "id"},
        )))

        assert response.status == "error"
        assert "did not return an SSH lease" in response.error_message
        executor._ssh_service.build_ssh_command.assert_not_called()

    def test_native_lease_without_public_identity_file_never_uses_local_key(self):
        executor = make_executors()
        lease = _VaultLease()
        lease.identity_file = ""
        executor.set_vault_runtime(_VaultRuntime(lease=lease))

        response = run(executor.execute(make_request(payload={"command": "id"})))

        assert response.status == "error"
        assert "strict connection metadata" in response.error_message
        executor._ssh_service.build_ssh_command.assert_not_called()

    def test_command_error_still_closes_native_lease(self):
        executor = make_executors()
        lease = _VaultLease()
        executor.set_vault_runtime(_VaultRuntime(lease=lease))
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(side_effect=RuntimeError("connection lost")),
        ):
            response = run(executor.execute(make_request(payload={"command": "id"})))

        assert response.status == "error"
        assert "connection lost" in response.error_message
        assert lease.closed == 1

    def test_runtime_discovers_shared_target_for_a_signed_lease(self):
        shared = {
            "id": "c2a4e6f8-1b3d-4f5a-9c7e-0a2b4c6d8e1f",
            "name": "shared-web", "is_shared": True, "team_slug": "example-team",
            "team_role": "member",
            "hostname": "shared.example.test", "port": 22,
        }
        executor = make_executors(instances=[])
        lease = _VaultLease()
        runtime = _VaultRuntime(lease=lease, target=shared)
        executor.set_vault_runtime(runtime)
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            response = run(executor.execute(make_request(
                target=shared["id"], payload={"command": "hostname"},
            )))

        assert response.status == "success"
        # The team's record, kept whole, as a server-list row with its host.
        resolved = runtime.resolved[0]
        assert {key: resolved[key] for key in shared} == shared
        assert resolved["public_ip"] == "shared.example.test"
        assert lease.closed == 1

    def test_native_scp_uses_agent_metadata_and_closes_lease(self, tmp_path, monkeypatch):
        import servonaut.services.relay_executors as executors_module

        transfers = tmp_path / "transfers"
        transfers.mkdir()
        local = transfers / "file.txt"
        local.write_text("payload", encoding="utf-8")
        monkeypatch.setattr(executors_module, "_TRANSFERS_DIR", transfers)
        executor = make_executors()
        lease = _VaultLease()
        executor.set_vault_runtime(_VaultRuntime(lease=lease))
        response = run(executor.execute(make_request(
            cmd_type=CommandType.TRANSFER_FILE,
            payload={"local_path": str(local), "remote_path": "/tmp/file.txt", "direction": "upload"},
        )))

        assert response.status == "success"
        call = executor._scp_service.build_upload_command.call_args.kwargs
        assert call["key_path"] is None
        assert call["username"] == "vault-login"
        assert call["identity_agent"] == "/tmp/servonaut-agent.sock"
        assert call["identity_file"] == "/tmp/servonaut-agent-key.pub"
        assert call["certificate_file"] == "/tmp/servonaut-cert.pub"
        assert call["known_hosts_file"] == "/tmp/servonaut-known-hosts"
        assert call["extra_options"] == ["BatchMode=yes"]
        assert lease.closed == 1


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
        # Force an unexpected exception in _run_command by making find_instance
        # raise (a provider that cannot be listed is tolerated by the lookup).
        ex._find_instance = AsyncMock(side_effect=RuntimeError("boom"))
        request = make_request(payload={"command": "ls"})
        resp = run(ex.execute(request))
        assert resp.status == "error"
        assert "boom" in resp.error_message


class _PinnedLease(_VaultLease):
    target_host = "pinned.example.com"
    target_port = 2200


class TestSharedServerRelayTarget:
    """A team's shared server found through the vault, as the relay reaches it."""

    _TARGET = {
        "id": "srv-1", "name": "team-web-1", "hostname": "team-web.example.com",
        "port": 22, "login_user": "deploy", "is_shared": True, "team_slug": "ops",
        "team_name": "Ops", "team_role": "member",
    }

    def test_the_team_record_becomes_a_row_with_its_host(self):
        executor = make_executors(instances=[])
        runtime = _VaultRuntime(lease=_VaultLease(), target=dict(self._TARGET))
        executor.set_vault_runtime(runtime)
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            response = run(executor.execute(make_request(
                target="srv-1", payload={"command": "uptime"},
            )))

        assert response.status == "success"
        resolved = runtime.resolved[0]
        assert resolved["public_ip"] == "team-web.example.com"
        assert resolved["team_slug"] == "ops"

    def test_commands_and_transfers_connect_where_the_lease_points(self):
        executor = make_executors(instances=[])
        executor.set_vault_runtime(_VaultRuntime(lease=_PinnedLease(), target=dict(self._TARGET)))
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            run(executor.execute(make_request(target="srv-1", payload={"command": "uptime"})))

        command = executor._ssh_service.build_ssh_command.call_args.kwargs
        assert (command["host"], command["port"]) == ("pinned.example.com", 2200)


class TestTeamRulesOnRelay:
    """An agent's relayed requests on a team's shared server run under the team's rule."""

    _TARGET = {
        "id": "srv-1", "name": "team-web-1", "hostname": "team-web.example.com",
        "port": 22, "login_user": "deploy", "is_shared": True, "team_slug": "ops",
        "team_name": "Ops",
    }

    @pytest.fixture(autouse=True)
    def _signed_team_rules(self):
        # Team Ops has verified signed rules: the format 1 defaults.
        trust_signed_team_rules("ops")

    def _executor(self, role="member", level="dangerous", allowlist=None, blocklist=None,
                  target=None):
        executor = make_executors()
        target = dict(target or self._TARGET)
        if role is not None:
            target["team_role"] = role
        executor.set_vault_runtime(_VaultRuntime(lease=_VaultLease(), target=target))
        # Set after construction: only what the executor reads per call
        # (the team guard) sees these settings, not the blocklist it
        # compiled when it was built.
        config = MCPConfig(guard_level=level)
        if allowlist is not None:
            config.command_allowlist = allowlist
        if blocklist is not None:
            config.command_blocklist = blocklist
        executor._config_manager.get.return_value = AppConfig(mcp=config)
        executor._audit = MagicMock()
        return executor

    @staticmethod
    def _audit_rows(executor):
        return [
            (call.args[0], call.args[4], call.kwargs.get("source"))
            for call in executor._audit.log.call_args_list
        ]

    @staticmethod
    def _ssh_ok():
        return patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        )

    def test_what_a_person_sends_keeps_todays_rules(self):
        # The web console and approved remediations are not an agent's.
        executor = self._executor(level="dangerous")
        with self._ssh_ok():
            response = run(executor.execute(make_request(
                target="srv-1", payload={"command": "systemctl restart nginx"},
            )))

        assert response.status == "success"
        executor._audit.log.assert_not_called()

    def test_a_command_the_team_does_not_allow_is_rejected(self):
        executor = self._executor(level="dangerous")
        with self._ssh_ok():
            response = run(executor.execute(make_request(from_agent=True, 
                target="srv-1", payload={"command": "systemctl restart nginx"},
            )))

        assert response.status == "rejected"
        assert response.error_message == (
            "Blocked: on team Ops's shared servers your agents run at the "
            "standard level (set by the team), and 'systemctl restart nginx' is "
            "not an allowed command there."
        )
        executor._ssh_service.build_ssh_command.assert_not_called()

    def test_the_same_command_runs_on_an_own_server(self):
        executor = self._executor(level="dangerous")
        with self._ssh_ok():
            response = run(executor.execute(make_request(from_agent=True, 
                target="i-abc123", payload={"command": "systemctl restart nginx"},
            )))

        assert response.status == "success"
        remote = executor._ssh_service.build_ssh_command.call_args.kwargs["remote_command"]
        assert remote == "systemctl restart nginx"

    def test_an_allowed_command_runs_as_the_team_guard_rendered_it(self):
        executor = self._executor()
        with self._ssh_ok():
            response = run(executor.execute(make_request(from_agent=True, 
                target="srv-1", payload={"command": "ps aux | grep 'nginx'"},
            )))

        assert response.status == "success"
        remote = executor._ssh_service.build_ssh_command.call_args.kwargs["remote_command"]
        assert remote == "ps aux | grep nginx"

    def test_quoting_does_not_hide_a_command_from_a_team_pattern(self):
        trust_signed_team_rules("ops", {
            "role_levels": {"owner": "standard", "admin": "standard",
                            "member": "standard", "viewer": "readonly"},
            "servers": {}, "command_allowlist": None, "command_blocklist": ["/etc/shadow"],
        }, version=2)
        executor = self._executor(level="dangerous")
        with self._ssh_ok():
            response = run(executor.execute(make_request(
                from_agent=True, target="srv-1", payload={"command": "cat /etc/sh'adow'"},
            )))

        assert response.status == "rejected"
        assert response.error_message.endswith(
            "is refused there: it matches the blocked pattern /etc/shadow."
        )
        executor._ssh_service.build_ssh_command.assert_not_called()
        assert self._audit_rows(executor) == [("run_command", "team_rule", "relay")]

    def test_a_team_pattern_too_slow_to_check_refuses_the_command(self):
        trust_signed_team_rules("ops", {
            "role_levels": {"owner": "standard", "admin": "standard",
                            "member": "dangerous", "viewer": "readonly"},
            "servers": {}, "command_allowlist": None, "command_blocklist": [r"^(a|aa)+$"],
        }, version=2)
        executor = self._executor(level="dangerous")
        executor._config_manager.get.return_value.mcp.team_pattern_timeout_ms = 20
        with self._ssh_ok():
            response = run(executor.execute(make_request(
                from_agent=True, target="srv-1", payload={"command": "a" * 60 + "b"},
            )))

        assert response.status == "rejected"
        assert response.error_message.endswith(
            "the team's blocked pattern '^(a|aa)+$' takes too long to check "
            "(a team owner or admin can change it)."
        )
        executor._ssh_service.build_ssh_command.assert_not_called()
        assert self._audit_rows(executor) == [("run_command", "team_rule", "relay")]

    def test_a_local_allowlist_addition_does_not_apply(self):
        allowlist = [*MCPConfig().command_allowlist, "systemctl"]
        executor = self._executor(level="standard", allowlist=allowlist)
        response = run(executor.execute(make_request(from_agent=True, 
            target="srv-1", payload={"command": "systemctl status nginx"},
        )))

        assert response.status == "rejected"

    @pytest.mark.parametrize("role", ["viewer", None])
    def test_a_viewer_or_an_unknown_role_runs_nothing(self, role):
        executor = self._executor(role=role)
        response = run(executor.execute(make_request(from_agent=True, 
            target="srv-1", payload={"command": "uptime"},
        )))

        assert response.status == "rejected"
        assert "run at the readonly level" in response.error_message

    def test_logs_are_read_at_the_standard_level(self):
        executor = self._executor()
        with self._ssh_ok():
            response = run(executor.execute(make_request(from_agent=True, 
                cmd_type=CommandType.GET_LOGS, target="srv-1",
                payload={"log_path": "/var/log/syslog", "lines": 10},
            )))

        assert response.status == "success"

    def test_transfers_are_rejected(self, tmp_path, monkeypatch):
        import servonaut.services.relay_executors as executors_module

        transfers = tmp_path / "transfers"
        transfers.mkdir()
        monkeypatch.setattr(executors_module, "_TRANSFERS_DIR", transfers)
        executor = self._executor(role="owner")
        response = run(executor.execute(make_request(from_agent=True, 
            cmd_type=CommandType.TRANSFER_FILE, target="srv-1",
            payload={
                "local_path": str(transfers / "file.txt"),
                "remote_path": "/tmp/file.txt", "direction": "download",
            },
        )))

        assert response.status == "rejected"
        assert "file transfers are not available there" in response.error_message
        executor._scp_service.execute_transfer.assert_not_called()

    def test_the_hosted_ai_path_gets_the_same_refusal(self):
        from servonaut.services.ai_tool_bridge import ToolCall

        executor = self._executor()
        result = run(executor.execute_for_ai(ToolCall(
            tool_call_id="tc-1", tool="run_command",
            args={"instance_id": "srv-1", "command": "systemctl restart nginx"},
            guard_level="standard", conversation_id="conv-1",
        )))

        assert result.status == "error"
        assert "is not an allowed command there" in result.result

    def test_a_local_blocklist_addition_made_after_start_applies(self):
        # The executor compiled its own blocklist when it was built, so only
        # the team guard (which reads the settings per call) can refuse this.
        blocklist = [*MCPConfig().command_blocklist, r"\buptime\b"]
        executor = self._executor(blocklist=blocklist)
        response = run(executor.execute(make_request(from_agent=True, 
            target="srv-1", payload={"command": "uptime"},
        )))

        assert response.status == "rejected"
        assert response.error_message.endswith(
            "and 'uptime' is refused there: it matches the blocked pattern \\buptime\\b."
        )
        assert self._audit_rows(executor) == [("run_command", "team_rule", "relay")]
        executor._ssh_service.build_ssh_command.assert_not_called()

    def test_a_local_readonly_level_stays_readonly(self):
        executor = self._executor(role="owner", level="readonly")
        response = run(executor.execute(make_request(from_agent=True, 
            target="srv-1", payload={"command": "uptime"},
        )))

        assert response.error_message == (
            "Blocked: on team Ops's shared servers your agents run at the "
            "readonly level (set by your MCP settings), and running commands is "
            "not available there."
        )
        assert self._audit_rows(executor) == [("run_command", "team_rule", "relay")]

    def test_every_refusal_is_audited_as_team_rule(self, tmp_path, monkeypatch):
        import servonaut.services.relay_executors as executors_module

        transfers = tmp_path / "transfers"
        transfers.mkdir()
        monkeypatch.setattr(executors_module, "_TRANSFERS_DIR", transfers)
        executor = self._executor(role="viewer")
        run(executor.execute(make_request(from_agent=True, 
            target="srv-1", payload={"command": "uptime"},
        )))
        run(executor.execute(make_request(from_agent=True, 
            cmd_type=CommandType.TRANSFER_FILE, target="srv-1",
            payload={
                "local_path": str(transfers / "file.txt"),
                "remote_path": "/tmp/file.txt", "direction": "download",
            },
        )))

        assert self._audit_rows(executor) == [
            ("run_command", "team_rule", "relay"), ("transfer_file", "team_rule", "relay"),
        ]
        audited = executor._audit.log.call_args_list[0]
        assert audited.args[1] == {
            "instance_id": "srv-1", "request_type": "run_command", "command": "uptime",
        }
        assert audited.args[3] is False

    def test_without_an_audit_trail_the_configured_one_is_used(self, tmp_path):
        import json

        executor = self._executor(level="dangerous")
        executor._audit = None
        audit_path = tmp_path / "mcp_audit.jsonl"
        executor._config_manager.get.return_value.mcp.audit_path = str(audit_path)
        run(executor.execute(make_request(from_agent=True, 
            target="srv-1", payload={"command": "systemctl restart nginx"},
        )))

        rows = [json.loads(line) for line in audit_path.read_text().splitlines()]
        assert [(row["tool"], row["reason"]) for row in rows] == [("run_command", "team_rule")]

    def test_an_option_the_standard_level_refuses_is_named(self):
        executor = self._executor()
        response = run(executor.execute(make_request(from_agent=True, 
            target="srv-1", payload={"command": "find / -name x -delete"},
        )))

        assert response.error_message.endswith(
            "and 'find / -name x -delete' is refused there: find actions that run "
            "programs, delete or write files are not allowed."
        )

    def test_a_log_read_is_refused_as_a_log_read(self):
        executor = self._executor(role="viewer")
        response = run(executor.execute(make_request(from_agent=True, 
            cmd_type=CommandType.GET_LOGS, target="srv-1",
            payload={"log_path": "/var/log/syslog", "lines": 10},
        )))

        assert response.status == "rejected"
        assert response.error_message.endswith("and reading logs is not available there.")
        audited = executor._audit.log.call_args
        assert audited.args[1]["requested_as"] == "reading logs"

    def test_a_remediation_is_refused_by_name_not_by_its_wrapped_command(self):
        from servonaut.services.remediation_executor import wrap_with_exit_marker

        executor = self._executor(role="owner")
        request = make_request(from_agent=True, target="srv-1", payload={
            "command": wrap_with_exit_marker("sudo -n systemctl restart nginx", "abc"),
        })
        request.requested_as = "the restart_service remediation"
        response = run(executor.execute(request))

        assert response.status == "rejected"
        assert response.error_message.endswith(
            "and the restart_service remediation is not allowed there."
        )
        assert "rc=$?" not in response.error_message

    def test_a_team_without_a_name_reads_naturally(self):
        target = {**self._TARGET, "team_slug": "", "team_name": ""}
        executor = self._executor(target=target)
        response = run(executor.execute(make_request(from_agent=True, 
            target="srv-1", payload={"command": "systemctl restart nginx"},
        )))

        assert response.error_message.startswith(
            "Blocked: on this team's shared servers your agents run at"
        )

    def test_a_team_without_verified_rules_runs_nothing_and_says_why(self):
        target = {**self._TARGET, "team_slug": "db-team", "team_name": "DB"}
        executor = self._executor(role="owner", target=target)
        response = run(executor.execute(make_request(from_agent=True,
            target="srv-1", payload={"command": "uptime"},
        )))

        assert response.status == "rejected"
        assert response.error_message == (
            "Blocked: on team DB's shared servers your agents run at the readonly "
            "level (because the team's agent rules have not been loaded yet), and "
            "running commands is not available there."
        )
        assert self._audit_rows(executor) == [("run_command", "team_rule", "relay")]
        executor._ssh_service.build_ssh_command.assert_not_called()


class _TeamKeyRuntime(_VaultRuntime):
    """A vault runtime whose own-server binding uses team *slug*'s vault key."""

    def __init__(self, slug="ops", error=None, servers=()) -> None:
        super().__init__(lease=None)
        self.slug = slug
        self.check_error = error
        self.teams = MagicMock()
        self.teams.list_teams = AsyncMock(
            return_value=[{"id": "team-id-ops", "slug": "ops", "name": "Ops", "role": "member"}],
        )
        self.teams.list_shared_servers = AsyncMock(return_value=list(servers))

    async def credential_team(self, instance):
        if self.check_error is not None:
            raise self.check_error
        return self.slug


class TestTeamRulesFetchedOnRelay:
    """The relay fetches a team's rules before an agent acts, when they are not in force."""

    _TARGET = TestTeamRulesOnRelay._TARGET

    def _executor(self, refresher):
        executor = make_executors()
        executor.set_vault_runtime(_VaultRuntime(lease=_VaultLease(), target=dict(
            self._TARGET, team_role="member",
        )))
        executor.set_team_policy(refresher)
        executor._audit = MagicMock()
        return executor

    def test_an_agents_request_makes_sure_the_teams_rules_are_loaded(self):
        trust_signed_team_rules("ops")
        refresher = MagicMock(ensure_loaded=AsyncMock())
        executor = self._executor(refresher)
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            response = run(executor.execute(make_request(
                from_agent=True, target="srv-1", payload={"command": "uptime"},
            )))

        assert response.status == "success"
        refresher.ensure_loaded.assert_awaited_once_with("ops")

    def test_what_a_person_sends_fetches_nothing(self):
        refresher = MagicMock(ensure_loaded=AsyncMock())
        executor = self._executor(refresher)
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            run(executor.execute(make_request(target="srv-1", payload={"command": "uptime"})))

        refresher.ensure_loaded.assert_not_awaited()


class TestTeamKeyOnAnOwnServerOnRelay:
    """An own server reached with a team's vault key runs an agent's request under that team's rules."""

    def _executor(self, runtime, level="dangerous"):
        executor = make_executors()
        executor.set_vault_runtime(runtime)
        executor._config_manager.get.return_value = AppConfig(mcp=MCPConfig(guard_level=level))
        executor._audit = MagicMock()
        return executor

    def test_the_teams_rule_refuses_what_local_settings_allow(self):
        trust_signed_team_rules("ops", {
            "role_levels": {"owner": "standard", "admin": "standard",
                            "member": "readonly", "viewer": "readonly"},
            "servers": {}, "command_allowlist": None, "command_blocklist": [],
        })
        executor = self._executor(_TeamKeyRuntime())
        response = run(executor.execute(make_request(
            from_agent=True, target="i-abc123", payload={"command": "uptime"},
        )))

        # Without the check the own server ran it under the local dangerous level.
        assert response.status == "rejected"
        assert response.error_message == (
            "Blocked: on team Ops's shared servers your agents run at the "
            "readonly level (set by the team), and running commands is not "
            "available there."
        )
        executor._ssh_service.build_ssh_command.assert_not_called()

    def test_the_teams_server_override_applies_when_the_team_shares_it(self):
        trust_signed_team_rules("ops", {
            "role_levels": {"owner": "standard", "admin": "standard",
                            "member": "standard", "viewer": "readonly"},
            "servers": {"srv-1": {"role_levels": {"member": "readonly"}}},
            "command_allowlist": None, "command_blocklist": [],
        })
        shared_copy = {"id": "srv-1", "name": "web-server", "hostname": "54.1.2.3", "port": 22}
        executor = self._executor(_TeamKeyRuntime(servers=[shared_copy]))
        response = run(executor.execute(make_request(
            from_agent=True, target="i-abc123", payload={"command": "uptime"},
        )))

        assert response.status == "rejected"
        assert "run at the readonly level (set by the team)" in response.error_message

    def test_a_personal_key_keeps_the_local_rules(self):
        executor = self._executor(_TeamKeyRuntime(slug=None))
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            response = run(executor.execute(make_request(
                from_agent=True, target="i-abc123",
                payload={"command": "systemctl restart nginx"},
            )))

        assert response.status == "success"

    def test_a_key_that_cannot_be_checked_refuses_the_request_and_is_audited(self):
        executor = self._executor(_TeamKeyRuntime(error=RuntimeError("vault offline")))
        response = run(executor.execute(make_request(
            from_agent=True, target="i-abc123", payload={"command": "uptime"},
        )))

        assert response.status == "rejected"
        assert response.error_message == (
            "Error: could not check which vault key this server uses, so agents "
            "cannot act on it right now. Try again shortly."
        )
        assert "vault offline" not in response.error_message
        executor._ssh_service.build_ssh_command.assert_not_called()
        assert [
            (call.args[0], call.args[4], call.kwargs.get("source"))
            for call in executor._audit.log.call_args_list
        ] == [("run_command", "credential_check_failed", "relay")]

    def test_a_transfer_whose_key_cannot_be_checked_is_audited_too(self):
        executor = self._executor(_TeamKeyRuntime(error=RuntimeError("vault offline")))
        response = run(executor.execute(make_request(
            cmd_type=CommandType.TRANSFER_FILE, from_agent=True, target="i-abc123",
            payload={"local_path": str(_TRANSFERS_DIR / "a.txt"), "remote_path": "/tmp/b",
                     "direction": "download"},
        )))

        assert response.status == "rejected"
        assert executor._audit.log.call_args.args[4] == "credential_check_failed"
        executor._scp_service.execute_transfer.assert_not_called()

    def test_whose_key_it_is_is_remembered_between_requests(self):
        trust_signed_team_rules("ops")
        runtime = _TeamKeyRuntime()
        runtime.credential_team = AsyncMock(return_value="ops")
        executor = self._executor(runtime)
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            for request_id in ("req-1", "req-2"):
                response = run(executor.execute(make_request(
                    from_agent=True, req_id=request_id, target="i-abc123",
                    payload={"command": "uptime"},
                )))
                assert response.status == "success"

        # Without the memo every request cost these API calls again.
        runtime.credential_team.assert_awaited_once()
        runtime.teams.list_teams.assert_awaited_once()
        runtime.teams.list_shared_servers.assert_awaited_once()

    def test_a_new_vault_runtime_checks_the_key_again(self):
        trust_signed_team_rules("ops")
        first = _TeamKeyRuntime()
        first.credential_team = AsyncMock(return_value="ops")
        executor = self._executor(first)
        run(executor.execute(make_request(
            from_agent=True, target="i-abc123", payload={"command": "systemctl restart nginx"},
        )))
        second = _TeamKeyRuntime(slug=None)
        executor.set_vault_runtime(second)
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            response = run(executor.execute(make_request(
                from_agent=True, target="i-abc123", payload={"command": "systemctl restart nginx"},
            )))

        assert response.status == "success"

    def test_what_a_person_sends_keeps_todays_rules(self):
        trust_signed_team_rules("ops")
        runtime = _TeamKeyRuntime()
        executor = self._executor(runtime)
        with patch(
            "servonaut.services.relay_executors.run_ssh_subprocess",
            new=AsyncMock(return_value=(b"ok", b"")),
        ):
            response = run(executor.execute(make_request(
                target="i-abc123", payload={"command": "systemctl restart nginx"},
            )))

        assert response.status == "success"
