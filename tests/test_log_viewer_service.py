"""Tests for LogViewerService."""

from __future__ import annotations

import asyncio
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig
from servonaut.services.log_viewer_service import LogViewerService


class FakeConfigManager:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._saved: List[AppConfig] = []

    def get(self) -> AppConfig:
        return self._config

    def save(self, config: AppConfig) -> None:
        self._config = config
        self._saved.append(config)


@pytest.fixture
def default_service():
    config = AppConfig()
    manager = FakeConfigManager(config)
    return LogViewerService(manager)


@pytest.fixture
def service_with_custom():
    config = AppConfig(
        log_viewer_custom_paths={"i-abc123": ["/var/log/app.log", "/tmp/debug.log"]}
    )
    manager = FakeConfigManager(config)
    return LogViewerService(manager)


class TestGetTailCommand:

    def test_follow_mode(self, default_service):
        cmd = default_service.get_tail_command("/var/log/syslog")
        assert cmd == "tail -n 100 -f /var/log/syslog"

    def test_no_follow(self, default_service):
        cmd = default_service.get_tail_command("/var/log/syslog", follow=False)
        assert cmd == "tail -n 100 /var/log/syslog"

    def test_custom_num_lines(self, default_service):
        cmd = default_service.get_tail_command("/var/log/auth.log", num_lines=50)
        assert cmd == "tail -n 50 -f /var/log/auth.log"

    def test_custom_num_lines_no_follow(self, default_service):
        cmd = default_service.get_tail_command("/var/log/nginx/access.log", num_lines=200, follow=False)
        assert cmd == "tail -n 200 /var/log/nginx/access.log"


class TestGetCustomPaths:

    def test_unknown_instance_returns_empty(self, default_service):
        result = default_service.get_custom_paths("i-unknown")
        assert result == []

    def test_known_instance_returns_paths(self, service_with_custom):
        result = service_with_custom.get_custom_paths("i-abc123")
        assert result == ["/var/log/app.log", "/tmp/debug.log"]

    def test_returns_copy_not_reference(self, service_with_custom):
        result = service_with_custom.get_custom_paths("i-abc123")
        result.append("/extra")
        assert "/extra" not in service_with_custom.get_custom_paths("i-abc123")


class TestSetCustomPaths:

    def test_persists_paths(self, default_service):
        default_service.set_custom_paths("i-new", ["/var/log/app.log"])
        assert default_service.get_custom_paths("i-new") == ["/var/log/app.log"]

    def test_saves_config(self, default_service):
        manager = default_service._config_manager
        default_service.set_custom_paths("i-abc", ["/log/a", "/log/b"])
        assert len(manager._saved) == 1
        assert manager._saved[0].log_viewer_custom_paths["i-abc"] == ["/log/a", "/log/b"]

    def test_overwrites_existing(self, service_with_custom):
        service_with_custom.set_custom_paths("i-abc123", ["/new/path.log"])
        assert service_with_custom.get_custom_paths("i-abc123") == ["/new/path.log"]


class TestClassifyLogFile:

    def test_active_log(self, default_service):
        assert default_service.classify_log_file("/var/log/syslog") == "active"

    def test_active_log_with_extension(self, default_service):
        assert default_service.classify_log_file("/var/log/nginx/access.log") == "active"

    def test_compressed_gz(self, default_service):
        assert default_service.classify_log_file("/var/log/syslog.2.gz") == "compressed"

    def test_compressed_bz2(self, default_service):
        assert default_service.classify_log_file("/var/log/auth.log.1.bz2") == "compressed"

    def test_compressed_xz(self, default_service):
        assert default_service.classify_log_file("/var/log/messages.xz") == "compressed"

    def test_compressed_zst(self, default_service):
        assert default_service.classify_log_file("/var/log/journal.zst") == "compressed"

    def test_rotated_single_digit(self, default_service):
        assert default_service.classify_log_file("/var/log/syslog.1") == "rotated"

    def test_rotated_multi_digit(self, default_service):
        assert default_service.classify_log_file("/var/log/auth.log.10") == "rotated"

    def test_gz_takes_priority_over_rotated(self, default_service):
        # e.g. syslog.3.gz should be "compressed" not "rotated"
        assert default_service.classify_log_file("/var/log/syslog.3.gz") == "compressed"


class TestGetReadCommand:

    def test_active_uses_tail_follow(self, default_service):
        cmd = default_service.get_read_command("/var/log/syslog")
        assert cmd == "tail -n 100 -f /var/log/syslog"

    def test_active_custom_lines(self, default_service):
        cmd = default_service.get_read_command("/var/log/syslog", num_lines=50)
        assert cmd == "tail -n 50 -f /var/log/syslog"

    def test_rotated_uses_tail_no_follow(self, default_service):
        cmd = default_service.get_read_command("/var/log/syslog.1")
        assert cmd == "tail -n 100 /var/log/syslog.1"
        assert "-f" not in cmd

    def test_compressed_gz_uses_zcat(self, default_service):
        cmd = default_service.get_read_command("/var/log/syslog.2.gz")
        assert cmd == "zcat /var/log/syslog.2.gz"

    def test_compressed_bz2_uses_bzcat(self, default_service):
        cmd = default_service.get_read_command("/var/log/auth.log.1.bz2")
        assert cmd == "bzcat /var/log/auth.log.1.bz2"

    def test_compressed_xz_uses_xzcat(self, default_service):
        cmd = default_service.get_read_command("/var/log/messages.xz")
        assert cmd == "xzcat /var/log/messages.xz"

    def test_compressed_zst_uses_zstdcat(self, default_service):
        cmd = default_service.get_read_command("/var/log/journal.zst")
        assert cmd == "zstdcat /var/log/journal.zst"


class TestResolveConnection:

    def test_custom_server(self, default_service):
        instance = {
            "id": "custom-1",
            "name": "my-server",
            "public_ip": "1.2.3.4",
            "private_ip": "10.0.0.1",
            "username": "admin",
            "key_name": "/home/user/.ssh/id_rsa",
            "port": 2222,
            "is_custom": True,
        }
        mock_ssh = MagicMock()
        mock_conn = MagicMock()

        result = default_service._resolve_connection(instance, mock_ssh, mock_conn)

        assert result["host"] == "1.2.3.4"
        assert result["username"] == "admin"
        assert result["key_path"] == "/home/user/.ssh/id_rsa"
        assert result["proxy_args"] == []
        assert result["port"] == 2222

    def test_custom_server_fallback_private_ip(self, default_service):
        instance = {
            "id": "custom-2",
            "public_ip": "",
            "private_ip": "10.0.0.5",
            "is_custom": True,
        }
        mock_ssh = MagicMock()
        mock_conn = MagicMock()

        result = default_service._resolve_connection(instance, mock_ssh, mock_conn)
        assert result["host"] == "10.0.0.5"
        assert result["username"] == "root"

    def test_aws_instance_with_profile(self, default_service):
        instance = {
            "id": "i-abc123",
            "name": "web-server",
            "public_ip": "54.1.2.3",
            "private_ip": "10.0.0.1",
            "key_name": "prod-key",
        }

        mock_ssh = MagicMock()
        mock_ssh.get_key_path.return_value = None
        mock_ssh.discover_key.return_value = "/home/user/.ssh/prod-key.pem"

        mock_profile = MagicMock()
        mock_profile.username = None
        mock_conn = MagicMock()
        mock_conn.resolve_profile.return_value = mock_profile
        mock_conn.get_target_host.return_value = "54.1.2.3"
        mock_conn.get_proxy_args.return_value = ["-J", "bastion@jump"]

        result = default_service._resolve_connection(instance, mock_ssh, mock_conn)

        assert result["host"] == "54.1.2.3"
        assert result["username"] == "ec2-user"
        assert result["key_path"] == "/home/user/.ssh/prod-key.pem"
        assert result["proxy_args"] == ["-J", "bastion@jump"]
        assert result["port"] is None

    def test_aws_instance_no_profile(self, default_service):
        instance = {
            "id": "i-def456",
            "name": "api-server",
            "public_ip": "54.4.5.6",
            "key_name": "api-key",
        }

        mock_ssh = MagicMock()
        mock_ssh.get_key_path.return_value = "/home/user/.ssh/api-key.pem"

        mock_conn = MagicMock()
        mock_conn.resolve_profile.return_value = None
        mock_conn.get_target_host.return_value = "54.4.5.6"

        result = default_service._resolve_connection(instance, mock_ssh, mock_conn)

        assert result["host"] == "54.4.5.6"
        assert result["proxy_args"] == []
        assert result["key_path"] == "/home/user/.ssh/api-key.pem"


class TestProbeLogPaths:

    @pytest.fixture
    def instance(self):
        return {
            "id": "i-abc123",
            "name": "web-server",
            "public_ip": "54.1.2.3",
            "private_ip": "10.0.0.1",
            "key_name": "prod-key",
            "state": "running",
        }

    @pytest.fixture
    def mock_ssh_service(self):
        svc = MagicMock()
        svc.get_key_path.return_value = None
        svc.discover_key.return_value = "/home/user/.ssh/prod-key.pem"
        svc.build_ssh_command.return_value = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "ec2-user@54.1.2.3", "test -r /var/log/syslog && echo /var/log/syslog",
        ]
        return svc

    @pytest.fixture
    def mock_connection_service(self):
        svc = MagicMock()
        svc.resolve_profile.return_value = None
        svc.get_target_host.return_value = "54.1.2.3"
        svc.get_proxy_args.return_value = []
        return svc

    def test_returns_readable_paths(self, default_service, instance, mock_ssh_service, mock_connection_service):
        readable_output = b"/var/log/syslog\n/var/log/auth.log\n"

        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(return_value=(readable_output, b""))
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = asyncio.run(
                default_service.probe_log_paths(instance, mock_ssh_service, mock_connection_service)
            )

        assert "/var/log/syslog" in result
        assert "/var/log/auth.log" in result

    def test_returns_empty_on_timeout(self, default_service, instance, mock_ssh_service, mock_connection_service):
        with patch("asyncio.create_subprocess_exec", side_effect=asyncio.TimeoutError):
            result = asyncio.run(
                default_service.probe_log_paths(instance, mock_ssh_service, mock_connection_service)
            )

        assert result == []

    def test_returns_empty_on_exception(self, default_service, instance, mock_ssh_service, mock_connection_service):
        with patch("asyncio.create_subprocess_exec", side_effect=OSError("connection refused")):
            result = asyncio.run(
                default_service.probe_log_paths(instance, mock_ssh_service, mock_connection_service)
            )

        assert result == []

    def test_includes_custom_paths_in_probe(self, instance, mock_ssh_service, mock_connection_service):
        config = AppConfig(
            log_viewer_custom_paths={"i-abc123": ["/var/log/app.log"]}
        )
        manager = FakeConfigManager(config)
        service = LogViewerService(manager)

        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(return_value=(b"/var/log/app.log\n", b""))
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            asyncio.run(
                service.probe_log_paths(instance, mock_ssh_service, mock_connection_service)
            )

        # The SSH command's remote_command arg should include the custom path
        call_kwargs = mock_ssh_service.build_ssh_command.call_args
        remote_cmd = call_kwargs[1].get("remote_command", "") or ""
        assert "/var/log/app.log" in remote_cmd


class TestScanLogDirectories:

    @pytest.fixture
    def instance(self):
        return {
            "id": "i-abc123",
            "name": "web-server",
            "public_ip": "54.1.2.3",
            "private_ip": "10.0.0.1",
            "key_name": "prod-key",
        }

    @pytest.fixture
    def mock_ssh_service(self):
        svc = MagicMock()
        svc.get_key_path.return_value = None
        svc.discover_key.return_value = "/home/user/.ssh/prod-key.pem"
        svc.build_ssh_command.return_value = ["ssh", "user@host", "find ..."]
        return svc

    @pytest.fixture
    def mock_connection_service(self):
        svc = MagicMock()
        svc.resolve_profile.return_value = None
        svc.get_target_host.return_value = "54.1.2.3"
        return svc

    def test_returns_sorted_deduplicated_paths(
        self, default_service, instance, mock_ssh_service, mock_connection_service
    ):
        find_output = b"/var/log/auth.log\n/var/log/syslog\n/var/log/syslog\n/var/log/auth.log\n"

        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(return_value=(find_output, b""))
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = asyncio.run(
                default_service.scan_log_directories(
                    instance, mock_ssh_service, mock_connection_service
                )
            )

        assert result == ["/var/log/auth.log", "/var/log/syslog"]

    def test_builds_find_command_with_directories(
        self, default_service, instance, mock_ssh_service, mock_connection_service
    ):
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(return_value=(b"", b""))
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            asyncio.run(
                default_service.scan_log_directories(
                    instance, mock_ssh_service, mock_connection_service,
                    directories=["/var/log", "/opt/logs"],
                    max_depth=3,
                )
            )

        call_kwargs = mock_ssh_service.build_ssh_command.call_args[1]
        remote_cmd = call_kwargs.get("remote_command", "")
        assert "/var/log" in remote_cmd
        assert "/opt/logs" in remote_cmd
        assert "-maxdepth 3" in remote_cmd

    def test_returns_empty_on_timeout(
        self, default_service, instance, mock_ssh_service, mock_connection_service
    ):
        with patch("asyncio.create_subprocess_exec", side_effect=asyncio.TimeoutError):
            result = asyncio.run(
                default_service.scan_log_directories(
                    instance, mock_ssh_service, mock_connection_service
                )
            )

        assert result == []

    def test_returns_empty_on_exception(
        self, default_service, instance, mock_ssh_service, mock_connection_service
    ):
        with patch("asyncio.create_subprocess_exec", side_effect=OSError("fail")):
            result = asyncio.run(
                default_service.scan_log_directories(
                    instance, mock_ssh_service, mock_connection_service
                )
            )

        assert result == []

    def test_returns_empty_for_empty_directories(
        self, instance, mock_ssh_service, mock_connection_service
    ):
        config = AppConfig(log_viewer_scan_directories=[])
        manager = FakeConfigManager(config)
        service = LogViewerService(manager)

        result = asyncio.run(
            service.scan_log_directories(
                instance, mock_ssh_service, mock_connection_service
            )
        )

        assert result == []


# ---------------------------------------------------------------------------
# T10 — memory cache integration
# ---------------------------------------------------------------------------

class TestProbeLogPathsUsesMemoryCache:
    """probe_log_paths consults memory.logs before spawning an SSH probe."""

    def _instance(self):
        return {
            "id": "i-cache-test",
            "name": "cache-host",
            "public_ip": "1.2.3.4",
            "provider": "custom",
        }

    def _make_service_with_memory(self, memory_service):
        config = AppConfig()
        manager = FakeConfigManager(config)
        return LogViewerService(manager, memory_service=memory_service)

    def test_cache_hit_bypasses_ssh(self):
        from datetime import datetime, timezone

        recent = datetime.now(tz=timezone.utc).isoformat()
        mem = MagicMock()
        mem.get.return_value = {
            "observed": {"probed_paths": ["/var/log/syslog", "/var/log/app.log"]},
            "probed_at": recent,
            "ttl_seconds": 86400,
        }
        service = self._make_service_with_memory(mem)
        ssh = MagicMock()
        conn = MagicMock()

        with patch(
            "servonaut.services.log_viewer_service.run_ssh_subprocess",
            new_callable=AsyncMock,
        ) as spawn:
            result = asyncio.run(
                service.probe_log_paths(self._instance(), ssh, conn)
            )

        assert result == ["/var/log/syslog", "/var/log/app.log"]
        # SSH path must never have been entered.
        spawn.assert_not_called()
        assert service.last_probe_source == "cache"
        assert service.last_probe_probed_at == recent

    def test_cache_miss_falls_back_to_ssh(self):
        mem = MagicMock()
        mem.get.return_value = None
        service = self._make_service_with_memory(mem)

        ssh = MagicMock()
        ssh.build_ssh_command.return_value = ["ssh", "fake"]
        conn = MagicMock()
        conn.resolve_profile.return_value = None
        conn.get_target_host.return_value = "1.2.3.4"
        conn.get_extra_options.return_value = []
        ssh.get_key_path.return_value = None
        ssh.discover_key.return_value = None

        async def fake_spawn(cmd, timeout):
            return (b"/var/log/syslog\n/var/log/auth.log\n", b"")

        with patch(
            "servonaut.services.log_viewer_service.run_ssh_subprocess",
            side_effect=fake_spawn,
        ):
            result = asyncio.run(
                service.probe_log_paths(self._instance(), ssh, conn)
            )

        assert "/var/log/syslog" in result
        assert service.last_probe_source == "live"

    def _ssh_and_conn(self):
        ssh = MagicMock()
        ssh.build_ssh_command.return_value = ["ssh", "fake"]
        ssh.get_key_path.return_value = None
        ssh.discover_key.return_value = None
        conn = MagicMock()
        conn.resolve_profile.return_value = None
        conn.get_target_host.return_value = "1.2.3.4"
        conn.get_extra_options.return_value = []
        return ssh, conn

    def _cached_memory(self, is_disabled: bool):
        from datetime import datetime, timezone

        mem = MagicMock()
        mem.get.return_value = {
            "observed": {"probed_paths": ["/var/log/syslog", "/var/log/auth.log"]},
            "probed_at": datetime.now(tz=timezone.utc).isoformat(),
            "ttl_seconds": 86400,
        }
        mem.is_memory_disabled.return_value = is_disabled
        return mem

    def test_per_server_opt_out_skips_the_cache(self):
        """A server opted out of memory gets a live probe of the configured
        paths, not the stale cached list — the opt-out must hold on reads too."""
        mem = self._cached_memory(is_disabled=True)
        config = AppConfig()
        config.log_viewer_default_paths = ["/var/log/fail2ban.log"]
        service = LogViewerService(FakeConfigManager(config), memory_service=mem)
        ssh, conn = self._ssh_and_conn()

        async def fake_spawn(cmd, timeout):
            return (b"/var/log/fail2ban.log\n", b"")

        with patch(
            "servonaut.services.log_viewer_service.run_ssh_subprocess",
            side_effect=fake_spawn,
        ):
            result = asyncio.run(service.probe_log_paths(self._instance(), ssh, conn))

        assert result == ["/var/log/fail2ban.log"]
        assert service.last_probe_source == "live"
        mem.is_memory_disabled.assert_called_once_with("i-cache-test", "cache-host")

    def test_disabled_logs_module_skips_the_cache(self):
        mem = self._cached_memory(is_disabled=False)
        config = AppConfig()
        config.memory.disabled_modules = ["logs"]
        config.log_viewer_default_paths = ["/var/log/fail2ban.log"]
        service = LogViewerService(FakeConfigManager(config), memory_service=mem)
        ssh, conn = self._ssh_and_conn()

        async def fake_spawn(cmd, timeout):
            return (b"/var/log/fail2ban.log\n", b"")

        with patch(
            "servonaut.services.log_viewer_service.run_ssh_subprocess",
            side_effect=fake_spawn,
        ):
            result = asyncio.run(service.probe_log_paths(self._instance(), ssh, conn))

        assert result == ["/var/log/fail2ban.log"]
        assert service.last_probe_source == "live"
        mem.get.assert_not_called()

    def test_cache_still_served_when_nothing_is_opted_out(self):
        mem = self._cached_memory(is_disabled=False)
        service = self._make_service_with_memory(mem)
        ssh, conn = self._ssh_and_conn()

        with patch(
            "servonaut.services.log_viewer_service.run_ssh_subprocess",
            new_callable=AsyncMock,
        ) as spawn:
            result = asyncio.run(service.probe_log_paths(self._instance(), ssh, conn))

        assert result == ["/var/log/syslog", "/var/log/auth.log"]
        spawn.assert_not_called()

    def test_cache_empty_probed_paths_falls_back(self):
        """A logs module exists but probed_paths is empty → fallback to SSH."""
        mem = MagicMock()
        mem.get.return_value = {
            "observed": {"probed_paths": []},
            "probed_at": "2026-04-20T00:00:00+00:00",
            "ttl_seconds": 86400,
        }
        service = self._make_service_with_memory(mem)

        ssh = MagicMock()
        ssh.build_ssh_command.return_value = ["ssh", "fake"]
        conn = MagicMock()
        conn.resolve_profile.return_value = None
        conn.get_target_host.return_value = "1.2.3.4"
        conn.get_extra_options.return_value = []
        ssh.get_key_path.return_value = None
        ssh.discover_key.return_value = None

        async def fake_spawn(cmd, timeout):
            return (b"/var/log/syslog\n", b"")

        with patch(
            "servonaut.services.log_viewer_service.run_ssh_subprocess",
            side_effect=fake_spawn,
        ):
            result = asyncio.run(
                service.probe_log_paths(self._instance(), ssh, conn)
            )

        assert result == ["/var/log/syslog"]
        assert service.last_probe_source == "live"

    def test_stale_cache_still_used_with_warning(self, caplog):
        from datetime import datetime, timedelta, timezone

        stale = (datetime.now(tz=timezone.utc) - timedelta(days=10)).isoformat()
        mem = MagicMock()
        mem.get.return_value = {
            "observed": {"probed_paths": ["/var/log/old.log"]},
            "probed_at": stale,
            "ttl_seconds": 86400,
        }
        service = self._make_service_with_memory(mem)
        ssh = MagicMock()
        conn = MagicMock()

        with caplog.at_level("WARNING"):
            result = asyncio.run(
                service.probe_log_paths(self._instance(), ssh, conn)
            )

        assert result == ["/var/log/old.log"]
        assert any("stale" in rec.message.lower() for rec in caplog.records), (
            "Stale cache hit must emit a warning log entry"
        )
        assert service.last_probe_source == "cache"

    def test_no_memory_service_uses_ssh(self):
        """When memory_service is None, behaviour is identical to pre-T10."""
        service = LogViewerService(FakeConfigManager(AppConfig()), memory_service=None)
        ssh = MagicMock()
        ssh.build_ssh_command.return_value = ["ssh", "fake"]
        conn = MagicMock()
        conn.resolve_profile.return_value = None
        conn.get_target_host.return_value = "1.2.3.4"
        conn.get_extra_options.return_value = []
        ssh.get_key_path.return_value = None
        ssh.discover_key.return_value = None

        async def fake_spawn(cmd, timeout):
            return (b"/var/log/syslog\n", b"")

        with patch(
            "servonaut.services.log_viewer_service.run_ssh_subprocess",
            side_effect=fake_spawn,
        ):
            result = asyncio.run(
                service.probe_log_paths(self._instance(), ssh, conn)
            )

        assert result == ["/var/log/syslog"]
        assert service.last_probe_source == "live"

    def test_memory_get_raises_is_treated_as_miss(self):
        mem = MagicMock()
        mem.get.side_effect = ValueError("bad instance id")
        service = self._make_service_with_memory(mem)
        ssh = MagicMock()
        ssh.build_ssh_command.return_value = ["ssh", "fake"]
        conn = MagicMock()
        conn.resolve_profile.return_value = None
        conn.get_target_host.return_value = "1.2.3.4"
        conn.get_extra_options.return_value = []
        ssh.get_key_path.return_value = None
        ssh.discover_key.return_value = None

        async def fake_spawn(cmd, timeout):
            return (b"/var/log/syslog\n", b"")

        with patch(
            "servonaut.services.log_viewer_service.run_ssh_subprocess",
            side_effect=fake_spawn,
        ):
            result = asyncio.run(
                service.probe_log_paths(self._instance(), ssh, conn)
            )

        # Live SSH path ran — cache miss on exception is graceful.
        assert service.last_probe_source == "live"
        assert "/var/log/syslog" in result

    def test_set_memory_service_rebinds(self):
        service = LogViewerService(FakeConfigManager(AppConfig()), memory_service=None)
        mem = MagicMock()
        mem.get.return_value = {
            "observed": {"probed_paths": ["/var/log/hit.log"]},
            "probed_at": "2026-04-20T00:00:00+00:00",
            "ttl_seconds": 86400,
        }
        service.set_memory_service(mem)

        result = asyncio.run(
            service.probe_log_paths(self._instance(), MagicMock(), MagicMock())
        )
        assert result == ["/var/log/hit.log"]
        assert service.last_probe_source == "cache"
