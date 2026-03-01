"""Tests for LogViewerService."""

from __future__ import annotations

import asyncio
import json
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
            result = asyncio.get_event_loop().run_until_complete(
                default_service.probe_log_paths(instance, mock_ssh_service, mock_connection_service)
            )

        assert "/var/log/syslog" in result
        assert "/var/log/auth.log" in result

    def test_returns_empty_on_timeout(self, default_service, instance, mock_ssh_service, mock_connection_service):
        with patch("asyncio.create_subprocess_exec", side_effect=asyncio.TimeoutError):
            result = asyncio.get_event_loop().run_until_complete(
                default_service.probe_log_paths(instance, mock_ssh_service, mock_connection_service)
            )

        assert result == []

    def test_returns_empty_on_exception(self, default_service, instance, mock_ssh_service, mock_connection_service):
        with patch("asyncio.create_subprocess_exec", side_effect=OSError("connection refused")):
            result = asyncio.get_event_loop().run_until_complete(
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

        with patch("asyncio.create_subprocess_exec", return_value=mock_process) as mock_exec:
            asyncio.get_event_loop().run_until_complete(
                service.probe_log_paths(instance, mock_ssh_service, mock_connection_service)
            )

        # The SSH command's remote_command arg should include the custom path
        call_kwargs = mock_ssh_service.build_ssh_command.call_args
        remote_cmd = call_kwargs[1].get("remote_command", "") or ""
        assert "/var/log/app.log" in remote_cmd
