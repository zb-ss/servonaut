"""Live monitoring distinguishes SSH failures from real resource snapshots."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from servonaut.config.schema import AppConfig, SSHConfig
from servonaut.services.connection_service import ConnectionService
from servonaut.services.live_stats_service import LiveStatsError, LiveStatsService
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.services.ssh_service import SSHService
from servonaut.utils.live_stats import LIVE_STATS_COMMAND


@pytest.mark.asyncio
async def test_collect_executes_real_read_only_command() -> None:
    from servonaut.utils.ssh_utils import run_ssh_subprocess

    async def local_runner(command: str) -> tuple[str, str, int]:
        stdout, stderr = await run_ssh_subprocess(["sh", "-c", command], check=True)
        return stdout.decode(), stderr.decode(), 0

    service = LiveStatsService(lambda instance: local_runner, SSHConfig())
    stats = await service.collect({})
    assert stats.cpu_pct is not None
    assert stats.mem_pct is not None
    assert stats.load_1m is not None
    assert stats.uptime is not None
    assert stats.disk_pct is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("stderr,expected", [
    ("deploy@example.net: Permission denied (publickey)", "authentication failed"),
    ("Authentication failed", "authentication failed"),
    ("Host key verification failed", "host verification failed"),
    ("Connection refused", "connection refused"),
    ("Connection timed out", "timed out"),
    ("remote command failed", "could not collect metrics"),
])
async def test_ssh_failures_stop_polling_without_leaking_diagnostics(
    stderr: str, expected: str,
) -> None:
    runner = AsyncMock(return_value=("SVN_MEM\nMem: 1000 250\n", stderr, 255))
    service = LiveStatsService(lambda instance: runner, SSHConfig())
    with pytest.raises(LiveStatsError, match=expected) as error:
        async for _ in service.watch({}):
            pytest.fail("A failed SSH command must not publish a snapshot")
    assert "example.net" not in str(error.value)
    assert "deploy@" not in str(error.value)
    runner.assert_awaited_once_with(LIVE_STATS_COMMAND)


@pytest.mark.asyncio
@pytest.mark.parametrize("output", ["", "login banner\n", "SVN_CPU\nSVN_MEM\nSVN_LOAD\nSVN_UP\nSVN_DISK\n"])
async def test_empty_metrics_are_an_error(output: str) -> None:
    runner = AsyncMock(return_value=(output, "", 0))
    service = LiveStatsService(lambda instance: runner, SSHConfig())
    with pytest.raises(LiveStatsError, match="no Linux host metrics"):
        await service.collect({})


@pytest.mark.asyncio
async def test_timeout_is_actionable_and_cancellation_propagates() -> None:
    runner = AsyncMock(side_effect=asyncio.TimeoutError)
    service = LiveStatsService(lambda instance: runner, SSHConfig())
    with pytest.raises(LiveStatsError, match="timed out"):
        await service.collect({})
    runner.side_effect = asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await service.collect({})


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["live_stats_interval_seconds", "live_stats_timeout_seconds"])
@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), "fast", None, True])
async def test_invalid_poll_configuration_does_not_connect(field: str, value: object) -> None:
    factory = Mock()
    service = LiveStatsService(factory, SSHConfig(**{field: value}))
    with pytest.raises(LiveStatsError, match="positive number"):
        await anext(service.watch({}))
    factory.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("is_demo", [False, True])
async def test_memory_runner_uses_ovh_settings_and_real_exit_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, is_demo: bool,
) -> None:
    config = AppConfig(default_username="ec2-user", default_key="/keys/global")
    config.ovh.default_username = "debian"
    config.ovh.default_ssh_key = "/keys/ovh"
    manager = Mock()
    manager.get.return_value = config
    ssh = SSHService(manager)
    original = {"id": "vps-web-1", "is_ovh": True, "provider_type": "vps", "public_ip": "192.0.2.1"}
    shown = {**original, "id": "demo-1", "public_ip": "192.0.2.2"} if is_demo else original
    service = MemoryService(
        store=MemoryStore(root=tmp_path), config=config.memory,
        ssh_service=ssh, connection_service=ConnectionService(manager),
    )
    service.set_instance_resolver(lambda row: original, lambda value: original["id"])
    build_command = Mock(return_value=[
        sys.executable, "-c", "import sys; sys.stderr.write('Permission denied'); sys.exit(255)",
    ])
    monkeypatch.setattr(ssh, "build_ssh_command", build_command)
    result = await service.make_ssh_runner(shown, timeout=2)(LIVE_STATS_COMMAND)
    assert result == ("", "Permission denied", 255)
    assert build_command.call_args.kwargs["host"] == original["public_ip"]
    assert build_command.call_args.kwargs["username"] == "debian"
    assert build_command.call_args.kwargs["key_path"] == "/keys/ovh"
    assert build_command.call_args.kwargs["extra_options"][0] == "BatchMode=yes"
