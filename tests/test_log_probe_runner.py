"""The log-path probe of a memory build runs through the build's ssh runner.

It used to open a connection of its own, outside the build's shared
connection, bastion cap and rate-limit handling.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

from servonaut.config.schema import AppConfig
from servonaut.services.log_viewer_service import LogViewerService
from servonaut.services.memory.modules.logs import LogsProber

INSTANCE = {"id": "i-0001", "name": "web-1", "provider": "aws"}


class _Manager:
    def __init__(self, config):
        self._config = config

    def get(self):
        return self._config


def _viewer(**config):
    return LogViewerService(_Manager(AppConfig(log_viewer_default_paths=["/var/log/a.log", "/var/log/b.log"], **config)))


class TestProbeThroughRunner:
    def test_the_compound_command_runs_through_the_runner(self):
        commands = []

        async def runner(command):
            commands.append(command)
            return "/var/log/a.log\n", "", 1  # the last test failed: the status is not an error

        ssh_service = MagicMock()
        with patch("servonaut.services.log_viewer_service.run_ssh_subprocess") as direct:
            paths = asyncio.run(_viewer().probe_log_paths(INSTANCE, ssh_service, MagicMock(), runner=runner))

        assert paths == ["/var/log/a.log"]
        assert commands == ["test -r /var/log/a.log && echo /var/log/a.log; test -r /var/log/b.log && echo /var/log/b.log"]
        direct.assert_not_called()
        ssh_service.build_ssh_command.assert_not_called()

    def test_a_runner_timeout_gives_no_paths(self):
        async def runner(command):
            raise asyncio.TimeoutError

        assert asyncio.run(_viewer().probe_log_paths(INSTANCE, MagicMock(), MagicMock(), runner=runner)) == []

    def test_the_prober_hands_its_runner_to_the_viewer(self):
        seen = {}

        async def probe(instance, ssh_service, connection_service, **kwargs):
            seen.update(kwargs)
            return []

        viewer = MagicMock()
        viewer.probe_log_paths = probe

        async def runner(command):
            return "", "", 0

        runner.instance = INSTANCE
        asyncio.run(LogsProber(viewer, MagicMock(), MagicMock()).probe(runner))

        assert seen["runner"] is runner

