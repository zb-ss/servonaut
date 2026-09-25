"""Keyword scans reach custom servers and report the ones they cannot reach.

Custom servers have no power-state API, so their state is ``unknown``. A scan
must still try them, skip only instances a provider reports as stopped, and
turn an SSH connection failure into a reported error instead of "no matches".
"""
from __future__ import annotations

import contextlib
import subprocess
from types import SimpleNamespace
from typing import Any, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App
from textual.widgets import Static
from textual.worker import WorkerFailed

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig, CustomServer, ScanRule
from servonaut.screens.scan_results import ScanResultsScreen
from servonaut.services.connection_service import ConnectionService
from servonaut.services.custom_server_service import CustomServerService
from servonaut.services.scan_service import (
    ScanConnectionError,
    ScanService,
    is_scannable,
)
from servonaut.services.ssh_service import SSHService

_REFUSED = "ssh: connect to host 10.0.0.5 port 2222: Connection refused"


def _config_manager(config: Optional[AppConfig] = None) -> MagicMock:
    manager = MagicMock()
    manager.get.return_value = config or AppConfig(default_username="ec2-user")
    return manager


def _custom_instance(name: str = "web-1") -> dict:
    server = CustomServer(
        name=name, host="10.0.0.5", username="deploy",
        ssh_key="/keys/web-1.pem", port=2222,
    )
    return CustomServerService(_config_manager()).to_instance_dict(server)


def _aws_instance(name: str = "web-2", state: str = "running") -> dict:
    return {
        "id": f"i-{name}", "name": name, "state": state,
        "public_ip": "9.9.9.9", "private_ip": "10.0.0.6", "region": "us-east-1",
        "key_name": "",
    }


def _scan_config() -> AppConfig:
    return AppConfig(
        default_username="ec2-user",
        default_scan_paths=["/srv/app", "/var/www"],
        scan_rules=[ScanRule(name="all", match_conditions={}, scan_commands=["uptime"])],
    )


async def _scan(instance: dict, run_result: Any) -> tuple:
    manager = _config_manager(_scan_config())
    scan = ScanService(manager)
    with patch(
        "servonaut.services.scan_service.subprocess.run", return_value=run_result,
    ) as run:
        try:
            results = await scan.scan_server(
                instance, SSHService(manager), ConnectionService(manager),
            )
        except ScanConnectionError as exc:
            return exc, run
    return results, run


def _ok(stdout: str = "output") -> SimpleNamespace:
    return SimpleNamespace(returncode=0, stdout=stdout, stderr="")


# ---------------------------------------------------------------------------
# Which instances are scanned
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("state", ["unknown", "stopped", "", None])
def test_custom_servers_are_always_scannable(state):
    assert is_scannable({**_custom_instance(), "state": state}) is True


@pytest.mark.parametrize(
    "state, expected",
    [
        ("running", True),
        ("pending", True),
        ("stopped", False),
        ("stopping", False),
        ("terminated", False),
        ("shutting-down", False),
    ],
)
def test_provider_instances_skip_only_known_down_states(state, expected):
    assert is_scannable(_aws_instance(state=state)) is expected


@pytest.mark.asyncio
async def test_custom_server_with_unknown_state_is_scanned():
    instance = _custom_instance()
    assert instance["state"] == "unknown"

    results, run = await _scan(instance, _ok())

    assert [r["source"] for r in results] == [
        "path:/srv/app", "path:/var/www", "command:uptime",
    ]
    assert run.call_count == 3


@pytest.mark.asyncio
async def test_stopped_aws_instance_is_skipped_without_ssh():
    results, run = await _scan(_aws_instance(state="stopped"), _ok())

    assert results == []
    run.assert_not_called()


# ---------------------------------------------------------------------------
# How each ssh call is run
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_every_scan_call_is_non_interactive():
    """Path and command scans alike: stdin is /dev/null and prompts are off.

    A child that inherits stdin competes with the TUI for keystrokes, and a
    password prompt in a captured-output call can only stall.
    """
    _, run = await _scan(_custom_instance(), _ok())

    assert run.call_count == 3
    for call in run.call_args_list:
        assert call.kwargs.get("stdin") is subprocess.DEVNULL
        argv: List[str] = call.args[0]
        assert "BatchMode=yes" in argv


# ---------------------------------------------------------------------------
# Unreachable servers are reported, and quickly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unreachable_server_raises_after_one_attempt():
    refused = SimpleNamespace(returncode=255, stdout="", stderr=f"{_REFUSED}\n")

    outcome, run = await _scan(_custom_instance(), refused)

    assert isinstance(outcome, ScanConnectionError)
    assert "Connection refused" in str(outcome)
    # Two paths + one command configured, but the scan stops at the first
    # connection failure instead of waiting out the timeout three times.
    assert run.call_count == 1


@pytest.mark.asyncio
async def test_failing_remote_command_is_not_a_connection_error():
    """A path that does not exist exits 2: skip it, keep scanning."""
    missing = SimpleNamespace(returncode=2, stdout="", stderr="")

    results, run = await _scan(_custom_instance(), missing)

    assert results == []
    assert run.call_count == 3


@pytest.mark.asyncio
async def test_instance_without_an_address_is_reported():
    instance = {**_aws_instance(), "public_ip": "", "private_ip": ""}

    outcome, run = await _scan(instance, _ok())

    assert isinstance(outcome, ScanConnectionError)
    run.assert_not_called()


# ---------------------------------------------------------------------------
# "Scan all" (sidebar) names the servers it could not reach
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_all_includes_custom_servers_and_names_unreachable_ones():
    custom = _custom_instance("web-1")
    stopped = _aws_instance("web-2", state="stopped")
    running = _aws_instance("web-3")
    notes: List[tuple] = []

    async def _scan_server(instance, *_):
        if instance["name"] == "web-1":
            raise ScanConnectionError(_REFUSED)
        return [{"source": "command:uptime", "content": "up", "timestamp": "t"}]

    fake_app = SimpleNamespace(
        instances=[custom, stopped, running],
        scan_service=SimpleNamespace(scan_server=AsyncMock(side_effect=_scan_server)),
        ssh_service=object(),
        connection_service=object(),
        keyword_store=MagicMock(),
        connection_instance=lambda inst: inst,
        real_instance_id=lambda iid: iid,
        notify=lambda message, **kw: notes.append((message, kw.get("severity"))),
    )

    await ServonautApp._do_global_scan(fake_app)

    scanned = [c.args[0]["name"] for c in fake_app.scan_service.scan_server.call_args_list]
    assert scanned == ["web-1", "web-3"]
    fake_app.keyword_store.save_results.assert_called_once_with("i-web-3", [
        {"source": "command:uptime", "content": "up", "timestamp": "t"},
    ])
    summary, severity = notes[-1]
    assert "1/2 servers scanned" in summary
    assert "Could not connect to: web-1" in summary
    assert severity == "warning"


# ---------------------------------------------------------------------------
# Per-server scan screen
# ---------------------------------------------------------------------------

class _ScanScreenApp(App):
    def __init__(self, instance: dict, scan_server: AsyncMock) -> None:
        super().__init__()
        self.demo_mode = False
        self.redaction_service = None
        self.keyword_store = MagicMock()
        self.keyword_store.get_results.return_value = []
        self.scan_service = SimpleNamespace(scan_server=scan_server)
        self.ssh_service = object()
        self.connection_service = object()
        self._instance = instance

    def on_mount(self) -> None:
        self.push_screen(ScanResultsScreen(self._instance))


@pytest.mark.asyncio
async def test_scan_screen_reports_an_unreachable_server_without_crashing():
    scan_server = AsyncMock(side_effect=ScanConnectionError(_REFUSED))
    app = _ScanScreenApp(_custom_instance(), scan_server)

    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        screen = app.screen
        screen.action_scan_now()
        # The worker ends in ERROR by design; the screen must absorb it.
        with contextlib.suppress(WorkerFailed):
            await screen.workers.wait_for_complete()
        await pilot.pause()

        assert app.is_running
        assert app.screen is screen
        status = str(screen.query_one("#scan_status", Static).render())
        assert "Could not connect" in status
        assert "Connection refused" in status

    scan_server.assert_awaited_once()
    app.keyword_store.save_results.assert_not_called()


@pytest.mark.asyncio
async def test_scan_screen_explains_a_stopped_instance():
    scan_server = AsyncMock(return_value=[])
    app = _ScanScreenApp(_aws_instance(state="stopped"), scan_server)

    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        app.screen.action_scan_now()
        await pilot.pause()
        status = str(app.screen.query_one("#scan_status", Static).render())

    assert "stopped" in status
    scan_server.assert_not_awaited()
