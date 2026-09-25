"""Keyword scans reach custom servers and report the ones they cannot reach.

Custom servers have no power-state API, so their state is ``unknown``. A scan
must still try them, scan provider instances only while they are running, and
turn an SSH connection failure into a reported error instead of "no matches".
In demo mode the report must not reveal the real host or user.
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
_HOSTNAME = "db-1.corp.example.net"
_DENIED = f"deploy@{_HOSTNAME}: Permission denied (publickey)."


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


async def _scan(instance: dict, run_result: Any = None, *, sequence: Any = None) -> tuple:
    """Scan *instance*; every ssh call returns *run_result*, or the next of *sequence*."""
    manager = _config_manager(_scan_config())
    scan = ScanService(manager)
    with patch(
        "servonaut.services.scan_service.subprocess.run",
        return_value=run_result, side_effect=sequence,
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


def _exit(code: int, stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=code, stdout="", stderr=stderr)


def _remote_command(call) -> str:
    return call.args[0][-1]


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
        ("Running", True),
        ("pending", False),
        ("stopped", False),
        ("stopping", False),
        ("terminated", False),
        ("shutting-down", False),
        ("error", False),
        ("maintenance", False),
        ("", False),
    ],
)
def test_provider_instances_are_scanned_only_while_running(state, expected):
    assert is_scannable(_aws_instance(state=state)) is expected


@pytest.mark.asyncio
async def test_custom_server_with_unknown_state_is_scanned():
    instance = _custom_instance()
    assert instance["state"] == "unknown"

    results, run = await _scan(instance, _ok())

    assert [r["source"] for r in results] == [
        "path:/srv/app", "path:/var/www", "command:uptime",
    ]
    # One connection check, then two paths and one command.
    assert [_remote_command(c) for c in run.call_args_list][0] == "true"
    assert run.call_count == 4


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

    assert run.call_count == 4
    for call in run.call_args_list:
        assert call.kwargs.get("stdin") is subprocess.DEVNULL
        argv: List[str] = call.args[0]
        assert "BatchMode=yes" in argv


# ---------------------------------------------------------------------------
# Unreachable servers are reported, and quickly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unreachable_server_raises_after_one_attempt():
    outcome, run = await _scan(_custom_instance(), _exit(255, f"{_REFUSED}\n"))

    assert isinstance(outcome, ScanConnectionError)
    assert outcome.reason == "connection refused"
    assert "Connection refused" in outcome.describe(redact=False)
    # Two paths + one command configured, but the scan stops at the
    # connection check instead of waiting out the timeout three times.
    assert run.call_count == 1


@pytest.mark.asyncio
async def test_connection_check_timeout_is_reported():
    timeout = subprocess.TimeoutExpired(cmd="ssh", timeout=30)

    outcome, run = await _scan(_custom_instance(), sequence=[timeout])

    assert isinstance(outcome, ScanConnectionError)
    assert outcome.reason == "connection timed out"
    assert run.call_count == 1


@pytest.mark.asyncio
async def test_failing_remote_command_is_not_a_connection_error():
    """A path that does not exist exits 2: skip it, keep scanning."""
    results, run = await _scan(_custom_instance(), sequence=[_ok(), *[_exit(2)] * 3])

    assert results == []
    assert run.call_count == 4


@pytest.mark.asyncio
async def test_scan_command_exiting_255_keeps_the_other_results():
    """PHP CLI fatals exit 255: once connected, that is the command's own status."""
    php_fatal = _exit(255, "PHP Fatal error:  Uncaught Error in artisan")

    results, run = await _scan(
        _custom_instance(), sequence=[_ok(), _ok("a"), _ok("b"), php_fatal],
    )

    assert [r["source"] for r in results] == ["path:/srv/app", "path:/var/www"]
    assert run.call_count == 4


@pytest.mark.asyncio
async def test_instance_without_an_address_is_reported():
    instance = {**_aws_instance(), "public_ip": "", "private_ip": ""}

    outcome, run = await _scan(instance, _ok())

    assert isinstance(outcome, ScanConnectionError)
    run.assert_not_called()


# ---------------------------------------------------------------------------
# Why a connection failed: detailed normally, host-free in demo mode
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "stderr, reason",
    [
        (f"ssh: Could not resolve hostname {_HOSTNAME}: Name or service not known",
         "host name could not be resolved"),
        (f"ssh: connect to host {_HOSTNAME} port 22: Connection timed out",
         "connection timed out"),
        (_REFUSED, "connection refused"),
        (f"ssh: connect to host {_HOSTNAME} port 22: No route to host", "host unreachable"),
        (_DENIED, "authentication failed"),
        ("Host key verification failed.", "host key verification failed"),
        ("kex_exchange_identification: Connection closed by remote host", "connection closed by the server"),
        ("", "connection failed"),
    ],
)
def test_ssh_errors_map_to_host_free_reasons(stderr, reason):
    error = ScanConnectionError.from_ssh_stderr(
        f"Warning: Permanently added '{_HOSTNAME}' to the list of known hosts.\n{stderr}\n"
    )

    assert error.reason == reason
    redacted = error.describe(redact=True)
    assert _HOSTNAME not in redacted and "10.0.0.5" not in redacted
    assert "deploy" not in redacted


def test_detailed_message_is_ssh_own_last_line():
    error = ScanConnectionError.from_ssh_stderr(f"{_REFUSED}\n")
    assert error.describe(redact=False) == _REFUSED


def test_publickey_denial_suggests_loading_the_key_into_the_agent():
    error = ScanConnectionError.from_ssh_stderr(_DENIED)

    for text in (error.describe(redact=True), error.describe(redact=False)):
        assert "ssh-add" in text
    assert not ScanConnectionError.from_ssh_stderr(_REFUSED).hint


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
        demo_mode=False,
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


@pytest.mark.asyncio
async def test_scan_all_in_demo_mode_uses_real_records_and_hides_hosts():
    """Rows are redacted stand-ins; scanning must use and key by the real record."""
    real_ok = {**_custom_instance("web-1"), "public_ip": "10.0.0.5"}
    real_denied = {**_custom_instance("db-1"), "id": "custom-db-1", "public_ip": _HOSTNAME}
    shown = [
        {**real_ok, "id": "demo-1", "name": "server-a", "public_ip": "192.0.2.10"},
        {**real_denied, "id": "demo-2", "name": "server-b", "public_ip": "192.0.2.11"},
    ]
    real_by_fake = {"demo-1": real_ok, "demo-2": real_denied}
    notes: List[str] = []

    async def _scan_server(instance, *_):
        if instance is real_denied:
            raise ScanConnectionError.from_ssh_stderr(_DENIED)
        return [{"source": "path:/srv/app", "content": "x", "timestamp": "t"}]

    fake_app = SimpleNamespace(
        demo_mode=True,
        instances=shown,
        scan_service=SimpleNamespace(scan_server=AsyncMock(side_effect=_scan_server)),
        ssh_service=object(),
        connection_service=object(),
        keyword_store=MagicMock(),
        connection_instance=lambda inst: real_by_fake[inst["id"]],
        real_instance_id=lambda iid: real_by_fake[iid]["id"],
        notify=lambda message, **kw: notes.append(message),
    )

    await ServonautApp._do_global_scan(fake_app)

    scanned = [c.args[0] for c in fake_app.scan_service.scan_server.call_args_list]
    assert scanned[0] is real_ok and scanned[1] is real_denied
    assert fake_app.keyword_store.save_results.call_args.args[0] == real_ok["id"]
    shown_text = "\n".join(notes)
    assert "authentication failed" in shown_text
    assert _HOSTNAME not in shown_text
    assert "deploy" not in shown_text
    assert "Could not connect to: server-b" in notes[-1]


# ---------------------------------------------------------------------------
# Per-server scan screen
# ---------------------------------------------------------------------------

class _ScanScreenApp(App):
    def __init__(
        self, instance: dict, scan_server: AsyncMock, *, demo_mode: bool = False,
    ) -> None:
        super().__init__()
        self.demo_mode = demo_mode
        self.redaction_service = (
            SimpleNamespace(scrub_stream=lambda text: text) if demo_mode else None
        )
        self.keyword_store = MagicMock()
        self.keyword_store.get_results.return_value = []
        self.scan_service = SimpleNamespace(scan_server=scan_server)
        self.ssh_service = object()
        self.connection_service = object()
        self._instance = instance

    def real_instance_id(self, instance_id: str) -> str:
        return f"real-{instance_id}" if self.demo_mode else instance_id

    def on_mount(self) -> None:
        self.push_screen(ScanResultsScreen(self._instance))


async def _scan_on_screen(app: _ScanScreenApp, pilot) -> str:
    await pilot.pause()
    screen = app.screen
    screen.action_scan_now()
    # A connection failure ends the worker in ERROR; the screen absorbs it.
    with contextlib.suppress(WorkerFailed):
        await screen.workers.wait_for_complete()
    await pilot.pause()
    assert app.is_running
    assert app.screen is screen
    return str(screen.query_one("#scan_status", Static).render())


@pytest.mark.asyncio
async def test_scan_screen_reports_an_unreachable_server_without_crashing():
    error = ScanConnectionError.from_ssh_stderr(_REFUSED)
    scan_server = AsyncMock(side_effect=error)
    app = _ScanScreenApp(_custom_instance(), scan_server)

    async with app.run_test(headless=True) as pilot:
        status = await _scan_on_screen(app, pilot)

    assert "Could not connect" in status
    assert "Connection refused" in status
    scan_server.assert_awaited_once()
    app.keyword_store.save_results.assert_not_called()


@pytest.mark.asyncio
async def test_scan_screen_in_demo_mode_hides_the_host():
    scan_server = AsyncMock(side_effect=ScanConnectionError.from_ssh_stderr(_DENIED))
    app = _ScanScreenApp(_custom_instance(), scan_server, demo_mode=True)

    async with app.run_test(headless=True) as pilot:
        status = await _scan_on_screen(app, pilot)

    assert "authentication failed" in status
    assert _HOSTNAME not in status and "deploy" not in status


@pytest.mark.asyncio
async def test_scan_screen_in_demo_mode_keys_results_by_the_real_id():
    found = [{"source": "path:/srv/app", "content": "x", "timestamp": "t"}]
    app = _ScanScreenApp(
        _custom_instance(), AsyncMock(return_value=found), demo_mode=True,
    )

    async with app.run_test(headless=True) as pilot:
        await _scan_on_screen(app, pilot)

    app.keyword_store.get_results.assert_called_once_with("real-custom-web-1")
    app.keyword_store.save_results.assert_called_once_with("real-custom-web-1", found)


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
    assert "only running servers" in status
    scan_server.assert_not_awaited()
