"""A memory build that cannot reach the server keeps the stored snapshot.

ssh's own failures (refused login, unreachable host), an unusable vault key and
a server that answers no command in time used to produce empty module output
that was saved as a successful probe, replacing the last good snapshot.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, MemoryConfig
from servonaut.services.connection_service import ConnectionService
from servonaut.services.memory.modules.os import OSProber
from servonaut.services.memory.service import (
    SSH_FAILED_BUILD_REASON,
    BuildReport,
    MemoryService,
    ModuleBuildFailure,
)
from servonaut.services.memory.store import MemoryStore
from servonaut.services.ssh_service import SSHService
from servonaut.utils.ssh_utils import ssh_connection_failure

SERVER = {
    "id": "custom-web-1", "name": "web-1", "is_custom": True, "provider": "custom",
    "public_ip": "192.0.2.10", "username": "deploy", "port": 22,
}
OS_RELEASE = b'ID=ubuntu\nPRETTY_NAME="Ubuntu 24.04 LTS"\n'


def _run(coro):
    return asyncio.run(coro)


def _service(tmp_path: Path) -> MemoryService:
    manager = MagicMock()
    manager.get.return_value = AppConfig()
    return MemoryService(
        store=MemoryStore(root=tmp_path / "memory"), config=MemoryConfig(),
        probers=[OSProber()],
        ssh_service=SSHService(manager), connection_service=ConnectionService(manager),
    )


def _fake_ssh(stdout: bytes = b"", returncode: int = 0, diagnostics: str = "") -> MagicMock:
    """Play ssh: log *diagnostics* to the private ``-E`` file, print, exit."""
    async def spawn(*argv, **kwargs):
        args: List[str] = [str(a) for a in argv]
        if "-E" in args:
            Path(args[args.index("-E") + 1]).write_text(diagnostics)
        process = MagicMock()
        # The shared connection (-N) runs no command: it either opens or it fails.
        opens_only = "-N" in args
        process.communicate = AsyncMock(return_value=(b"" if opens_only else stdout, b""))
        process.returncode = 0 if opens_only and not diagnostics else returncode
        process.wait = AsyncMock(return_value=process.returncode)
        process._transport = None
        return process

    return MagicMock(side_effect=spawn)


def _build(service: MemoryService, ssh: MagicMock) -> BuildReport:
    with patch("servonaut.utils.ssh_utils.asyncio.create_subprocess_exec", ssh):
        return _run(service.build_report(dict(SERVER)))


def _stored(service: MemoryService) -> dict:
    return service.get_all_modules(SERVER["id"], "custom")


# ---------------------------------------------------------------------------
# Recognising ssh's own failures
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("diagnostics", "reason"), [
    ("deploy@192.0.2.10: Permission denied (publickey).", "ssh_auth_failed"),
    ("Received disconnect: Too many authentication failures", "ssh_auth_failed"),
    ("ssh: connect to host 192.0.2.10 port 22: Connection refused", "ssh_unreachable"),
    ("ssh: Could not resolve hostname web-1: Name or service not known", "ssh_unreachable"),
    ("kex_exchange_identification: read: Connection reset by peer", "ssh_unreachable"),
    ("Bad configuration option: nonsense", "ssh_failed"),
])
def test_ssh_failures_are_classified(diagnostics, reason):
    assert ssh_connection_failure(255, b"", diagnostics) == reason


@pytest.mark.parametrize(("returncode", "stdout", "diagnostics"), [
    (1, b"", "Permission denied (publickey)."),       # not ssh's exit status
    (255, b"output", "Connection refused"),           # the remote command printed
    (255, b"", ""),                                   # a remote command exited 255
    (255, b"", "Warning: Permanently added '192.0.2.10' (ED25519) to the list of known hosts."),
])
def test_remote_command_failures_are_not_connection_failures(returncode, stdout, diagnostics):
    assert ssh_connection_failure(returncode, stdout, diagnostics) is None


# ---------------------------------------------------------------------------
# The build keeps the stored snapshot
# ---------------------------------------------------------------------------

def test_a_refused_login_keeps_the_stored_snapshot(tmp_path):
    service = _service(tmp_path)
    good = _build(service, _fake_ssh(stdout=OS_RELEASE))
    assert "os" in good.successes
    before = _stored(service)

    refused = _fake_ssh(returncode=255, diagnostics="deploy@192.0.2.10: Permission denied (publickey).")
    report = _build(service, refused)

    assert report.overall_reason == SSH_FAILED_BUILD_REASON
    assert not report.successes
    assert report.failures[0].reason == "ssh_auth_failed"
    assert "SSH refused the login" in report.failures[0].message
    assert "stored memory was kept" in report.failures[0].message
    # No host name: the report reaches MCP clients and hosted AI.
    assert "192.0.2.10" not in report.failures[0].message
    assert _stored(service) == before
    # The second command was not sent once the login had been refused.
    assert refused.call_count == 1


def test_an_unreachable_server_is_reported(tmp_path):
    service = _service(tmp_path)
    unreachable = _fake_ssh(returncode=255, diagnostics="ssh: connect to host 192.0.2.10 port 22: No route to host")

    report = _build(service, unreachable)

    assert report.overall_reason == SSH_FAILED_BUILD_REASON
    assert report.failures[0].reason == "ssh_unreachable"
    assert _stored(service) == {}


def test_a_server_that_answers_nothing_in_time_keeps_the_stored_snapshot(tmp_path):
    service = _service(tmp_path)
    _build(service, _fake_ssh(stdout=OS_RELEASE))
    before = _stored(service)

    with patch("servonaut.utils.ssh_utils.run_ssh_subprocess",
               AsyncMock(side_effect=asyncio.TimeoutError)):
        report = _run(service.build_report(dict(SERVER)))

    assert report.overall_reason == SSH_FAILED_BUILD_REASON
    assert report.failures[0].reason == "ssh_no_response"
    assert _stored(service) == before


def test_an_unusable_vault_key_is_reported_once(tmp_path):
    service = _service(tmp_path)
    runtime = MagicMock(resolve_ssh=AsyncMock(side_effect=RuntimeError("locked")))
    service.set_vault_runtime(runtime)
    ssh = _fake_ssh(stdout=OS_RELEASE)

    report = _build(service, ssh)

    assert report.overall_reason == SSH_FAILED_BUILD_REASON
    assert report.failures[0].reason == "vault_credential_unavailable"
    assert "could not be used" in report.failures[0].message
    runtime.resolve_ssh.assert_awaited_once()
    ssh.assert_not_called()
    assert _stored(service) == {}


@pytest.mark.parametrize(("stdout", "returncode", "diagnostics"), [
    (b"", 3, ""),                 # a command that found nothing
    (OS_RELEASE, 255, ""),        # a command that printed and exited 255
])
def test_commands_that_ran_on_the_server_are_still_stored(tmp_path, stdout, returncode, diagnostics):
    service = _service(tmp_path)

    report = _build(service, _fake_ssh(stdout=stdout, returncode=returncode, diagnostics=diagnostics))

    assert report.overall_reason is None
    assert "os" in report.successes
    assert "os" in _stored(service)


# ---------------------------------------------------------------------------
# Probers and surfaces
# ---------------------------------------------------------------------------

def test_a_module_with_a_failed_command_is_partial():
    async def runner(command: str):
        if command.startswith("cat /etc/os-release"):
            raise asyncio.TimeoutError
        return "6.8.0 x86_64", "", 0

    result = _run(OSProber().probe(runner))

    assert result.partial is True
    assert "<timeout>" in result.raw_output


def test_mcp_memory_build_explains_a_failed_connection():
    from servonaut.mcp.guards import GuardLevel
    from tests.test_mcp_tools import make_tools

    tools = make_tools(guard_level=GuardLevel.DANGEROUS)
    message = "SSH refused the login. Nothing was probed; the stored memory was kept."
    tools._memory_service = MagicMock()
    tools._memory_service.build_report = AsyncMock(return_value=BuildReport(
        failures=[ModuleBuildFailure("ssh", "ssh_auth_failed", message)],
        overall_reason=SSH_FAILED_BUILD_REASON,
    ))

    payload = json.loads(_run(tools.build_server_memory("i-abc123")))

    assert payload["reason"] == SSH_FAILED_BUILD_REASON
    assert payload["message"] == message


def test_the_memory_screen_shows_why_nothing_was_probed():
    from servonaut.screens.memory import MemoryScreen

    message = "The server could not be reached over SSH. Nothing was probed; the stored memory was kept."
    service = MagicMock()
    service.refresh_report = AsyncMock(return_value=BuildReport(
        failures=[ModuleBuildFailure("ssh", "ssh_unreachable", message)],
        overall_reason=SSH_FAILED_BUILD_REASON,
    ))

    assert _run(MemoryScreen(dict(SERVER))._refresh_memory(service)) == message


def test_the_cli_says_the_memory_was_not_updated(tmp_path, capsys):
    from types import SimpleNamespace

    from servonaut.cli.memory import _cmd_build, _cmd_refresh

    message = "SSH refused the login. Nothing was probed; the stored memory was kept."
    report = BuildReport(
        failures=[ModuleBuildFailure("ssh", "ssh_auth_failed", message)],
        overall_reason=SSH_FAILED_BUILD_REASON,
    )
    service = MagicMock()
    service.build_report = AsyncMock(return_value=report)
    service.refresh_report = AsyncMock(return_value=report)
    args = SimpleNamespace(json=False, modules=None)

    assert _cmd_build(args, None, service, dict(SERVER)) != 0
    assert _cmd_refresh(args, None, service, dict(SERVER)) != 0

    err = capsys.readouterr().err
    assert err.count(f"Memory for {SERVER['id']} was not updated: {message}") == 2
