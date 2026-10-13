"""Recording a server's host key by connecting to it once, as a first SSH login does."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig, ConnectionProfile, ConnectionRule, SSHConfig
from servonaut.services import host_key_recording
from servonaut.services.connection_service import ConnectionService
from servonaut.services.host_key_recording import records_new_host_keys, visit_for_host_key, visit_timeout
from servonaut.services.ssh_service import SSHService
from servonaut.utils.ssh_utils import SSHOutput

APP = {"id": "i-0123456789abcdef0", "name": "app-1", "region": "eu-west-2", "public_ip": "9.9.9.9", "private_ip": "10.0.1.21"}
WEB = {"id": "i-0fedcba9876543210", "name": "web-1", "region": "eu-west-2", "public_ip": "8.8.8.8", "private_ip": "10.0.1.22"}


def _services(host_key_checking: str = "accept-new"):
    config = AppConfig(
        ssh=SSHConfig(host_key_checking=host_key_checking, connect_timeout=7),
        connection_profiles=[ConnectionProfile(
            name="via-bastion", bastion_host="bastion.example.com", bastion_user="ec2-user",
            bastion_key="~/.ssh/bastion.pem",
        )],
        connection_rules=[ConnectionRule(
            name="private", match_conditions={"name_contains": "app"}, profile_name="via-bastion",
        )],
    )
    manager = MagicMock()
    manager.get.return_value = config
    return config, ConnectionService(manager), SSHService(manager)


def _run_ssh(monkeypatch, output=None, error=None) -> list:
    calls: list = []

    async def fake(argv, timeout=30, **_kw):
        calls.append((list(argv), timeout))
        if error is not None:
            raise error
        return output

    monkeypatch.setattr(host_key_recording, "run_ssh_subprocess", fake)
    return calls


def test_only_accept_new_records_a_new_servers_key() -> None:
    assert records_new_host_keys(_services("accept-new")[1]) is True
    assert records_new_host_keys(_services("yes")[1]) is False  # a new server is refused
    assert records_new_host_keys(_services("off")[1]) is False  # nothing is recorded


def test_accept_new_is_not_offered_when_servonauts_own_file_is_unsafe() -> None:
    _, connection, _ = _services("accept-new")
    path = connection.host_key_policy().known_hosts_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="ascii")
    path.chmod(0o666)  # others could add keys: OpenSSH is then told "yes"
    try:
        assert records_new_host_keys(connection) is False
    finally:
        path.chmod(0o600)


def test_a_visit_logs_in_once_over_the_bastion_route(monkeypatch) -> None:
    config, connection, ssh = _services()
    calls = _run_ssh(monkeypatch, SSHOutput(b"", b"", 0, ""))

    assert asyncio.run(visit_for_host_key(APP, connection, ssh, "ubuntu", timeout=visit_timeout(config.ssh))) is None

    ((argv, timeout),) = calls
    assert timeout == 21  # three connect timeouts: the hop, the server, the login
    assert argv[-3:] == ["--", "ubuntu@10.0.1.21", "true"]  # the private address, through the bastion
    options = [argv[i + 1] for i, arg in enumerate(argv) if arg == "-o"]
    assert "StrictHostKeyChecking=accept-new" in options
    assert "BatchMode=yes" in options  # never a prompt
    assert "HostKeyAlias=aws:eu-west-2:i-0123456789abcdef0" in options  # recorded under the name lookups use
    assert any(option.startswith("ProxyCommand=") for option in options)


def test_a_direct_server_is_visited_at_its_public_address(monkeypatch) -> None:
    _, connection, ssh = _services()
    calls = _run_ssh(monkeypatch, SSHOutput(b"", b"", 0, ""))
    asyncio.run(visit_for_host_key(WEB, connection, ssh, "ec2-user", timeout=5))
    ((argv, _),) = calls
    assert argv[-3:] == ["--", "ec2-user@8.8.8.8", "true"]
    assert not any(arg.startswith("ProxyCommand=") for arg in argv)


def test_a_refused_login_says_what_ssh_said(monkeypatch) -> None:
    # The key exchange, and so the recording, happens before the login.
    _, connection, ssh = _services()
    _run_ssh(monkeypatch, SSHOutput(b"", b"", 255, "debug noise\nubuntu@8.8.8.8: Permission denied (publickey).\n"))
    reason = asyncio.run(visit_for_host_key(WEB, connection, ssh, "ubuntu", timeout=5))
    assert reason == "ubuntu@8.8.8.8: Permission denied (publickey)."


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [(b"ssh: Could not resolve hostname web-1: Name or service not known\r\n",
      "ssh: Could not resolve hostname web-1: Name or service not known"),
     (b"", "ssh could not connect (exit status 255).")],
)
def test_without_its_log_ssh_says_why_on_stderr(monkeypatch, stderr, expected) -> None:
    # ssh can stop before it writes its log (a bad option, an unknown host name).
    _, connection, ssh = _services()
    _run_ssh(monkeypatch, SSHOutput(b"", stderr, 255, ""))
    assert asyncio.run(visit_for_host_key(WEB, connection, ssh, "ubuntu", timeout=5)) == expected


def test_a_changed_host_key_is_named_as_such(monkeypatch) -> None:
    _, connection, ssh = _services()
    known = str(connection.host_key_policy().known_hosts_file)
    alias = "aws:eu-west-2:i-0fedcba9876543210"
    stderr = (
        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
        f"Offending ED25519 key in {known}:1\n"
        f"Host key for {alias} has changed and you have requested strict checking.\n"
        "Host key verification failed.\n"
    )
    _run_ssh(monkeypatch, SSHOutput(b"", b"", 255, stderr))
    reason = asyncio.run(visit_for_host_key(WEB, connection, ssh, "ubuntu", timeout=5))
    # The refusal is explained, not just ssh's last line.
    assert reason is not None and reason.startswith(f"SSH host key for {alias} has changed")


@pytest.mark.parametrize(
    ("error", "expected"),
    [(asyncio.TimeoutError(), "The server did not answer in time."),
     (FileNotFoundError(2, "No such file or directory"), "Could not run ssh (No such file or directory).")],
)
def test_no_connection_says_why(monkeypatch, error, expected) -> None:
    _, connection, ssh = _services()
    _run_ssh(monkeypatch, error=error)
    assert asyncio.run(visit_for_host_key(WEB, connection, ssh, "ubuntu", timeout=5)) == expected


def test_a_server_without_an_address_is_not_visited(monkeypatch) -> None:
    _, connection, ssh = _services()
    calls = _run_ssh(monkeypatch, SSHOutput(b"", b"", 0, ""))
    stopped = {"id": "i-0aaaaaaaaaaaaaaaa", "name": "web-2", "region": "eu-west-2", "public_ip": None, "private_ip": None}
    assert asyncio.run(visit_for_host_key(stopped, connection, ssh, "ubuntu", timeout=5)) == (
        "This server has no address to connect to."
    )
    assert calls == []


@pytest.mark.parametrize("connect", [None, 0, -1, True, "15"])
def test_a_missing_or_odd_connect_timeout_uses_the_default(connect) -> None:
    assert visit_timeout(MagicMock(connect_timeout=connect)) == SSHConfig().connect_timeout * 3
