"""Executable behaviour checks for the isolated Vault ssh-agent."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

from servonaut.services.vault.ssh_agent import PrivateSshAgent, PrivateSshAgentError
from servonaut.services.vault.identity_store import IdentityStore
from servonaut.services.vault.command_service import VaultSshLease
from servonaut.config.schema import AppConfig, SSHConfig
from servonaut.services.auth_service import AuthService, AuthToken
from servonaut.services.ssh_service import SSHService


@pytest.fixture
def short_socket_dir():
    """An owned directory below the Unix-domain socket path limit."""
    with tempfile.TemporaryDirectory(prefix="sn-agent-", dir="/tmp") as value:
        yield Path(value)


def _private_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
    )


def _available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_sshd(port: int, process: subprocess.Popen[bytes]) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(process.stderr.read().decode("utf-8", errors="replace"))
        with socket.socket() as client:
            if client.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.02)
    raise RuntimeError("temporary sshd did not listen")


@pytest.mark.skipif(not os.path.exists("/bin/ssh-agent"), reason="OpenSSH is unavailable")
def test_private_agent_adds_stdin_key_without_changing_global_environment(short_socket_dir):
    before_socket = os.environ.get("SSH_AUTH_SOCK")
    before_pid = os.environ.get("SSH_AGENT_PID")
    agent = PrivateSshAgent.start(short_socket_dir)
    try:
        agent.add_private_key(_private_key(), ttl_seconds=60)
        env = agent._environment()
        listed = subprocess.run(
            ["ssh-add", "-l"], capture_output=True, check=False, env=env, timeout=10
        )
        assert listed.returncode == 0
        assert os.environ.get("SSH_AUTH_SOCK") == before_socket
        assert os.environ.get("SSH_AGENT_PID") == before_pid
        assert agent.ssh_options() == [
            "-o", f"IdentityAgent={agent.socket_path}", "-o", "IdentitiesOnly=yes"
        ]
    finally:
        agent.close()
    assert not agent.socket_path.exists()


def test_stale_socket_is_removed_but_live_process_socket_is_preserved(short_socket_dir):
    stale = short_socket_dir / "agent-99999999-0123456789abcdef.sock"
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(stale))
    sock.close()
    live = short_socket_dir / f"agent-{os.getpid()}-0123456789abcdef.sock"
    live.write_text("not ours", encoding="utf-8")

    PrivateSshAgent.cleanup_stale_sockets(short_socket_dir)

    assert not stale.exists()
    assert live.exists()


def test_closed_agent_rejects_new_key(short_socket_dir):
    agent = PrivateSshAgent.start(short_socket_dir)
    agent.close()
    with pytest.raises(PrivateSshAgentError, match="closed"):
        agent.add_private_key(_private_key())


def test_windows_fails_before_starting_a_unix_socket_agent(monkeypatch):
    called = False

    def run(*_, **__):
        nonlocal called
        called = True
        raise AssertionError("ssh-agent must not run on Windows")

    monkeypatch.setattr("servonaut.services.vault.ssh_agent.os.name", "nt")
    monkeypatch.setattr("servonaut.services.vault.ssh_agent.subprocess.run", run)

    with pytest.raises(PrivateSshAgentError, match="not supported on Windows"):
        PrivateSshAgent.start()
    assert not called


@pytest.mark.parametrize("via_parent_link", [False, True])
def test_start_rejects_symlinked_socket_directory_without_touching_target(
    tmp_path, monkeypatch, via_parent_link,
):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    socket_dir = target / "agent"
    socket_dir.mkdir(mode=0o755)
    if via_parent_link:
        link = tmp_path / "agent-parent"
        link.symlink_to(target, target_is_directory=True)
        requested = link / "agent"
    else:
        requested = tmp_path / "agent-link"
        requested.symlink_to(socket_dir, target_is_directory=True)

    called = False

    def run(*_, **__):
        nonlocal called
        called = True
        raise AssertionError("ssh-agent must not run for an unsafe directory")

    monkeypatch.setattr("servonaut.services.vault.ssh_agent.shutil.which", lambda _: "/usr/bin/ssh-agent")
    monkeypatch.setattr("servonaut.services.vault.ssh_agent.subprocess.run", run)

    with pytest.raises(PrivateSshAgentError, match="symbolic link"):
        PrivateSshAgent.start(requested)

    assert stat.S_IMODE(socket_dir.stat().st_mode) == 0o755
    assert not called


def test_start_rejects_world_readable_socket_directory_without_chmod(tmp_path, monkeypatch):
    socket_dir = tmp_path / "world-readable-agent"
    socket_dir.mkdir(mode=0o755)
    os.chmod(socket_dir, 0o755)
    called = False

    def run(*_, **__):
        nonlocal called
        called = True
        raise AssertionError("ssh-agent must not run for an unsafe directory")

    monkeypatch.setattr("servonaut.services.vault.ssh_agent.shutil.which", lambda _: "/usr/bin/ssh-agent")
    monkeypatch.setattr("servonaut.services.vault.ssh_agent.subprocess.run", run)

    with pytest.raises(PrivateSshAgentError, match="unsafe ownership or permissions"):
        PrivateSshAgent.start(socket_dir)

    assert stat.S_IMODE(socket_dir.stat().st_mode) == 0o755
    assert not called


def test_default_start_migrates_owned_legacy_servonaut_parent(
    short_socket_dir, monkeypatch,
):
    home = short_socket_dir
    state_dir = home / ".servonaut"
    state_dir.mkdir(mode=0o755)
    os.chmod(state_dir, 0o755)
    calls = []

    def run(command, **_):
        calls.append(command)
        if command[:2] == ["ssh-agent", "-a"]:
            socket_path = command[2]
            return SimpleNamespace(
                returncode=0,
                stdout=f"SSH_AUTH_SOCK={socket_path}; SSH_AGENT_PID=123;",
            )
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr("servonaut.services.vault.ssh_agent.Path.home", lambda: home)
    monkeypatch.setattr("servonaut.services.vault.ssh_agent.shutil.which", lambda _: "/usr/bin/ssh-agent")
    monkeypatch.setattr("servonaut.services.vault.ssh_agent.subprocess.run", run)

    agent = PrivateSshAgent.start()
    agent.close()

    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert calls[0][:2] == ["ssh-agent", "-a"]


def test_socket_directory_creation_is_private(tmp_path):
    socket_dir = tmp_path / "new" / "private-agent"

    PrivateSshAgent._ensure_private_socket_directory(socket_dir)

    assert stat.S_IMODE(socket_dir.stat().st_mode) == 0o700


def test_start_rejects_an_overlong_socket_path_before_running_ssh_agent(
    tmp_path, monkeypatch,
):
    socket_dir = tmp_path / ("socket-" + "x" * 80)
    socket_dir.mkdir(mode=0o700)
    called = False

    def run(*_, **__):
        nonlocal called
        called = True
        raise AssertionError("ssh-agent must not run for an overlong socket path")

    monkeypatch.setattr("servonaut.services.vault.ssh_agent.shutil.which", lambda _: "/usr/bin/ssh-agent")
    monkeypatch.setattr("servonaut.services.vault.ssh_agent.subprocess.run", run)

    with pytest.raises(PrivateSshAgentError, match="socket path is too long"):
        PrivateSshAgent.start(socket_dir)

    assert not called


def test_lease_close_removes_its_public_identity_file(tmp_path):
    identity_file = tmp_path / "agent-identity.pub"
    identity_file.write_text("ssh-ed25519 AAAApublic\n", encoding="ascii")
    agent = MagicMock()
    lease = VaultSshLease(
        "vault", "/tmp/agent.sock", None, "/tmp/known-hosts", "deploy", (),
        "ssh-ed25519 AAAApublic", str(identity_file), "vault-1", "item-1", None, agent,
    )

    lease.close()

    agent.close.assert_called_once()
    assert not identity_file.exists()


@pytest.mark.skipif(not os.path.exists("/bin/ssh-agent"), reason="OpenSSH is unavailable")
def test_two_private_agents_can_hold_independent_leases(short_socket_dir):
    first = PrivateSshAgent.start(short_socket_dir)
    second = PrivateSshAgent.start(short_socket_dir)
    try:
        assert first.socket_path != second.socket_path
        first.add_private_key(_private_key(), ttl_seconds=60)
        second.add_private_key(_private_key(), ttl_seconds=60)
        for agent in (first, second):
            listed = subprocess.run(
                ["ssh-add", "-l"], capture_output=True, check=False,
                env=agent._environment(), timeout=10,
            )
            assert listed.returncode == 0
    finally:
        first.close()
        second.close()


@pytest.mark.skipif(
    not os.path.exists("/bin/ssh-agent") or shutil.which("sshd") is None,
    reason="OpenSSH client, agent, or server is unavailable",
)
def test_private_agent_authenticates_with_public_identity_file_only(tmp_path, monkeypatch):
    """OpenSSH selects an agent key under IdentitiesOnly via its public file."""
    # OpenSSH Unix sockets have a short path limit, so the default HOME used
    # for this real agent journey must be shorter than pytest's test path.
    servonaut_home = Path(tempfile.mkdtemp(prefix="servonaut-"))
    auth_file = servonaut_home / ".servonaut" / "auth.json"
    monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
    auth = AuthService()
    auth._token = AuthToken(
        access_token="access", refresh_token="refresh", expires_at=time.time() + 60,
        plan="solo",
    )
    auth._save_token()
    os.chmod(auth_file.parent, 0o775)
    # The default custody setup migrates the normal login/config root before
    # materialising the private-agent socket there.
    monkeypatch.setattr("servonaut.services.vault.ssh_agent.Path.home", lambda: servonaut_home)
    store = IdentityStore(environment_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    assert store.path == servonaut_home / ".servonaut" / "vault" / "vault_keys.json"
    assert stat.S_IMODE(auth_file.parent.stat().st_mode) == 0o700

    try:
        port = _available_port()
    except PermissionError:
        pytest.skip("sandbox forbids local sockets")
    user = pwd.getpwuid(os.getuid()).pw_name
    home = tmp_path / "isolated-home"
    home.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    public = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    authorized_keys = tmp_path / "authorized_keys"
    authorized_keys.write_bytes(public + b"\n")
    os.chmod(authorized_keys, 0o600)
    identity_file = tmp_path / "agent-identity.pub"
    identity_file.write_bytes(public + b"\n")
    os.chmod(identity_file, 0o600)
    assert stat.S_IMODE(identity_file.stat().st_mode) == 0o600
    host_key = tmp_path / "host-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-N", "", "-t", "ed25519", "-f", str(host_key)],
        check=True,
    )
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        f"[127.0.0.1]:{port} {host_key.with_suffix('.pub').read_text().strip()}\n",
        encoding="ascii",
    )
    config = tmp_path / "sshd_config"
    config.write_text(
        "\n".join(
            (
                f"Port {port}", "ListenAddress 127.0.0.1", f"HostKey {host_key}",
                f"AuthorizedKeysFile {authorized_keys}", "PasswordAuthentication no",
                "KbdInteractiveAuthentication no", "UsePAM no", "StrictModes no",
                "PermitRootLogin no", "PidFile none", "LogLevel VERBOSE", f"AllowUsers {user}",
            )
        ) + "\n",
        encoding="utf-8",
    )
    sshd = subprocess.Popen(
        [str(shutil.which("sshd")), "-D", "-e", "-f", str(config)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        _wait_for_sshd(port, sshd)
        agent = PrivateSshAgent.start()
        try:
            assert agent.socket_path.parent == servonaut_home / ".servonaut" / "vault" / "tmp"
            agent.add_private_key(private, ttl_seconds=60)
            manager = MagicMock()
            manager.get.return_value = AppConfig(ssh=SSHConfig())
            command = SSHService(manager).build_ssh_command(
                host="127.0.0.1", username=user, port=port,
                remote_command="echo native-agent-ok", identity_agent=str(agent.socket_path),
                identity_file=str(identity_file), known_hosts_file=str(known_hosts),
                extra_options=["HostKeyAlias=aws:example:i-12345678"],
            )
            command[1:1] = ["-F", "/dev/null"]
            assert "HostKeyAlias=aws:example:i-12345678" not in command
            env = {**os.environ, "HOME": str(home)}
            env.pop("SSH_AUTH_SOCK", None)
            result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=20)
            assert result.returncode == 0, result.stderr
            assert result.stdout.strip() == "native-agent-ok"
            assert "PRIVATE KEY" not in identity_file.read_text(encoding="ascii")
            assert list(home.iterdir()) == []
        finally:
            agent.close()
    finally:
        sshd.terminate()
        sshd.wait(timeout=10)
        shutil.rmtree(servonaut_home, ignore_errors=True)
