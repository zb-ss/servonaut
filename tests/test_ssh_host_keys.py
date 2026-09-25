"""Host-key verification on every ssh/scp command Servonaut builds.

Covers the ``ssh.host_key_checking`` setting, the options each call site
emits per mode (``off`` reproducing the previous argv exactly), the
owner-only known_hosts file, and turning OpenSSH's refusal output into a
message that names the host and the recovery command.
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rich.text import Text
from textual.app import App

from servonaut.cli import servers as cli_servers
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import (
    CONFIG_VERSION,
    AppConfig,
    ConnectionProfile,
    MemoryConfig,
    ScanRule,
    SSHConfig,
)
from servonaut.screens.command_overlay import CommandOverlay
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.services import ssh_host_keys
from servonaut.services.connection_service import ConnectionService
from servonaut.services.memory.interfaces import ModuleProberInterface, ModuleResult
from servonaut.services.memory.service import HOST_KEY_BUILD_REASON, MemoryService
from servonaut.services.memory.store import MemoryStore
from servonaut.services.scan_service import ScanService
from servonaut.services.scp_service import SCPService
from servonaut.services.ssh_host_keys import (
    HOST_KEY_CHANGED,
    HOST_KEY_UNKNOWN,
    HOST_KEY_UNVERIFIED,
    HostKeyPolicy,
    HostKeyVerificationError,
    detect_host_key_problem,
)
from servonaut.services.ssh_service import SSHService

# Captured before the autouse fixture in conftest replaces it per test.
_REAL_SERVONAUT_KNOWN_HOSTS_PATH = ssh_host_keys.servonaut_known_hosts_path

MODES = ("accept-new", "yes", "off")
VERIFYING_MODES = ("accept-new", "yes")
KEYED_BASTION = ConnectionProfile(
    name="keyed", bastion_host="bastion.example.com",
    bastion_user="ec2-user", bastion_key="/keys/bastion.pem",
)
KEYLESS_BASTION = ConnectionProfile(
    name="keyless", bastion_host="bastion.example.com",
    bastion_user="ubuntu", ssh_port=2222,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def known_hosts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Servonaut's and the user's known_hosts files under a temporary home."""
    files = SimpleNamespace(
        servonaut=tmp_path / "data" / "known_hosts",
        user=tmp_path / "home" / ".ssh" / "known_hosts",
    )
    monkeypatch.setattr(ssh_host_keys, "servonaut_known_hosts_path", lambda: files.servonaut)
    monkeypatch.setattr(ssh_host_keys, "user_known_hosts_path", lambda: files.user)
    return files


@pytest.fixture
def posix_hop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the bastion-hop form independent of the machine running the tests."""
    monkeypatch.setattr("servonaut.services.connection_service.get_os", lambda: "linux")


def _expected_options(mode: str, files: SimpleNamespace) -> List[str]:
    if mode == "off":
        return ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    return [
        "-o", f"StrictHostKeyChecking={mode}",
        "-o", f'UserKnownHostsFile="{files.servonaut}" "{files.user}"',
    ]


def _config_manager(mode: str = "accept-new", **config_fields) -> MagicMock:
    manager = MagicMock()
    manager.get.return_value = AppConfig(
        ssh=SSHConfig(host_key_checking=mode), **config_fields,
    )
    return manager


def _destination(profile: ConnectionProfile) -> str:
    """The bastion hop's ``user@host`` for *profile*."""
    return f"{profile.bastion_user}@{profile.bastion_host}"


def _contains_run(argv: List[str], run: List[str]) -> bool:
    """True when *run* appears as a contiguous slice of *argv*."""
    return any(argv[i:i + len(run)] == run for i in range(len(argv) - len(run) + 1))


def _proxy_command_argv(proxy_args: List[str]) -> List[str]:
    assert proxy_args[0] == "-o" and proxy_args[1].startswith("ProxyCommand=")
    return shlex.split(proxy_args[1][len("ProxyCommand="):])


def _host_key_values(argv: List[str]) -> Iterator[str]:
    """Yield every host-key option value, including a ProxyCommand hop's."""
    for index, arg in enumerate(argv):
        if arg.startswith(("StrictHostKeyChecking=", "UserKnownHostsFile=")):
            yield arg
        if arg == "-o" and index + 1 < len(argv) and argv[index + 1].startswith("ProxyCommand="):
            yield from _host_key_values(shlex.split(argv[index + 1][len("ProxyCommand="):]))


def _run(coro):
    return asyncio.run(coro)


def _changed_stderr(host: str, offending_file: str) -> str:
    """OpenSSH's refusal of a changed host key (as printed by OpenSSH 10)."""
    return (
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n"
        "Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n"
        "It is also possible that a host key has just been changed.\n"
        "The fingerprint for the ED25519 key sent by the remote host is\n"
        "SHA256:c2VydmVyLWV4YW1wbGUta2V5LWZpbmdlcnByaW50.\n"
        "Please contact your system administrator.\n"
        f"Add correct host key in {offending_file} to get rid of this message.\n"
        f"Offending ED25519 key in {offending_file}:1\n"
        "  remove with:\n"
        f"  ssh-keygen -f '{offending_file}' -R '{host}'\n"
        f"Host key for {host} has changed and you have requested strict checking.\n"
        "Host key verification failed.\n"
    )


def _unknown_stderr(host: str) -> str:
    """OpenSSH's refusal of an unknown host under StrictHostKeyChecking=yes."""
    return (
        f"No ED25519 host key is known for {host} and you have requested strict checking.\n"
        "Host key verification failed.\n"
    )


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

class TestHostKeyCheckingSetting:
    def test_default_is_accept_new(self):
        assert SSHConfig().host_key_checking == "accept-new"
        assert AppConfig().ssh.host_key_checking == "accept-new"

    @pytest.mark.parametrize(
        "raw, expected",
        [("accept-new", "accept-new"), ("yes", "yes"), ("off", "off"),
         (" YES ", "yes"), ("Accept-New", "accept-new")],
    )
    def test_supported_values(self, raw, expected):
        assert SSHConfig(host_key_checking=raw).host_key_checking == expected

    @pytest.mark.parametrize("raw", ["no", "strict", "", None, 1, False, ["off"]])
    def test_unsupported_value_falls_back_to_verifying_default(self, raw, caplog):
        with caplog.at_level(logging.WARNING, logger="servonaut.config.schema"):
            config = SSHConfig(host_key_checking=raw)
        # Never "off": a typo must not disable verification.
        assert config.host_key_checking == "accept-new"
        assert "host_key_checking" in caplog.text

    @pytest.mark.parametrize(
        "ssh_section, expected",
        [({"host_key_checking": "yes"}, "yes"),
         ({"host_key_checking": "off"}, "off"),
         ({"host_key_checking": "bogus"}, "accept-new"),
         ({}, "accept-new")],
    )
    def test_config_file_value_is_loaded_and_validated(self, tmp_path, ssh_section, expected):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"version": CONFIG_VERSION, "ssh": ssh_section}))
        loaded = ConfigManager(config_path=path).load()
        assert loaded.ssh.host_key_checking == expected


# ---------------------------------------------------------------------------
# The shared helper
# ---------------------------------------------------------------------------

class TestHostKeyPolicy:
    @pytest.mark.parametrize("mode", MODES)
    def test_options_per_mode(self, known_hosts, mode):
        policy = HostKeyPolicy.from_ssh_config(SSHConfig(host_key_checking=mode))
        assert policy.ssh_options() == _expected_options(mode, known_hosts)

    def test_servonaut_file_is_listed_first_so_new_keys_land_there(self, known_hosts):
        options = HostKeyPolicy.from_ssh_config(None).ssh_options()
        value = options[3]
        assert value.index(str(known_hosts.servonaut)) < value.index(str(known_hosts.user))

    def test_off_without_discard_keeps_only_strict_no(self, known_hosts):
        policy = HostKeyPolicy.from_ssh_config(SSHConfig(host_key_checking="off"))
        assert policy.ssh_options(discard_keys_when_off=False) == [
            "-o", "StrictHostKeyChecking=no",
        ]

    def test_paths_follow_home_and_are_absolute(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        assert _REAL_SERVONAUT_KNOWN_HOSTS_PATH() == tmp_path / ".servonaut" / "known_hosts"
        assert ssh_host_keys.user_known_hosts_path() == tmp_path / ".ssh" / "known_hosts"

    @pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client not installed")
    def test_openssh_reads_both_known_hosts_files(self, tmp_path, monkeypatch):
        spaced = tmp_path / "data dir" / "known_hosts"
        user = tmp_path / "home" / ".ssh" / "known_hosts"
        monkeypatch.setattr(ssh_host_keys, "servonaut_known_hosts_path", lambda: spaced)
        monkeypatch.setattr(ssh_host_keys, "user_known_hosts_path", lambda: user)
        options = HostKeyPolicy.from_ssh_config(None).ssh_options()
        resolved = subprocess.run(
            ["ssh", "-F", "/dev/null", "-G", *options, "host.example.invalid"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.splitlines()
        assert "stricthostkeychecking accept-new" in resolved
        assert f"userknownhostsfile {spaced} {user}" in resolved


# ---------------------------------------------------------------------------
# Servonaut's known_hosts file
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
class TestKnownHostsFile:
    def test_created_owner_only_on_first_command(self, known_hosts):
        assert not known_hosts.servonaut.parent.exists()
        SSHService(_config_manager()).build_ssh_command("10.0.0.5", "deploy")
        assert stat.S_IMODE(known_hosts.servonaut.stat().st_mode) == 0o600
        assert stat.S_IMODE(known_hosts.servonaut.parent.stat().st_mode) == 0o700
        assert known_hosts.servonaut.read_text() == ""

    def test_scp_creates_it_too(self, known_hosts):
        SCPService().build_download_command("/etc/hosts", "/tmp/hosts", "10.0.0.5", "deploy")
        assert stat.S_IMODE(known_hosts.servonaut.stat().st_mode) == 0o600

    def test_existing_file_is_left_untouched(self, known_hosts):
        known_hosts.servonaut.parent.mkdir(parents=True)
        known_hosts.servonaut.write_text("10.0.0.5 ssh-ed25519 AAAA\n")
        os.chmod(known_hosts.servonaut, 0o644)
        SSHService(_config_manager()).build_ssh_command("10.0.0.5", "deploy")
        assert known_hosts.servonaut.read_text() == "10.0.0.5 ssh-ed25519 AAAA\n"
        assert stat.S_IMODE(known_hosts.servonaut.stat().st_mode) == 0o644

    def test_off_mode_creates_nothing(self, known_hosts):
        SSHService(_config_manager("off")).build_ssh_command("10.0.0.5", "deploy")
        assert not known_hosts.servonaut.exists()


# ---------------------------------------------------------------------------
# Every call site carries the options
# ---------------------------------------------------------------------------

class TestSshAndScpBuilders:
    @pytest.mark.parametrize("mode", MODES)
    def test_ssh_command_leads_with_host_key_options(self, known_hosts, mode):
        argv = SSHService(_config_manager(mode)).build_ssh_command("10.0.0.5", "deploy")
        assert argv[1:5] == _expected_options(mode, known_hosts)

    @pytest.mark.parametrize("mode", MODES)
    def test_scp_commands_lead_with_host_key_options(self, known_hosts, mode):
        scp = SCPService(SSHConfig(host_key_checking=mode))
        upload = scp.build_upload_command("/tmp/a", "/srv/a", "10.0.0.5", "deploy")
        download = scp.build_download_command("/srv/a", "/tmp/a", "10.0.0.5", "deploy")
        assert upload[1:5] == _expected_options(mode, known_hosts)
        assert download[1:5] == _expected_options(mode, known_hosts)

    def test_off_reproduces_previous_ssh_argv(self, known_hosts):
        argv = SSHService(_config_manager("off")).build_ssh_command(
            host="10.0.0.5", username="deploy", key_path="/keys/web-1.pem",
            remote_command="uptime", proxy_args=["-o", "ProxyCommand=nc %h %p"],
            port=2222, extra_options=["Ciphers=+aes128-cbc"],
        )
        assert argv == [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=5",
            "-o", "TCPKeepAlive=yes", "-o", "ConnectTimeout=15",
            "-p", "2222", "-o", "Ciphers=+aes128-cbc", "-o", "ProxyCommand=nc %h %p",
            "-o", "IdentitiesOnly=yes", "-i", "/keys/web-1.pem",
            # The end-of-options marker applies in every mode.
            "--", "deploy@10.0.0.5", "uptime",
        ]

    def test_off_reproduces_previous_scp_argv(self, known_hosts):
        argv = SCPService(SSHConfig(host_key_checking="off")).build_upload_command(
            local_path="/tmp/app.tar", remote_path="/srv/app.tar", host="10.0.0.5",
            username="deploy", key_path="/keys/web-1.pem", port=2222,
        )
        assert argv == [
            "scp", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=5",
            "-o", "TCPKeepAlive=yes", "-o", "ConnectTimeout=15", "-P", "2222",
            "-o", "IdentitiesOnly=yes", "-i", "/keys/web-1.pem",
            # The end-of-options marker applies in every mode.
            "--", "/tmp/app.tar", "deploy@10.0.0.5:/srv/app.tar",
        ]

    def test_extra_options_cannot_weaken_host_key_checking(self, known_hosts):
        argv = SSHService(_config_manager()).build_ssh_command(
            "10.0.0.5", "deploy", extra_options=["StrictHostKeyChecking=no"],
        )
        # OpenSSH honours the first value of an option.
        first = next(a for a in argv if a.startswith("StrictHostKeyChecking="))
        assert first == "StrictHostKeyChecking=accept-new"


class TestBastionHop:
    @pytest.mark.parametrize("mode", VERIFYING_MODES)
    def test_keyed_hop_carries_host_key_options(self, known_hosts, mode):
        args = ConnectionService(_config_manager(mode)).get_proxy_args(KEYED_BASTION)
        hop = _proxy_command_argv(args)
        assert hop[:3] == ["ssh", "-i", "/keys/bastion.pem"]
        assert _contains_run(hop, _expected_options(mode, known_hosts))
        assert hop[-4:] == ["-W", "%h:%p", "--", _destination(KEYED_BASTION)]

    @pytest.mark.parametrize("mode", VERIFYING_MODES)
    def test_keyless_hop_becomes_proxy_command_with_options(self, known_hosts, posix_hop, mode):
        args = ConnectionService(_config_manager(mode)).get_proxy_args(KEYLESS_BASTION)
        hop = _proxy_command_argv(args)
        assert "-J" not in args
        assert _contains_run(hop, _expected_options(mode, known_hosts))
        assert "-i" not in hop
        assert hop[-6:] == ["-p", "2222", "-W", "%h:%p", "--", _destination(KEYLESS_BASTION)]

    def test_keyless_hop_without_user_lets_ssh_choose(self, known_hosts, posix_hop):
        profile = ConnectionProfile(name="p", bastion_host="bastion.example.com")
        hop = _proxy_command_argv(ConnectionService(_config_manager()).get_proxy_args(profile))
        assert hop[-1] == "bastion.example.com"

    def test_off_reproduces_previous_keyed_hop(self, known_hosts):
        args = ConnectionService(_config_manager("off")).get_proxy_args(KEYED_BASTION)
        assert args == [
            "-o",
            "ProxyCommand=ssh -i /keys/bastion.pem -o StrictHostKeyChecking=no "
            "-o IdentitiesOnly=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=5 "
            "-o TCPKeepAlive=yes -o ConnectTimeout=15 -W %h:%p -- "
            + _destination(KEYED_BASTION),
        ]

    def test_off_reproduces_previous_proxy_jump(self, known_hosts, posix_hop):
        args = ConnectionService(_config_manager("off")).get_proxy_args(KEYLESS_BASTION)
        assert args == ["-J", f"{_destination(KEYLESS_BASTION)}:2222"]

    def test_windows_keeps_proxy_jump(self, known_hosts, monkeypatch):
        monkeypatch.setattr("servonaut.services.connection_service.get_os", lambda: "windows")
        args = ConnectionService(_config_manager()).get_proxy_args(KEYLESS_BASTION)
        assert args == ["-J", f"{_destination(KEYLESS_BASTION)}:2222"]

    def test_raw_proxy_command_is_used_verbatim(self, known_hosts):
        profile = ConnectionProfile(name="raw", proxy_command="nc -X 5 -x proxy:1080 %h %p")
        args = ConnectionService(_config_manager()).get_proxy_args(profile)
        assert args == ["-o", "ProxyCommand=nc -X 5 -x proxy:1080 %h %p"]


class _ProbeApp:
    """Just enough app for ServerActionsScreen._run_ssh_probe."""

    def __init__(self, mode: str) -> None:
        self.config_manager = _config_manager(mode, default_username="deploy")
        self.connection_service = ConnectionService(self.config_manager)
        self.notifications: List[dict] = []

    def notify(self, message, *, severity="information", markup=True, timeout=None):
        self.notifications.append({"message": message, "severity": severity})


def _probe_screen(app: _ProbeApp, instance: Optional[dict] = None) -> ServerActionsScreen:
    patched = type("ProbeScreen", (ServerActionsScreen,), {"app": property(lambda self: app)})
    screen = patched.__new__(patched)
    screen._instance = instance or {"id": "i-0abc", "name": "web-1", "username": "deploy"}
    return screen


def _completed(returncode: int = 0, stdout=b"", stderr=b"") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestVerifySshProbe:
    def _argv(self, mode: str) -> List[str]:
        screen = _probe_screen(_ProbeApp(mode))
        with patch("servonaut.screens.server_actions.subprocess.run", return_value=_completed()) as run:
            assert _run(screen._run_ssh_probe(None, "10.0.0.5")) == "verified"
        return run.call_args.args[0]

    @pytest.mark.parametrize("mode", VERIFYING_MODES)
    def test_probe_carries_host_key_options(self, known_hosts, mode):
        argv = self._argv(mode)
        assert argv[:5] == ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
        assert argv[5:9] == _expected_options(mode, known_hosts)

    def test_off_reproduces_previous_probe_argv(self, known_hosts):
        assert self._argv("off") == [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no", "deploy@10.0.0.5", "true",
        ]


class TestCliVerifyProbe:
    def test_default_policy_verifies(self, known_hosts):
        with patch("servonaut.cli.servers.subprocess.run", return_value=_completed()) as run:
            cli_servers._run_ssh_probe("/keys/web-1.pem", "deploy", "10.0.0.5", None, 5)
        assert _contains_run(run.call_args.args[0], _expected_options("accept-new", known_hosts))

    @pytest.mark.parametrize("mode", MODES)
    def test_configured_policy_is_used(self, known_hosts, mode):
        policy = HostKeyPolicy.from_ssh_config(SSHConfig(host_key_checking=mode))
        with patch("servonaut.cli.servers.subprocess.run", return_value=_completed()) as run:
            cli_servers._run_ssh_probe("/keys/web-1.pem", "deploy", "10.0.0.5", 2222, 5, policy)
        argv = run.call_args.args[0]
        assert _contains_run(argv, _expected_options(mode, known_hosts))
        assert argv[1:3] == ["-p", "2222"]


class _OverlayHost(App):
    def __init__(self, mode: str) -> None:
        super().__init__()
        self.config_manager = _config_manager(mode, default_username="deploy")
        self.connection_service = ConnectionService(self.config_manager)
        self.ssh_service = SSHService(self.config_manager)
        self.command_history = None
        self.demo_mode = False
        self.redaction_service = None

    def on_mount(self) -> None:
        self.push_screen(CommandOverlay({
            "id": "i-0abc", "name": "web-1", "state": "running",
            "public_ip": "10.0.0.5", "private_ip": "10.0.0.5", "key_name": "",
        }))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", MODES)
async def test_command_overlay_argv_carries_host_key_options(known_hosts, mode):
    app = _OverlayHost(mode)
    with patch.object(CommandOverlay, "_run_ssh_command") as run:
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            app.screen._execute_command("uptime")
            await app.screen.workers.wait_for_complete()
    assert run.call_args.args[0][1:5] == _expected_options(mode, known_hosts)


def _scan_service(mode: str):
    manager = _config_manager(
        mode, default_username="deploy", default_scan_paths=["/srv/app"],
        scan_rules=[ScanRule(name="all", match_conditions={}, scan_commands=["uptime"])],
    )
    return ScanService(manager), SSHService(manager), ConnectionService(manager)


_SCAN_INSTANCE = {
    "id": "i-0abc", "name": "web-1", "state": "running",
    "public_ip": "10.0.0.5", "private_ip": "10.0.0.5", "key_name": "",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", MODES)
async def test_scan_argv_carries_host_key_options(known_hosts, mode):
    scan, ssh, connection = _scan_service(mode)
    ok = SimpleNamespace(returncode=0, stdout="output", stderr="")
    with patch("servonaut.services.scan_service.subprocess.run", return_value=ok) as run:
        await scan.scan_server(_SCAN_INSTANCE, ssh, connection)
    argvs = [c.args[0] for c in run.call_args_list]
    assert len(argvs) == 2
    for argv in argvs:
        assert argv[1:5] == _expected_options(mode, known_hosts)


class TestNoTildeInHostKeyOptions:
    """OpenSSH expands ``~`` from the password database, not ``$HOME``."""

    @pytest.mark.parametrize("mode", MODES)
    def test_every_built_argv_uses_absolute_paths(self, tmp_path, monkeypatch, posix_hop, mode):
        monkeypatch.setenv("HOME", str(tmp_path))
        manager = _config_manager(mode, default_username="deploy")
        ssh = SSHService(manager)
        connection = ConnectionService(manager)
        scp = SCPService(SSHConfig(host_key_checking=mode))
        keyed = ConnectionProfile(
            name="k", bastion_host="bastion.example.com", bastion_key="~/.ssh/bastion.pem",
        )
        argvs = [
            ssh.build_ssh_command("10.0.0.5", "deploy", key_path="~/.ssh/web-1.pem",
                                  proxy_args=connection.get_proxy_args(keyed)),
            ssh.build_ssh_command("10.0.0.5", "deploy",
                                  proxy_args=connection.get_proxy_args(KEYLESS_BASTION)),
            scp.build_upload_command("/tmp/a", "/srv/a", "10.0.0.5", "deploy"),
        ]
        with patch("servonaut.cli.servers.subprocess.run", return_value=_completed()) as run:
            cli_servers._run_ssh_probe(
                "/keys/web-1.pem", "deploy", "10.0.0.5", None, 5,
                HostKeyPolicy.from_ssh_config(SSHConfig(host_key_checking=mode)),
            )
        argvs.append(run.call_args.args[0])
        with patch("servonaut.screens.server_actions.subprocess.run", return_value=_completed()) as run:
            _run(_probe_screen(_ProbeApp(mode))._run_ssh_probe(None, "10.0.0.5"))
        argvs.append(run.call_args.args[0])

        values = [value for argv in argvs for value in _host_key_values(argv)]
        assert values, "no host-key options found"
        assert all("~" not in value for value in values), values
        if mode != "off":
            assert any(str(tmp_path / ".ssh" / "known_hosts") in value for value in values)


# ---------------------------------------------------------------------------
# Recognising a refused host key
# ---------------------------------------------------------------------------

class TestDetectHostKeyProblem:
    def test_changed_key_names_host_and_exact_recovery_command(self, known_hosts):
        stderr = _changed_stderr("[10.0.0.5]:2222", str(known_hosts.servonaut))
        problem = detect_host_key_problem(stderr, host="10.0.0.5", port=2222)
        assert problem.kind == HOST_KEY_CHANGED
        assert problem.host == "[10.0.0.5]:2222"
        assert problem.recovery_command == (
            f"ssh-keygen -R '[10.0.0.5]:2222' -f {known_hosts.servonaut}"
        )
        assert "[10.0.0.5]:2222 has changed" in problem.message
        assert problem.recovery_command in problem.message
        assert problem.reason_code == "ssh_host_key_changed"

    def test_stale_key_in_users_file_is_removed_from_that_file(self, known_hosts):
        stderr = _changed_stderr("web-1.example.com", str(known_hosts.user))
        problem = detect_host_key_problem(stderr, host="10.0.0.5")
        assert problem.host == "web-1.example.com"
        assert problem.recovery_command == (
            f"ssh-keygen -R web-1.example.com -f {known_hosts.user}"
        )

    def test_older_openssh_wording(self, known_hosts):
        stderr = (
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
            "Offending ECDSA key in /srv/ops/known hosts:7\n"
            "  remove with:\n"
            '  ssh-keygen -f "/srv/ops/known hosts" -R "web-1.example.com"\n'
            "ECDSA host key for web-1.example.com has changed and you have "
            "requested strict checking.\n"
            "Host key verification failed.\n"
        )
        problem = detect_host_key_problem(stderr)
        assert problem.kind == HOST_KEY_CHANGED
        assert problem.host == "web-1.example.com"
        assert problem.known_hosts_file == "/srv/ops/known hosts"
        assert problem.recovery_command.endswith("-f '/srv/ops/known hosts'")

    def test_unknown_host_in_strict_mode(self, known_hosts):
        problem = detect_host_key_problem(_unknown_stderr("[10.0.0.5]:2222"), host="10.0.0.5")
        assert problem.kind == HOST_KEY_UNKNOWN
        assert problem.host == "[10.0.0.5]:2222"
        assert problem.recovery_command is None
        assert '"yes"' in problem.message and "accept-new" in problem.message
        assert str(known_hosts.servonaut) in problem.message

    def test_bare_verification_failure_names_the_target(self, known_hosts):
        problem = detect_host_key_problem(
            "Host key verification failed.\n", host="10.0.0.5", port=2222,
        )
        assert problem.kind == HOST_KEY_UNVERIFIED
        assert problem.host == "[10.0.0.5]:2222"
        assert "verification failed for [10.0.0.5]:2222" in problem.message

    def test_warning_without_refusal_is_not_a_problem(self):
        # With verification off, ssh prints the banner and connects anyway.
        stderr = (
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
            "Password authentication is disabled to avoid man-in-the-middle attacks.\n"
        )
        assert detect_host_key_problem(stderr, host="10.0.0.5") is None

    @pytest.mark.parametrize("stderr", [
        "", "deploy@10.0.0.5: Permission denied (publickey).\n",
        "ssh: connect to host 10.0.0.5 port 22: Connection refused\n",
    ])
    def test_other_failures_are_not_host_key_problems(self, stderr):
        assert detect_host_key_problem(stderr, host="10.0.0.5") is None


# ---------------------------------------------------------------------------
# Surfaces that capture ssh stderr report the clear message
# ---------------------------------------------------------------------------

class TestMcpRunCommand:
    def test_changed_key_is_reported_without_ssm_fallback(self, known_hosts):
        from servonaut.mcp.guards import GuardLevel
        from tests.test_mcp_tools import make_tools

        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        # The bastion hop's refusal also prints "Connection closed", which
        # alone would read as an unreachable host.
        stderr = _changed_stderr("bastion.example.com", str(known_hosts.servonaut))
        stderr += "Connection closed by UNKNOWN port 65535\n"
        ssm = MagicMock()
        with patch("servonaut.mcp.tools.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"", stderr.encode()))), \
                patch("servonaut.services.ssm_service.SSMService", ssm):
            result = _run(tools.run_command("i-abc123", "uptime", transport="auto"))

        assert result.startswith("Error: SSH host key for bastion.example.com has changed")
        assert f"ssh-keygen -R bastion.example.com -f {known_hosts.servonaut}" in result
        ssm.assert_not_called()
        audit = tools._audit.log.call_args
        assert audit.args[3] is False
        assert audit.args[4] == "ssh_host_key_changed"

    def test_get_logs_reports_it_too(self, known_hosts):
        from servonaut.mcp.guards import GuardLevel
        from tests.test_mcp_tools import make_tools

        tools = make_tools(guard_level=GuardLevel.DANGEROUS)
        stderr = _changed_stderr("10.0.0.5", str(known_hosts.servonaut)).encode()
        with patch("servonaut.mcp.tools.run_ssh_subprocess",
                   new=AsyncMock(return_value=(b"", stderr))):
            result = _run(tools.get_logs("i-abc123", "/var/log/syslog", 10))
        assert "SSH host key for 10.0.0.5 has changed" in result


def test_mcp_transfer_file_leads_with_the_explanation(known_hosts):
    from servonaut.mcp.guards import GuardLevel
    from tests.test_mcp_tools import make_tools

    tools = make_tools(guard_level=GuardLevel.DANGEROUS)
    stderr = _changed_stderr("10.0.0.5", str(known_hosts.servonaut))
    tools._scp_service.execute_transfer = AsyncMock(return_value=(255, "", stderr))
    result = _run(tools.transfer_file("i-abc123", "/tmp/app.tar", "/srv/app.tar", "upload"))
    first_lines = result.splitlines()[:2]
    assert first_lines[0] == "Transfer failed (exit 255)"
    assert first_lines[1].startswith("SSH host key for 10.0.0.5 has changed")


def test_relay_run_command_reports_changed_key(known_hosts):
    from servonaut.models.relay_messages import CommandType
    from tests.test_relay_executors import make_executors, make_request

    executors = make_executors()
    stderr = _changed_stderr("10.0.0.5", str(known_hosts.servonaut)).encode()
    with patch("servonaut.services.relay_executors.run_ssh_subprocess",
               new=AsyncMock(return_value=(b"", stderr))):
        response = _run(executors.execute(make_request(
            cmd_type=CommandType.RUN_COMMAND, payload={"command": "uptime"},
        )))
    assert response.status == "error"
    assert "SSH host key for 10.0.0.5 has changed" in response.error_message


class _OverlayApp:
    def __init__(self) -> None:
        self.demo_mode = False
        self.redaction_service = None

    @staticmethod
    def call_from_thread(callback, *args):
        return callback(*args)


def test_command_overlay_explains_a_changed_key(known_hosts):
    app = _OverlayApp()
    patched = type("Overlay", (CommandOverlay,), {"app": property(lambda self: app)})
    overlay = patched.__new__(patched)
    overlay._host, overlay._port, overlay._output_lines = "web-1.example.com", 2222, []
    widget = MagicMock()

    overlay._report_host_key_problem(
        _changed_stderr("[web-1.example.com]:2222", str(known_hosts.servonaut)),
        widget, lambda t: t,
    )

    shown = widget.append_error.call_args.args[0]
    # Escaped: Rich would otherwise read "[web-1.example.com]" as a style tag.
    assert "\\[web-1.example.com]:2222 has changed" in shown
    assert Text.from_markup(shown).plain.startswith(
        "SSH host key for [web-1.example.com]:2222 has changed"
    )
    assert overlay._output_lines[-1].startswith(
        "SSH host key for [web-1.example.com]:2222 has changed"
    )


class _FakeProcess:
    """A finished ssh process for CommandOverlay._run_ssh_command."""

    def __init__(self, stderr: str, returncode: int) -> None:
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(stderr.encode())
        self.returncode = None
        self._exit = returncode

    def wait(self) -> int:
        self.returncode = self._exit
        return self._exit


def test_command_overlay_run_reports_a_refused_key(known_hosts):
    app = _OverlayApp()
    patched = type("Overlay", (CommandOverlay,), {"app": property(lambda self: app)})
    overlay = patched.__new__(patched)
    overlay._host, overlay._port, overlay._output_lines = "10.0.0.5", None, []
    overlay._running_process = None
    widget = MagicMock()
    stderr = _changed_stderr("10.0.0.5", str(known_hosts.servonaut))

    with patch("servonaut.screens.command_overlay.subprocess.Popen",
               return_value=_FakeProcess(stderr, 255)):
        overlay._run_ssh_command(["ssh", "deploy@10.0.0.5", "uptime"], widget)

    errors = [c.args[0] for c in widget.append_error.call_args_list]
    assert any(e.startswith("SSH host key for 10.0.0.5 has changed") for e in errors)
    assert f"ssh-keygen -R 10.0.0.5 -f {known_hosts.servonaut}" in overlay._output_lines[-1]


@pytest.mark.asyncio
async def test_scan_stops_on_a_changed_key(known_hosts):
    scan, ssh, connection = _scan_service("accept-new")
    refused = SimpleNamespace(
        returncode=255, stdout="", stderr=_changed_stderr("10.0.0.5", str(known_hosts.servonaut)),
    )
    with patch("servonaut.services.scan_service.subprocess.run", return_value=refused) as run:
        with pytest.raises(HostKeyVerificationError) as raised:
            await scan.scan_server(_SCAN_INSTANCE, ssh, connection)
    assert run.call_count == 1  # the remaining scans would be refused too
    assert "SSH host key for 10.0.0.5 has changed" in str(raised.value)


class _RunnerProber(ModuleProberInterface):
    """Runs one command through the real SSH runner, like the real probers."""

    name = "os"
    ttl_seconds = 3600

    async def probe(self, ssh_runner) -> ModuleResult:
        stdout, _stderr, _rc = await ssh_runner("uname -a")
        return ModuleResult(
            module=self.name, instance_id="", observed={"uname": stdout},
            probed_at="", ttl_seconds=self.ttl_seconds, partial=True,
        )


def test_memory_build_reports_changed_key_and_keeps_snapshot(tmp_path, known_hosts):
    manager = _config_manager(default_username="deploy")
    store = MemoryStore(root=tmp_path / "memory")
    service = MemoryService(
        store=store, config=MemoryConfig(), probers=[_RunnerProber()],
        ssh_service=SSHService(manager), connection_service=ConnectionService(manager),
    )
    process = MagicMock()
    process.communicate = AsyncMock(return_value=(
        b"", _changed_stderr("10.0.0.5", str(known_hosts.servonaut)).encode(),
    ))
    process.returncode = 255
    process._transport = None
    instance = {"id": "i-0abc", "name": "web-1", "provider": "aws",
                "public_ip": "10.0.0.5", "key_name": ""}

    with patch("servonaut.utils.ssh_utils.asyncio.create_subprocess_exec",
               return_value=process):
        report = _run(service.build_report(instance))

    assert report.overall_reason == HOST_KEY_BUILD_REASON
    assert report.failures[0].reason == "ssh_host_key_changed"
    assert "ssh-keygen -R 10.0.0.5" in report.failures[0].message
    assert not report.successes
    assert store.get_all_modules("i-0abc", "aws") == {}


def test_mcp_memory_build_explains_changed_key(known_hosts):
    from servonaut.mcp.guards import GuardLevel
    from servonaut.services.memory.service import BuildReport, ModuleBuildFailure
    from tests.test_mcp_tools import make_tools

    tools = make_tools(guard_level=GuardLevel.DANGEROUS)
    message = "SSH host key for 10.0.0.5 has changed ..."
    tools._memory_service = MagicMock()
    tools._memory_service.build_report = AsyncMock(return_value=BuildReport(
        failures=[ModuleBuildFailure("ssh", "ssh_host_key_changed", message)],
        overall_reason=HOST_KEY_BUILD_REASON,
    ))
    payload = json.loads(_run(tools.build_server_memory("i-abc123")))
    assert payload["reason"] == HOST_KEY_BUILD_REASON
    assert payload["message"] == message


def test_verify_probe_reports_changed_key_instead_of_unreachable(known_hosts):
    app = _ProbeApp("accept-new")
    screen = _probe_screen(app)
    refused = _completed(255, stderr=_changed_stderr("10.0.0.5", str(known_hosts.servonaut)).encode())
    with patch("servonaut.screens.server_actions.subprocess.run", return_value=refused):
        status = _run(screen._run_ssh_probe(None, "10.0.0.5"))
    assert status == "not_found"  # the reported status set is unchanged
    assert screen._ssh_probe_host_key_message.startswith(
        "SSH host key for 10.0.0.5 has changed"
    )


def test_cli_probe_prints_the_recovery_command(known_hosts, capsys):
    refused = _completed(255, stderr=_changed_stderr("10.0.0.5", str(known_hosts.servonaut)).encode())
    with patch("servonaut.cli.servers.subprocess.run", return_value=refused):
        rc = cli_servers._run_ssh_probe("/keys/web-1.pem", "deploy", "10.0.0.5", None, 5)
    assert rc == 255
    assert f"ssh-keygen -R 10.0.0.5 -f {known_hosts.servonaut}" in capsys.readouterr().err


def test_transfer_screen_explains_a_changed_key(known_hosts):
    from servonaut.screens.scp_transfer import SCPTransferScreen

    notices: List[tuple] = []
    app = SimpleNamespace(
        demo_mode=False, redaction_service=None,
        notify=lambda message, **kwargs: notices.append((message, kwargs)),
    )
    patched = type("Transfer", (SCPTransferScreen,), {"app": property(lambda self: app)})
    screen = patched.__new__(patched)
    status = MagicMock()
    screen.query_one = lambda *args, **kwargs: status
    stderr = _changed_stderr("[web-1.example.com]:2222", str(known_hosts.servonaut))
    worker = SimpleNamespace(
        name="scp_transfer", is_finished=True, error=None, result=(1, "", stderr),
    )

    screen.on_worker_state_changed(SimpleNamespace(worker=worker))

    message, kwargs = notices[-1]
    assert message.startswith("Transfer failed: SSH host key for [web-1.example.com]:2222 has changed")
    assert "@@@" not in message
    assert kwargs["markup"] is False
    shown = Text.from_markup(status.update.call_args.args[0]).plain
    assert "ssh-keygen -R '[web-1.example.com]:2222'" in shown
