"""A remote command, path or host must never be read as a local ssh option.

OpenSSH keeps parsing options after the destination, so without an explicit
end of options a remote command such as ``-oProxyCommand=...`` would set a
local ProxyCommand and run a program on this machine. The same holds for scp
paths.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig, ConnectionProfile
from servonaut.services.connection_service import ConnectionService
from servonaut.services.scp_service import SCPService
from servonaut.services.ssh_service import SSHService

INJECTED = "-oProxyCommand=touch /tmp/servonaut-should-not-exist"


def _config_manager() -> MagicMock:
    manager = MagicMock()
    manager.get.return_value = AppConfig(default_key="", instance_keys={})
    return manager


def _ssh_command(remote_command: str) -> list[str]:
    return SSHService(_config_manager()).build_ssh_command(
        host="10.0.0.11", username="deploy", remote_command=remote_command,
    )


def test_options_end_before_the_destination():
    cmd = _ssh_command(INJECTED)

    destination = cmd.index("deploy@10.0.0.11")
    assert cmd[destination - 1] == "--"
    assert cmd[destination + 1] == INJECTED


@pytest.mark.skipif(shutil.which("ssh") is None, reason="needs the OpenSSH client")
def test_openssh_does_not_apply_a_dash_remote_command_as_an_option():
    # `ssh -G` prints the effective configuration without connecting.
    cmd = _ssh_command(INJECTED)
    resolved = subprocess.run(
        [cmd[0], "-G", *cmd[1:]], capture_output=True, text=True, timeout=10,
    )

    assert resolved.returncode == 0, resolved.stderr
    assert "servonaut-should-not-exist" not in resolved.stdout


@pytest.mark.parametrize("direction", ["upload", "download"])
def test_scp_paths_follow_an_end_of_options_marker(direction):
    scp = SCPService()
    if direction == "upload":
        cmd = scp.build_upload_command(
            local_path=INJECTED, remote_path="/tmp/x", host="10.0.0.11", username="deploy",
        )
    else:
        cmd = scp.build_download_command(
            remote_path="/tmp/x", local_path=INJECTED, host="10.0.0.11", username="deploy",
        )

    marker = cmd.index("--")
    assert INJECTED in cmd[marker + 1:]
    assert all(arg != INJECTED for arg in cmd[:marker])


def test_bastion_destination_is_quoted_for_the_proxy_shell():
    profile = ConnectionProfile(
        name="bastion",
        bastion_host="bastion-1.example.com;touch /tmp/x",
        bastion_user="ops",
        bastion_key="/keys/bastion.pem",
    )
    manager = MagicMock()
    manager.get.return_value = AppConfig()

    args = ConnectionService(manager).get_proxy_args(profile)

    proxy_command = args[1].removeprefix("ProxyCommand=")
    words = shlex.split(proxy_command)
    assert words[-2:] == ["--", "ops@bastion-1.example.com;touch /tmp/x"]
