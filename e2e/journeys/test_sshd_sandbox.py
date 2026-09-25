"""The loopback SSH tier stays inside the sandbox.

The real OpenSSH client may only run through the pass-through on the
journey's PATH, only with the sandbox config, and only towards loopback;
remote commands see the remote root as their machine.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from e2e.harness import fleet
from e2e.harness.bootstrap import HARNESS_DIR, load_guard
from e2e.harness.processes import require_armed
from e2e.harness.sshd import LOOPBACK

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

GUARD = load_guard()


def _ssh(journey, sshd, *args: str) -> subprocess.CompletedProcess:
    """Run the journey's ``ssh`` (the pass-through) with the target's key."""
    return subprocess.run(
        ["ssh", "-i", str(sshd.client_key_path), "-p", str(sshd.target.port), *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )


def _child(journey, code: str) -> subprocess.CompletedProcess:
    sandbox = journey.new_sandbox("probe")
    return subprocess.run(
        [sys.executable, "-c", code],
        env=journey.child_env(sandbox),
        cwd=sandbox.base,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_commands_see_the_remote_root_as_their_machine(journey, sshd):
    sshd.target.remote.write("/srv/marker.txt", "inside the remote root\n")

    user = fleet.WEB_1.username
    result = _ssh(journey, sshd, f"{user}@{LOOPBACK}", "cat /srv/marker.txt; pwd; echo $PATH")

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["inside the remote root", f"/home/{user}", "/bin"]
    assert sshd.target.commands() == ["cat /srv/marker.txt; pwd; echo $PATH"]
    # The pass-through itself ran with the guard installed.
    require_armed(journey.armed_log, marker=str(HARNESS_DIR / "openssh_shim.py"))


def test_non_loopback_destinations_are_refused(journey, sshd):
    result = _ssh(journey, sshd, "deploy@9.9.9.9", "true")

    assert result.returncode == 255
    assert "refused to connect: '9.9.9.9' is not a loopback address" in result.stderr
    assert sshd.target.sessions() == []


def test_non_loopback_jump_hosts_are_refused(journey, sshd):
    # OpenSSH starts a jump hop with its own binary, so the pass-through
    # checks the hops before the client runs.
    result = _ssh(journey, sshd, "-J", "ec2-user@9.9.9.9", f"deploy@{LOOPBACK}", "true")

    assert result.returncode == 255
    assert "jump host '9.9.9.9': '9.9.9.9' is not a loopback address" in result.stderr
    assert sshd.bastion.sessions() == [] and sshd.target.sessions() == []


def test_another_ssh_config_is_refused(journey, sshd):
    other = journey.directory / "other_config"
    other.write_text("Host *\n    HostName 9.9.9.9\n", encoding="utf-8")

    result = _ssh(journey, sshd, "-F", str(other), f"deploy@{LOOPBACK}", "true")

    assert result.returncode == 255
    assert "only the sandbox ssh config may be used" in result.stderr


def test_the_real_client_starts_only_with_the_sandbox_config(journey, sshd):
    real_ssh = sshd.openssh["ssh"]
    attempts = [[real_ssh, "-V"], [real_ssh, "-F", str(sshd.config_path), "-V"]]
    probe = (
        "import subprocess, sys\n"
        f"for argv in {attempts!r}:\n"
        "    try:\n"
        "        subprocess.run(argv, check=False, capture_output=True)\n"
        "        print('started')\n"
        "    except PermissionError:\n"
        "        print('refused')\n"
    )
    completed = _child(journey, probe)

    assert completed.stdout.split() == ["refused", "started"], completed.stderr
    recorded = GUARD.read_log(journey.guard_log)
    journey.guard_log.unlink(missing_ok=True)
    assert [(entry["kind"], entry["target"]) for entry in recorded] == [
        ("spawn", f"subprocess.Popen {real_ssh}")
    ]
