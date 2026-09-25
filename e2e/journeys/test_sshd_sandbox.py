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


def test_bubblewrap_hides_the_host_when_available(journey, sshd):
    if sshd.confinement != "bwrap":
        pytest.skip(f"remote commands are not sandboxed here: {sshd.target.launcher.detail}")
    home = journey.ctx.protected_dirs[0].lstrip("/")
    root = str(journey.ctx.root).lstrip("/")
    # Relative paths from "/" step around the lexical re-rooting on purpose.
    script = (
        f"cd / && ls -A {home} | wc -l; ls -A {root}; "
        "touch tmp/e2e-sandbox-probe 2>/dev/null && echo wrote || echo read-only; "
        f"(echo > /dev/tcp/{LOOPBACK}/{sshd.target.port}) 2>/dev/null "
        "&& echo connected || echo no-network"
    )

    result = _ssh(journey, sshd, f"deploy@{LOOPBACK}", script)

    assert result.stdout.split() == ["0", "tests", "read-only", "no-network"], result.stderr


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


def _refused(result: subprocess.CompletedProcess, reason: str, sshd) -> None:
    # 255 from the pass-through itself; scp reports a refused ssh as its own failure.
    assert result.returncode != 0, result.stderr
    assert "e2e: " in result.stderr and reason in result.stderr, result.stderr
    assert sshd.target.sessions() == [] and sshd.bastion.sessions() == []


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        pytest.param(["-F", "{other}"], "only the sandbox ssh config", id="other-config"),
        pytest.param(["-vF{other}"], "only the sandbox ssh config", id="clustered-config"),
        pytest.param(["-E", "{log}"], "writing a log file (-E)", id="log-file"),
        pytest.param(["-S", "{log}"], "a control socket (-S)", id="control-socket"),
        pytest.param(["-o", "UserKnownHostsFile=~/kh"], "userknownhostsfile", id="tilde-known-hosts"),
        pytest.param(["-o", "ControlPath=%d/cp"], "controlpath", id="home-control-path"),
        pytest.param(["-o", "IdentityFile=/etc/ssh/key"], "identityfile", id="outside-identity"),
        pytest.param(
            ["-o", "PermitLocalCommand=yes", "-o", "LocalCommand=true"],
            "permitlocalcommand", id="local-command",
        ),
        pytest.param(["-o", "KnownHostsCommand=/bin/true"], "knownhostscommand", id="kh-command"),
        pytest.param(["-o", "IdentityAgent=SSH_AUTH_SOCK"], "identityagent", id="agent"),
        pytest.param(["-A"], "forwardagent", id="agent-forwarding"),
        pytest.param(["-I", "/usr/lib/pkcs11.so"], "pkcs11provider", id="pkcs11"),
        pytest.param(["-o", "SecurityKeyProvider=/tmp/sk.so"], "securitykeyprovider", id="sk"),
        pytest.param(
            ["-o", "ProxyCommand=ssh $(true) -W %h:%p x"], "may not use shell syntax",
            id="proxy-command-substitution",
        ),
        pytest.param(["-o", "ProxyCommand=nc %h %p"], "ProxyCommand 'nc'", id="proxy-command"),
    ],
)
def test_unsafe_ssh_options_are_refused(journey, sshd, options, reason):
    other = journey.directory / "other_config"
    other.write_text("Host *\n    HostName 9.9.9.9\n", encoding="utf-8")
    values = {"other": str(other), "log": str(journey.directory / "ssh.log")}
    args = [option.format(**values) for option in options]

    _refused(_ssh(journey, sshd, *args, f"deploy@{LOOPBACK}", "true"), reason, sshd)


def test_options_after_the_destination_are_checked_too(journey, sshd):
    # ssh reads options after the destination, so the pass-through does too.
    result = _ssh(journey, sshd, f"deploy@{LOOPBACK}", "-o", "IdentityAgent=SSH_AUTH_SOCK", "true")

    _refused(result, "identityagent", sshd)


def test_known_hosts_files_in_the_home_are_accepted(journey, sshd):
    # Absolute paths built from the (sandboxed) home stay inside the test root.
    home = journey.ctx.sandbox.home
    (home / ".servonaut").mkdir(exist_ok=True)
    files = f"{home}/.servonaut/known_hosts {home}/.ssh/known_hosts"
    result = _ssh(
        journey, sshd, "-o", "StrictHostKeyChecking=accept-new", "-o",
        f"UserKnownHostsFile={files}", f"deploy@{LOOPBACK}", "hostname",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == sshd.target.name
    assert (home / ".servonaut" / "known_hosts").read_text().startswith(f"[{LOOPBACK}]:")


def _scp(journey, sshd, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["scp", "-i", str(sshd.client_key_path), "-P", str(sshd.target.port), *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        pytest.param(["-ro", "ProxyCommand=nc %h %p"], "ProxyCommand 'nc'", id="clustered-o"),
        pytest.param(["-rJ", "ec2-user@9.9.9.9"], "is not a loopback address", id="clustered-J"),
        pytest.param(["-D", "/bin/sh"], "a local SFTP server program (-D)", id="local-sftp"),
        pytest.param(["-S", "/usr/bin/ssh"], "another ssh program (-S)", id="ssh-program"),
        pytest.param(["-t"], "scp server mode (-t)", id="server-mode"),
    ],
)
def test_unsafe_scp_options_are_refused(journey, sshd, options, reason):
    source = journey.directory / "payload.txt"
    source.write_text("payload\n", encoding="utf-8")

    result = _scp(journey, sshd, *options, str(source), f"deploy@{LOOPBACK}:/tmp/payload.txt")

    _refused(result, reason, sshd)
    assert not sshd.target.remote.path("/tmp/payload.txt").exists()


def test_scp_copies_only_to_or_from_a_server(journey, sshd):
    source = journey.directory / "payload.txt"
    source.write_text("payload\n", encoding="utf-8")

    result = _scp(journey, sshd, str(source), str(journey.directory / "copy.txt"))

    assert result.returncode == 255
    assert "scp needs a remote side" in result.stderr
    assert not (journey.directory / "copy.txt").exists()


def test_the_real_client_starts_only_as_the_pass_through_allows(journey, sshd):
    real_ssh, config = sshd.openssh["ssh"], str(sshd.config_path)
    other = str(journey.directory / "other_config")
    attempts = [
        [real_ssh, "-F", config, "-V"],  # before the allowance: refused
        [real_ssh, "-V"],
        [real_ssh, "-F", other, "-V"],
        [real_ssh, "-F", config, "-vF" + other, "-V"],
        [real_ssh, "-F", config, "-V"],
    ]
    probe = (
        "import subprocess, sys\n"
        "guard = sys.modules['_servonaut_e2e_netguard']\n"
        f"attempts = {attempts!r}\n"
        "for index, argv in enumerate(attempts):\n"
        "    if index == 1:\n"
        f"        guard.allow_ssh_clients({{{real_ssh!r}: 'ssh'}}, {config!r})\n"
        "    try:\n"
        "        subprocess.run(argv, check=False, capture_output=True)\n"
        "        print('started')\n"
        "    except PermissionError:\n"
        "        print('refused')\n"
    )
    completed = _child(journey, probe)

    assert completed.stdout.split() == ["refused"] * 4 + ["started"], completed.stderr
    recorded = GUARD.read_log(journey.guard_log)
    journey.guard_log.unlink(missing_ok=True)
    assert [entry["kind"] for entry in recorded] == ["spawn"] * 4
