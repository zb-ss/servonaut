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
from servonaut.services.vault.ssh_agent import PrivateSshAgent

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


def _agent_ssh(journey, sshd, agent: str, identity_file: str) -> subprocess.CompletedProcess:
    """Connect with a Vault agent and its public selector, never ``-i``."""
    return subprocess.run(
        [
            "ssh", "-p", str(sshd.target.port), "-o", f"IdentityAgent={agent}", "-o",
            "IdentitiesOnly=yes", "-o", f"IdentityFile={identity_file}",
            f"deploy@{LOOPBACK}", "hostname",
        ],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )


def _public_identity_file(journey, sshd):
    import asyncssh

    path = journey.directory / "vault-agent.pub"
    public = asyncssh.read_private_key(str(sshd.client_key_path)).export_public_key()
    path.write_bytes(public)
    path.chmod(0o600)
    return path


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
        pytest.param(["-E", "{outside_log}"], "a log file (-E) outside the test root", id="log-file"),
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
    values = {
        "other": str(other),
        "log": str(journey.directory / "ssh.log"),
        "outside_log": f"{journey.ctx.protected_dirs[0]}/ssh.log",
    }
    args = [option.format(**values) for option in options]

    _refused(_ssh(journey, sshd, *args, f"deploy@{LOOPBACK}", "true"), reason, sshd)


def test_options_after_the_destination_are_checked_too(journey, sshd):
    # ssh reads options after the destination, so the pass-through does too.
    result = _ssh(journey, sshd, f"deploy@{LOOPBACK}", "-o", "IdentityAgent=SSH_AUTH_SOCK", "true")

    _refused(result, "identityagent", sshd)


def test_vault_agent_socket_inside_custody_authenticates(journey, sshd):
    """A real agent works only from the guarded Vault custody directory."""
    identity_file = _public_identity_file(journey, sshd)
    directory = journey.ctx.sandbox.home / ".servonaut" / "vault" / "tmp"
    try:
        agent = PrivateSshAgent.start()
    except OSError as exc:
        pytest.skip(f"OpenSSH agent sockets are unavailable: {exc}")
    try:
        agent.add_private_key(sshd.client_key_path.read_bytes(), ttl_seconds=60)
        result = _agent_ssh(journey, sshd, str(agent.socket_path), str(identity_file))
    finally:
        agent.close()

    assert agent.socket_path.parent == directory
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == sshd.target.name
    assert [call.argv for call in journey.shims.calls("ssh-add")] == [["-t", "60", "-"]]
    assert [call.argv for call in journey.shims.calls("ssh-agent")] == [
        ["-a", str(agent.socket_path), "-s"], ["-k"],
    ]


def test_vault_agent_refuses_outside_custody_and_a_named_regular_file(journey, sshd):
    """Neither an outside path nor a filename alone grants agent access."""
    identity_file = _public_identity_file(journey, sshd)
    outside = "/tmp/agent-1-0123456789abcdef.sock"
    agent_start = subprocess.run(
        ["ssh-agent", "-a", outside, "-s"], capture_output=True, text=True,
        stdin=subprocess.DEVNULL, timeout=30, check=False,
    )
    assert agent_start.returncode == 255
    assert "agent socket is outside the Vault custody directory" in agent_start.stderr
    add_file = subprocess.run(
        ["ssh-add", "-t", "60", "/tmp/outside-private-key"], capture_output=True, text=True,
        stdin=subprocess.DEVNULL, timeout=30, check=False,
    )
    assert add_file.returncode == 255
    assert "ssh-add arguments are not allowed" in add_file.stderr
    add_unbounded = subprocess.run(
        ["ssh-add", "-t", "3601", "-"], capture_output=True, text=True,
        stdin=subprocess.DEVNULL, timeout=30, check=False,
    )
    assert add_unbounded.returncode == 255
    assert "ssh-add TTL is not allowed" in add_unbounded.stderr
    _refused(
        _agent_ssh(journey, sshd, outside, str(identity_file)), "outside the Vault custody directory", sshd,
    )

    directory = journey.ctx.sandbox.home / ".servonaut" / "vault" / "tmp"
    directory.mkdir(mode=0o700, parents=True)
    candidate = directory / "agent-1-0123456789abcdef.sock"
    candidate.write_text("not a socket\n", encoding="ascii")
    _refused(
        _agent_ssh(journey, sshd, str(candidate), str(identity_file)), "not an owned Unix socket", sshd,
    )


def test_vault_agent_refuses_unsafe_custody_links_and_private_identity(journey, sshd):
    """The agent exception cannot weaken custody or accept private key files."""
    identity_file = _public_identity_file(journey, sshd)
    directory = journey.ctx.sandbox.home / ".servonaut" / "vault" / "tmp"
    agent = PrivateSshAgent.start(directory)
    try:
        _refused(
            _agent_ssh(journey, sshd, str(agent.socket_path), str(sshd.client_key_path)),
            "may only use a public IdentityFile", sshd,
        )

        directory.chmod(0o755)
        _refused(
            _agent_ssh(journey, sshd, str(agent.socket_path), str(identity_file)),
            "unsafe ownership or permissions", sshd,
        )
        directory.chmod(0o700)

        linked_socket = directory / "agent-1-0123456789abcdef.sock"
        linked_socket.symlink_to(agent.socket_path)
        _refused(
            _agent_ssh(journey, sshd, str(linked_socket), str(identity_file)),
            "contains a symbolic link", sshd,
        )
    finally:
        directory.chmod(0o700)
        agent.close()


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


def test_a_log_file_inside_the_test_root_is_allowed(journey, sshd):
    """Servonaut sends ssh's own messages to a private log (``ssh -E``)."""
    log = journey.directory / "ssh.log"
    user = fleet.WEB_1.username

    result = _ssh(journey, sshd, "-E", str(log), f"{user}@{LOOPBACK}", "true")

    assert result.returncode == 0, result.stderr
    assert log.exists()
