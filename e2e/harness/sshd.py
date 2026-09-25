"""Loopback SSH servers for journeys that need a real remote machine.

:class:`SshWorld` starts two in-process asyncssh servers on ``127.0.0.1``
with ephemeral ports:

``target``
    The machine the application manages. It runs commands inside its remote
    root (see :mod:`e2e.harness.remote_root`), serves SFTP (which modern
    ``scp`` uses) confined to that root, and accepts only the client key the
    journey installs in the application's ``~/.ssh``.
``bastion``
    A jump host. It accepts only the bastion key named in the sandbox SSH
    config, and forwards ``direct-tcpip`` requests (ProxyJump) for the
    private addresses a journey routes, always to the target on loopback.
    Unknown destinations are refused.

The application reaches them with the real OpenSSH client: the ``ssh`` and
``scp`` programs on the journey's PATH are replaced by a guarded pass-through
(:mod:`e2e.harness.openssh_shim`) that runs ``/usr/bin/ssh -F <sandbox
config>``. The sandbox config pins identities, known hosts and host aliases
inside the test root, so no real ``~/.ssh`` file is read.

Every session is recorded in a JSON-lines command log (user, command, exit
status, file transfers, forwards), which the fixture keeps with the failure
artifacts.
"""

from __future__ import annotations

import asyncio
import json
import os
import posixpath
import shlex
import shutil
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import asyncssh

from e2e.harness.bootstrap import HARNESS_DIR
from e2e.harness.remote_root import SYSTEM_TOOL_DIRS, RemoteRoot

LOOPBACK = "127.0.0.1"
KEY_TYPE = "ssh-ed25519"
START_TIMEOUT_SECONDS = 10.0
# The alias the sandbox SSH config gives the jump host.
BASTION_ALIAS = "bastion-1"
DEFAULT_USERS = ("deploy", "ec2-user")
# How long a finished command's output may take to drain before any
# background children it left are stopped.
OUTPUT_DRAIN_SECONDS = 2.0


class OpenSshMissing(RuntimeError):
    """The host has no OpenSSH client for the loopback-server journeys."""


def find_openssh() -> dict[str, str]:
    """Real paths of the OpenSSH ``ssh`` and ``scp`` clients.

    Looked up in the fixed system directories only, never on the invoking
    PATH (the suite replaces PATH anyway).
    """
    found: dict[str, str] = {}
    search = os.pathsep.join(SYSTEM_TOOL_DIRS)
    for tool in ("ssh", "scp"):
        path = shutil.which(tool, path=search)
        if path is None:
            raise OpenSshMissing(
                f"the OpenSSH client ({tool}) was not found in {', '.join(SYSTEM_TOOL_DIRS)}; "
                "install openssh-client, or deselect these journeys with -m 'not needs_sshd'"
            )
        found[tool] = os.path.realpath(path)
    return found


# ---------------------------------------------------------------------------
# The event loop the servers run on
# ---------------------------------------------------------------------------


class _LoopThread:
    """One background event loop per test process, shared by every server."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="e2e-sshd", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def call(self, coroutine: Any, timeout: float = START_TIMEOUT_SECONDS) -> Any:
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result(timeout)


_LOOP: Optional[_LoopThread] = None
_KEYS: dict[str, asyncssh.SSHKey] = {}


def _loop() -> _LoopThread:
    global _LOOP
    if _LOOP is None:
        _LOOP = _LoopThread()
    return _LOOP


def _public_line(key: asyncssh.SSHKey) -> str:
    return key.export_public_key().decode().strip()


def _key(name: str) -> asyncssh.SSHKey:
    """A key generated once per test process (ed25519 is cheap, but not free)."""
    if name not in _KEYS:
        _KEYS[name] = asyncssh.generate_private_key(KEY_TYPE, comment=f"e2e-{name}")
    return _KEYS[name]


# ---------------------------------------------------------------------------
# Command log
# ---------------------------------------------------------------------------


class CommandLog:
    """JSON lines describing every session the servers handled."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()

    def add(self, **entry: Any) -> None:
        entry.setdefault("time", round(time.time(), 3))
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

    def entries(self, host: Optional[str] = None, event: Optional[str] = None) -> list[dict]:
        with self._lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        out = [json.loads(line) for line in lines if line.strip()]
        return [
            e for e in out
            if (host is None or e.get("host") == host)
            and (event is None or e.get("event") == event)
        ]


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


async def _pump_output(reader: asyncio.StreamReader, writer: Any, mapper: Any) -> None:
    while True:
        chunk = await reader.read(65536)
        if not chunk:
            break
        mapped = mapper.feed(chunk)
        if mapped:
            try:
                writer.write(mapped)
            except (asyncssh.Error, OSError, BrokenPipeError):
                return
    rest = mapper.flush()
    if rest:
        try:
            writer.write(rest)
        except (asyncssh.Error, OSError, BrokenPipeError):
            pass


async def _pump_input(process: Any, stdin: asyncio.StreamWriter, remote: RemoteRoot,
                      rewrite_lines: bool) -> None:
    """Copy the client's stdin to the command; shell input is re-rooted too."""
    pending = b""
    try:
        while True:
            chunk = await process.stdin.read(65536)
            if not chunk:
                break
            if rewrite_lines:
                pending += chunk
                cut = pending.rfind(b"\n") + 1
                chunk, pending = pending[:cut], pending[cut:]
                chunk = remote.rewrite(chunk.decode("utf-8", "replace")).encode()
            stdin.write(chunk)
            await stdin.drain()
        if pending:
            stdin.write(remote.rewrite(pending.decode("utf-8", "replace")).encode())
    except (asyncssh.Error, OSError, BrokenPipeError, ConnectionResetError):
        pass
    finally:
        try:
            stdin.close()
        except (OSError, RuntimeError):
            pass


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


class _SandboxSFTPServer(asyncssh.SFTPServer):
    """SFTP confined to the remote root; relative paths start at the user's home."""

    def __init__(self, chan: Any, host: "RemoteHost") -> None:
        super().__init__(chan, chroot=str(host.remote.base).encode())
        self._host = host
        self._user = chan.get_extra_info("username") or "root"
        home = host.remote.home_of(self._user)
        self._home = ("/" + str(home.relative_to(host.remote.base))).encode()
        host.log.add(host=host.name, event="sftp", user=self._user)

    def map_path(self, path: bytes) -> bytes:
        if not path.startswith(b"/"):
            path = posixpath.join(self._home, path)
        return super().map_path(path)

    def exit(self) -> Any:
        # OpenSSH's sftp-server ends with exit status 0, and scp counts a
        # session that ends without one as a failed transfer.
        try:
            self.channel.exit(0)
        except (asyncssh.Error, OSError):
            pass
        return super().exit()

    def open(self, path: bytes, pflags: int, attrs: Any) -> Any:
        mode = "write" if pflags & (asyncssh.FXF_WRITE | asyncssh.FXF_CREAT) else "read"
        self._host.log.add(
            host=self._host.name, event="sftp-open", user=self._user,
            path=path.decode("utf-8", "replace"), mode=mode,
        )
        return super().open(path, pflags, attrs)


# ---------------------------------------------------------------------------
# One host
# ---------------------------------------------------------------------------


@dataclass
class RemoteHost:
    """One loopback SSH server and the machine it pretends to be."""

    name: str
    remote: RemoteRoot
    log: CommandLog
    host_key: asyncssh.SSHKey
    authorized: list[asyncssh.SSHKey]
    routes: dict[tuple[str, int], "RemoteHost"] = field(default_factory=dict)
    port: int = 0
    _server: Any = None
    _connections: set = field(default_factory=set)

    # -- observation ------------------------------------------------------

    def commands(self, user: Optional[str] = None) -> list[str]:
        """Commands run on this host, as the client sent them, oldest first."""
        return [
            e["command"] for e in self.log.entries(self.name, "exec")
            if user is None or e.get("user") == user
        ]

    def sessions(self, event: Optional[str] = None) -> list[dict]:
        return self.log.entries(self.name, event)

    # -- lifecycle --------------------------------------------------------

    async def _start(self) -> None:
        self._server = await asyncssh.create_server(
            lambda: _ServerCallbacks(self),
            LOOPBACK,
            0,
            server_host_keys=[self.host_key],
            process_factory=self._handle_process,
            sftp_factory=lambda chan: _SandboxSFTPServer(chan, self),
            allow_scp=True,
            encoding=None,
            # No GSS: its default host name costs a reverse DNS lookup.
            gss_host=None,
            agent_forwarding=False,
            x11_forwarding=False,
            line_editor=False,
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def _stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # Drop live sessions too, so no client (a ``tail -f``) outlives the journey.
        for conn in list(self._connections):
            conn.close()
        for conn in list(self._connections):
            await conn.wait_closed()
        self._connections.clear()

    # -- sessions ---------------------------------------------------------

    async def _handle_process(self, process: Any) -> None:
        user = process.get_extra_info("username") or "root"
        command = process.command
        if process.subsystem:
            self.log.add(host=self.name, event="subsystem", user=user, name=process.subsystem)
            process.stderr.write(f"subsystem {process.subsystem} is not available\n".encode())
            process.exit(1)
            return
        event = "exec" if command is not None else "shell"
        self.log.add(host=self.name, event=event, user=user, command=command)
        try:
            status = await self._run(process, user, command)
        except Exception as exc:  # noqa: BLE001 - reported to the client and the log
            self.log.add(host=self.name, event="error", user=user, command=command, error=repr(exc))
            status = 1
        self.log.add(host=self.name, event="exit", user=user, command=command, status=status)
        try:
            process.exit(status)
        except (asyncssh.Error, OSError):
            pass  # the client already went away

    async def _run(self, process: Any, user: str, command: Optional[str]) -> int:
        remote = self.remote
        argv = [remote.shell()]
        if command is not None:
            argv += ["-c", remote.rewrite(command)]
        env = remote.environment(user)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=env["HOME"],
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        assert proc.stdin and proc.stdout and proc.stderr
        feeding = asyncio.ensure_future(
            _pump_input(process, proc.stdin, remote, rewrite_lines=command is None)
        )
        outputs = asyncio.gather(
            _pump_output(proc.stdout, process.stdout, remote.output_mapper()),
            _pump_output(proc.stderr, process.stderr, remote.output_mapper()),
        )
        closed = asyncio.ensure_future(process.wait_closed())
        finished = asyncio.ensure_future(proc.wait())
        await asyncio.wait({finished, closed}, return_when=asyncio.FIRST_COMPLETED)
        if not finished.done():
            # The client went away (a stopped ``tail -f``): end the command.
            _kill_group(proc)
        status = await finished
        try:
            await asyncio.wait_for(asyncio.shield(outputs), OUTPUT_DRAIN_SECONDS)
        except asyncio.TimeoutError:
            # A background child still holds the output open; while it lives
            # the group id cannot be reused, so signalling the group is safe.
            _kill_group(proc)
            await outputs
        feeding.cancel()
        closed.cancel()
        return status if status >= 0 else 128 - status


class _ServerCallbacks(asyncssh.SSHServer):
    """Authentication and port forwarding for one :class:`RemoteHost`."""

    def __init__(self, host: RemoteHost) -> None:
        self._host = host
        self._conn: Any = None

    def connection_made(self, conn: Any) -> None:
        self._conn = conn
        self._host._connections.add(conn)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._host._connections.discard(self._conn)

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return False

    def kbdint_auth_supported(self) -> bool:
        return False

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        accepted = any(key.public_data == known.public_data for known in self._host.authorized)
        self._host.log.add(
            host=self._host.name, event="auth", user=username,
            key=key.get_comment() or key.get_fingerprint(), accepted=accepted,
        )
        return accepted

    def connection_requested(self, dest_host: str, dest_port: int,
                             orig_host: str, orig_port: int) -> Any:
        target = self._host.routes.get((dest_host, dest_port))
        self._host.log.add(
            host=self._host.name, event="forward", destination=f"{dest_host}:{dest_port}",
            to=target.name if target else None,
        )
        if target is None:
            return False
        return self._conn.forward_connection(LOOPBACK, target.port)


# ---------------------------------------------------------------------------
# Target + bastion, with the client-side files that reach them
# ---------------------------------------------------------------------------


@dataclass
class SshWorld:
    """A target and a bastion on loopback, plus the sandbox client config.

    *directory* holds everything client-side (keys, ``ssh_config``,
    ``known_hosts``); *remote_dir* holds each host's remote root.
    """

    directory: Path
    remote_dir: Path
    log: CommandLog
    target_name: str = "web-1"
    users: Iterable[str] = DEFAULT_USERS
    target: RemoteHost = field(init=False)
    bastion: RemoteHost = field(init=False)
    openssh: dict[str, str] = field(default_factory=find_openssh)

    def __post_init__(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        client_key, bastion_key = _key("client"), _key("bastion")
        self.target = RemoteHost(
            name=self.target_name,
            remote=RemoteRoot(self.remote_dir / self.target_name, self.target_name, self.users),
            log=self.log,
            host_key=_key("target-host"),
            authorized=[client_key],
        )
        self.bastion = RemoteHost(
            name=BASTION_ALIAS,
            remote=RemoteRoot(self.remote_dir / BASTION_ALIAS, BASTION_ALIAS, self.users),
            log=self.log,
            host_key=_key("bastion-host"),
            authorized=[bastion_key],
        )
        self.client_key_path = self._write_private_key("client_ed25519", client_key)
        self.bastion_key_path = self._write_private_key("bastion_ed25519", bastion_key)

    # -- lifecycle --------------------------------------------------------

    def start(self) -> "SshWorld":
        loop = _loop()
        loop.call(self.target._start())
        loop.call(self.bastion._start())
        self._write_client_config()
        return self

    def stop(self) -> None:
        loop = _loop()
        for host in (self.target, self.bastion):
            try:
                loop.call(host._stop())
            except Exception as exc:  # noqa: BLE001 - teardown must finish
                self.log.add(host=host.name, event="stop-error", error=repr(exc))

    # -- client-side files ------------------------------------------------

    @property
    def config_path(self) -> Path:
        return self.directory / "ssh_config"

    @property
    def known_hosts_path(self) -> Path:
        return self.directory / "known_hosts"

    def _write_private_key(self, name: str, key: asyncssh.SSHKey) -> Path:
        path = self.directory / name
        path.write_bytes(key.export_private_key("openssh"))
        path.chmod(0o600)
        return path

    def _write_client_config(self) -> None:
        known = [
            f"[{LOOPBACK}]:{self.target.port} {_public_line(self.target.host_key)}",
            f"{BASTION_ALIAS} {_public_line(self.bastion.host_key)}",
        ]
        self.known_hosts_path.write_text("\n".join(known) + "\n", encoding="utf-8")
        self.known_hosts_path.chmod(0o600)
        no_identity = self.directory / "no-default-identity"
        lines = [
            "# Written by the servonaut e2e suite. Every OpenSSH client a journey",
            "# runs reads this file and no other (no ~/.ssh/config, no system config).",
            f"Host {BASTION_ALIAS}",
            f"    HostName {LOOPBACK}",
            f"    Port {self.bastion.port}",
            f"    IdentityFile {self.bastion_key_path}",
            f"    HostKeyAlias {BASTION_ALIAS}",
            "",
            "Host *",
            # A named identity keeps OpenSSH from trying its default key files
            # in the real home directory; this one does not exist.
            f"    IdentityFile {no_identity}",
            "    IdentityAgent none",
            f"    UserKnownHostsFile {self.known_hosts_path}",
            "    GlobalKnownHostsFile /dev/null",
            "    StrictHostKeyChecking yes",
            "    CheckHostIP no",
            "    UpdateHostKeys no",
            "    HashKnownHosts no",
            "    BatchMode yes",
            "    PasswordAuthentication no",
            "    KbdInteractiveAuthentication no",
            "    ControlMaster no",
            "    ControlPath none",
            "    ForwardAgent no",
            "    ForwardX11 no",
            "    PermitLocalCommand no",
            "    CanonicalizeHostname no",
            "    VerifyHostKeyDNS no",
        ]
        self.config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.config_path.chmod(0o600)

    def install_client_key(self, home: Path, name: str = "e2e_web1") -> Path:
        """Copy the key the target accepts into ``<home>/.ssh/<name>``."""
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = ssh_dir / name
        shutil.copyfile(self.client_key_path, path)
        path.chmod(0o600)
        return path

    def route(self, address: str, port: int = 22) -> None:
        """Let the bastion forward ``address:port`` (a private address) to the target."""
        self.bastion.routes[(address, port)] = self.target

    # -- the pass-through clients ------------------------------------------

    def install_clients(self, shim_dir: Path) -> None:
        """Replace the fake ``ssh``/``scp`` in *shim_dir* with the real clients."""
        shim = HARNESS_DIR / "openssh_shim.py"
        python = shlex.quote(sys.executable)
        for tool in ("ssh", "scp"):
            script = shim_dir / tool
            script.write_text(
                "#!/bin/sh\n"
                f"exec {python} -s {shlex.quote(str(shim))} {shlex.quote(str(shim_dir))} "
                f"{tool} {shlex.quote(self.openssh[tool])} {shlex.quote(self.openssh['ssh'])} "
                f"{shlex.quote(str(self.config_path))} \"$@\"\n",
                encoding="utf-8",
            )
            script.chmod(0o755)

    def guard_environment(self) -> dict[str, str]:
        """What a guarded child needs to start the real clients (and nothing else)."""
        return {
            "SERVONAUT_E2E_SSH_PROGRAMS": os.pathsep.join(sorted(set(self.openssh.values()))),
            "SERVONAUT_E2E_SSH_CONFIG": str(self.config_path),
        }
