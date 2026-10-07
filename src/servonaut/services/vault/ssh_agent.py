"""Private, process-scoped OpenSSH agents for Vault credentials.

The application agent must never replace ``SSH_AUTH_SOCK`` for the shell that
started Servonaut.  Callers instead add :meth:`ssh_options` to the exact SSH
invocation which needs a Vault key.
"""

from __future__ import annotations

import atexit
import logging
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import ClassVar, Iterable

from .identity_store import IdentityStoreError, ensure_default_custody_root
from .errors import VaultUserError


logger = logging.getLogger(__name__)

_AGENT_PID_RE = re.compile(r"SSH_AGENT_PID=(\d+);")
_AGENT_SOCKET_RE = re.compile(r"SSH_AUTH_SOCK=([^;]+);")
_SOCKET_RE = re.compile(r"agent-(\d+)-[0-9a-f]{16}\.sock$")
_DEFAULT_TTL_SECONDS = 3600
# ``sockaddr_un.sun_path`` has 108 bytes on the supported POSIX targets; the
# NUL terminator consumes one byte.  Check before invoking ssh-agent so a
# deep workspace path yields an actionable error instead of opaque failure.
# sun_path holds 108 bytes on Linux and 104 on macOS/BSD, including the NUL.
_UNIX_SOCKET_PATH_MAX = 107 if sys.platform.startswith("linux") else 103


class PrivateSshAgentError(VaultUserError):
    """The private agent could not be started or used (fixed, user-safe text)."""


class PrivateSshAgent:
    """An OpenSSH agent isolated to this process's Vault connections."""

    _instances: ClassVar[set["PrivateSshAgent"]] = set()
    _cleanup_registered: ClassVar[bool] = False

    def __init__(self, socket_path: Path, pid: int, private_directory: Path | None = None) -> None:
        self.socket_path = socket_path
        self.pid = pid
        # A per-agent directory created for this socket, removed on close.
        self._private_directory = private_directory
        self._closed = False

    @classmethod
    def start(cls, directory: Path | None = None) -> "PrivateSshAgent":
        """Start an agent without mutating this process's environment."""
        if os.name == "nt":
            raise PrivateSshAgentError(
                "Private Vault SSH agents are not supported on Windows yet; use a supported OpenSSH platform"
            )
        if shutil.which("ssh-agent") is None:
            raise PrivateSshAgentError("OpenSSH ssh-agent is not available")

        private_parent = Path.home() if directory is None else None
        if directory is None:
            try:
                socket_dir = ensure_default_custody_root() / "vault" / "tmp"
            except IdentityStoreError as exc:
                raise PrivateSshAgentError(str(exc)) from exc
        else:
            socket_dir = directory
        cls._ensure_private_socket_directory(socket_dir, private_parent=private_parent)
        cls.cleanup_stale_sockets(socket_dir)

        socket_name = f"agent-{os.getpid()}-{secrets.token_hex(8)}.sock"
        socket_path = socket_dir / socket_name
        private_directory: Path | None = None
        if len(os.fsencode(socket_path)) > _UNIX_SOCKET_PATH_MAX and directory is None:
            # A long home directory leaves no room for a Unix socket name.
            # Like OpenSSH's own agent, use a fresh private directory in the
            # system temporary directory instead.
            private_directory = cls._private_temporary_directory(socket_name)
            socket_path = private_directory / socket_name
        if len(os.fsencode(socket_path)) > _UNIX_SOCKET_PATH_MAX:
            cls._remove_private_directory(private_directory)
            raise PrivateSshAgentError(
                "Private SSH agent socket path is too long; choose a shorter socket directory"
            )
        result = subprocess.run(
            ["ssh-agent", "-a", str(socket_path), "-s"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            cls._remove_private_directory(private_directory)
            raise PrivateSshAgentError("Could not start the private SSH agent")
        socket_match = _AGENT_SOCKET_RE.search(result.stdout)
        pid_match = _AGENT_PID_RE.search(result.stdout)
        if socket_match is None or pid_match is None:
            cls._terminate_agent(int(pid_match.group(1)) if pid_match else None)
            cls._remove_private_directory(private_directory)
            raise PrivateSshAgentError("ssh-agent returned an invalid response")
        reported_socket = Path(socket_match.group(1))
        if reported_socket != socket_path:
            cls._terminate_agent(int(pid_match.group(1)))
            cls._remove_private_directory(private_directory)
            raise PrivateSshAgentError("ssh-agent returned an unexpected socket")

        agent = cls(socket_path=socket_path, pid=int(pid_match.group(1)), private_directory=private_directory)
        cls._instances.add(agent)
        cls._register_cleanup()
        return agent

    @classmethod
    def _private_temporary_directory(cls, socket_name: str) -> Path:
        """A new 0700 directory, created atomically, under the real temporary directory.

        The temporary directory is resolved first because on some systems it
        lies behind a symbolic link, which the socket checks refuse. When even
        that is too long for a socket (a long ``TMPDIR``), ``/tmp`` is used.
        """
        # "svn-agent-" plus mkdtemp's eight random characters and a separator.
        room = len("svn-agent-") + 8 + 2 + len(socket_name)
        base = os.path.realpath(tempfile.gettempdir())
        if len(os.fsencode(base)) + room > _UNIX_SOCKET_PATH_MAX and os.path.isdir("/tmp"):
            base = os.path.realpath("/tmp")
        try:
            created = Path(tempfile.mkdtemp(prefix="svn-agent-", dir=base))
        except OSError as exc:
            raise PrivateSshAgentError("Private SSH agent directory cannot be created") from exc
        try:
            cls._assert_no_symlink_components(created)
            cls._assert_private_socket_directory(created)
        except PrivateSshAgentError:
            cls._remove_private_directory(created)
            raise
        return created

    @staticmethod
    def _remove_private_directory(directory: Path | None) -> None:
        if directory is None:
            return
        try:
            directory.rmdir()
        except OSError:
            pass

    @classmethod
    def _ensure_private_socket_directory(
        cls, directory: Path, *, private_parent: Path | None = None,
    ) -> None:
        """Create *directory* only below non-symlinked path components.

        A private agent socket authenticates every key loaded into it.  Its
        directory must therefore never be redirected through a symlink or
        inherited from a group/world-readable directory.  Existing paths are
        rejected instead of being chmod'd: mutating an attacker-selected path
        would itself be a security bug.
        """
        target = directory.expanduser()
        if not target.is_absolute():
            target = Path.cwd() / target
        target = Path(os.path.abspath(target))

        cls._assert_no_symlink_components(target)
        missing: list[Path] = []
        current = target
        while True:
            try:
                info = current.lstat()
            except FileNotFoundError:
                missing.append(current)
                parent = current.parent
                if parent == current:
                    raise PrivateSshAgentError("Private SSH agent directory cannot be created")
                current = parent
                continue
            except OSError as exc:
                raise PrivateSshAgentError("Could not inspect private SSH agent directory") from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise PrivateSshAgentError("Private SSH agent directory is not a real directory")
            break

        for path in reversed(missing):
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                # A concurrent creator may have raced us.  The complete
                # post-create walk below validates the replacement.
                pass
            except OSError as exc:
                raise PrivateSshAgentError("Private SSH agent directory cannot be created") from exc

        # Repeat the component walk after creation so a racing rename/link
        # cannot leave the socket under a path different from the one checked.
        cls._assert_no_symlink_components(target)
        if private_parent is not None:
            cls._assert_private_descendants(target, private_parent)
        cls._assert_private_socket_directory(target)

    @staticmethod
    def _assert_no_symlink_components(path: Path) -> None:
        """Reject a link in *path* without resolving it first."""
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                # Descendants will be checked after their creation.
                return
            except OSError as exc:
                raise PrivateSshAgentError("Could not inspect private SSH agent directory") from exc
            if stat.S_ISLNK(info.st_mode):
                raise PrivateSshAgentError("Private SSH agent directory contains a symbolic link")

    @staticmethod
    def _assert_private_socket_directory(path: Path) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise PrivateSshAgentError("Could not inspect private SSH agent directory") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PrivateSshAgentError("Private SSH agent directory is not a real directory")
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PrivateSshAgentError(
                "Private SSH agent directory has unsafe ownership or permissions"
            )

    @classmethod
    def _assert_private_descendants(cls, target: Path, parent: Path) -> None:
        """Check the default ``~/.servonaut`` ancestors before using them."""
        base = Path(os.path.abspath(parent.expanduser()))
        try:
            relative = target.relative_to(base)
        except ValueError as exc:
            raise PrivateSshAgentError("Private SSH agent directory has an invalid parent") from exc
        try:
            home_info = base.lstat()
        except OSError as exc:
            raise PrivateSshAgentError("Could not inspect private SSH agent directory") from exc
        if stat.S_ISLNK(home_info.st_mode) or not stat.S_ISDIR(home_info.st_mode):
            raise PrivateSshAgentError("Private SSH agent directory is not a real directory")
        if home_info.st_uid != os.getuid():
            raise PrivateSshAgentError("Private SSH agent directory has unsafe ownership")

        current = base
        for part in relative.parts:
            current /= part
            cls._assert_private_socket_directory(current)

    @classmethod
    def cleanup_stale_sockets(cls, directory: Path) -> None:
        """Remove sockets whose named owner process no longer exists."""
        try:
            entries: Iterable[Path] = tuple(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            match = _SOCKET_RE.fullmatch(entry.name)
            if match is None:
                continue
            try:
                os.kill(int(match.group(1)), 0)
            except ProcessLookupError:
                try:
                    entry.unlink()
                except OSError:
                    pass
            except PermissionError:
                # It is alive, but belongs to a process we may not inspect.
                continue

    @classmethod
    def _register_cleanup(cls) -> None:
        if cls._cleanup_registered:
            return
        atexit.register(cls.close_all)
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous = signal.getsignal(signum)

            def handler(received: int, frame: object, old: object = previous) -> None:
                cls.close_all()
                if callable(old):
                    old(received, frame)
                if old is signal.SIG_DFL:
                    signal.signal(received, signal.SIG_DFL)
                    os.kill(os.getpid(), received)

            signal.signal(signum, handler)
        cls._cleanup_registered = True

    @classmethod
    def close_all(cls) -> None:
        """Best-effort teardown used by normal and interrupted shutdown."""
        for agent in tuple(cls._instances):
            agent.close()

    @staticmethod
    def _terminate_agent(pid: int | None) -> None:
        if pid is None:
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass

    def _environment(self, *, include_pid: bool = False) -> dict[str, str]:
        environment = os.environ.copy()
        environment["SSH_AUTH_SOCK"] = str(self.socket_path)
        environment.pop("SSH_AGENT_PID", None)
        if include_pid:
            environment["SSH_AGENT_PID"] = str(self.pid)
        return environment

    def add_private_key(
        self, private_key: bytes | bytearray, ttl_seconds: int = _DEFAULT_TTL_SECONDS
    ) -> None:
        """Load an OpenSSH private key from stdin and give it a bounded TTL."""
        if self._closed:
            raise PrivateSshAgentError("The private SSH agent is closed")
        if shutil.which("ssh-add") is None:
            raise PrivateSshAgentError("OpenSSH ssh-add is not available")
        if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        result = subprocess.run(
            ["ssh-add", "-t", str(ttl_seconds), "-"],
            input=bytes(private_key),
            check=False,
            capture_output=True,
            env=self._environment(),
            timeout=15,
        )
        if result.returncode != 0:
            logger.warning("Private SSH agent rejected a Vault key")
            raise PrivateSshAgentError("Could not load the Vault key into its SSH agent")

    def ssh_options(self, certificate_path: Path | None = None) -> list[str]:
        """Return explicit options for one SSH command using this agent."""
        if self._closed:
            raise PrivateSshAgentError("The private SSH agent is closed")
        options = [
            "-o",
            f"IdentityAgent={self.socket_path}",
            "-o",
            "IdentitiesOnly=yes",
        ]
        if certificate_path is not None:
            options.extend(["-o", f"CertificateFile={certificate_path}"])
        return options

    def close(self) -> None:
        """Terminate the agent and remove only its own socket."""
        if self._closed:
            return
        self._closed = True
        try:
            subprocess.run(
                ["ssh-agent", "-k"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                env=self._environment(include_pid=True),
            )
        except (OSError, subprocess.SubprocessError):
            self._terminate_agent(self.pid)
        try:
            self.socket_path.unlink(missing_ok=True)
        except OSError:
            pass
        self._remove_private_directory(self._private_directory)
        self._instances.discard(self)

    def __enter__(self) -> "PrivateSshAgent":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
