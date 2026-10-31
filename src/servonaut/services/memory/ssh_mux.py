"""One OpenSSH master connection per memory build.

Every probe command used to open its own SSH connection, which through a
bastion is two handshakes each: a fleet refresh then sent a bastion's sshd
dozens at once, and it dropped the ones past its ``MaxStartups`` limit. With
connection multiplexing a build opens ONE master connection for its server
and runs every probe command over it.

The master's control socket lives in a private (0700) temporary directory
that exists only for the build. Windows' OpenSSH has no ControlMaster, so
nothing is multiplexed there and the connection caps apply instead.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Callable, List, Optional

from servonaut.utils.platform_utils import get_os
from servonaut.utils import ssh_utils

logger = logging.getLogger(__name__)

# A Unix socket path holds about 104 bytes (macOS) and ssh binds
# ``<path>.<16 random characters>`` first.
_SOCKET_PATH_LIMIT = 100
_BIND_SUFFIX_LENGTH = 17
# The directory belongs to one build and one server, so the socket needs no
# per-host ``%C`` hash (40 characters): a short name keeps long bases usable.
_SOCKET_NAME = "m"
_STDERR_NAME = "err"
# Used only when the user's temp directory is too long for a socket path.
_FALLBACK_BASE_DIR = "/tmp"

#: Options for a command that does not share a connection: never start or use a master.
DIRECT_OPTIONS = ("ControlMaster=no", "ControlPath=none")

#: ``argv`` builder: the ssh command for these extra ``-o`` options, no remote command.
ArgvBuilder = Callable[[List[str]], List[str]]


def multiplexing_supported() -> bool:
    """Whether this computer's OpenSSH can share a connection (not Windows)."""
    return get_os() != "windows"


def _fits(base: str) -> bool:
    """Whether a socket under a private directory in *base* stays within the path limit (in bytes)."""
    # mkdtemp adds an 8-character random suffix after the prefix.
    length = len(os.fsencode(base)) + len("/sv-") + 8 + 1 + len(_SOCKET_NAME) + _BIND_SUFFIX_LENGTH
    return length <= _SOCKET_PATH_LIMIT


def _usable(base: str) -> bool:
    # ssh splits an option value at spaces and expands "%" tokens in it.
    return " " not in base and "%" not in base and os.path.isdir(base) and os.access(base, os.W_OK)


def _socket_dir_base(configured: str = "") -> Optional[str]:
    """Where to make the build's socket directory, or None when connection sharing must stay off.

    The configured directory, else the user's temp directory when a socket
    path fits there, else ``/tmp`` when the temp directory's path is too long.
    """
    if configured:
        if " " in configured or "%" in configured:
            logger.warning("SSH multiplexing off: the socket directory contains a space or '%'")
            return None
        if not _usable(configured) or not _fits(configured):
            logger.warning("SSH multiplexing off: the configured socket directory is missing, read-only or too long")
            return None
        return configured
    temp = tempfile.gettempdir()
    if _usable(temp) and _fits(temp):
        return temp
    if _usable(_FALLBACK_BASE_DIR) and _fits(_FALLBACK_BASE_DIR):
        return _FALLBACK_BASE_DIR
    logger.debug("SSH multiplexing off: no temp directory with a short enough path")
    return None


class ControlMaster:
    """A build's shared master connection to one server.

    Args:
        persist_seconds: ``ControlPersist``: how long an idle master outlives
            its last client, so a master whose build was killed still ends.
        connect_timeout: Seconds the master's own handshake may take (the
            per-command deadline is for commands, not the first handshake).
        close_timeout: Seconds ``ssh -O exit`` may take to end the master.
        socket_dir: Where to create the private socket folder; empty picks a
            short system location.
    """

    def __init__(
        self, *, persist_seconds: float, connect_timeout: float, socket_dir: str = "", close_timeout: float = 5.0,
    ) -> None:
        self._close_timeout = close_timeout
        self._socket_dir = socket_dir
        self._persist = max(1, int(persist_seconds))
        self._connect_timeout = connect_timeout
        self._dir: Optional[Path] = None
        self._opened = False

    @property
    def is_open(self) -> bool:
        return self._opened

    def socket_alive(self) -> bool:
        """Whether the master's control socket still exists."""
        return self._dir is not None and (self._dir / _SOCKET_NAME).exists()

    def mark_lost(self) -> None:
        """The master ended: commands must not be bound to it any more."""
        self._opened = False

    def command_options(self) -> List[str]:
        """``-o`` values that make a command use the open master (never start one)."""
        return ["ControlMaster=no", f"ControlPath={self._socket_pattern()}"]

    def _socket_pattern(self) -> str:
        assert self._dir is not None
        return f"{self._dir}/{_SOCKET_NAME}"

    def _master_options(self) -> List[str]:
        return [
            "ControlMaster=yes",
            f"ControlPath={self._socket_pattern()}",
            f"ControlPersist={self._persist}s",
        ]

    def _prepare_dir(self) -> bool:
        """Create the private socket directory; False when its path would be too long."""
        if self._dir is not None:  # a retry reuses the build's directory
            return True
        base = _socket_dir_base(self._socket_dir)
        if base is None:
            return False
        try:
            self._dir = Path(tempfile.mkdtemp(prefix="sv-", dir=base))
        except OSError as exc:
            logger.debug("SSH multiplexing off: no private socket directory (%s)", type(exc).__name__)
            return False
        return True

    async def open(self, build_argv: ArgvBuilder) -> bool:
        """Start the master; False (nothing to clean up) when multiplexing cannot be used.

        Raises:
            subprocess.CalledProcessError: ssh refused or could not reach the
                server (the caller classifies why).
            asyncio.TimeoutError: the handshake exceeded the connect budget.
            OSError: ssh could not be started.
        """
        if not multiplexing_supported() or not self._prepare_dir():
            return False
        argv = build_argv(self._master_options())
        # -N: no command; -f: go to the background once authenticated.
        argv[1:1] = ["-N", "-f"]
        # Only the parent's exit is awaited: the master it forks may keep the
        # output descriptors, which a pipe-reading wait would block on.
        assert self._dir is not None
        await ssh_utils.run_ssh_daemonizing(argv, self._dir / _STDERR_NAME, timeout=self._connect_timeout)
        self._opened = True
        return True

    async def close(self, build_argv: Optional[ArgvBuilder]) -> None:
        """Ask the master to exit and remove its socket directory. Never raises."""
        directory = self._dir
        if directory is None:
            return
        try:
            # A socket may exist even when open() was interrupted after ssh
            # forked its master: ask whatever is there to exit.
            if build_argv is not None and any(p.name != _STDERR_NAME for p in directory.iterdir()):
                exit_argv = build_argv(self.command_options())
                exit_argv[1:1] = ["-O", "exit"]
                await ssh_utils.run_ssh_subprocess(exit_argv, timeout=self._close_timeout, check=True)
        except Exception as exc:  # noqa: BLE001 - best effort: ControlPersist ends a master anyway
            logger.info(
                "The SSH master did not confirm it exited (%s); ControlPersist ends it within %ds",
                type(exc).__name__, self._persist,
            )
        finally:
            self._opened = False
            self._dir = None
            shutil.rmtree(directory, ignore_errors=True)
