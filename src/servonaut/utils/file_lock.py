"""Exclusive advisory lock on a file, shared between processes.

The app, a standalone MCP server and the CLI can run on one machine at once;
a ``threading`` lock only orders threads of one process. This lock is taken
on a small file instead, with the same primitive as the relay and OAuth
locks (:func:`servonaut.services.relay_lock.try_lock_exclusive`: ``flock`` on
POSIX, ``msvcrt.locking`` on Windows). The kernel drops it when the
descriptor closes, so a crashed holder never wedges the file.

Two :class:`FileLock` objects on one path exclude each other, within a
process as well as across processes. Waiting is bounded: :meth:`acquire` polls
and gives up with :class:`FileLockTimeout`, an ``OSError``, so callers that
already treat an ``OSError`` as a failed write keep their behaviour.
"""
from __future__ import annotations

import contextlib
import logging
import os
import time
from pathlib import Path
from typing import Iterator, Optional, Union

from servonaut.services.relay_lock import try_lock_exclusive, unlock

logger = logging.getLogger(__name__)

_DIR_MODE = 0o700
_FILE_MODE = 0o600


class FileLockTimeout(OSError):
    """The lock stayed busy for the whole wait."""


class FileLock:
    """One advisory lock on *path*; the file is created 0600 in a 0700 folder.

    Not re-entrant: a second :meth:`try_acquire` on the same object while held
    is refused like any other holder. Callers that need re-entrancy count
    their own nesting (see ``MemoryStore.annotation_lock``).
    """

    def __init__(self, path: Union[str, Path]) -> None:
        self._path = Path(path)
        self._fd: Optional[int] = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def try_acquire(self) -> bool:
        """Take the lock if it is free right now; ``False`` when another holder has it."""
        if self._fd is not None:
            return False
        fd = self._open()
        if not try_lock_exclusive(fd):
            os.close(fd)
            return False
        self._fd = fd
        return True

    def acquire(self, timeout: float, poll_seconds: float) -> None:
        """Take the lock, polling every *poll_seconds* for at most *timeout* seconds.

        Raises:
            FileLockTimeout: still busy after *timeout*.
            OSError: the lock file cannot be created or opened.
        """
        deadline = time.monotonic() + max(timeout, 0.0)
        pause = max(poll_seconds, 0.001)
        while not self.try_acquire():
            if time.monotonic() >= deadline:
                raise FileLockTimeout(f"{self._path.name} is held by another process")
            time.sleep(pause)

    def release(self) -> None:
        """Let go of the lock; safe to call when not held."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        unlock(fd)
        os.close(fd)

    @contextlib.contextmanager
    def hold(self, timeout: float, poll_seconds: float) -> Iterator[None]:
        """Hold the lock for the ``with`` block (bounded wait, see :meth:`acquire`)."""
        self.acquire(timeout, poll_seconds)
        try:
            yield
        finally:
            self.release()

    def _open(self) -> int:
        directory = self._path.parent
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            # mkdir's mode is cut by the umask; the lock folder is private.
            os.chmod(directory, _DIR_MODE)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        return os.open(self._path, flags, _FILE_MODE)
