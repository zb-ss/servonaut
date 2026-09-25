"""Run a full-screen program in a pseudo-terminal and read what it draws.

The in-process ``tui`` fixture drives the app from the checkout. An installed
console script runs in its own interpreter, so :func:`run_in_terminal` gives
it a real terminal instead: it starts the program on a pty of a fixed size,
collects the output, waits until the plain text (escape sequences removed)
satisfies a condition, then types keys (by default Ctrl+Q, quit) and waits for
the program to exit.
"""

from __future__ import annotations

import fcntl
import os
import re
import select
import signal
import struct
import subprocess
import termios
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

QUIT_KEYS = b"\x11"  # Ctrl+Q
DEFAULT_SIZE = (160, 50)
_ESCAPES = re.compile(
    rb"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI
    rb"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC
    rb"|\x1b[P^_][^\x1b]*\x1b\\"  # DCS, PM, APC
    rb"|\x1b[()][0-9A-Za-z]"  # charset selection
    rb"|\x1b[@-Z\\-_=>]"  # other two-byte sequences
)


class TerminalTimeout(AssertionError):
    """The program never drew what the journey waited for, or never exited."""


@dataclass(frozen=True)
class TerminalRun:
    """What a program drew and how it ended."""

    argv: list[str]
    pid: int
    returncode: int
    raw: bytes

    @property
    def text(self) -> str:
        return plain_text(self.raw)


def plain_text(raw: bytes) -> str:
    """The characters a program wrote, without terminal escape sequences."""
    return _ESCAPES.sub(b"", raw).decode("utf-8", "replace")


def _set_size(fd: int, size: tuple[int, int]) -> None:
    columns, rows = size
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))


def _read_available(master: int, deadline: float) -> Optional[bytes]:
    """Bytes the program wrote before *deadline*; None once it closed the terminal."""
    ready, _, _ = select.select([master], [], [], max(0.0, min(0.2, deadline - time.monotonic())))
    if not ready:
        return b""
    try:
        chunk = os.read(master, 65536)
    except OSError:  # EIO: the slave side is closed
        return None
    return chunk if chunk else None


def run_in_terminal(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    until: Callable[[str], bool],
    description: str,
    keys: bytes = QUIT_KEYS,
    size: tuple[int, int] = DEFAULT_SIZE,
    timeout: float = 45.0,
) -> TerminalRun:
    """Run *argv* on a pty until *until(text)* holds, type *keys*, wait for exit."""
    master, slave = os.openpty()
    _set_size(slave, size)
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=dict(env),
            cwd=str(cwd),
            start_new_session=True,
            close_fds=True,
        )
    finally:
        os.close(slave)
    raw = bytearray()
    deadline = time.monotonic() + timeout
    typed = False
    try:
        while True:
            chunk = _read_available(master, deadline)
            if chunk is None:
                break
            raw.extend(chunk)
            if not typed and until(plain_text(bytes(raw))):
                os.write(master, keys)
                typed = True
                deadline = time.monotonic() + timeout
            if time.monotonic() > deadline:
                raise TerminalTimeout(
                    f"{description}: {'did not exit' if typed else 'never appeared'} within "
                    f"{timeout:.0f}s; last output:\n{plain_text(bytes(raw))[-2000:]}"
                )
        returncode = process.wait(timeout=timeout)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        os.close(master)
    if not typed:
        raise TerminalTimeout(
            f"{description}: the program exited ({returncode}) first; last output:\n"
            f"{plain_text(bytes(raw))[-2000:]}"
        )
    return TerminalRun(argv=list(argv), pid=process.pid, returncode=returncode, raw=bytes(raw))
