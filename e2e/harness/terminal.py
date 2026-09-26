"""Run a full-screen program in a pseudo-terminal and read what it draws.

The in-process ``tui`` fixture drives the app from the checkout. An installed
console script runs in its own interpreter, so :func:`run_in_terminal` gives
it a real terminal instead: it starts the program on a pty of a fixed size,
collects the output, waits until the plain text (escape sequences removed)
satisfies a condition, then types keys (by default Ctrl+Q, quit) and waits for
the program to exit.
"""

from __future__ import annotations

import codecs
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
from typing import Callable, Mapping, Sequence

QUIT_KEYS = b"\x11"  # Ctrl+Q
DEFAULT_SIZE = (160, 50)
_ESCAPES = re.compile(
    rb"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI
    rb"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC
    rb"|\x1b[P^_][^\x1b]*\x1b\\"  # DCS, PM, APC
    rb"|\x1b[()][0-9A-Za-z]"  # charset selection
    rb"|\x1b[@-Z\\-_=>]"  # other two-byte sequences
)


class TerminalTimeout(RuntimeError):
    """The program never drew what the journey waited for, or never exited.

    Not an ``AssertionError``: a hung program is never the failure an
    expected-failure journey documents.
    """


@dataclass(frozen=True)
class TerminalRun:
    """What a program drew and how it ended."""

    argv: list[str]
    pid: int
    returncode: int
    text: str  # everything it wrote, as plain text


class _PlainText:
    """A program's output as plain text, built up as it arrives.

    Escape sequences are removed chunk by chunk; one cut off at the end of a
    read waits for the rest, and so does a multi-byte character.
    """

    def __init__(self) -> None:
        self.text = ""
        self._pending = b""
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def feed(self, chunk: bytes) -> None:
        data = self._pending + chunk
        cut = data.rfind(b"\x1b")
        if cut != -1 and not _ESCAPES.match(data, cut):
            data, self._pending = data[:cut], data[cut:]
        else:
            self._pending = b""
        self.text += self._decoder.decode(_ESCAPES.sub(b"", data))


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
    process, master = _start_on_pty(argv, env=env, cwd=cwd, size=size)
    screen = _PlainText()
    try:
        if not _read_until(master, screen, until, time.monotonic() + timeout, description):
            raise TerminalTimeout(
                f"{description}: the program exited first; last output:\n{screen.text[-2000:]}"
            )
        os.write(master, keys)
        _read_until(master, screen, lambda _text: False, time.monotonic() + timeout, description)
        returncode = process.wait(timeout=timeout)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        os.close(master)
    return TerminalRun(list(argv), process.pid, returncode, screen.text)


def _start_on_pty(
    argv: Sequence[str], *, env: Mapping[str, str], cwd: Path, size: tuple[int, int]
) -> tuple[subprocess.Popen, int]:
    master, slave = os.openpty()
    columns, rows = size
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
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
    except OSError:
        os.close(master)
        raise
    finally:
        os.close(slave)
    return process, master


def _read_until(
    master: int, screen: _PlainText, done: Callable[[str], bool], deadline: float, what: str
) -> bool:
    """Read into *screen* until *done* holds (True) or the program closes the terminal."""
    while not done(screen.text):
        if time.monotonic() > deadline:
            raise TerminalTimeout(f"{what}: timed out; last output:\n{screen.text[-2000:]}")
        ready, _, _ = select.select([master], [], [], 0.2)
        if not ready:
            continue
        try:
            chunk = os.read(master, 65536)
        except OSError:  # EIO: the slave side is closed
            chunk = b""
        if not chunk:
            return False
        screen.feed(chunk)
    return True
