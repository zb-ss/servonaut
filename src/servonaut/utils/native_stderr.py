"""Keep native-library stderr chatter off the terminal while the TUI runs.

Several native dependencies the voice stack loads (the speech-synthesis
runtime, PortAudio, ALSA) write diagnostics straight to the process's
stderr FILE DESCRIPTOR from C/C++ code. Textual captures Python's
``sys.stderr`` object, but it cannot intercept fd-level writes — every
such line lands raw on the terminal, scribbling over the interface.

The subtlety: Textual RENDERS THE INTERFACE through the Python stderr
object, which normally wraps that same fd 2. Redirecting the fd alone
would therefore send the whole interface into the log file and leave the
terminal blank. So the split happens at the object/fd boundary:

1. fd 2 is duplicated — the duplicate stays connected to the terminal;
2. ``sys.stderr`` / ``sys.__stderr__`` are rebound to a stream over that
   duplicate, so every PYTHON-level writer (Textual's renderer, crash
   output, warnings) still reaches the terminal;
3. fd 2 itself is then pointed at the log file, so every NATIVE writer
   (which knows nothing of Python file objects) lands in the log.

Everything is restored on exit. The redirect is only engaged for the
interactive TUI: headless modes (MCP server, CLI subcommands) keep
stderr as their legitimate output channel.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def redirect_native_stderr(log_path: Path) -> Iterator[Optional[Path]]:
    """Send fd-2 writes to *log_path* while Python stderr keeps the terminal.

    Yields the log path when the redirect engaged, or None when it could
    not (in which case stderr is simply left alone — a failed redirect
    must never take the app down with it). On exit the original fd and
    the original ``sys.stderr``/``sys.__stderr__`` objects are restored,
    so post-run output behaves exactly as before.
    """
    saved_stderr = sys.stderr
    saved_dunder_stderr = sys.__stderr__
    terminal_stream = None
    target_fd: Optional[int] = None
    restore_fd: Optional[int] = None
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        target_fd = os.open(
            str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        # Two duplicates of the terminal: one becomes the Python-level
        # stderr stream, one is kept raw to restore fd 2 afterwards
        # (closing the stream must not close the fd we restore from).
        terminal_stream = os.fdopen(os.dup(2), "w", buffering=1)
        restore_fd = os.dup(2)
        sys.stderr = terminal_stream
        sys.__stderr__ = terminal_stream  # type: ignore[misc] — Textual renders through this
        os.dup2(target_fd, 2)
    except OSError as e:
        logger.debug("Could not redirect native stderr: %s", e)
        sys.stderr = saved_stderr
        sys.__stderr__ = saved_dunder_stderr  # type: ignore[misc]
        if terminal_stream is not None:
            terminal_stream.close()
        if restore_fd is not None:
            os.close(restore_fd)
        if target_fd is not None:
            os.close(target_fd)
        yield None
        return

    try:
        yield log_path
    finally:
        try:
            os.dup2(restore_fd, 2)
        except OSError as e:  # pragma: no cover — restoring the tty failed
            logger.error("Could not restore stderr after the TUI run: %s", e)
        sys.stderr = saved_stderr
        sys.__stderr__ = saved_dunder_stderr  # type: ignore[misc]
        try:
            terminal_stream.close()
        except OSError:  # pragma: no cover — nothing left to flush to
            pass
        os.close(restore_fd)
        os.close(target_fd)
