"""Keep native-library stderr chatter off the terminal while the TUI runs.

Several native dependencies the voice stack loads (the speech-synthesis
runtime, PortAudio, ALSA) write diagnostics straight to the process's
stderr FILE DESCRIPTOR from C/C++ code. Textual captures Python's
``sys.stderr`` object, but it cannot intercept fd-level writes — every
such line lands raw on the terminal, scribbling over the interface.

The fix is at the same level as the problem: while the TUI runs, fd 2 is
pointed at a log file, and restored afterwards so anything printed after
the app exits — crash tracebacks included — reaches the terminal again.
Python-level logging is unaffected (it goes to the app's own log file),
and the redirect is only engaged for the interactive TUI: headless modes
(MCP server, CLI subcommands) keep stderr as their legitimate output
channel.
"""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def redirect_native_stderr(log_path: Path) -> Iterator[Optional[Path]]:
    """Point OS-level stderr (fd 2) at *log_path* for the duration.

    Yields the log path when the redirect engaged, or None when it could
    not (in which case stderr is simply left alone — a failed redirect
    must never take the app down with it). The original fd is always
    restored on exit, so post-run output is visible again.
    """
    saved_fd: Optional[int] = None
    target_fd: Optional[int] = None
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        target_fd = os.open(
            str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        saved_fd = os.dup(2)
        os.dup2(target_fd, 2)
    except OSError as e:
        logger.debug("Could not redirect native stderr: %s", e)
        if saved_fd is not None:
            os.close(saved_fd)
            saved_fd = None
        if target_fd is not None:
            os.close(target_fd)
            target_fd = None
        yield None
        return

    try:
        yield log_path
    finally:
        try:
            os.dup2(saved_fd, 2)
        except OSError as e:  # pragma: no cover — restoring the tty failed
            logger.error("Could not restore stderr after the TUI run: %s", e)
        os.close(saved_fd)
        os.close(target_fd)
