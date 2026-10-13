"""Log where the interface was stuck when its event loop stops answering.

Work that blocks the event loop freezes the whole interface without raising
anything, so nothing reaches the log and a hang cannot be told apart from a
slow network. The app's loop beats a heartbeat; a daemon thread checks it,
and once the loop has not run for the stall threshold it logs the stack the
loop is stuck in (code locations only, never variable values), then how
long the stall lasted when the loop answers again.

``SERVONAUT_UI_STALL_SECONDS`` changes the threshold; ``0`` turns it off.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
import traceback
from collections.abc import Callable
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_STALL_SECONDS = 10.0
STALL_SECONDS_ENV = "SERVONAUT_UI_STALL_SECONDS"


def stall_seconds_from_env(environ: Optional[dict[str, str]] = None) -> float:
    """The threshold from the environment; the default when unset or invalid."""
    raw = (os.environ if environ is None else environ).get(STALL_SECONDS_ENV, "")
    try:
        value = float(raw) if raw.strip() else DEFAULT_STALL_SECONDS
    except ValueError:
        return DEFAULT_STALL_SECONDS
    return value if value >= 0 else DEFAULT_STALL_SECONDS


class UiStallWatchdog:
    """Watch one thread's event loop and log the stack of a long stall."""

    def __init__(
        self,
        loop_thread_id: int,
        *,
        stall_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        check_every: float = 1.0,
    ) -> None:
        self._thread_id = loop_thread_id
        self._stall_seconds = stall_seconds
        self._clock = clock
        self._check_every = check_every
        self._last_beat = clock()
        self._stalled_since: Optional[float] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def beat(self) -> None:
        """Called by the event loop: it is answering."""
        now = self._clock()
        if self._stalled_since is not None:
            logger.warning("The interface is responding again after %.0f s", now - self._stalled_since)
            self._stalled_since = None
        self._last_beat = now

    def check(self) -> None:
        """One check from the watching thread."""
        idle = self._clock() - self._last_beat
        if self._stalled_since is not None or idle < self._stall_seconds:
            return
        self._stalled_since = self._last_beat
        frame = sys._current_frames().get(self._thread_id)
        stack = "".join(traceback.format_stack(frame)) if frame is not None else "  (stack unavailable)\n"
        logger.warning("The interface has not responded for %.0f s; it is busy in:\n%s", idle, stack.rstrip())

    def start(self) -> None:
        if self._stall_seconds <= 0 or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._watch, name="servonaut-ui-watchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._check_every * 2)
            self._thread = None

    def _watch(self) -> None:
        while not self._stop.wait(self._check_every):
            self.check()
