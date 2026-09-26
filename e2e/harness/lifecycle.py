"""Make sure an interrupted run still tears its journeys down.

Child processes (relay listeners especially) are stopped by fixture
teardown, so the run must reach teardown however it ends:

* a journey that exceeds its time limit is interrupted with ``SIGALRM`` in
  the test's own thread (pytest-timeout's ``signal`` method), so it fails
  and its fixtures are torn down. The project default, the ``thread``
  method, ends the whole process with ``os._exit`` instead, which skips
  teardown and leaves children behind;
* ``SIGTERM`` (CI cancelling the job, a developer's ``kill``) becomes a
  ``KeyboardInterrupt``, which pytest turns into an orderly session end
  that still tears down the active fixtures.

The last line of defence, for a run that is killed outright, is the owner
watchdog every child starts (see ``child_site/sitecustomize.py``).
"""

from __future__ import annotations

import signal
import threading
from typing import Any

import pytest


def _interrupt(signum: int, frame: Any) -> None:
    raise KeyboardInterrupt(f"terminated by signal {signum}")


def interrupt_on_sigterm() -> None:
    """Turn ``SIGTERM`` into ``KeyboardInterrupt`` in this process."""
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _interrupt)


def use_signal_timeout(item: pytest.Item, default_seconds: float) -> None:
    """Give *item* a time limit enforced by ``SIGALRM``.

    Keeps the seconds (and ``func_only``) of a ``timeout`` marker the test
    declares; otherwise uses *default_seconds*.
    """
    if not hasattr(signal, "SIGALRM"):
        return
    declared = item.get_closest_marker("timeout")
    seconds: Any = default_seconds
    func_only = None
    if declared is not None:
        if declared.args:
            seconds = declared.args[0]
        seconds = declared.kwargs.get("timeout", seconds)
        func_only = declared.kwargs.get("func_only")
    marker = pytest.mark.timeout(seconds, method="signal", func_only=func_only)
    item.add_marker(marker, append=False)
