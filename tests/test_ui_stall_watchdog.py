"""A frozen interface leaves the stack it was stuck in in the log."""
from __future__ import annotations

import logging
import threading

from servonaut.utils.ui_stall_watchdog import (
    DEFAULT_STALL_SECONDS,
    UiStallWatchdog,
    stall_seconds_from_env,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_a_long_stall_logs_the_stuck_stack_once_and_its_end(caplog) -> None:
    clock = _Clock()
    watchdog = UiStallWatchdog(threading.get_ident(), stall_seconds=10, clock=clock)
    caplog.set_level(logging.WARNING, logger="servonaut.utils.ui_stall_watchdog")

    clock.now += 9
    watchdog.check()
    assert caplog.records == []  # a short pause is not a stall

    clock.now += 3
    watchdog.check()
    watchdog.check()
    (stall,) = caplog.records
    assert "has not responded for 12 s" in stall.getMessage()
    # The stack is this thread's: the test that "froze" it.
    assert "test_a_long_stall_logs_the_stuck_stack_once_and_its_end" in stall.getMessage()

    clock.now += 5
    watchdog.beat()
    assert "responding again after 17 s" in caplog.records[-1].getMessage()
    clock.now += 1
    watchdog.check()
    assert len(caplog.records) == 2


def test_the_threshold_comes_from_the_environment() -> None:
    assert stall_seconds_from_env({}) == DEFAULT_STALL_SECONDS
    assert stall_seconds_from_env({"SERVONAUT_UI_STALL_SECONDS": "30"}) == 30
    assert stall_seconds_from_env({"SERVONAUT_UI_STALL_SECONDS": "0"}) == 0
    assert stall_seconds_from_env({"SERVONAUT_UI_STALL_SECONDS": "soon"}) == DEFAULT_STALL_SECONDS
    assert stall_seconds_from_env({"SERVONAUT_UI_STALL_SECONDS": "-1"}) == DEFAULT_STALL_SECONDS


def test_a_disabled_watchdog_starts_no_thread_and_stops_cleanly() -> None:
    off = UiStallWatchdog(threading.get_ident(), stall_seconds=0)
    off.start()
    assert off._thread is None

    on = UiStallWatchdog(threading.get_ident(), stall_seconds=60, check_every=0.01)
    on.start()
    assert on._thread is not None and on._thread.is_alive()
    on.stop()
    assert on._thread is None
