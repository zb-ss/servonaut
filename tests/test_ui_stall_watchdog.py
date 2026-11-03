"""A frozen interface leaves the stack it was stuck in in the log."""
from __future__ import annotations

import logging
import threading

import pytest

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


def test_a_paused_watchdog_logs_nothing_and_restarts_its_count(caplog) -> None:
    """Time the app spends handed over to another program is not a stall."""
    clock = _Clock()
    watchdog = UiStallWatchdog(threading.get_ident(), stall_seconds=10, clock=clock)
    caplog.set_level(logging.WARNING, logger="servonaut.utils.ui_stall_watchdog")

    with watchdog.paused():
        clock.now += 30
        watchdog.check()
    watchdog.check()  # the count starts again when the pause ends
    assert caplog.records == []

    clock.now += 11
    watchdog.check()
    assert "has not responded for 11 s" in caplog.records[-1].getMessage()


def test_suspending_the_app_pauses_the_watchdog(caplog) -> None:
    """While the terminal belongs to an editor, the watchdog stays quiet."""
    import contextlib
    from unittest.mock import patch

    from textual.app import SuspendNotSupported

    from servonaut.app import ServonautApp

    clock = _Clock()
    app = ServonautApp()
    app._ui_stall_watchdog = UiStallWatchdog(threading.get_ident(), stall_seconds=10, clock=clock)
    caplog.set_level(logging.WARNING, logger="servonaut.utils.ui_stall_watchdog")

    @contextlib.contextmanager
    def handed_over(self):
        yield

    with patch("textual.app.App.suspend", handed_over):
        with app.suspend():
            clock.now += 27  # an editor session
            app._ui_stall_watchdog.check()
    assert caplog.records == []

    def refused(self):
        raise SuspendNotSupported("no terminal to hand over")

    with patch("textual.app.App.suspend", contextlib.contextmanager(refused)):
        with pytest.raises(SuspendNotSupported):
            with app.suspend():
                pass
    # A refused suspend never paused it: a real stall is still reported.
    clock.now += 11
    app._ui_stall_watchdog.check()
    assert "has not responded" in caplog.records[-1].getMessage()


def test_the_terminal_comes_back_when_the_program_fails_to_start() -> None:
    """Textual resumes only when the wrapped code returns; an error must not skip it."""
    import contextlib
    from unittest.mock import patch

    from servonaut.app import ServonautApp

    events = []

    def like_textual(self):  # no try/finally, like Textual's own suspend
        events.append("suspended")
        yield
        events.append("resumed")

    app = ServonautApp()
    with patch("textual.app.App.suspend", contextlib.contextmanager(like_textual)):
        with pytest.raises(FileNotFoundError):
            with app.suspend():
                raise FileNotFoundError("no-such-editor")
    assert events == ["suspended", "resumed"]
