"""Tests for the cross-process advisory file lock."""
from __future__ import annotations

import multiprocessing
import os
import stat
import sys
import time

import pytest

from servonaut.utils.file_lock import FileLock, FileLockTimeout


def _hold(path: str, ready, release) -> None:
    lock = FileLock(path)
    assert lock.try_acquire()
    ready.set()
    release.wait(10)
    lock.release()


@pytest.fixture
def lock_path(tmp_path):
    return tmp_path / "locks" / "a.lock"


def test_try_acquire_then_busy_for_a_second_holder(lock_path):
    first, second = FileLock(lock_path), FileLock(lock_path)
    assert first.try_acquire() is True
    assert second.try_acquire() is False
    first.release()
    assert second.try_acquire() is True
    second.release()


def test_acquire_times_out_with_an_oserror_subclass(lock_path):
    holder = FileLock(lock_path)
    assert holder.try_acquire()
    started = time.monotonic()
    with pytest.raises(FileLockTimeout) as caught:
        FileLock(lock_path).acquire(timeout=0.2, poll_seconds=0.02)
    assert isinstance(caught.value, OSError)
    assert 0.15 <= time.monotonic() - started < 3
    holder.release()


def test_acquire_waits_until_the_holder_lets_go(lock_path):
    import threading

    holder = FileLock(lock_path)
    assert holder.try_acquire()
    threading.Timer(0.1, holder.release).start()
    waiter = FileLock(lock_path)
    waiter.acquire(timeout=3, poll_seconds=0.02)
    waiter.release()


def test_release_is_idempotent_and_context_manager_releases(lock_path):
    lock = FileLock(lock_path)
    with lock.hold(timeout=1, poll_seconds=0.02):
        assert FileLock(lock_path).try_acquire() is False
    lock.release()
    other = FileLock(lock_path)
    assert other.try_acquire()
    other.release()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_lock_file_is_private_in_a_private_directory(lock_path):
    lock = FileLock(lock_path)
    assert lock.try_acquire()
    lock.release()
    assert stat.S_IMODE(os.stat(lock_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(lock_path.parent).st_mode) == 0o700


def test_second_process_is_excluded_until_release(lock_path):
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    child = ctx.Process(target=_hold, args=(str(lock_path), ready, release))
    child.start()
    try:
        assert ready.wait(20)
        assert FileLock(lock_path).try_acquire() is False
        with pytest.raises(FileLockTimeout):
            FileLock(lock_path).acquire(timeout=0.2, poll_seconds=0.02)
        release.set()
        child.join(20)
        again = FileLock(lock_path)
        assert again.try_acquire()
        again.release()
    finally:
        release.set()
        child.join(5)
        if child.is_alive():
            child.kill()


def test_acquire_never_sleeps_past_the_deadline(lock_path):
    holder = FileLock(lock_path)
    assert holder.try_acquire()
    started = time.monotonic()
    with pytest.raises(FileLockTimeout):
        FileLock(lock_path).acquire(timeout=0.05, poll_seconds=2.0)
    assert time.monotonic() - started < 0.5
    holder.release()


def test_acquire_uses_a_small_configured_poll_unchanged(lock_path, monkeypatch):
    holder = FileLock(lock_path)
    assert holder.try_acquire()
    slept = []
    real_sleep = time.sleep
    monkeypatch.setattr(
        "servonaut.utils.file_lock.time.sleep", lambda s: (slept.append(s), real_sleep(s))
    )
    with pytest.raises(FileLockTimeout):
        FileLock(lock_path).acquire(timeout=0.02, poll_seconds=0.0001)
    holder.release()
    assert slept and max(slept) <= 0.0001 + 1e-9
