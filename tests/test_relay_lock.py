"""Tests for the RelayLock advisory lock.

``fcntl.flock`` is per-FD but tracked on the inode, so two different
processes attempting to acquire the same lock file always conflict. Inside a
single process the kernel is more permissive (re-locking the same FD with
``LOCK_EX`` succeeds without blocking on POSIX), so we use a second file
descriptor to prove the overlap case rather than two ``RelayLock`` objects
against the same FD.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from servonaut.services.relay_lock import (
    LockOwner,
    RelayAlreadyActiveError,
    RelayLock,
    is_pid_alive,
    read_owner,
)


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows locking semantics differ; covered by separate smoke.",
)


@pytest.fixture
def lock_path(tmp_path) -> Path:
    return tmp_path / "relay.lock"


class TestBasicAcquireRelease:
    def test_acquire_creates_file_with_owner_metadata(self, lock_path):
        with RelayLock(mode="tui", path=lock_path) as lock:
            assert lock_path.exists()
            assert (lock_path.stat().st_mode & 0o777) == 0o600
            payload = json.loads(lock_path.read_text())
            assert payload["pid"] == os.getpid()
            assert payload["mode"] == "tui"
            assert isinstance(payload["acquired_at"], (int, float))

    def test_release_truncates_file(self, lock_path):
        lock = RelayLock(mode="bg", path=lock_path)
        lock.acquire()
        lock.release()
        assert lock_path.exists()
        assert lock_path.read_text() == ""

    def test_reacquire_after_release(self, lock_path):
        """Release + reacquire must succeed in the same process."""
        lock = RelayLock(mode="tui", path=lock_path)
        lock.acquire()
        lock.release()
        lock.acquire()
        try:
            payload = json.loads(lock_path.read_text())
            assert payload["mode"] == "tui"
        finally:
            lock.release()


class TestContention:
    def test_second_process_cannot_acquire_while_first_holds(self, lock_path, tmp_path):
        """Run a child process that tries to grab the same lock while we hold it."""
        import subprocess
        with RelayLock(mode="tui", path=lock_path):
            script = tmp_path / "probe.py"
            script.write_text(
                "import sys, json\n"
                f"sys.path.insert(0, {repr(str(Path(__file__).parent.parent / 'src'))})\n"
                "from servonaut.services.relay_lock import RelayLock, RelayAlreadyActiveError\n"
                f"lock = RelayLock(mode='bg', path={repr(str(lock_path))})\n"
                "try:\n"
                "    lock.acquire()\n"
                "    print('UNEXPECTED_ACQUIRE')\n"
                "except RelayAlreadyActiveError as e:\n"
                "    print(json.dumps({'blocked': True, 'owner_mode': e.owner.mode, "
                "'owner_pid': e.owner.pid}))\n"
            )
            result = subprocess.run(
                [sys.executable, str(script)],
                capture_output=True, text=True, timeout=15,
            )
            out = result.stdout.strip().splitlines()[-1] if result.stdout else ""
            parsed = json.loads(out)
            assert parsed["blocked"] is True
            assert parsed["owner_mode"] == "tui"
            assert parsed["owner_pid"] == os.getpid()

    def test_owner_info_raised_to_caller(self, lock_path, tmp_path):
        """RelayAlreadyActiveError surfaces the held-lock payload verbatim."""
        import subprocess
        with RelayLock(mode="tui", path=lock_path):
            # Second RelayLock in a child process.
            script = tmp_path / "probe2.py"
            script.write_text(
                "import sys\n"
                f"sys.path.insert(0, {repr(str(Path(__file__).parent.parent / 'src'))})\n"
                "from servonaut.services.relay_lock import RelayLock, RelayAlreadyActiveError\n"
                f"try:\n    RelayLock(mode='bg', path={repr(str(lock_path))}).acquire()\n"
                "    sys.exit(2)\n"
                "except RelayAlreadyActiveError as e:\n"
                "    print(e)\n"
                "    sys.exit(0)\n"
            )
            result = subprocess.run(
                [sys.executable, str(script)],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0
            assert "mode=tui" in result.stdout
            assert f"pid={os.getpid()}" in result.stdout


class TestStaleLock:
    def test_dead_holder_allows_new_acquire(self, lock_path):
        """If the previous holder died without releasing, the next acquire succeeds.

        When a process dies the kernel drops its flock on FD close, so the file
        may still contain the old PID+mode but the lock itself is available.
        """
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps({
            "pid": 999_999_999,  # very unlikely to be a real PID
            "mode": "tui",
            "acquired_at": 0.0,
        }))
        # File has stale PID data but no real flock — we must be able to take it.
        new_lock = RelayLock(mode="bg", path=lock_path)
        new_lock.acquire()
        try:
            payload = json.loads(lock_path.read_text())
            assert payload["pid"] == os.getpid()
            assert payload["mode"] == "bg"
        finally:
            new_lock.release()


class TestReadOwner:
    def test_returns_unknown_when_file_missing(self, tmp_path):
        assert read_owner(tmp_path / "nope.lock") == LockOwner.unknown()

    def test_returns_unknown_when_file_empty(self, lock_path):
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text("")
        assert read_owner(lock_path) == LockOwner.unknown()

    def test_parses_written_payload(self, lock_path):
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps({"pid": 42, "mode": "tui", "acquired_at": 1.5}))
        owner = read_owner(lock_path)
        assert owner.pid == 42
        assert owner.mode == "tui"
        assert owner.acquired_at == 1.5

    def test_is_pid_alive_self(self):
        assert is_pid_alive(os.getpid()) is True

    def test_is_pid_alive_none(self):
        assert is_pid_alive(None) is False
        assert is_pid_alive(0) is False


class TestValidation:
    def test_invalid_mode_rejected(self, lock_path):
        with pytest.raises(ValueError, match="mode must be"):
            RelayLock(mode="random", path=lock_path)

    def test_double_acquire_same_instance_errors(self, lock_path):
        """Calling acquire() twice on the same RelayLock is a programmer bug."""
        lock = RelayLock(mode="tui", path=lock_path)
        lock.acquire()
        try:
            with pytest.raises(RelayAlreadyActiveError):
                lock.acquire()
        finally:
            lock.release()
