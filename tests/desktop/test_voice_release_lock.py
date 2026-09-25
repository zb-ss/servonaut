"""Tests for the voice runtime's cross-process locks and worker launcher."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

import servonaut
from servonaut.desktop.voice import release_lock
from servonaut.desktop.voice.release_lock import (
    LockTimeoutError,
    can_lock,
    open_and_lock,
    try_lock,
    unlock,
)

SOURCE_ROOT = Path(servonaut.__file__).resolve().parents[1]


def _hold_in_subprocess(path: Path, *, exclusive: bool) -> subprocess.Popen[bytes]:
    """Hold a lock from another process until its stdin closes."""
    holder = subprocess.Popen(
        [
            sys.executable, "-c",
            "import sys; from pathlib import Path; "
            "from servonaut.desktop.voice.release_lock import open_and_lock; "
            f"open_and_lock(Path(sys.argv[1]), exclusive={exclusive}, timeout=0.0); "
            "print('held', flush=True); sys.stdin.read()",
            str(path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(SOURCE_ROOT)},
    )
    assert holder.stdout is not None and holder.stdout.readline().strip() == b"held"
    return holder


def _release(holder: subprocess.Popen[bytes]) -> None:
    holder.communicate(timeout=10)


class TestLocks:
    def test_shared_holders_coexist_and_exclude_an_exclusive_one(self, tmp_path: Path) -> None:
        path = tmp_path / ".in-use"
        first = open_and_lock(path, exclusive=False, timeout=0.0)
        second = open_and_lock(path, exclusive=False, timeout=0.0)
        try:
            assert can_lock(path, exclusive=False)
            assert not can_lock(path, exclusive=True)
            with pytest.raises(LockTimeoutError):
                open_and_lock(path, exclusive=True, timeout=0.0)
        finally:
            os.close(first)
            os.close(second)
        assert can_lock(path, exclusive=True)

    def test_an_exclusive_holder_in_another_process_is_seen(self, tmp_path: Path) -> None:
        path = tmp_path / "lock"
        holder = _hold_in_subprocess(path, exclusive=True)
        try:
            assert not can_lock(path, exclusive=False)
            assert not can_lock(path, exclusive=True)
        finally:
            _release(holder)
        assert can_lock(path, exclusive=False)

    def test_a_shared_holder_in_another_process_blocks_only_exclusive(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / ".in-use"
        holder = _hold_in_subprocess(path, exclusive=False)
        try:
            assert can_lock(path, exclusive=False)
            assert not can_lock(path, exclusive=True)
        finally:
            _release(holder)

    def test_probing_a_missing_file_does_not_create_it(self, tmp_path: Path) -> None:
        path = tmp_path / "absent"

        assert can_lock(path, exclusive=True)
        assert not path.exists()

    def test_lock_waits_until_the_timeout(self, tmp_path: Path) -> None:
        path = tmp_path / "lock"
        held = open_and_lock(path, exclusive=True, timeout=0.0)
        try:
            with pytest.raises(LockTimeoutError):
                open_and_lock(path, exclusive=True, timeout=0.2)
        finally:
            os.close(held)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX descriptor semantics")
    def test_errors_other_than_contention_are_raised(self, tmp_path: Path) -> None:
        path = tmp_path / "lock"
        path.touch()
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)

        with pytest.raises(OSError):
            try_lock(fd, exclusive=False)

    def test_unlock_releases_for_other_holders(self, tmp_path: Path) -> None:
        path = tmp_path / "lock"
        fd = open_and_lock(path, exclusive=True, timeout=0.0)
        try:
            unlock(fd)
            assert can_lock(path, exclusive=True)
        finally:
            os.close(fd)


class TestLauncher:
    def test_usage_errors_exit_with_status_two(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert release_lock.main(["--models-root", "x"]) == 2
        assert "usage" in capsys.readouterr().err

    def test_a_release_being_removed_is_not_started(self, tmp_path: Path) -> None:
        path = tmp_path / ".in-use"
        held = open_and_lock(path, exclusive=True, timeout=0.0)
        try:
            assert release_lock.main(["--hold", str(path), "--", "--models-root", "x"]) == 3
        finally:
            os.close(held)

    def test_a_momentary_probe_does_not_stop_the_worker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / ".in-use"
        probe = open_and_lock(path, exclusive=True, timeout=0.0)
        threading.Timer(0.2, os.close, args=(probe,)).start()
        monkeypatch.setattr(release_lock.runpy, "run_module", lambda name, **kwargs: None)
        monkeypatch.setattr(sys, "argv", ["launcher"])

        assert release_lock.main(["--hold", str(path), "--"]) == 0

    def test_holds_the_lock_while_running_the_worker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / ".in-use"
        seen: dict[str, Any] = {}

        def fake_run_module(name: str, **kwargs: Any) -> None:
            seen["name"] = name
            seen["kwargs"] = kwargs
            seen["argv"] = list(sys.argv)
            seen["in_use"] = not can_lock(path, exclusive=True)

        monkeypatch.setattr(release_lock.runpy, "run_module", fake_run_module)
        monkeypatch.setattr(sys, "argv", ["launcher"])

        result = release_lock.main(
            ["--hold", str(path), "--", "--models-root", "/models", "--manifest-id", "v1-x"]
        )

        assert result == 0
        assert seen == {
            "name": "servonaut.desktop.voice.worker",
            "kwargs": {"run_name": "__main__", "alter_sys": True},
            "argv": [
                "servonaut.desktop.voice.worker",
                "--models-root", "/models", "--manifest-id", "v1-x",
            ],
            "in_use": True,
        }
