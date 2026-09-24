"""Bounded shell-free command execution tests."""

from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.bounded_command import _capture_stream, run_bounded_command


class _SpyStream(io.BytesIO):
    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.requests: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.requests.append(size)
        return super().read(min(size, 2))


def test_rejects_non_neutral_diagnostic_label_before_launch(tmp_path: Path) -> None:
    with pytest.raises(ArtifactEvidenceError, match="diagnostic label is invalid"):
        run_bounded_command(
            [sys.executable, "-c", "raise SystemExit(0)"],
            {},
            tmp_path,
            5,
            32,
            32,
            str(tmp_path),
        )


def test_returns_stdout_and_drains_stderr(tmp_path: Path) -> None:
    output = run_bounded_command(
        [
            sys.executable,
            "-c",
            "import sys;sys.stdout.write('ok');sys.stderr.write('diagnostic')",
        ],
        {},
        tmp_path,
        5,
        32,
        32,
        "command fixture",
    )

    assert output == b"ok"
    assert not tuple(tmp_path.iterdir())


def test_stream_reads_only_remaining_cap_plus_overflow_probe() -> None:
    stream = _SpyStream(b"123456")
    retained = bytearray()
    overflow = threading.Event()
    read_error = threading.Event()

    _capture_stream(stream, retained, 5, overflow, read_error)

    assert stream.requests == [6, 4, 2]
    assert retained == b"12345"
    assert overflow.is_set()
    assert not read_error.is_set()


@pytest.mark.parametrize("stream", ("stdout", "stderr"))
def test_stops_and_reaps_on_bounded_stream_overflow(
    tmp_path: Path, stream: str
) -> None:
    script = f"import sys;sys.{stream}.buffer.write(b'x' * 262144);sys.{stream}.flush()"

    with pytest.raises(ArtifactEvidenceError, match="exceeded its output limit"):
        run_bounded_command(
            [sys.executable, "-c", script],
            {},
            tmp_path,
            5,
            16,
            16,
            "bounded fixture",
        )

    assert not tuple(tmp_path.iterdir())


def test_timeout_stops_and_reaps_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _capture_process(monkeypatch)

    started = time.monotonic()
    with pytest.raises(ArtifactEvidenceError, match="timed out"):
        run_bounded_command(
            [sys.executable, "-c", "import time;time.sleep(30)"],
            {},
            tmp_path,
            1,
            1024,
            1024,
            "timed fixture",
        )

    assert time.monotonic() - started < 5
    assert len(captured) == 1
    assert captured[0].poll() is not None


@pytest.mark.skipif(os.name == "nt", reason="SIGALRM is unavailable on Windows")
def test_interruption_stops_and_reaps_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = _capture_process(monkeypatch)

    def interrupt(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGALRM, interrupt)
    signal.setitimer(signal.ITIMER_REAL, 0.1)
    try:
        with pytest.raises(KeyboardInterrupt):
            run_bounded_command(
                [sys.executable, "-c", "import time;time.sleep(30)"],
                {},
                tmp_path,
                10,
                1024,
                1024,
                "interrupted fixture",
            )
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)

    assert len(captured) == 1
    assert captured[0].poll() is not None


def _capture_process(
    monkeypatch: pytest.MonkeyPatch,
) -> list[subprocess.Popen[bytes]]:
    real_popen = subprocess.Popen
    captured: list[subprocess.Popen[bytes]] = []

    def capture(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        captured.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", capture)
    return captured


@pytest.mark.skipif(os.name == "nt", reason="a POSIX shell creates the descendant")
def test_timeout_stops_descendants_that_keep_output_open(tmp_path: Path) -> None:
    late_write = tmp_path / "descendant-survived"
    script = f"(sleep 3; echo late > '{late_write}') & exec sleep 60"

    started = time.monotonic()
    with pytest.raises(ArtifactEvidenceError, match="timed out"):
        run_bounded_command(
            ["/bin/sh", "-c", script],
            {"PATH": os.defpath},
            tmp_path,
            1,
            1024,
            1024,
            "descendant fixture",
        )
    elapsed = time.monotonic() - started
    time.sleep(3)

    assert elapsed < 2.5
    assert not late_write.exists()
