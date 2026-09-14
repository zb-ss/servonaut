"""Shell-free command execution with bounded output and cleanup."""

from __future__ import annotations

import re
import subprocess
import threading
import time
from pathlib import Path
from typing import BinaryIO

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError

_POLL_INTERVAL_SECONDS = 0.05
_PROCESS_REAP_TIMEOUT_SECONDS = 2.0
_READER_DRAIN_TIMEOUT_SECONDS = 2.0
_LABEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 -]{0,63}$")


def run_bounded_command(
    command: list[str],
    environment: dict[str, str],
    working_directory: Path,
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    label: str,
) -> bytes:
    """Run an argv command and return stdout without retaining unbounded output."""
    _validate_limits(timeout_seconds, max_stdout_bytes, max_stderr_bytes, label)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_directory,
            env=environment,
            shell=False,
        )
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} could not run") from error
    return _collect_process(
        process,
        timeout_seconds,
        max_stdout_bytes,
        max_stderr_bytes,
        label,
    )


def _collect_process(
    process: subprocess.Popen[bytes],
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    label: str,
) -> bytes:
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    read_error = threading.Event()
    readers: list[threading.Thread] = []
    streams: tuple[BinaryIO, BinaryIO] | None = None
    failure: str | None = None
    try:
        if process.stdout is None or process.stderr is None:
            raise ArtifactEvidenceError(f"{label} capture is unavailable")
        streams = (process.stdout, process.stderr)
        readers = _start_readers(
            process,
            streams,
            stdout,
            stderr,
            max_stdout_bytes,
            max_stderr_bytes,
            overflow,
            read_error,
        )
        failure = _wait_for_process(process, timeout_seconds, overflow, read_error)
    except BaseException:
        _terminate_and_reap(process)
        _settle_readers(readers)
        raise
    process_reaped = _terminate_and_reap(process)
    readers_settled = _settle_readers(readers)
    if not process_reaped or not readers_settled:
        raise ArtifactEvidenceError(f"{label} cleanup did not complete")
    if failure == "timeout":
        raise ArtifactEvidenceError(f"{label} timed out")
    if overflow.is_set():
        raise ArtifactEvidenceError(f"{label} exceeded its output limit")
    if read_error.is_set():
        raise ArtifactEvidenceError(f"{label} output could not be read")
    if process.returncode != 0:
        raise ArtifactEvidenceError(f"{label} failed")
    return bytes(stdout)


def _validate_limits(
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    label: str,
) -> None:
    values = (timeout_seconds, max_stdout_bytes, max_stderr_bytes)
    if not isinstance(label, str) or not _LABEL_RE.fullmatch(label):
        raise ArtifactEvidenceError("Command diagnostic label is invalid")
    if any(type(value) is not int or value < 1 for value in values):
        raise ArtifactEvidenceError(f"{label} execution limit is invalid")


def _start_readers(
    process: subprocess.Popen[bytes],
    streams: tuple[BinaryIO, BinaryIO],
    stdout: bytearray,
    stderr: bytearray,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    overflow: threading.Event,
    read_error: threading.Event,
) -> list[threading.Thread]:
    readers = [
        threading.Thread(
            target=_capture_stream,
            args=(streams[0], stdout, max_stdout_bytes, overflow, read_error),
            daemon=True,
        ),
        threading.Thread(
            target=_capture_stream,
            args=(streams[1], stderr, max_stderr_bytes, overflow, read_error),
            daemon=True,
        ),
    ]
    started: list[threading.Thread] = []
    try:
        for reader in readers:
            reader.start()
            started.append(reader)
    except BaseException:
        _terminate_and_reap(process)
        _settle_readers(started)
        raise
    return readers


def _wait_for_process(
    process: subprocess.Popen[bytes],
    timeout_seconds: int,
    overflow: threading.Event,
    read_error: threading.Event,
) -> str | None:
    deadline = time.monotonic() + timeout_seconds
    while process.poll() is None and not overflow.is_set() and not read_error.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        overflow.wait(min(remaining, _POLL_INTERVAL_SECONDS))
    return None


def _capture_stream(
    stream: BinaryIO,
    destination: bytearray,
    limit: int,
    overflow: threading.Event,
    read_error: threading.Event,
) -> None:
    try:
        while True:
            remaining = limit - len(destination)
            chunk = stream.read(min(64 * 1024, remaining + 1))
            if not chunk:
                break
            if len(chunk) > remaining:
                destination.extend(chunk[:remaining])
                overflow.set()
                return
            destination.extend(chunk)
    except (OSError, ValueError):
        read_error.set()
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            read_error.set()


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=_PROCESS_REAP_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def _settle_readers(readers: list[threading.Thread]) -> bool:
    _join_readers(readers, _READER_DRAIN_TIMEOUT_SECONDS)
    return not any(reader.is_alive() for reader in readers)


def _join_readers(readers: list[threading.Thread], timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    for reader in readers:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        reader.join(remaining)
