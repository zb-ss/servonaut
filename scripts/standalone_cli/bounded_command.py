"""Shell-free command execution with bounded output and process-tree cleanup."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Literal

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError

_POLL_INTERVAL_SECONDS = 0.05
_PROCESS_REAP_TIMEOUT_SECONDS = 2.0
_READER_DRAIN_TIMEOUT_SECONDS = 2.0
_LABEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 -]{0,63}$")

ProcessFailure = Literal["timeout", "overflow", "read-error", "input-error"]


@dataclass(frozen=True)
class BoundedProcessResult:
    """Retained output and the first failure observed while one command ran."""

    exit_code: int | None
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float
    failure: ProcessFailure | None
    cleaned_up: bool


@dataclass(frozen=True)
class _StreamEvents:
    overflow: threading.Event
    read_error: threading.Event
    input_error: threading.Event


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
        result = run_bounded_process(
            command,
            environment,
            working_directory,
            timeout_seconds,
            max_stdout_bytes,
            max_stderr_bytes,
        )
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} could not run") from error
    if not result.cleaned_up:
        raise ArtifactEvidenceError(f"{label} cleanup did not complete")
    if result.failure == "timeout":
        raise ArtifactEvidenceError(f"{label} timed out")
    if result.failure == "overflow":
        raise ArtifactEvidenceError(f"{label} exceeded its output limit")
    if result.failure is not None:
        raise ArtifactEvidenceError(f"{label} output could not be read")
    if result.exit_code != 0:
        raise ArtifactEvidenceError(f"{label} failed")
    return result.stdout


def run_bounded_process(
    argv: Sequence[str],
    environment: Mapping[str, str],
    working_directory: Path,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    *,
    stdin: bytes | None = None,
) -> BoundedProcessResult:
    """Run one argv under a single deadline, then remove its whole process tree.

    Output beyond either limit, a read failure, or the deadline stops the tree
    at once. Stream threads are daemons joined against one shared deadline, so
    a descendant that keeps a pipe open cannot hang the caller.
    """
    started = time.monotonic()
    process = start_process_tree(
        argv,
        environment=environment,
        working_directory=working_directory,
        stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout = bytearray()
    stderr = bytearray()
    events = _StreamEvents(threading.Event(), threading.Event(), threading.Event())
    threads: list[threading.Thread] = []
    try:
        threads = _start_io_threads(
            process,
            stdin,
            (stdout, stderr),
            (max_stdout_bytes, max_stderr_bytes),
            events,
        )
        timed_out = _wait_for_process(process, started + timeout_seconds, events)
    except BaseException:
        reap_process_tree(process)
        _join_threads(threads, time.monotonic() + _READER_DRAIN_TIMEOUT_SECONDS)
        raise
    reaped = reap_process_tree(process)
    settled = _join_threads(threads, time.monotonic() + _READER_DRAIN_TIMEOUT_SECONDS)
    return BoundedProcessResult(
        exit_code=process.returncode if reaped else None,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
        elapsed_seconds=time.monotonic() - started,
        failure=_first_failure(timed_out, events),
        cleaned_up=reaped and settled,
    )


def start_process_tree(
    argv: Sequence[str],
    *,
    environment: Mapping[str, str],
    working_directory: Path,
    stdin: int | IO[bytes] | None,
    stdout: int | IO[bytes] | None,
    stderr: int | IO[bytes] | None,
    text: bool = False,
) -> subprocess.Popen:
    """Start one argv without a shell as the root of a process tree we can kill.

    On POSIX the child leads a new session, so its process group reaches every
    descendant that does not deliberately leave it.
    """
    return subprocess.Popen(
        list(argv),
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        cwd=working_directory,
        env=dict(environment),
        shell=False,
        text=text,
        start_new_session=os.name != "nt",
    )


def reap_process_tree(process: subprocess.Popen) -> bool:
    """Kill a started process tree and report whether its root was reaped."""
    kill_process_tree(process)
    try:
        process.wait(timeout=_PROCESS_REAP_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def kill_process_tree(process: subprocess.Popen) -> None:
    """Kill the root process and every descendant still reachable through it."""
    if os.name == "nt":
        _kill_windows_tree(process)
    else:
        # The recorded group is signalled even after its root has exited, so
        # descendants that outlived the root are removed as well.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _kill_windows_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        return
    taskkill = Path(system_root) / "System32" / "taskkill.exe"
    try:
        subprocess.run(
            [str(taskkill), "/T", "/F", "/PID", str(process.pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_PROCESS_REAP_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return


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


def _start_io_threads(
    process: subprocess.Popen,
    stdin: bytes | None,
    destinations: tuple[bytearray, bytearray],
    limits: tuple[int, int],
    events: _StreamEvents,
) -> list[threading.Thread]:
    threads = [
        threading.Thread(
            target=_capture_stream,
            args=(stream, destination, limit, events.overflow, events.read_error),
            daemon=True,
        )
        for stream, destination, limit in zip(
            (process.stdout, process.stderr), destinations, limits
        )
    ]
    if stdin is not None:
        threads.append(
            threading.Thread(
                target=_write_stream,
                args=(process.stdin, stdin, events.input_error),
                daemon=True,
            )
        )
    started: list[threading.Thread] = []
    try:
        for thread in threads:
            thread.start()
            started.append(thread)
    except BaseException:
        reap_process_tree(process)
        _join_threads(started, time.monotonic() + _READER_DRAIN_TIMEOUT_SECONDS)
        raise
    return threads


def _wait_for_process(
    process: subprocess.Popen, deadline: float, events: _StreamEvents
) -> bool:
    """Wait for exit, overflow or a read failure; return whether time ran out."""
    while (
        process.poll() is None
        and not events.overflow.is_set()
        and not events.read_error.is_set()
    ):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        events.overflow.wait(min(remaining, _POLL_INTERVAL_SECONDS))
    return False


def _first_failure(timed_out: bool, events: _StreamEvents) -> ProcessFailure | None:
    if timed_out:
        return "timeout"
    if events.overflow.is_set():
        return "overflow"
    if events.read_error.is_set():
        return "read-error"
    if events.input_error.is_set():
        return "input-error"
    return None


def _capture_stream(
    stream: IO[bytes],
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


def _write_stream(stream: IO[bytes], data: bytes, input_error: threading.Event) -> None:
    try:
        if data:
            stream.write(data)
            stream.flush()
    except (OSError, ValueError):
        input_error.set()
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            input_error.set()


def _join_threads(threads: list[threading.Thread], deadline: float) -> bool:
    """Join every thread against one shared deadline; report whether all ended."""
    for thread in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        thread.join(remaining)
    return not any(thread.is_alive() for thread in threads)
