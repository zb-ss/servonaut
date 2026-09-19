"""Desktop child process runner, control handshake, and parent-death watchdog.

Executes in the private child process to accept the startup control frame,
reconstruct the pre-bound listener socket, signal readiness, and monitor the
parent control pipe for unexpected parent death or graceful shutdown.
"""

from __future__ import annotations

import argparse
import contextlib
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from typing import BinaryIO, Final

from servonaut.desktop.control import (
    DesktopControlError,
    encode_control_frame,
    read_parent_frame,
)
from servonaut.desktop.model import (
    DesktopChildErrorCode,
    ErrorResponse,
    PosixListener,
    ReadyResponse,
    StartRequest,
    WindowsSharedListener,
)

_CREATE_BREAKAWAY_FROM_JOB: Final = 0x01000000


class ChildStartupError(RuntimeError):
    """Raised when child startup or handshake fails."""

    def __init__(self, message: str, code: DesktopChildErrorCode | None = None) -> None:
        super().__init__(message)
        self.code = code or DesktopChildErrorCode.STARTUP_FAILED


class ParentDeathWatchdog:
    """Monitors the parent control pipe stream and triggers shutdown on parent death."""

    def __init__(
        self,
        stream: BinaryIO,
        *,
        on_parent_death: Callable[[], None] | None = None,
        poll_interval: float = 0.05,
    ) -> None:
        self._stream = stream
        self._on_parent_death = on_parent_death
        self._poll_interval = poll_interval
        self._dead_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def is_parent_dead(self) -> bool:
        return self._dead_event.is_set()

    def start(self) -> None:
        """Start the watchdog background thread."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="ServonautParentDeathWatchdog",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the watchdog thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=0.5)

    def wait_for_parent_death(self, timeout: float | None = None) -> bool:
        """Block until parent death is detected or timeout expires."""
        return self._dead_event.wait(timeout=timeout)

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                # Read 1 byte from the parent control stream.
                # In normal state, parent holds pipe open without writing or sends EOF on close.
                # If parent dies, crashes, or closes pipe, read() returns b"" (EOF).
                chunk = self._stream.read(1)
                if not chunk:
                    # Parent pipe EOF detected!
                    self._handle_parent_death()
                    break
            except (OSError, ValueError):
                # Stream closed or broken pipe
                self._handle_parent_death()
                break

    def _handle_parent_death(self) -> None:
        if self._dead_event.is_set():
            return
        self._dead_event.set()
        if self._on_parent_death:
            with contextlib.suppress(Exception):
                self._on_parent_death()


class DesktopChildSession:
    """Represents an authenticated, running desktop child session."""

    def __init__(
        self,
        start_request: StartRequest,
        listener: socket.socket,
        watchdog: ParentDeathWatchdog,
    ) -> None:
        self.start_request = start_request
        self.listener = listener
        self.watchdog = watchdog
        self._closed = False

    def close(self) -> None:
        """Idempotently close the child session and release resources."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            self.watchdog.stop()
        with contextlib.suppress(OSError):
            self.listener.close()


def _normalize_platform(name: str | None) -> str:
    if name is None:
        return "nt" if sys.platform == "win32" else "posix"
    if name in {"win32", "windows", "nt"}:
        return "nt"
    return "posix"


def reconstruct_listener(
    start_request: StartRequest,
    *,
    platform_name: str | None = None,
) -> socket.socket:
    """Reconstruct a live socket from the StartRequest listener specification."""
    target_platform = _normalize_platform(platform_name)

    if target_platform == "nt":
        if not isinstance(start_request.listener, WindowsSharedListener):
            raise ChildStartupError(
                "Expected WindowsSharedListener for win32 platform",
                DesktopChildErrorCode.LISTENER_REJECTED,
            )
        try:
            return socket.fromshare(start_request.listener.data)
        except Exception as error:
            raise ChildStartupError(
                f"socket.fromshare failed: {error}",
                DesktopChildErrorCode.LISTENER_REJECTED,
            ) from error

    # POSIX
    if not isinstance(start_request.listener, PosixListener):
        raise ChildStartupError(
            "Expected PosixListener for POSIX platform",
            DesktopChildErrorCode.LISTENER_REJECTED,
        )
    try:
        sock = socket.fromfd(
            start_request.listener.fd, socket.AF_INET, socket.SOCK_STREAM
        )
        return sock
    except Exception as error:
        raise ChildStartupError(
            f"socket.fromfd failed: {error}",
            DesktopChildErrorCode.LISTENER_REJECTED,
        ) from error


def run_child_handshake(
    stdin_stream: BinaryIO,
    stdout_stream: BinaryIO,
    *,
    platform_name: str | None = None,
    on_parent_death: Callable[[], None] | None = None,
) -> DesktopChildSession:
    """Accept the start request, reconstruct the socket, emit ready, and start watchdog."""
    target_platform = _normalize_platform(platform_name)

    try:
        start_request = read_parent_frame(stdin_stream, platform_name=target_platform)
    except DesktopControlError as error:
        error_resp = ErrorResponse(code=DesktopChildErrorCode.INVALID_START)
        with contextlib.suppress(OSError, ValueError):
            stdout_stream.write(encode_control_frame(error_resp))
            stdout_stream.flush()
        raise ChildStartupError(
            f"Failed to read start frame: {error.code}",
            DesktopChildErrorCode.INVALID_START,
        ) from error

    try:
        listener = reconstruct_listener(start_request, platform_name=target_platform)
    except ChildStartupError as error:
        error_resp = ErrorResponse(code=error.code)
        with contextlib.suppress(OSError, ValueError):
            stdout_stream.write(encode_control_frame(error_resp))
            stdout_stream.flush()
        raise

    # Emit ready response frame to parent
    ready_resp = ReadyResponse(origin=start_request.origin)
    try:
        stdout_stream.write(encode_control_frame(ready_resp))
        stdout_stream.flush()
    except (DesktopControlError, OSError, ValueError) as error:
        with contextlib.suppress(OSError):
            listener.close()
        raise ChildStartupError(
            f"Failed to write ready response: {error}",
            DesktopChildErrorCode.STARTUP_FAILED,
        ) from error

    # Start parent death watchdog on the stdin pipe
    watchdog = ParentDeathWatchdog(stdin_stream, on_parent_death=on_parent_death)
    watchdog.start()

    return DesktopChildSession(
        start_request=start_request,
        listener=listener,
        watchdog=watchdog,
    )


# --- Standalone CLI Runner & Test Harness ---


def _terminate_grandchildren(procs: Sequence[subprocess.Popen[bytes]]) -> None:
    """Terminate all tracked grandchild processes."""
    for p in procs:
        if p.poll() is None:
            with contextlib.suppress(OSError):
                p.terminate()
    for p in procs:
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            p.wait(timeout=0.5)
        if p.poll() is None:
            with contextlib.suppress(OSError):
                p.kill()


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for child process execution and contract verification."""
    parser = argparse.ArgumentParser(description="Servonaut desktop child runner")
    parser.add_argument("--crash-before-start", action="store_true")
    parser.add_argument("--delay-ready", type=float, default=0.0)
    parser.add_argument("--exit-on-ready", type=int, default=None)
    parser.add_argument(
        "--spawn-grandchild",
        choices=["normal", "breakaway"],
        default=None,
    )
    parser.add_argument("--ignore-parent-eof", action="store_true")
    parser.add_argument("--sleep-duration", type=float, default=60.0)

    args = parser.parse_args(argv)

    if args.crash_before_start:
        return 42

    if args.delay_ready > 0:
        time.sleep(args.delay_ready)

    grandchildren: list[subprocess.Popen[bytes]] = []

    def on_parent_death() -> None:
        _terminate_grandchildren(grandchildren)

    try:
        session = run_child_handshake(
            sys.stdin.buffer,
            sys.stdout.buffer,
            on_parent_death=None if args.ignore_parent_eof else on_parent_death,
        )
    except ChildStartupError:
        return 1

    try:
        # Spawn grandchild if requested
        if args.spawn_grandchild:
            sub_cmd = [
                sys.executable,
                "-c",
                "import time; time.sleep(60)",
            ]
            creationflags = 0
            if sys.platform == "win32" and args.spawn_grandchild == "breakaway":
                creationflags = _CREATE_BREAKAWAY_FROM_JOB

            gc = subprocess.Popen(
                sub_cmd,
                creationflags=creationflags,
            )
            grandchildren.append(gc)

        if args.exit_on_ready is not None:
            return args.exit_on_ready

        # Wait for parent death or timeout
        deadline = time.monotonic() + args.sleep_duration
        while time.monotonic() < deadline:
            if not args.ignore_parent_eof and session.watchdog.is_parent_dead:
                break
            time.sleep(0.05)

        return 0

    finally:
        _terminate_grandchildren(grandchildren)
        session.close()


if __name__ == "__main__":
    sys.exit(main())
