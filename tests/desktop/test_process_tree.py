"""Contract tests for owned desktop child process trees and platform containment."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from unittest.mock import MagicMock

import pytest

from servonaut.desktop.model import SecretToken
from servonaut.desktop.process_tree import (
    _JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    PosixProcessTree,
    ProcessTreeError,
    WindowsJobProcessTree,
    launch_and_handshake_desktop_child,
    spawn_desktop_child,
)


def _bind_loopback() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock


def test_spawn_desktop_child_validates_argv() -> None:
    with pytest.raises(ProcessTreeError, match="argv-empty"):
        spawn_desktop_child([])

    with pytest.raises(ProcessTreeError, match="invalid-argv-arg"):
        spawn_desktop_child([""])

    with pytest.raises(ProcessTreeError, match="invalid-argv-arg"):
        spawn_desktop_child(["valid", ""])  # type: ignore[list-item]


def test_posix_spawn_creates_owned_tree_with_new_session() -> None:
    sock = _bind_loopback()
    try:
        cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
        tree = spawn_desktop_child(cmd, listener=sock, platform_name="posix")
        try:
            assert isinstance(tree, PosixProcessTree)
            assert tree.pid > 0
            assert tree.poll() is None

            # Verify the child is in its own session / process group
            child_pgid = os.getpgid(tree.pid)
            assert child_pgid == tree.pid
        finally:
            tree.close()

        assert tree.poll() is not None
    finally:
        sock.close()


def test_posix_process_tree_graceful_terminate() -> None:
    cmd = [
        sys.executable,
        "-c",
        "import sys, time; sys.stdin.read(); sys.exit(0)",
    ]
    tree = spawn_desktop_child(cmd, platform_name="posix")
    try:
        assert tree.poll() is None
        # Terminating should close stdin, allowing the child to exit cleanly
        tree.terminate(grace_seconds=1.0)
        assert tree.poll() == 0
    finally:
        tree.close()


def test_posix_process_tree_forces_sigkill_on_stubborn_child() -> None:
    # Child ignores SIGTERM and sleeps
    cmd = [
        sys.executable,
        "-c",
        (
            "import signal, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "time.sleep(30)"
        ),
    ]
    tree = spawn_desktop_child(cmd, platform_name="posix")
    try:
        assert tree.poll() is None
        start_time = time.monotonic()
        # Should escalate to SIGKILL after grace_seconds
        tree.terminate(grace_seconds=0.1)
        duration = time.monotonic() - start_time
        assert duration < 2.0
        assert tree.poll() is not None
        # On POSIX, killed by SIGKILL produces negative signal code -9
        assert tree.poll() in {-9, 137}
    finally:
        tree.close()


def test_posix_process_tree_close_is_idempotent() -> None:
    cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
    tree = spawn_desktop_child(cmd, platform_name="posix")

    tree.close()
    assert tree.poll() is not None

    # Subsequent close calls should be harmless no-ops
    tree.close()
    tree.close()


def test_posix_process_tree_reclaims_grandchildren() -> None:
    # Child spawns a grandchild in the same process group, writes grandchild PID, and sleeps
    script = (
        "import subprocess, sys, time\n"
        "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "sys.stdout.write(f'{gc.pid}\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(60)\n"
    )
    tree = spawn_desktop_child(
        [sys.executable, "-c", script],
        platform_name="posix",
    )
    try:
        assert tree.stdout is not None
        gc_pid_line = tree.stdout.readline().decode().strip()
        gc_pid = int(gc_pid_line)

        # Verify grandchild is alive
        os.kill(gc_pid, 0)

        # Terminating the tree must kill both child and grandchild
        tree.close()

        # Check grandchild is terminated
        time.sleep(0.1)
        with pytest.raises(ProcessLookupError):
            os.kill(gc_pid, 0)
    finally:
        tree.close()


def test_launch_and_handshake_success() -> None:
    sock = _bind_loopback()
    port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    token = SecretToken.generate()

    cmd = [sys.executable, "-m", "servonaut.desktop.child_process"]

    tree, ready = launch_and_handshake_desktop_child(
        cmd,
        origin=origin,
        token=token,
        listener=sock,
        startup_timeout=5.0,
        platform_name="posix" if sys.platform != "win32" else "win32",
    )
    try:
        assert ready.origin == origin
        assert tree.poll() is None
    finally:
        tree.close()
        sock.close()

    assert tree.poll() is not None


def test_launch_and_handshake_child_crash_before_start() -> None:
    sock = _bind_loopback()
    port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    token = SecretToken.generate()

    cmd = [
        sys.executable,
        "-m",
        "servonaut.desktop.child_process",
        "--crash-before-start",
    ]

    with pytest.raises(ProcessTreeError, match="child-exited-early:42"):
        launch_and_handshake_desktop_child(
            cmd,
            origin=origin,
            token=token,
            listener=sock,
            startup_timeout=5.0,
            platform_name="posix" if sys.platform != "win32" else "win32",
        )

    sock.close()


def test_launch_and_handshake_startup_timeout() -> None:
    sock = _bind_loopback()
    port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    token = SecretToken.generate()

    # Child delays ready response by 5.0 seconds
    cmd = [
        sys.executable,
        "-m",
        "servonaut.desktop.child_process",
        "--delay-ready",
        "5.0",
    ]

    # Handshake timeout is 0.2 seconds
    with pytest.raises(ProcessTreeError, match="startup-timeout"):
        launch_and_handshake_desktop_child(
            cmd,
            origin=origin,
            token=token,
            listener=sock,
            startup_timeout=0.2,
            platform_name="posix" if sys.platform != "win32" else "win32",
        )

    sock.close()


def test_windows_job_object_constants_and_limits() -> None:
    assert _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0x2000
    assert _JOB_OBJECT_LIMIT_BREAKAWAY_OK == 0x0800
    expected_flags = (
        _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_BREAKAWAY_OK
    )
    assert expected_flags == 0x2800


def test_windows_job_process_tree_idempotent_close() -> None:
    mock_proc = MagicMock(spec=subprocess.Popen)
    mock_proc.poll.return_value = 0
    mock_proc.stdin = None
    mock_proc.stdout = None
    mock_proc.stderr = None

    tree = WindowsJobProcessTree(mock_proc, job_handle=None)
    tree.close()
    tree.close()
    assert tree.poll() == 0


@pytest.mark.skipif(
    sys.platform != "win32", reason="Native Windows Job Object execution"
)
def test_windows_native_job_object_reclaims_child_and_grandchild() -> None:
    sock = _bind_loopback()
    port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    token = SecretToken.generate()

    cmd = [
        sys.executable,
        "-m",
        "servonaut.desktop.child_process",
        "--spawn-grandchild",
        "normal",
    ]

    tree, ready = launch_and_handshake_desktop_child(
        cmd,
        origin=origin,
        token=token,
        listener=sock,
        startup_timeout=5.0,
        platform_name="win32",
    )
    assert ready.origin == origin
    assert tree.poll() is None

    # Closing tree terminates the entire Job Object
    tree.close()
    sock.close()

    assert tree.poll() is not None
