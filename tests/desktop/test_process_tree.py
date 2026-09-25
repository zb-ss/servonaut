"""Contract tests for owned desktop child process trees and platform containment."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from unittest.mock import MagicMock

import pytest

from servonaut.desktop import process_tree
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


def _handshake_child_script(after_ready: str) -> str:
    """A child that completes the startup handshake, then runs ``after_ready``."""
    return (
        "import os, sys\n"
        "from servonaut.desktop.control import encode_control_frame, read_parent_frame\n"
        "from servonaut.desktop.model import ReadyResponse\n"
        "req = read_parent_frame(sys.stdin.buffer, platform_name='posix')\n"
        "sys.stdout.buffer.write(encode_control_frame(ReadyResponse(origin=req.origin)))\n"
        "sys.stdout.buffer.flush()\n"
        f"{after_ready}\n"
    )


def _wait_until_gone(pid: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


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


@pytest.mark.skipif(os.name == "nt", reason="POSIX process groups")
def test_posix_process_tree_reclaims_group_after_leader_exits() -> None:
    """Descendants keep the group alive after the child exits; close must end them."""
    script = (
        "import subprocess, sys\n"
        "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],"
        " stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "sys.stdout.write(f'{gc.pid}\\n')\n"
        "sys.stdout.flush()\n"
        "sys.exit(3)\n"
    )
    tree = spawn_desktop_child([sys.executable, "-c", script], platform_name="posix")
    assert tree.stdout is not None
    grandchild_pid = int(tree.stdout.readline().decode().strip())
    try:
        assert tree.wait(timeout=5.0) == 3

        tree.close()

        assert _wait_until_gone(grandchild_pid), "grandchild outlived the tree"
    finally:
        tree.close()
        with contextlib.suppress(ProcessLookupError):
            os.kill(grandchild_pid, signal.SIGKILL)


def test_launch_drains_child_output_after_ready(caplog: pytest.LogCaptureFixture) -> None:
    """Output written after the handshake must not fill the pipes and block the child."""
    script = _handshake_child_script(
        "line = b'x' * 1023 + b'\\n'\n"
        "for _ in range(256):\n"
        "    os.write(2, line)\n"
        "    os.write(1, line)\n"
        "os.write(2, b'child diagnostics end\\n')"
    )
    sock = _bind_loopback()
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    caplog.set_level(logging.WARNING, logger=process_tree.__name__)

    tree, _ready = launch_and_handshake_desktop_child(
        [sys.executable, "-c", script],
        origin=origin,
        token=SecretToken.generate(),
        listener=sock,
        startup_timeout=5.0,
        platform_name="posix",
    )
    try:
        # The parent keeps the control pipe open for the whole session.
        assert tree.wait(timeout=5.0) == 0
    finally:
        tree.close()
        sock.close()

    deadline = time.monotonic() + 3.0
    while "child diagnostics end" not in caplog.text and time.monotonic() < deadline:
        time.sleep(0.05)
    assert "child diagnostics end" in caplog.text


def test_launch_logs_child_stderr_when_handshake_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    script = (
        "import sys\n"
        "sys.stderr.write('frontend assets are missing\\n')\n"
        "sys.exit(1)\n"
    )
    sock = _bind_loopback()
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    caplog.set_level(logging.WARNING, logger=process_tree.__name__)

    with pytest.raises(ProcessTreeError, match="child-exited-early:1"):
        launch_and_handshake_desktop_child(
            [sys.executable, "-c", script],
            origin=origin,
            token=SecretToken.generate(),
            listener=sock,
            startup_timeout=5.0,
            platform_name="posix",
        )
    sock.close()

    assert "frontend assets are missing" in caplog.text


class _FakeStartupInfo:
    def __init__(self, *, dwFlags: int = 0, wShowWindow: int = 0) -> None:  # noqa: N803
        self.dwFlags = dwFlags
        self.wShowWindow = wShowWindow


def test_windows_spawn_hides_the_child_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """A console child of the windowless GUI must get a hidden console of its own.

    Exercised with mocks; the Win32 calls themselves only run on Windows.
    """
    popen = MagicMock()
    monkeypatch.setattr(process_tree, "_create_job_object", lambda: 1)
    monkeypatch.setattr(process_tree, "_set_job_limits", lambda _handle: None)
    monkeypatch.setattr(process_tree, "_assign_process_to_job", lambda _h, _pid: None)
    monkeypatch.setattr(process_tree.subprocess, "Popen", popen)
    monkeypatch.setattr(
        process_tree.subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False
    )

    spawn_desktop_child(["child.exe"], platform_name="nt")

    kwargs = popen.call_args.kwargs
    create_new_console = 0x00000010
    create_new_process_group = 0x00000200
    create_breakaway_from_job = 0x01000000
    flags = kwargs["creationflags"]
    assert flags & create_new_console
    assert flags & create_new_process_group
    assert not flags & create_breakaway_from_job
    startupinfo = kwargs["startupinfo"]
    startf_useshowwindow = 0x00000001
    sw_hide = 0
    assert startupinfo.dwFlags & startf_useshowwindow
    assert startupinfo.wShowWindow == sw_hide
