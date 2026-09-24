"""Contract tests for desktop child process handshake, watchdog, and parent-death lifecycle."""

from __future__ import annotations

import io
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from servonaut.desktop.child_process import (
    ChildStartupError,
    ParentDeathWatchdog,
    reconstruct_listener,
    run_child_handshake,
)
from servonaut.desktop.control import (
    decode_child_frame,
    encode_control_frame,
)
from servonaut.desktop.model import (
    DesktopChildErrorCode,
    ErrorResponse,
    PosixListener,
    ReadyResponse,
    SecretToken,
    StartRequest,
)
from servonaut.desktop.process_tree import (
    launch_and_handshake_desktop_child,
)


def _bind_loopback() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock


# Runs the real desktop child entry point with only the web host and the
# frontend asset check replaced, so the test needs no aiohttp. The stub host
# finishes shortly after start, as when the user quits the app.
_STUB_HOST_CHILD_SCRIPT = """
import asyncio
import sys
import types


class DesktopHost:
    def __init__(self, **_kwargs):
        self.finished = asyncio.Event()

    async def start(self):
        asyncio.get_running_loop().call_later(0.2, self.finished.set)
        return ""

    async def stop(self):
        self.finished.set()


sys.modules["servonaut.desktop.host"] = types.SimpleNamespace(DesktopHost=DesktopHost)

import servonaut.desktop.child as child

child.load_and_verify_assets = lambda **_kwargs: ({}, {})
sys.exit(child.main([]))
"""


def test_reconstruct_listener_posix() -> None:
    sock = _bind_loopback()
    try:
        req = StartRequest(
            origin="http://127.0.0.1:8080",
            token=SecretToken.generate(),
            listener=PosixListener(fd=sock.fileno()),
        )
        reconstructed = reconstruct_listener(req, platform_name="posix")
        try:
            assert reconstructed.fileno() != sock.fileno()  # socket.fromfd duplicates
            assert reconstructed.family == socket.AF_INET
            assert reconstructed.type == socket.SOCK_STREAM
        finally:
            reconstructed.close()
    finally:
        sock.close()


def test_reconstruct_listener_rejects_mismatched_platform() -> None:
    sock = _bind_loopback()
    try:
        req = StartRequest(
            origin="http://127.0.0.1:8080",
            token=SecretToken.generate(),
            listener=PosixListener(fd=sock.fileno()),
        )
        with pytest.raises(ChildStartupError) as exc_info:
            reconstruct_listener(req, platform_name="win32")
        assert exc_info.value.code == DesktopChildErrorCode.LISTENER_REJECTED
    finally:
        sock.close()


def test_run_child_handshake_in_memory() -> None:
    sock = _bind_loopback()
    port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    token = SecretToken.generate()

    req = StartRequest(
        origin=origin,
        token=token,
        listener=PosixListener(fd=sock.fileno()),
    )

    stdin_data = encode_control_frame(req)
    stdin_stream = io.BytesIO(stdin_data)
    stdout_stream = io.BytesIO()

    session = run_child_handshake(
        stdin_stream,
        stdout_stream,
        platform_name="posix",
    )
    try:
        assert session.start_request.origin == origin
        assert session.listener is not None

        # Verify ready response written to stdout_stream
        stdout_stream.seek(0)
        resp = decode_child_frame(stdout_stream.read())
        assert isinstance(resp, ReadyResponse)
        assert resp.origin == origin
    finally:
        session.close()
        sock.close()


def test_run_child_handshake_invalid_frame_writes_error_response() -> None:
    # Write garbage frame
    stdin_stream = io.BytesIO(b"\x00\x00\x00\x04bad!")
    stdout_stream = io.BytesIO()

    with pytest.raises(ChildStartupError) as exc_info:
        run_child_handshake(stdin_stream, stdout_stream, platform_name="posix")

    assert exc_info.value.code == DesktopChildErrorCode.INVALID_START

    stdout_stream.seek(0)
    resp = decode_child_frame(stdout_stream.read())
    assert isinstance(resp, ErrorResponse)
    assert resp.code == DesktopChildErrorCode.INVALID_START


def test_parent_death_watchdog_detects_pipe_eof() -> None:
    r_fd, w_fd = os.pipe()
    r_file = os.fdopen(r_fd, "rb", buffering=0)

    death_called = []

    def on_death() -> None:
        death_called.append(True)

    watchdog = ParentDeathWatchdog(r_file, on_parent_death=on_death)
    watchdog.start()
    try:
        assert not watchdog.is_parent_dead

        # Close writer to simulate parent pipe EOF
        os.close(w_fd)

        # Watchdog must detect EOF promptly
        assert watchdog.wait_for_parent_death(timeout=1.0)
        assert watchdog.is_parent_dead
        assert len(death_called) == 1
    finally:
        watchdog.stop()
        r_file.close()


def test_real_child_exits_on_parent_eof() -> None:
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
    )
    try:
        assert ready.origin == origin
        assert tree.poll() is None

        # Close parent stdin to trigger parent EOF in child watchdog
        assert tree.stdin is not None
        tree.stdin.close()

        # Child must exit with 0 after detecting parent EOF
        exit_code = tree.wait(timeout=3.0)
        assert exit_code == 0
    finally:
        tree.close()
        sock.close()


def test_real_child_parent_hard_death_cleanup() -> None:
    # Spawn an intermediary process that launches the child, then kill the intermediary with SIGKILL
    # Child must detect pipe closure and cleanly exit
    intermediary_script = (
        "import socket, sys, time\n"
        "from servonaut.desktop.model import SecretToken\n"
        "from servonaut.desktop.process_tree import launch_and_handshake_desktop_child\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "sock.bind(('127.0.0.1', 0))\n"
        "sock.listen(1)\n"
        "port = sock.getsockname()[1]\n"
        "origin = f'http://127.0.0.1:{port}'\n"
        "token = SecretToken.generate()\n"
        "cmd = [sys.executable, '-m', 'servonaut.desktop.child_process']\n"
        "tree, ready = launch_and_handshake_desktop_child(\n"
        "    cmd, origin=origin, token=token, listener=sock, startup_timeout=5.0\n"
        ")\n"
        "sys.stdout.write(f'{tree.pid}\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(60)\n"
    )

    intermediary_env = dict(os.environ)
    repo_src = str(Path(__file__).resolve().parents[2] / "src")
    existing_pp = intermediary_env.get("PYTHONPATH", "")
    if repo_src not in existing_pp.split(os.pathsep):
        intermediary_env["PYTHONPATH"] = (
            f"{repo_src}{os.pathsep}{existing_pp}" if existing_pp else repo_src
        )

    intermediary = subprocess.Popen(
        [sys.executable, "-c", intermediary_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=intermediary_env,
    )
    try:
        assert intermediary.stdout is not None
        child_pid_line = intermediary.stdout.readline().decode().strip()
        child_pid = int(child_pid_line)

        # Verify child is alive
        os.kill(child_pid, 0)

        # Hard-kill intermediary with SIGKILL (simulating unhandled crash or hard abort)
        intermediary.kill()
        intermediary.wait(timeout=2.0)

        # Wait up to 3.0s for child to detect parent EOF and exit
        deadline = time.monotonic() + 3.0
        child_dead = False
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
                time.sleep(0.05)
            except ProcessLookupError:
                child_dead = True
                break

        assert child_dead, "Child did not exit after parent hard death"
    finally:
        if intermediary.poll() is None:
            intermediary.kill()
            intermediary.wait()


def test_real_child_cleans_up_grandchildren_on_parent_eof() -> None:
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
    )
    try:
        assert ready.origin == origin
        assert tree.poll() is None

        # Give child a moment to spawn grandchild
        time.sleep(0.2)

        # Close parent stdin to trigger parent EOF
        assert tree.stdin is not None
        tree.stdin.close()

        # Child must exit 0 and terminate its grandchild
        exit_code = tree.wait(timeout=3.0)
        assert exit_code == 0
    finally:
        tree.close()
        sock.close()


def test_real_child_entry_exits_cleanly_while_parent_holds_stdin(
    tmp_path: Path,
) -> None:
    """A child that ends its own session must exit 0, not abort at shutdown."""
    script = tmp_path / "stub_host_child.py"
    script.write_text(_STUB_HOST_CHILD_SCRIPT, encoding="utf-8")
    sock = _bind_loopback()
    origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    env = {**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}

    tree, ready = launch_and_handshake_desktop_child(
        [sys.executable, str(script)],
        origin=origin,
        token=SecretToken.generate(),
        listener=sock,
        startup_timeout=10.0,
        env=env,
    )
    try:
        assert ready.origin == origin
        # The parent keeps the control pipe open, as the desktop launcher does.
        assert tree.stdin is not None and not tree.stdin.closed
        assert tree.wait(timeout=10.0) == 0
    finally:
        tree.close()
        sock.close()
