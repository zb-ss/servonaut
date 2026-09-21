"""Tests for the desktop child runner and startup sequence."""

from __future__ import annotations

import asyncio
import io
import json
import os
import socket
from pathlib import Path

import pytest

pytest.importorskip("aiohttp")

from servonaut.desktop.child import main, run_desktop_child
from servonaut.desktop.control import (
    ParentStartupGate,
    read_child_frame,
)
from servonaut.desktop.model import (
    DesktopChildErrorCode,
    ErrorResponse,
    PosixListener,
    ReadyResponse,
    SecretToken,
    StartRequest,
)
from servonaut.runtime import detect_runtime


@pytest.fixture
def test_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    return sock


@pytest.mark.asyncio
async def test_child_successful_startup_and_ready_frame(
    test_socket: socket.socket,
) -> None:
    """Child must verify assets, start host, and emit ReadyResponse to stdout."""
    port = test_socket.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    token = SecretToken.generate()

    start_request = StartRequest(
        origin=origin,
        token=token,
        listener=PosixListener(fd=test_socket.fileno()),
    )
    runtime = detect_runtime()

    stdout_reader, stdout_writer = os.pipe()
    stdin_reader, stdin_writer = os.pipe()

    stdout_r = os.fdopen(stdout_reader, "rb", buffering=0)
    stdout_w = os.fdopen(stdout_writer, "wb", buffering=0)
    stdin_r = os.fdopen(stdin_reader, "rb", buffering=0)
    stdin_w = os.fdopen(stdin_writer, "wb", buffering=0)

    # Launch child task
    child_task = asyncio.create_task(
        run_desktop_child(
            start_request,
            runtime,
            listener=test_socket,
            stdout_stream=stdout_w,
            stdin_stream=stdin_r,
            platform_name="posix",
        )
    )

    # Parent reads ready frame asynchronously
    loop = asyncio.get_running_loop()
    resp = await loop.run_in_executor(None, read_child_frame, stdout_r)
    assert isinstance(resp, ReadyResponse)
    assert resp.origin == origin

    gate = ParentStartupGate(expected_origin=origin)
    accepted = gate.accept(resp)
    assert isinstance(accepted, ReadyResponse)

    # Simulate parent termination / close pipe to trigger watchdog exit
    stdin_w.close()
    await asyncio.wait_for(child_task, timeout=3.0)

    stdout_r.close()
    stdout_w.close()
    stdin_r.close()


@pytest.mark.asyncio
async def test_child_tampered_asset_fails_startup(
    test_socket: socket.socket, tmp_path: Path
) -> None:
    """Tampered asset must cause child to emit ErrorResponse(STARTUP_FAILED)."""
    port = test_socket.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    token = SecretToken.generate()

    # Create tampered frontend directory
    bad_frontend = tmp_path / "frontend"
    bad_frontend.mkdir()
    (bad_frontend / "assets.lock.json").write_text(
        json.dumps({"schema_version": 1, "assets": {}})
    )

    start_request = StartRequest(
        origin=origin,
        token=token,
        listener=PosixListener(fd=test_socket.fileno()),
    )
    runtime = detect_runtime()

    stdout_reader, stdout_writer = os.pipe()
    stdout_r = os.fdopen(stdout_reader, "rb", buffering=0)
    stdout_w = os.fdopen(stdout_writer, "wb", buffering=0)

    exit_code = await run_desktop_child(
        start_request,
        runtime,
        listener=test_socket,
        stdout_stream=stdout_w,
        stdin_stream=io.BytesIO(),
        frontend_dir=bad_frontend,
    )
    assert exit_code == 1

    resp = read_child_frame(stdout_r)
    assert isinstance(resp, ErrorResponse)
    assert resp.code == DesktopChildErrorCode.STARTUP_FAILED

    stdout_r.close()
    stdout_w.close()


def test_child_main_invalid_frame_returns_error() -> None:
    """main() must reject invalid start frames with INVALID_START."""
    stdin_stream = io.BytesIO(b"\x00\x00\x00\x05junk!")
    stdout_stream = io.BytesIO()

    code = main(
        argv=[],
        stdin_stream=stdin_stream,
        stdout_stream=stdout_stream,
        platform_name="posix",
    )
    assert code == 1

    stdout_stream.seek(0)
    resp = read_child_frame(stdout_stream)
    assert isinstance(resp, ErrorResponse)
    assert resp.code == DesktopChildErrorCode.INVALID_START
