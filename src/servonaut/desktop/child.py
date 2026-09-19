"""Private desktop child process runner.

Accepts inherited listener socket and control frame from parent, verifies
packaged frontend asset integrity before signalling readiness, hosts the
aiohttp server and real ServonautApp, and monitors the parent control pipe.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import socket
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO

from servonaut.desktop.assets import DesktopAssetError, load_and_verify_assets
from servonaut.desktop.child_process import (
    ChildStartupError,
    ParentDeathWatchdog,
    reconstruct_listener,
)
from servonaut.desktop.control import (
    ChildStartGate,
    DesktopControlError,
    encode_control_frame,
    read_parent_frame,
)
from servonaut.desktop.host import DesktopHost
from servonaut.desktop.model import (
    DesktopChildErrorCode,
    ErrorResponse,
    ReadyResponse,
    StartRequest,
)
from servonaut.runtime import RuntimeLayout, detect_runtime


async def run_desktop_child(
    start_request: StartRequest,
    runtime: RuntimeLayout,
    *,
    listener: socket.socket | None = None,
    stdout_stream: BinaryIO | None = None,
    stdin_stream: BinaryIO | None = None,
    platform_name: str | None = None,
    frontend_dir: Path | None = None,
) -> int:
    """Run the authenticated desktop host and real app within the child process."""
    out = stdout_stream or sys.stdout.buffer
    in_stream = stdin_stream or sys.stdin.buffer

    # Reconstruct listener socket if not provided
    sock = listener
    if sock is None:
        try:
            sock = reconstruct_listener(start_request, platform_name=platform_name)
        except ChildStartupError as err:
            with contextlib.suppress(Exception):
                out.write(encode_control_frame(ErrorResponse(code=err.code)))
                out.flush()
            return 1

    # Verify packaged frontend asset manifest before reporting readiness
    try:
        assets_map, _ = load_and_verify_assets(
            frontend_dir=frontend_dir,
            repo_root=runtime.resource_root,
        )
    except (DesktopAssetError, OSError, ValueError, KeyError):
        with contextlib.suppress(OSError):
            out.write(
                encode_control_frame(
                    ErrorResponse(code=DesktopChildErrorCode.STARTUP_FAILED)
                )
            )
            out.flush()
        with contextlib.suppress(OSError):
            sock.close()
        return 1

    # Initialize authenticated loopback host
    host = DesktopHost(
        token=start_request.token,
        listener=sock,
        origin=start_request.origin,
        assets=assets_map,
        runtime_layout=runtime,
    )

    try:
        await host.start()
    except OSError:
        with contextlib.suppress(OSError):
            out.write(
                encode_control_frame(
                    ErrorResponse(code=DesktopChildErrorCode.STARTUP_FAILED)
                )
            )
            out.flush()
        await host.stop()
        return 1

    # Emit ReadyResponse to parent
    ready = ReadyResponse(origin=start_request.origin)
    try:
        out.write(encode_control_frame(ready))
        out.flush()
    except OSError:
        await host.stop()
        return 1

    # Start watchdog to monitor parent control stream for unexpected termination
    loop = asyncio.get_running_loop()

    def on_parent_death() -> None:
        if not loop.is_closed():
            loop.call_soon_threadsafe(lambda: asyncio.create_task(host.stop()))

    watchdog = ParentDeathWatchdog(in_stream, on_parent_death=on_parent_death)
    watchdog.start()

    try:
        await host.finished.wait()
    finally:
        watchdog.stop()
        await host.stop()

    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin_stream: BinaryIO | None = None,
    stdout_stream: BinaryIO | None = None,
    runtime_layout: RuntimeLayout | None = None,
    platform_name: str | None = None,
) -> int:
    """CLI entry point for the private desktop child."""
    parser = argparse.ArgumentParser(
        prog="servonaut-desktop-child",
        description="Private desktop host child process (internal use only).",
    )
    parser.parse_args(argv)

    in_stream = stdin_stream or sys.stdin.buffer
    out_stream = stdout_stream or sys.stdout.buffer
    runtime = runtime_layout or detect_runtime()
    gate = ChildStartGate()

    # Read and validate startup frame
    try:
        target_platform = platform_name or (
            "nt" if sys.platform == "win32" else "posix"
        )
        msg = read_parent_frame(in_stream, platform_name=target_platform)
        start_request = gate.accept(msg, target_platform)
    except DesktopControlError:
        with contextlib.suppress(OSError):
            out_stream.write(
                encode_control_frame(
                    ErrorResponse(code=DesktopChildErrorCode.INVALID_START)
                )
            )
            out_stream.flush()
        return 1

    return asyncio.run(
        run_desktop_child(
            start_request,
            runtime,
            stdout_stream=out_stream,
            stdin_stream=in_stream,
            platform_name=target_platform,
        )
    )


if __name__ == "__main__":
    sys.exit(main())
