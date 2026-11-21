"""Contract tests for real ServonautApp execution in the desktop host."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import ClientSession, WSMsgType

from servonaut.app import ServonautApp
from servonaut.desktop.driver import (
    DesktopDriverTransport,
    desktop_driver_class,
)
from servonaut.desktop.host import DesktopHost
from servonaut.desktop.model import SecretToken
from servonaut.runtime import detect_runtime
from tests._async_bounds import STEP_TIMEOUT_SECONDS, wait_until

# Booting a real ServonautApp under parallel test load needs more headroom than
# the default 5 s shutdown timeout; a healthy boot finishes well under this bound.
_BOOT_TIMEOUT_SECONDS = max(STEP_TIMEOUT_SECONDS, 15.0)


async def _receive_initial_frame(
    ws: aiohttp.ClientWebSocketResponse,
    *,
    min_bytes: int = 200,
    timeout: float = _BOOT_TIMEOUT_SECONDS,
) -> bytes:
    """Read WebSocket frames until more than ``min_bytes`` of binary output arrive."""
    chunks: list[bytes] = []
    total = 0

    async def _collect() -> bytes:
        nonlocal total
        while total <= min_bytes:
            msg = await ws.receive()
            if msg.type == WSMsgType.BINARY:
                chunks.append(msg.data)
                total += len(msg.data)
            elif msg.type in (
                WSMsgType.CLOSE,
                WSMsgType.CLOSING,
                WSMsgType.CLOSED,
                WSMsgType.ERROR,
            ):
                break
        return b"".join(chunks)

    return await asyncio.wait_for(_collect(), timeout=timeout)


@pytest.fixture
def isolated_config(tmp_path: Path) -> Path:
    config_file = tmp_path / "servonaut_config.json"
    config_file.write_text(json.dumps({"version": 4, "providers": {}}))
    return config_file


@pytest.fixture
def host_listener() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    return sock


def test_default_app_signs_in_as_the_desktop(host_listener: socket.socket) -> None:
    """The window's app names itself "desktop" to sign-in; a terminal app stays "tui"."""
    host = DesktopHost(token=SecretToken.generate(), listener=host_listener)

    app = host._default_app_factory(DesktopDriverTransport())

    assert isinstance(app, ServonautApp)
    assert app.client_kind == "desktop"
    assert ServonautApp().client_kind == "tui"


@pytest.mark.asyncio
async def test_real_servonaut_app_boot_and_initial_screen(
    host_listener: socket.socket, isolated_config: Path
) -> None:
    """Real ServonautApp must initialize, mount InstanceListScreen, and stream terminal output."""
    token = SecretToken.generate()
    runtime = detect_runtime()

    def real_app_factory(transport: DesktopDriverTransport) -> ServonautApp:
        return ServonautApp(
            runtime_layout=runtime,
            config_path=isolated_config,
            driver_class=desktop_driver_class(transport),
        )

    host = DesktopHost(
        token=token,
        listener=host_listener,
        app_factory=real_app_factory,
        shutdown_seconds=_BOOT_TIMEOUT_SECONDS,
    )
    try:
        origin = await host.start()
        port = host_listener.getsockname()[1]
        headers = {"Host": f"127.0.0.1:{port}", "Origin": origin}
        protocols = ["servonaut.desktop.v1", f"auth.{token.encoded_value()}"]

        async with ClientSession() as session:
            ws = await session.ws_connect(
                f"{origin}/ws?width=120&height=40",
                headers=headers,
                protocols=protocols,
            )

            all_output = await _receive_initial_frame(ws)
            assert len(all_output) > 200

            # Initial ANSI setup bytes can arrive before InstanceListScreen finishes mounting.
            await wait_until(
                lambda: isinstance(host._active_app, ServonautApp)
                and host._active_app.is_running
                and host._active_app.screen.__class__.__name__ == "InstanceListScreen",
                timeout=_BOOT_TIMEOUT_SECONDS,
            )
            app = host._active_app
            assert isinstance(app, ServonautApp)
            assert app.is_running
            assert app.screen.__class__.__name__ == "InstanceListScreen"

            # Quit cleanly via action_quit
            await app.action_quit()
            # Complete the client close handshake before waiting for the host.
            await ws.close()
            await asyncio.wait_for(host.finished.wait(), timeout=_BOOT_TIMEOUT_SECONDS)
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_real_servonaut_app_navigation_and_modal_flow(
    host_listener: socket.socket, isolated_config: Path
) -> None:
    """Real ServonautApp must handle modal navigation (HelpScreen) and dismissal via key input."""
    token = SecretToken.generate()
    runtime = detect_runtime()

    def real_app_factory(transport: DesktopDriverTransport) -> ServonautApp:
        return ServonautApp(
            runtime_layout=runtime,
            config_path=isolated_config,
            driver_class=desktop_driver_class(transport),
        )

    host = DesktopHost(
        token=token,
        listener=host_listener,
        app_factory=real_app_factory,
        shutdown_seconds=_BOOT_TIMEOUT_SECONDS,
    )
    try:
        origin = await host.start()
        port = host_listener.getsockname()[1]
        headers = {"Host": f"127.0.0.1:{port}", "Origin": origin}
        protocols = ["servonaut.desktop.v1", f"auth.{token.encoded_value()}"]

        async with ClientSession() as session:
            ws = await session.ws_connect(
                f"{origin}/ws?width=120&height=40",
                headers=headers,
                protocols=protocols,
            )

            await _receive_initial_frame(ws)
            await wait_until(
                lambda: isinstance(host._active_app, ServonautApp)
                and host._active_app.is_running
                and host._active_app.screen.__class__.__name__ == "InstanceListScreen"
                and host._active_app.screen.is_mounted,
                timeout=_BOOT_TIMEOUT_SECONDS,
            )
            app = host._active_app
            assert isinstance(app, ServonautApp)
            assert app.screen.__class__.__name__ == "InstanceListScreen"

            # Send '?' to open help modal
            await ws.send_str(json.dumps(["stdin", "?"]))
            await wait_until(
                lambda: app.screen.__class__.__name__ == "HelpScreen",
                timeout=_BOOT_TIMEOUT_SECONDS,
            )
            assert app.screen.__class__.__name__ == "HelpScreen"

            # Send 'q' to dismiss HelpScreen back to InstanceListScreen
            await ws.send_str(json.dumps(["stdin", "q"]))
            await wait_until(
                lambda: app.screen.__class__.__name__ == "InstanceListScreen",
                timeout=_BOOT_TIMEOUT_SECONDS,
            )
            assert app.screen.__class__.__name__ == "InstanceListScreen"

            # Close client connection and await host finish
            await ws.close()
            await asyncio.wait_for(host.finished.wait(), timeout=_BOOT_TIMEOUT_SECONDS)
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_real_servonaut_app_disconnect_drains_and_rejects_reconnect(
    host_listener: socket.socket, isolated_config: Path
) -> None:
    """Disconnecting client must stop app, set finished, and reject reconnects with 409."""
    token = SecretToken.generate()
    runtime = detect_runtime()

    def real_app_factory(transport: DesktopDriverTransport) -> ServonautApp:
        return ServonautApp(
            runtime_layout=runtime,
            config_path=isolated_config,
            driver_class=desktop_driver_class(transport),
        )

    host = DesktopHost(
        token=token,
        listener=host_listener,
        app_factory=real_app_factory,
        shutdown_seconds=_BOOT_TIMEOUT_SECONDS,
    )
    try:
        origin = await host.start()
        port = host_listener.getsockname()[1]
        headers = {"Host": f"127.0.0.1:{port}", "Origin": origin}
        protocols = ["servonaut.desktop.v1", f"auth.{token.encoded_value()}"]

        async with ClientSession() as session:
            ws = await session.ws_connect(
                f"{origin}/ws?width=120&height=40",
                headers=headers,
                protocols=protocols,
            )
            await wait_until(
                lambda: isinstance(host._active_app, ServonautApp)
                and host._active_app.is_running,
                timeout=_BOOT_TIMEOUT_SECONDS,
            )
            app = host._active_app
            assert isinstance(app, ServonautApp)
            assert app.is_running

            # Client disconnects
            await ws.close()
            await asyncio.wait_for(host.finished.wait(), timeout=_BOOT_TIMEOUT_SECONDS)

            # App should be stopped
            assert not app.is_running

            # Reconnect attempt must fail with 409 Conflict
            with pytest.raises(aiohttp.WSServerHandshakeError) as exc_info:
                await session.ws_connect(
                    f"{origin}/ws", headers=headers, protocols=protocols
                )
            assert exc_info.value.status == 409
    finally:
        await host.stop()
