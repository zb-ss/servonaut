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
    )
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

        # Receive rendered terminal escape sequences
        chunks = []
        for _ in range(20):
            msg = await ws.receive(timeout=3.0)
            if msg.type == WSMsgType.BINARY:
                chunks.append(msg.data)
                if len(b"".join(chunks)) > 200:
                    break

        all_output = b"".join(chunks)
        assert len(all_output) > 0

        # Assert real app is running with InstanceListScreen
        app = host._active_app
        assert isinstance(app, ServonautApp)
        assert app.is_running
        assert app.screen.__class__.__name__ == "InstanceListScreen"

        # Quit cleanly via action_quit
        await app.action_quit()
        await host.finished.wait()

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
    )
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

        # Drain initial frames
        await asyncio.sleep(0.3)
        app = host._active_app
        assert isinstance(app, ServonautApp)
        assert app.screen.__class__.__name__ == "InstanceListScreen"

        # Send '?' to open help modal
        await ws.send_str(json.dumps(["stdin", "?"]))
        for _ in range(30):
            if app.screen.__class__.__name__ == "HelpScreen":
                break
            await asyncio.sleep(0.05)
        assert app.screen.__class__.__name__ == "HelpScreen"

        # Send 'q' to dismiss HelpScreen back to InstanceListScreen
        await ws.send_str(json.dumps(["stdin", "q"]))
        for _ in range(30):
            if app.screen.__class__.__name__ == "InstanceListScreen":
                break
            await asyncio.sleep(0.05)
        assert app.screen.__class__.__name__ == "InstanceListScreen"

        # Close client connection and await host finish
        await ws.close()
        await asyncio.wait_for(host.finished.wait(), timeout=3.0)

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
    )
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
        await asyncio.sleep(0.2)
        app = host._active_app
        assert isinstance(app, ServonautApp)
        assert app.is_running

        # Client disconnects
        await ws.close()
        await asyncio.wait_for(host.finished.wait(), timeout=3.0)

        # App should be stopped
        assert not app.is_running

        # Reconnect attempt must fail with 409 Conflict
        with pytest.raises(aiohttp.WSServerHandshakeError) as exc_info:
            await session.ws_connect(
                f"{origin}/ws", headers=headers, protocols=protocols
            )
        assert exc_info.value.status == 409

    await host.stop()
