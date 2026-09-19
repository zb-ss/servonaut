"""Tests for DesktopHost authenticated loopback web server."""

from __future__ import annotations

import json
import socket

import pytest

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import ClientSession, WSMsgType
from textual.app import App
from textual.widgets import Label

from servonaut.desktop.driver import (
    DesktopDriverTransport,
    desktop_driver_class,
)
from servonaut.desktop.host import DesktopHost
from servonaut.desktop.model import SecretToken


class MiniTestApp(App[None]):
    def compose(self):
        yield Label("Host Test Terminal")


def dummy_app_factory(transport: DesktopDriverTransport) -> App[None]:
    return MiniTestApp(driver_class=desktop_driver_class(transport))


@pytest.fixture
def loopback_listener() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    return sock


@pytest.fixture
def secret_token() -> SecretToken:
    return SecretToken.generate()


@pytest.mark.asyncio
async def test_static_asset_routes_and_security_headers(
    loopback_listener: socket.socket, secret_token: SecretToken
) -> None:
    """Host must serve finite routes with strict security headers on all responses."""
    host = DesktopHost(
        token=secret_token,
        listener=loopback_listener,
        app_factory=dummy_app_factory,
    )
    origin = await host.start()
    port = loopback_listener.getsockname()[1]
    expected_host = f"127.0.0.1:{port}"

    expected_routes = [
        ("/", "text/html; charset=utf-8"),
        ("/index.html", "text/html; charset=utf-8"),
        ("/bootstrap.js", "text/javascript; charset=utf-8"),
        ("/style.css", "text/css; charset=utf-8"),
        ("/textual.js", "text/javascript; charset=utf-8"),
        ("/xterm.css", "text/css; charset=utf-8"),
        ("/mono.ttf", "font/ttf"),
        ("/licenses.json", "application/json; charset=utf-8"),
    ]

    async with ClientSession() as session:
        for path, content_type in expected_routes:
            url = f"{origin}{path}"
            async with session.get(url, headers={"Host": expected_host}) as resp:
                assert resp.status == 200
                assert resp.headers.get("Content-Type") == content_type
                assert "Content-Security-Policy" in resp.headers
                assert resp.headers.get("Cache-Control") == "no-store"
                assert resp.headers.get("X-Content-Type-Options") == "nosniff"
                assert resp.headers.get("Referrer-Policy") == "no-referrer"
                assert resp.headers.get("X-Frame-Options") == "DENY"

    await host.stop()


@pytest.mark.asyncio
async def test_query_string_on_asset_rejected(
    loopback_listener: socket.socket, secret_token: SecretToken
) -> None:
    """Query strings on static assets must be rejected with 400 Bad Request."""
    host = DesktopHost(
        token=secret_token,
        listener=loopback_listener,
        app_factory=dummy_app_factory,
    )
    origin = await host.start()
    port = loopback_listener.getsockname()[1]

    async with (
        ClientSession() as session,
        session.get(
            f"{origin}/bootstrap.js?foo=bar",
            headers={"Host": f"127.0.0.1:{port}"},
        ) as resp,
    ):
        assert resp.status == 400
        assert "Content-Security-Policy" in resp.headers
        assert resp.headers.get("Cache-Control") == "no-store"

    await host.stop()


@pytest.mark.asyncio
async def test_unlisted_path_and_unsupported_method(
    loopback_listener: socket.socket, secret_token: SecretToken
) -> None:
    """Unlisted routes must 404 and unsupported methods must 405."""
    host = DesktopHost(
        token=secret_token,
        listener=loopback_listener,
        app_factory=dummy_app_factory,
    )
    origin = await host.start()
    port = loopback_listener.getsockname()[1]
    host_header = {"Host": f"127.0.0.1:{port}"}

    async with ClientSession() as session:
        # 404 for unlisted route
        async with session.get(f"{origin}/not-found.html", headers=host_header) as resp:
            assert resp.status == 404
            assert "Content-Security-Policy" in resp.headers

        # 405 for POST
        async with session.post(
            f"{origin}/index.html", data=b"post", headers=host_header
        ) as resp:
            assert resp.status == 405
            assert "Content-Security-Policy" in resp.headers

    await host.stop()


@pytest.mark.asyncio
async def test_host_header_validation(
    loopback_listener: socket.socket, secret_token: SecretToken
) -> None:
    """Host header must strictly equal 127.0.0.1:<port>."""
    host = DesktopHost(
        token=secret_token,
        listener=loopback_listener,
        app_factory=dummy_app_factory,
    )
    origin = await host.start()
    port = loopback_listener.getsockname()[1]

    async with ClientSession() as session:
        # Wrong host: localhost instead of 127.0.0.1
        async with session.get(
            f"{origin}/index.html", headers={"Host": f"localhost:{port}"}
        ) as resp:
            assert resp.status == 403

        # Wrong host: evil.com
        async with session.get(
            f"{origin}/index.html", headers={"Host": "evil.com"}
        ) as resp:
            assert resp.status == 403

        # Wrong port
        async with session.get(
            f"{origin}/index.html", headers={"Host": f"127.0.0.1:{port + 1}"}
        ) as resp:
            assert resp.status == 403

    await host.stop()


@pytest.mark.asyncio
async def test_ws_origin_validation(
    loopback_listener: socket.socket, secret_token: SecretToken
) -> None:
    """WebSocket handshake must validate single Origin header matching host origin."""
    host = DesktopHost(
        token=secret_token,
        listener=loopback_listener,
        app_factory=dummy_app_factory,
    )
    origin = await host.start()
    port = loopback_listener.getsockname()[1]
    host_header = f"127.0.0.1:{port}"
    protocols = ["servonaut.desktop.v1", f"auth.{secret_token.encoded_value()}"]

    async with ClientSession() as session:
        # Missing Origin
        with pytest.raises(aiohttp.WSServerHandshakeError) as exc_info:
            await session.ws_connect(
                f"{origin}/ws",
                headers={"Host": host_header},
                protocols=protocols,
            )
        assert exc_info.value.status == 403

        # Wrong Origin: evil.com
        with pytest.raises(aiohttp.WSServerHandshakeError) as exc_info:
            await session.ws_connect(
                f"{origin}/ws",
                headers={"Host": host_header, "Origin": "http://evil.com"},
                protocols=protocols,
            )
        assert exc_info.value.status == 403

        # Wrong Origin: altered port
        with pytest.raises(aiohttp.WSServerHandshakeError) as exc_info:
            await session.ws_connect(
                f"{origin}/ws",
                headers={
                    "Host": host_header,
                    "Origin": f"http://127.0.0.1:{port + 1}",
                },
                protocols=protocols,
            )
        assert exc_info.value.status == 403

    await host.stop()


@pytest.mark.asyncio
async def test_ws_protocol_authentication_and_no_token_echo(
    loopback_listener: socket.socket, secret_token: SecretToken
) -> None:
    """WebSocket requires valid token and never echoes the secret token."""
    host = DesktopHost(
        token=secret_token,
        listener=loopback_listener,
        app_factory=dummy_app_factory,
    )
    origin = await host.start()
    port = loopback_listener.getsockname()[1]
    host_header = f"127.0.0.1:{port}"

    async with ClientSession() as session:
        # Invalid token
        with pytest.raises(aiohttp.WSServerHandshakeError) as exc_info:
            await session.ws_connect(
                f"{origin}/ws",
                headers={"Host": host_header, "Origin": origin},
                protocols=[
                    "servonaut.desktop.v1",
                    "auth.invalid_token_1234567890123456789012345678901",
                ],
            )
        assert exc_info.value.status == 403

        # Missing protocol
        with pytest.raises(aiohttp.WSServerHandshakeError) as exc_info:
            await session.ws_connect(
                f"{origin}/ws",
                headers={"Host": host_header, "Origin": origin},
            )
        assert exc_info.value.status == 403

        # Valid connection
        ws = await session.ws_connect(
            f"{origin}/ws",
            headers={"Host": host_header, "Origin": origin},
            protocols=["servonaut.desktop.v1", f"auth.{secret_token.encoded_value()}"],
        )

        # Selected subprotocol must only be servonaut.desktop.v1, NEVER the token!
        assert ws.protocol == "servonaut.desktop.v1"
        assert secret_token.encoded_value() not in (ws.protocol or "")

        await ws.close()

    await host.stop()


@pytest.mark.asyncio
async def test_single_session_latch_and_reconnect_rejection(
    loopback_listener: socket.socket, secret_token: SecretToken
) -> None:
    """Host permits only one session and rejects concurrent or reconnect attempts with 409."""
    host = DesktopHost(
        token=secret_token,
        listener=loopback_listener,
        app_factory=dummy_app_factory,
    )
    origin = await host.start()
    port = loopback_listener.getsockname()[1]
    headers = {"Host": f"127.0.0.1:{port}", "Origin": origin}
    protocols = ["servonaut.desktop.v1", f"auth.{secret_token.encoded_value()}"]

    async with ClientSession() as session:
        # First connection connects and is latched
        ws1 = await session.ws_connect(
            f"{origin}/ws", headers=headers, protocols=protocols
        )
        assert host.is_used

        # Concurrent second connection attempt must fail with 409 Conflict
        with pytest.raises(aiohttp.WSServerHandshakeError) as exc_info:
            await session.ws_connect(
                f"{origin}/ws", headers=headers, protocols=protocols
            )
        assert exc_info.value.status == 409

        # Close first session
        await ws1.close()

        # Reconnect attempt after disconnect must also fail with 409 Conflict
        with pytest.raises(aiohttp.WSServerHandshakeError) as exc_info:
            await session.ws_connect(
                f"{origin}/ws", headers=headers, protocols=protocols
            )
        assert exc_info.value.status == 409

    await host.stop()


@pytest.mark.asyncio
async def test_ws_message_bridge_and_rejection(
    loopback_listener: socket.socket, secret_token: SecretToken
) -> None:
    """WebSocket dispatches valid messages and rejects malformed messages."""
    host = DesktopHost(
        token=secret_token,
        listener=loopback_listener,
        app_factory=dummy_app_factory,
    )
    origin = await host.start()
    port = loopback_listener.getsockname()[1]
    headers = {"Host": f"127.0.0.1:{port}", "Origin": origin}
    protocols = ["servonaut.desktop.v1", f"auth.{secret_token.encoded_value()}"]

    async with ClientSession() as session:
        ws = await session.ws_connect(
            f"{origin}/ws", headers=headers, protocols=protocols
        )

        # Receive initial binary data packet
        msg = await ws.receive()
        assert msg.type == WSMsgType.BINARY
        assert len(msg.data) > 0

        # Send ping, expect pong (skipping any concurrent binary data frames)
        await ws.send_str(json.dumps(["ping", "12345"]))
        reply = None
        for _ in range(50):
            m = await ws.receive()
            if m.type == WSMsgType.TEXT:
                reply = json.loads(m.data)
                break
        assert reply == ["pong", "12345"]

        # Send valid resize, focus, blur
        await ws.send_str(json.dumps(["resize", {"width": 100, "height": 30}]))
        await ws.send_str(json.dumps(["focus"]))
        await ws.send_str(json.dumps(["blur"]))

        # Send malformed envelope -> should trigger close code 1008
        await ws.send_str(json.dumps(["unsupported_kind"]))
        close_msg = None
        for _ in range(50):
            m = await ws.receive()
            if m.type in (WSMsgType.CLOSE, WSMsgType.CLOSED):
                close_msg = m
                break
        assert close_msg is not None
        assert ws.close_code == 1008

    await host.stop()
