"""Authenticated, single-use loopback host for packaged desktop frontend assets.

Runs an aiohttp web server on an inherited pre-bound loopback socket. Serves
finite static routes and an authenticated /ws endpoint connected to the
in-memory Textual application driver.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import socket
from collections.abc import Callable
from typing import Any, Final

import aiohttp
from aiohttp import WSMsgType, web
from textual.app import App

from servonaut.desktop.assets import build_csp_header, load_and_verify_assets
from servonaut.desktop.driver import (
    MAX_PACKET_BYTES,
    DesktopDriverBackpressureError,
    DesktopDriverTransport,
    desktop_driver_class,
)
from servonaut.desktop.model import SecretToken, _validate_origin
from servonaut.runtime import RuntimeLayout, detect_runtime

logger = logging.getLogger(__name__)

MAX_COLUMNS: Final[int] = 500
MAX_ROWS: Final[int] = 200
DEFAULT_COLUMNS: Final[int] = 80
DEFAULT_ROWS: Final[int] = 24
# A frame over this limit closes the socket and ends the session, so it
# matches the largest input the driver accepts (a big paste arrives as one
# frame).
MAX_MESSAGE_BYTES: Final[int] = MAX_PACKET_BYTES
SHUTDOWN_TIMEOUT_SECONDS: Final[float] = 5.0
PROTOCOL_SUBPROTOCOL: Final[str] = "servonaut.desktop.v1"


class DesktopHostError(RuntimeError):
    """Base error for desktop host failures."""


class DesktopHost:
    """Authenticated single-session loopback HTTP/WebSocket server."""

    def __init__(
        self,
        token: SecretToken,
        listener: socket.socket,
        *,
        origin: str | None = None,
        assets: dict[str, tuple[bytes, str]] | None = None,
        runtime_layout: RuntimeLayout | None = None,
        app_factory: Callable[[DesktopDriverTransport], App[Any]] | None = None,
        max_columns: int = MAX_COLUMNS,
        max_rows: int = MAX_ROWS,
        max_message_bytes: int = MAX_MESSAGE_BYTES,
        shutdown_seconds: float = SHUTDOWN_TIMEOUT_SECONDS,
    ) -> None:
        self.token = token
        self.listener = listener
        self.max_columns = max_columns
        self.max_rows = max_rows
        self.max_message_bytes = max_message_bytes
        self.shutdown_seconds = shutdown_seconds
        self.runtime_layout = runtime_layout or detect_runtime()
        self.app_factory = app_factory or self._default_app_factory

        # Derive port and origin from inherited listener socket
        port = self.listener.getsockname()[1]
        expected_origin = f"http://127.0.0.1:{port}"
        if origin is not None:
            _validate_origin(origin)
            if origin != expected_origin:
                raise DesktopHostError(
                    f"Provided origin {origin} does not match listener port {expected_origin}"
                )
        self.origin = expected_origin
        self.expected_host = f"127.0.0.1:{port}"

        # CSP and response security headers
        self.csp_header = build_csp_header(self.origin)

        # Assets mapping: route -> (content_bytes, content_type)
        if assets is not None:
            self.assets = assets
        else:
            loaded_assets, _ = load_and_verify_assets(
                repo_root=self.runtime_layout.resource_root
            )
            self.assets = loaded_assets

        self.finished = asyncio.Event()
        self._used = False
        self._runner: web.AppRunner | None = None
        self._site: web.SockSite | None = None
        self._active_websocket: web.WebSocketResponse | None = None
        self._active_app: App[Any] | None = None
        self._active_transport: DesktopDriverTransport | None = None

    @property
    def is_used(self) -> bool:
        """Whether the single allowed WebSocket session has been latched."""
        return self._used

    def _default_app_factory(self, transport: DesktopDriverTransport) -> App[Any]:
        """Construct real ServonautApp with the bounded desktop driver."""
        from servonaut.app import ServonautApp

        driver_cls = desktop_driver_class(transport)
        return ServonautApp(
            runtime_layout=self.runtime_layout,
            driver_class=driver_cls,
        )

    async def start(self) -> str:
        """Start the web server on the inherited listener socket."""
        app = web.Application()

        # Add security headers to all responses (including errors)
        app.on_response_prepare.append(self._add_security_headers)

        # Register finite routes
        app.router.add_get("/ws", self._handle_ws)
        for route in sorted(self.assets.keys()):
            app.router.add_get(route, self._handle_asset)

        # Catch-all route for any unlisted path to return 404 with security headers
        app.router.add_route("*", "/{tail:.*}", self._handle_unlisted)

        self._runner = web.AppRunner(
            app,
            access_log=None,  # Never log tokens or endpoints
            shutdown_timeout=self.shutdown_seconds,
        )
        await self._runner.setup()

        self.listener.setblocking(False)
        self._site = web.SockSite(self._runner, self.listener)
        await self._site.start()

        return self.origin

    async def stop(self) -> None:
        """Gracefully stop the host server and release resources."""
        if self._active_websocket and not self._active_websocket.closed:
            with contextlib.suppress(Exception):
                await self._active_websocket.close()
        if self._active_transport:
            self._active_transport.close()
        if self._runner is not None:
            with contextlib.suppress(Exception):
                await self._runner.cleanup()
        with contextlib.suppress(Exception):
            self.listener.close()
        self.finished.set()

    async def _add_security_headers(
        self, request: web.Request, response: web.StreamResponse
    ) -> None:
        """Enforce strict security and isolation headers on all responses."""
        response.headers["Content-Security-Policy"] = self.csp_header
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"

    def _validate_host_header(self, request: web.Request) -> None:
        """Validate raw Host header matches exact 127.0.0.1:<port>."""
        hosts = request.headers.getall("Host", [])
        if len(hosts) != 1 or hosts[0] != self.expected_host:
            raise web.HTTPForbidden()

    async def _handle_unlisted(self, request: web.Request) -> web.Response:
        self._validate_host_header(request)
        if request.method != "GET":
            raise web.HTTPMethodNotAllowed(
                method=request.method, allowed_methods=["GET"]
            )
        raise web.HTTPNotFound()

    async def _handle_asset(self, request: web.Request) -> web.Response:
        """Serve finite packaged static assets."""
        self._validate_host_header(request)

        # Reject any query string on static asset routes
        if request.query_string:
            raise web.HTTPBadRequest()

        if request.path not in self.assets:
            raise web.HTTPNotFound()

        data, raw_ct = self.assets[request.path]
        ct = raw_ct
        cs = None
        if "; charset=" in raw_ct:
            ct, _, cs = raw_ct.partition("; charset=")
        return web.Response(body=data, content_type=ct, charset=cs)

    async def _handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        """Authenticate and establish single-use WebSocket connection."""
        self._authenticate_ws_request(request)
        width, height = self._initial_size(request)

        ws = web.WebSocketResponse(
            protocols=(PROTOCOL_SUBPROTOCOL,),
            max_msg_size=self.max_message_bytes,
            timeout=self.shutdown_seconds,
            compress=False,
        )
        if not ws.can_prepare(request).ok:
            raise web.HTTPBadRequest()

        # Sole session latch: set before the first await, and only once every
        # check that can refuse the request has passed.
        if self._used:
            raise web.HTTPConflict()
        self._used = True

        # The latched session is the only one this host will ever serve, so
        # however it ends, the host is finished.
        try:
            await ws.prepare(request)
            self._active_websocket = ws
            await self._run_session(ws, width, height)
        finally:
            self.finished.set()

        return ws

    def _authenticate_ws_request(self, request: web.Request) -> None:
        """Reject any upgrade that is not from the assigned origin with the token."""
        self._validate_host_header(request)

        # Origin header must occur exactly once and match assigned origin
        origins = request.headers.getall("Origin", [])
        if origins != [self.origin]:
            raise web.HTTPForbidden()

        raw_protocols = request.headers.get("Sec-WebSocket-Protocol", "")
        if not self._offers_session_subprotocols(raw_protocols):
            raise web.HTTPForbidden()

    def _offers_session_subprotocols(self, raw_protocols: str) -> bool:
        """Match ["servonaut.desktop.v1", "auth.<token>"] in constant time."""
        protocols = [p.strip() for p in raw_protocols.split(",") if p.strip()]
        offered = ",".join(protocols)
        # Header values can carry any character; the expected value is ASCII.
        if len(protocols) != 2 or not offered.isascii():
            return False
        expected = f"{PROTOCOL_SUBPROTOCOL},auth.{self.token.encoded_value()}"
        return hmac.compare_digest(offered.encode("ascii"), expected.encode("ascii"))

    def _initial_size(self, request: web.Request) -> tuple[int, int]:
        """Parse the terminal size the page requested, clamped to the host bounds."""
        query = request.query
        try:
            width = int(query.get("width", str(DEFAULT_COLUMNS)))
            height = int(query.get("height", str(DEFAULT_ROWS)))
        except ValueError:
            raise web.HTTPBadRequest() from None
        return self._clamp_size(width, height)

    def _clamp_size(self, width: int, height: int) -> tuple[int, int]:
        """Bound a terminal size; a large window must not end the session."""
        return (
            min(max(width, 1), self.max_columns),
            min(max(height, 1), self.max_rows),
        )

    async def _run_session(
        self, ws: web.WebSocketResponse, width: int, height: int
    ) -> None:
        """Run the app for the prepared WebSocket until either side ends."""
        transport = DesktopDriverTransport()
        self._active_transport = transport
        app: App[Any] | None = None
        app_task: asyncio.Task[None] | None = None
        try:
            app = self.app_factory(transport)
            self._active_app = app
            app_task = asyncio.create_task(app.run_async(size=(width, height)))
            # Wait for Textual app to complete startup mode
            await asyncio.wait_for(
                transport.ready_event.wait(), timeout=self.shutdown_seconds
            )
            await self._run_bridge(ws, transport, app, app_task)
        except (TimeoutError, asyncio.TimeoutError):
            logger.error("Desktop app did not start within %ss", self.shutdown_seconds)
            await ws.close(code=1011, message=b"App startup timed out")
        except (OSError, RuntimeError, DesktopDriverBackpressureError):
            logger.exception("Desktop session failed")
            await ws.close(code=1011, message=b"Transport failure")
        finally:
            if app is not None and app_task is not None:
                await self._stop_app(app, app_task)
            transport.close()
            await ws.close()

    async def _stop_app(self, app: App[Any], app_task: asyncio.Task[None]) -> None:
        """Drain and stop the app."""
        if app.is_running:
            with contextlib.suppress(Exception):
                await app.action_quit()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(app_task, timeout=2.0)

    async def _run_bridge(
        self,
        ws: web.WebSocketResponse,
        transport: DesktopDriverTransport,
        app: App[Any],
        app_task: asyncio.Task[None],
    ) -> None:
        """Bridge bidirectional traffic between browser WebSocket and Textual driver."""
        forward_task = asyncio.create_task(self._forward_output(ws, transport))
        receive_task = asyncio.create_task(self._receive_messages(ws, transport, app))

        done, pending = await asyncio.wait(
            [forward_task, receive_task, app_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.gather(*pending, return_exceptions=True)

        # Retrieve every outcome so none is reported as never retrieved.
        errors = [task.exception() for task in done if not task.cancelled()]
        first_error = next((error for error in errors if error is not None), None)
        if first_error is not None:
            raise first_error

    async def _forward_output(
        self, ws: web.WebSocketResponse, transport: DesktopDriverTransport
    ) -> None:
        """Forward rendered terminal output packets from driver to WebSocket."""
        while not ws.closed:
            packet = await transport.output_queue.get()
            if packet is None:
                break
            if packet[:1] == b"D":
                length = int.from_bytes(packet[1:5], "big")
                payload = packet[5 : 5 + length]
                try:
                    await ws.send_bytes(payload)
                except (
                    ConnectionResetError,
                    aiohttp.ClientConnectionResetError,
                    OSError,
                ):
                    break
            elif packet[:1] == b"M":
                length = int.from_bytes(packet[1:5], "big")
                payload = packet[5 : 5 + length]
                try:
                    meta = json.loads(payload)
                    if meta.get("type") == "exit":
                        break
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

    async def _receive_messages(
        self,
        ws: web.WebSocketResponse,
        transport: DesktopDriverTransport,
        app: App[Any],
    ) -> None:
        """Process browser WebSocket frames and dispatch to driver."""
        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                await ws.close(code=1008, message=b"Text frames required")
                return

            try:
                envelope = json.loads(msg.data)
                if not isinstance(envelope, list) or not envelope:
                    raise ValueError("Invalid envelope")

                kind = envelope[0]
                if (
                    kind == "stdin"
                    and len(envelope) == 2
                    and isinstance(envelope[1], str)
                ):
                    transport.feed_stdin(envelope[1])
                elif (
                    kind == "resize"
                    and len(envelope) == 2
                    and isinstance(envelope[1], dict)
                ):
                    dims = envelope[1]
                    transport.feed_resize(
                        *self._clamp_size(int(dims["width"]), int(dims["height"]))
                    )
                elif kind == "focus" and len(envelope) == 1:
                    transport.feed_focus()
                elif kind == "blur" and len(envelope) == 1:
                    transport.feed_blur()
                elif (
                    kind == "ping"
                    and len(envelope) == 2
                    and isinstance(envelope[1], str)
                ):
                    await ws.send_json(["pong", envelope[1]])
                else:
                    raise ValueError("Unsupported message")
            except (ValueError, TypeError, KeyError, OverflowError):
                await ws.close(code=1008, message=b"Invalid message")
                return
