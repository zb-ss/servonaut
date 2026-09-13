"""Single-use authenticated loopback host for packaged Textual assets."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import socket
import sys
from collections.abc import Mapping, Sequence
from importlib import metadata, resources
from pathlib import Path

from aiohttp import WSMsgType, web

from .config import ProbeConfig, load_config
from .process import TextualChild


class ProbeHost:
    def __init__(self, command: Sequence[str] | None = None) -> None:
        self.config = load_config()
        self._token = secrets.token_urlsafe(32)
        self._used = False
        self.origin = ""
        self.finished = asyncio.Event()
        self.child = TextualChild(
            command or (sys.executable, "-m", "scripts.desktop_probe.child"),
            self.config,
        )
        self._runner: web.AppRunner | None = None
        self._socket: socket.socket | None = None
        self._websocket: web.WebSocketResponse | None = None
        self._assets = self._load_assets()

    def _load_assets(self) -> dict[str, tuple[bytes, str]]:
        if metadata.version("textual-serve") != self.config.textual_serve_version:
            raise RuntimeError("Install the probe's pinned renderer dependencies")
        upstream = resources.files("textual_serve").joinpath("static")
        renderer = upstream.joinpath("js/textual.js").read_bytes()
        if hashlib.sha256(renderer).hexdigest() != self.config.renderer_sha256:
            raise RuntimeError("Packaged renderer checksum mismatch")
        root = Path(__file__).parent
        return {
            "/": (
                (root / "index.html")
                .read_bytes()
                .replace(b"FONT_SIZE", str(self.config.font_size).encode()),
                "text/html",
            ),
            "/bootstrap.js": ((root / "bootstrap.js").read_bytes(), "text/javascript"),
            "/style.css": ((root / "style.css").read_bytes(), "text/css"),
            "/textual.js": (renderer, "text/javascript"),
            "/xterm.css": (upstream.joinpath("css/xterm.css").read_bytes(), "text/css"),
            "/mono.ttf": (
                upstream.joinpath(
                    "fonts/RobotoMono-VariableFont_wght.ttf"
                ).read_bytes(),
                "font/ttf",
            ),
        }

    def bootstrap_script(self) -> str:
        """Deliver directly to the renderer, never print or persist this value."""
        return f"window.startServonaut({json.dumps(self._token)});"

    async def start(self) -> str:
        app = web.Application()
        app.router.add_get("/ws", self._connect)
        for path in self._assets:
            app.router.add_get(path, self._asset)
        app.on_response_prepare.append(self._headers)
        self._runner = web.AppRunner(
            app, access_log=None, shutdown_timeout=self.config.shutdown_seconds
        )
        await self._runner.setup()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._socket.bind(("127.0.0.1", 0))
            self._socket.setblocking(False)
            port = self._socket.getsockname()[1]
            self.origin = f"http://127.0.0.1:{port}"
            await web.SockSite(self._runner, self._socket).start()
        except BaseException:
            await self.stop()
            raise
        return self.origin

    async def _headers(
        self, request: web.Request, response: web.StreamResponse
    ) -> None:
        response.headers.update(
            {
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; "
                    # Upstream xterm uses runtime-generated styles, but no eval.
                    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
                    f"connect-src {self.origin.replace('http:', 'ws:')}; "
                    "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
                ),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            }
        )

    def _validate_host(self, request: web.Request) -> None:
        if request.host != self.origin.removeprefix("http://"):
            raise web.HTTPForbidden()

    async def _asset(self, request: web.Request) -> web.Response:
        self._validate_host(request)
        if request.query_string:
            raise web.HTTPBadRequest()
        data, content_type = self._assets[request.path]
        return web.Response(body=data, content_type=content_type)

    async def _connect(self, request: web.Request) -> web.WebSocketResponse:
        self._validate_host(request)
        protocols = request.headers.get("Sec-WebSocket-Protocol", "").split(",")
        protocols = [value.strip() for value in protocols]
        expected = ["servonaut-probe", f"auth.{self._token}"]
        if request.headers.getall("Origin", []) != [self.origin]:
            raise web.HTTPForbidden()
        if len(protocols) != 2 or not hmac.compare_digest(
            ",".join(protocols).encode(), ",".join(expected).encode()
        ):
            raise web.HTTPForbidden()
        if self._used:
            raise web.HTTPConflict()
        try:
            width, height = terminal_size(request.query, self.config)
        except (TypeError, ValueError):
            raise web.HTTPBadRequest() from None
        websocket = web.WebSocketResponse(
            protocols=("servonaut-probe",),
            max_msg_size=self.config.max_message_bytes,
            timeout=self.config.shutdown_seconds,
        )
        if not websocket.can_prepare(request).ok:
            raise web.HTTPBadRequest()
        self._used = True  # Before the first await: concurrent requests cannot race.
        self._websocket = websocket
        await websocket.prepare(request)
        try:
            await self.child.start(width, height)
            await self._bridge(websocket)
        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError):
            await websocket.close(code=1011, message=b"Child transport failed")
        finally:
            await self.child.stop()
            await websocket.close()
            self.finished.set()
        return websocket

    async def _bridge(self, websocket: web.WebSocketResponse) -> None:
        tasks = [
            asyncio.create_task(self.child.forward(websocket.send_bytes)),
            asyncio.create_task(self._receive(websocket)),
        ]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _receive(self, websocket: web.WebSocketResponse) -> None:
        async for message in websocket:
            try:
                if message.type != WSMsgType.TEXT:
                    raise ValueError("Text frames required")
                envelope = json.loads(message.data)
                await self._dispatch(envelope, websocket)
            except (ValueError, TypeError, KeyError):
                await websocket.close(code=1008, message=b"Invalid message")
                return

    async def _dispatch(self, value: object, websocket: web.WebSocketResponse) -> None:
        if not isinstance(value, list) or not value or not isinstance(value[0], str):
            raise ValueError("Invalid envelope")
        kind = value[0]
        if kind in {"focus", "blur"} and len(value) == 1:
            await self.child.meta({"type": kind})
        elif kind == "stdin" and len(value) == 2 and isinstance(value[1], str):
            await self.child.send(b"D", value[1].encode())
        elif kind == "resize" and len(value) == 2 and isinstance(value[1], dict):
            width, height = terminal_size(value[1], self.config)
            await self.child.meta({"type": "resize", "width": width, "height": height})
        elif kind == "ping" and len(value) == 2 and isinstance(value[1], str):
            await websocket.send_json(["pong", value[1]])
        else:
            raise ValueError("Unsupported message")

    async def stop(self) -> None:
        if self._websocket is not None:
            await self._websocket.close()
        await self.child.stop()
        if self._runner is not None:
            await self._runner.cleanup()
        if self._socket is not None:
            self._socket.close()
        self.finished.set()


def terminal_size(value: Mapping[str, object], config: ProbeConfig) -> tuple[int, int]:
    """Strictly bound browser-provided dimensions before allocating a screen."""
    result = []
    for name, limit in (("width", config.max_columns), ("height", config.max_rows)):
        raw = value.get(name)
        if isinstance(raw, bool) or not isinstance(raw, (int, str)):
            raise TypeError("Invalid terminal dimensions")
        try:
            size = int(raw)
        except ValueError:
            raise ValueError("Invalid terminal dimensions") from None
        if not 1 <= size <= limit:
            raise ValueError("Invalid terminal dimensions")
        result.append(size)
    return result[0], result[1]
