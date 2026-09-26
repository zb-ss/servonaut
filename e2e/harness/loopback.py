"""A local aiohttp server on a free loopback port, in its own thread.

The fakes (FakeCloud, the bring-your-own AI providers) subclass
:class:`LoopbackServer`: they build their application in
:meth:`LoopbackServer.build_app`, optionally serve TLS, and are started
once per test process. The event loop runs in a daemon thread so journeys
can drive the app under test from their own loop.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
from typing import Optional

from aiohttp import web

START_TIMEOUT_SECONDS = 15
STOP_TIMEOUT_SECONDS = 10


class LoopbackServer:
    """Serves :meth:`build_app` on ``127.0.0.1:<free port>``."""

    #: Thread and error-message name; subclasses override it.
    NAME = "loopback"

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._ready = threading.Event()
        self._error: Optional[BaseException] = None
        self._port = 0

    # ------------------------------------------------------------------
    # For subclasses
    # ------------------------------------------------------------------

    def build_app(self) -> web.Application:
        raise NotImplementedError

    def ssl_context(self) -> Optional[ssl.SSLContext]:
        """The server's TLS context; None serves plain HTTP."""
        return None

    def before_stop(self) -> None:
        """Release anything that would hold up shutdown (open streams)."""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> "LoopbackServer":
        self._thread = threading.Thread(target=self._serve, name=self.NAME, daemon=True)
        self._thread.start()
        if not self._ready.wait(START_TIMEOUT_SECONDS):
            raise RuntimeError(f"{self.NAME} did not start in time")
        if self._error is not None:
            raise RuntimeError(f"{self.NAME} failed to start: {self._error}") from self._error
        return self

    def stop(self) -> None:
        self.before_stop()
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=STOP_TIMEOUT_SECONDS)

    def _serve(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            runner = web.AppRunner(self.build_app(), access_log=None)
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            self._port = listener.getsockname()[1]
            loop.run_until_complete(runner.setup())
            site = web.SockSite(runner, listener, ssl_context=self.ssl_context())
            loop.run_until_complete(site.start())
        except BaseException as exc:  # noqa: BLE001 - reported to the starting thread
            self._error = exc
            self._ready.set()
            loop.close()
            return
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(runner.cleanup())
            loop.close()
