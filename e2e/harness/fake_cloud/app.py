"""FakeCloud server: aiohttp over TLS on a loopback port, in its own thread.

One instance per test process (session scope); tests call :meth:`reset`
between journeys. It serves the account routes the CLI and TUI need, the
package index (the JSON the update check reads and a simple index pip and
pipx install from), and the ``/__e2e/`` control plane.
Every request is logged with credentials redacted; unknown routes answer
404 and are logged too, so a journey can assert it made no unexpected calls.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from pathlib import Path
from typing import Any, Optional

from aiohttp import web

from e2e.harness.fake_cloud import control, routes_auth, routes_pypi
from e2e.harness.fake_cloud.log import RequestLog, redact
from e2e.harness.fake_cloud.state import ACCESS_TOKEN, ScenarioStore
from e2e.harness.fake_cloud.tls import TlsMaterial

_START_TIMEOUT_SECONDS = 15


class FakeCloud:
    """Local HTTPS stand-in for the Servonaut API and the package index."""

    def __init__(self, tls: TlsMaterial, *, default_pypi_version: str) -> None:
        self._tls = tls
        self._store = ScenarioStore(default_pypi_version)
        self._log = RequestLog()
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._ready = threading.Event()
        self._error: Optional[BaseException] = None
        self._port = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self._port}"

    @property
    def pypi_json_url(self) -> str:
        return f"{self.url}{routes_pypi.PYPI_JSON_PATH}"

    def configure(self, **changes: Any) -> None:
        """Change the scenario (see ``state.Scenario`` for the keys)."""
        self._store.configure(**changes)

    def reset(self) -> None:
        """Restore the default scenario and forget logged requests."""
        self._store.reset()
        self._log.clear()

    def requests(self, path: Optional[str] = None, method: Optional[str] = None) -> list[dict]:
        """Requests received so far, oldest first (control routes excluded)."""
        return self._log.entries(path=path, method=method)

    def write_log(self, destination: Path) -> None:
        self._log.write_jsonl(destination)

    def start(self) -> "FakeCloud":
        self._thread = threading.Thread(target=self._serve, name="fake-cloud", daemon=True)
        self._thread.start()
        if not self._ready.wait(_START_TIMEOUT_SECONDS):
            raise RuntimeError("FakeCloud did not start in time")
        if self._error is not None:
            raise RuntimeError(f"FakeCloud failed to start: {self._error}") from self._error
        return self

    def stop(self) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=10)

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    def _build_app(self) -> web.Application:
        app = web.Application(middlewares=[self._log_middleware])
        routes_auth.add_routes(app, self._store, lambda: self.url)
        routes_pypi.add_routes(app, self._store)
        control.add_routes(app, self._store, self._log)
        return app

    @web.middleware
    async def _log_middleware(self, request: web.Request, handler: Any) -> web.StreamResponse:
        body: Any = None
        if request.can_read_body:
            raw = await request.read()
            try:
                body = redact(json.loads(raw)) if raw else None
            except ValueError:
                body = f"<{len(raw)} bytes>"
        try:
            response = await handler(request)
        except web.HTTPNotFound:
            response = web.json_response({"error": "not provided by FakeCloud"}, status=404)
        if not request.path.startswith(control.CONTROL_PREFIX):
            authorization = request.headers.get("Authorization")
            self._log.add(
                {
                    "method": request.method,
                    "path": request.path,
                    "query": redact(dict(request.query)),
                    "body": body,
                    "authorization": "Bearer <redacted>" if authorization else None,
                    "bearer_ok": authorization == f"Bearer {ACCESS_TOKEN}",
                    "status": response.status,
                }
            )
        return response

    def _serve(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        runner = web.AppRunner(self._build_app(), access_log=None)
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            self._port = listener.getsockname()[1]
            loop.run_until_complete(runner.setup())
            site = web.SockSite(runner, listener, ssl_context=self._tls.server_context())
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
