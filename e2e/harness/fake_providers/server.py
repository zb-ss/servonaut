"""FakeProviders server: plain HTTP on a loopback port, in its own thread.

One instance per test process (session scope); journeys call :meth:`reset`
between tests. It serves stand-ins for the Hetzner Cloud API under
``/hetzner/v1`` and the OVHcloud API under ``/ovh/1.0``. Every request is
logged with credentials redacted, and an unknown route answers 404 and is
logged too, so a journey can assert exactly which calls a user action made.

Plain HTTP is enough: both client libraries accept an ``http://`` base URL,
and the socket guard keeps every connection on loopback.
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
import threading
from pathlib import Path
from typing import Any, Optional

from aiohttp import web

from e2e.harness.fake_cloud.log import RequestLog, redact
from e2e.harness.fake_providers import hetzner, ovh

_START_TIMEOUT_SECONDS = 15


class FakeProviders:
    """Local stand-in for the Hetzner Cloud and OVHcloud APIs."""

    def __init__(self) -> None:
        self.hetzner = hetzner.HetznerState()
        self.ovh = ovh.OvhState()
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
        return f"http://127.0.0.1:{self._port}"

    @property
    def hetzner_url(self) -> str:
        """Base URL in the form hcloud expects (version path included)."""
        return f"{self.url}{hetzner.PREFIX}"

    @property
    def ovh_url(self) -> str:
        """Base URL in the form python-ovh's endpoint table holds."""
        return f"{self.url}{ovh.PREFIX}"

    def reset(self) -> None:
        """Restore both providers to empty accounts and forget logged requests."""
        self.hetzner.reset()
        self.ovh.reset()
        self._log.clear()

    def requests(
        self,
        provider: Optional[str] = None,
        *,
        method: Optional[str] = None,
        path: Optional[str] = None,
    ) -> list[dict]:
        """Logged requests, oldest first.

        *provider* is ``"hetzner"`` or ``"ovh"``; *path* is a regular
        expression matched in full against the path below the provider's
        base URL (``/servers/42/actions/reboot``, ``/vps``).
        """
        pattern = re.compile(path) if path else None
        out = []
        for entry in self._log.entries(method=method):
            if provider is not None and entry["provider"] != provider:
                continue
            if pattern is not None and not pattern.fullmatch(entry["api_path"]):
                continue
            out.append(entry)
        return out

    def mutations(self, provider: Optional[str] = None) -> list[dict]:
        """Every request that could change something (anything but GET)."""
        return [e for e in self.requests(provider) if e["method"] not in ("GET", "HEAD")]

    def write_log(self, destination: Path) -> None:
        self._log.write_jsonl(destination)

    def start(self) -> "FakeProviders":
        self._thread = threading.Thread(target=self._serve, name="fake-providers", daemon=True)
        self._thread.start()
        if not self._ready.wait(_START_TIMEOUT_SECONDS):
            raise RuntimeError("FakeProviders did not start in time")
        if self._error is not None:
            raise RuntimeError(f"FakeProviders failed to start: {self._error}") from self._error
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
        hetzner.add_routes(app, self.hetzner)
        ovh.add_routes(app, self.ovh)
        return app

    @staticmethod
    def _classify(path: str) -> tuple[str, str]:
        for provider, prefix in (("hetzner", hetzner.PREFIX), ("ovh", ovh.PREFIX)):
            if path == prefix or path.startswith(prefix + "/"):
                return provider, path[len(prefix):] or "/"
        return "unknown", path

    @web.middleware
    async def _log_middleware(self, request: web.Request, handler: Any) -> web.StreamResponse:
        body: Any = None
        if request.can_read_body:
            raw = await request.read()
            try:
                body = redact(json.loads(raw)) if raw else None
            except ValueError:
                body = f"<{len(raw)} bytes>"
        provider, api_path = self._classify(request.path)
        try:
            response = await handler(request)
        except web.HTTPNotFound:
            response = _not_found(provider, request.path)
        except web.HTTPMethodNotAllowed:
            response = web.json_response(
                {"error": "method not provided by FakeProviders"}, status=405
            )
        self._log.add(
            {
                "provider": provider,
                "method": request.method,
                "path": request.path,
                "api_path": api_path,
                "query": redact(dict(request.query)),
                "body": body,
                "authorization": "<redacted>" if request.headers.get("Authorization") else None,
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
            site = web.SockSite(runner, listener)
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


def _not_found(provider: str, path: str) -> web.Response:
    """A 404 in the error format of the provider the path belongs to."""
    if provider == "hetzner":
        return hetzner.error_response(404, "not_found", f"not provided by FakeProviders: {path}")
    if provider == "ovh":
        return ovh.error_response(404, f"not provided by FakeProviders: {path}")
    return web.json_response({"error": "not provided by FakeProviders"}, status=404)
