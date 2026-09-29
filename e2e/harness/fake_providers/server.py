"""FakeProviders server: plain HTTP on a loopback port, in its own thread.

One instance per test process (session scope); journeys call :meth:`reset`
between tests. It serves stand-ins for the Hetzner Cloud API under
``/hetzner/v1`` and the OVHcloud API under ``/ovh`` (``/ovh/1.0`` for
``ovh-eu``). Each provider has a primary account and can have more, each
answering its own credentials (:meth:`add_hetzner_project`,
:meth:`add_ovh_account`). Every request is logged with credentials redacted
and with the label of the account it reached, and an unknown route answers
404 and is logged too, so a journey can assert exactly which calls a user
action made, and for which account.

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
from e2e.harness.fake_providers.accounts import ACCOUNT

_START_TIMEOUT_SECONDS = 15


class FakeProviders:
    """Local stand-in for the Hetzner Cloud and OVHcloud APIs."""

    def __init__(self) -> None:
        self.hetzner_projects = hetzner.HetznerProjects()
        self.ovh_accounts = ovh.OvhAccounts()
        # The primary accounts, which single-account journeys seed directly.
        self.hetzner = self.hetzner_projects.primary
        self.ovh = self.ovh_accounts.primary
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
        """Base URL in the form python-ovh's endpoint table holds (``ovh-eu``)."""
        return f"{self.url}{ovh.PREFIX}"

    def ovh_endpoint_url(self, endpoint: str) -> str:
        """Base URL of the python-ovh endpoint name *endpoint* (``ovh-ca``, ...)."""
        return f"{self.url}{ovh.endpoint_prefix(endpoint)}"

    def ovh_endpoint_urls(self) -> dict[str, str]:
        """A base URL of its own for every endpoint name python-ovh knows."""
        from ovh import client as ovh_client

        return {name: self.ovh_endpoint_url(name) for name in ovh_client.ENDPOINTS}

    def add_hetzner_project(self, label: str, token: Optional[str] = None) -> hetzner.HetznerState:
        """A further, empty Hetzner project answering *token*.

        The token defaults to ``hetzner.token_for(label)``, which is also what
        ``HomeSeeder.hetzner_account(label)`` writes.
        """
        return self.hetzner_projects.add(label, token)

    def add_ovh_account(
        self,
        label: str,
        endpoint: str = ovh.DEFAULT_ENDPOINT,
        credentials: Optional[ovh.OvhCredentials] = None,
    ) -> ovh.OvhState:
        """A further, empty OVH account on *endpoint*, answering *credentials*.

        The credentials default to ``ovh.credentials_for(label)``, which is
        also what ``HomeSeeder.ovh_account(label)`` writes.
        """
        return self.ovh_accounts.add(label, endpoint, credentials)

    def reset(self) -> None:
        """Back to one empty account per provider; forget logged requests."""
        self.hetzner_projects.reset()
        self.ovh_accounts.reset()
        self._log.clear()

    def requests(
        self,
        provider: Optional[str] = None,
        *,
        method: Optional[str] = None,
        path: Optional[str] = None,
        account: Optional[str] = None,
    ) -> list[dict]:
        """Logged requests, oldest first.

        *provider* is ``"hetzner"`` or ``"ovh"``; *path* is a regular
        expression matched in full against the path below the provider's
        base URL (``/servers/42/actions/reboot``, ``/vps``); *account* is the
        label of the account a request reached (a refused request has none).
        Each entry also names the OVH ``endpoint`` it was sent to.
        """
        pattern = re.compile(path) if path else None
        out = []
        for entry in self._log.entries(method=method):
            if provider is not None and entry["provider"] != provider:
                continue
            if pattern is not None and not pattern.fullmatch(entry["api_path"]):
                continue
            if account is not None and entry["account"] != account:
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
        hetzner.add_routes(app, self.hetzner_projects)
        ovh.add_routes(app, self.ovh_accounts)
        return app

    @staticmethod
    def _classify(path: str) -> tuple[str, Optional[str], str]:
        """``(provider, OVH endpoint name, API path)`` of a request path."""
        if path == hetzner.PREFIX or path.startswith(hetzner.PREFIX + "/"):
            return "hetzner", None, path[len(hetzner.PREFIX):] or "/"
        ovh_path = ovh.split_path(path)
        if ovh_path is not None:
            return "ovh", *ovh_path
        return "unknown", None, path

    @web.middleware
    async def _log_middleware(self, request: web.Request, handler: Any) -> web.StreamResponse:
        body: Any = None
        if request.can_read_body:
            raw = await request.read()
            try:
                body = redact(json.loads(raw)) if raw else None
            except ValueError:
                body = f"<{len(raw)} bytes>"
        provider, endpoint, api_path = self._classify(request.path)
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
                "endpoint": endpoint,
                "account": request.get(ACCOUNT),
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
