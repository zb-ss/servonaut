"""FakeCloud server: aiohttp over TLS on a loopback port, in its own thread.

One instance per test process (session scope); tests call :meth:`reset`
between journeys. It serves the account routes the CLI and TUI need, the
relay (subscriber token, Mercure hub, heartbeat, results, status), account
data, the AI routes and hosted-MCP endpoint, the paid data features (Memory
Sync and team sharing, config snapshots, the secret-store config and SSH key
references, findings and remediation), the package-index JSON the update
check reads, and the ``/__e2e/`` control plane. Each path belongs to
exactly one route module; registering one twice fails at start-up.
Every request is logged with credentials redacted; unknown routes answer
404 and are logged too, so a journey can assert it made no unexpected calls.
The same requests are also kept unredacted, in memory only, so a journey can
prove a secret never crossed the wire (``assert_absent_on_wire``); that copy
is never written to the failure artifacts.
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

from e2e.harness.fake_cloud import (
    control,
    routes_account,
    routes_ai,
    routes_auth,
    routes_configs,
    routes_findings,
    routes_memory,
    routes_pypi,
    routes_relay,
    routes_secrets,
)
from e2e.harness.fake_cloud.log import RequestLog, redact
from e2e.harness.fake_cloud.relay import RelayHub
from e2e.harness.fake_cloud.routes_account import AccountData
from e2e.harness.fake_cloud.routes_ai import AiState
from e2e.harness.fake_cloud.routes_configs import ConfigSnapshots
from e2e.harness.fake_cloud.routes_findings import FindingsCloud
from e2e.harness.fake_cloud.routes_memory import MemoryCloud
from e2e.harness.fake_cloud.routes_secrets import SecretsData
from e2e.harness.fake_cloud.state import ScenarioStore
from e2e.harness.fake_cloud.tls import TlsMaterial
from e2e.harness.fake_cloud.wire import Value, WireCapture, WireRequest, find_on_wire

_START_TIMEOUT_SECONDS = 15


class FakeCloud:
    """Local HTTPS stand-in for the Servonaut API and the package index."""

    def __init__(self, tls: TlsMaterial, *, default_pypi_version: str) -> None:
        self._tls = tls
        self._store = ScenarioStore(default_pypi_version)
        self._log = RequestLog()
        self._wire = WireCapture()
        self.relay = RelayHub(lambda: self._store.snapshot().user_id)
        # Bumped by reset(): a request that began before a reset (a relay
        # stream that outlived its journey) is not logged into the next one.
        self._epoch = 0
        self.account = AccountData()
        self.ai = AiState()
        self.memory = MemoryCloud(lambda: self._store.snapshot().user_id)
        self.configs = ConfigSnapshots()
        self.secrets = SecretsData()
        self.findings = FindingsCloud()
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
        self._epoch += 1
        self._store.reset()
        self._log.clear()
        self._wire.clear()
        self.relay.reset()
        self.account.reset()
        self.ai.reset()
        self.memory.reset()
        self.configs.reset()
        self.secrets.reset()
        self.findings.reset()

    # The account's OAuth session (see ``session.TokenSession``).

    def tokens(self) -> tuple[str, str]:
        """The account's current (access, refresh) token pair."""
        return self._store.session.tokens()

    def expire_access_token(self) -> None:
        """The next API call with the current access token answers 401."""
        self._store.session.expire_access()

    def revoke_session(self) -> None:
        """Access and refresh tokens both stop working (refresh: invalid_grant)."""
        self._store.session.revoke()

    def entitlements(self) -> dict:
        """The document ``/api/entitlements`` currently returns."""
        return routes_auth.entitlements_payload(self._store)

    def requests(self, path: Optional[str] = None, method: Optional[str] = None) -> list[dict]:
        """Requests received so far, oldest first (control routes excluded)."""
        return self._log.entries(path=path, method=method)

    def statuses(self, path: str) -> list[int]:
        """The HTTP statuses FakeCloud answered on *path*, oldest first."""
        return [entry["status"] for entry in self._log.entries(path=path)]

    def write_log(self, destination: Path) -> None:
        """Write the redacted request log (never the unredacted wire capture)."""
        self._log.write_jsonl(destination)

    # What crossed the wire, unredacted (see ``wire.py``).

    def wire_mark(self) -> int:
        """A position for ``assert_absent_on_wire(..., since=...)``."""
        return self._wire.mark()

    def assert_absent_on_wire(self, *values: Value, since: int = 0) -> None:
        """Fail if any of *values* was sent to FakeCloud, in any encoding.

        Looks at the raw path, query, every header and the raw body of every
        request since *since*. The failure names the value's position and
        where it was found, never the value.
        """
        requests = self._wire.requests(since)
        problems = [
            f"value #{index} ({len(value)} long): {where}"
            for index, value in enumerate(values, 1)
            for where in find_on_wire(requests, value)
        ]
        if problems:
            raise AssertionError("sent to the service:\n  " + "\n  ".join(problems))

    def assert_no_unexpected_errors(self, *allowed: tuple[str, str, int]) -> None:
        """Fail on any 4xx or 5xx answer not matched by *allowed*.

        Each allowed entry is ``(method, path regex, status)``; see
        ``wire.EXPECTED`` for the named, shared ones.
        """
        unexpected = [
            f"{e['method']} {e['path']} -> {e['status']}"
            for e in self._log.entries()
            if e["status"] >= 400
            and not any(
                e["method"] == method and re.fullmatch(pattern, e["path"]) and e["status"] == status
                for method, pattern, status in allowed
            )
        ]
        if unexpected:
            raise AssertionError("unexpected error answers:\n  " + "\n  ".join(unexpected))

    def start(self) -> "FakeCloud":
        self._thread = threading.Thread(target=self._serve, name="fake-cloud", daemon=True)
        self._thread.start()
        if not self._ready.wait(_START_TIMEOUT_SECONDS):
            raise RuntimeError("FakeCloud did not start in time")
        if self._error is not None:
            raise RuntimeError(f"FakeCloud failed to start: {self._error}") from self._error
        return self

    def stop(self) -> None:
        self.relay.drop_streams()  # open subscriptions would hold up shutdown
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
        routes_relay.add_routes(app, self._store, self.relay)
        routes_account.add_routes(app, self._store, self.account)
        routes_ai.add_routes(app, self._store, self.ai)
        routes_memory.add_routes(app, self._store, self.memory)
        routes_configs.add_routes(app, self._store, self.configs)
        routes_secrets.add_routes(app, self._store, self.secrets)
        routes_findings.add_routes(app, self._store, self.findings)
        routes_pypi.add_routes(app, self._store)
        control.add_routes(app, self._store, self._log)
        require_unique_routes(app)
        return app

    @web.middleware
    async def _log_middleware(self, request: web.Request, handler: Any) -> web.StreamResponse:
        epoch = self._epoch
        body: Any = None
        authorization = request.headers.get("Authorization")
        bearer_ok = self._store.session.bearer_valid(authorization)
        raw = await request.read() if request.can_read_body else b""
        if raw:
            try:
                body = redact(json.loads(raw))
            except ValueError:
                body = f"<{len(raw)} bytes>"
        if epoch == self._epoch and not request.path.startswith(control.CONTROL_PREFIX):
            self._wire.add(
                WireRequest(
                    method=request.method,
                    target=request.raw_path.encode("utf-8", "surrogateescape"),
                    headers=tuple(request.raw_headers),
                    body=raw,
                )
            )
        try:
            response = await handler(request)
        except web.HTTPNotFound:
            response = web.json_response({"error": "not provided by FakeCloud"}, status=404)
        if epoch == self._epoch and not request.path.startswith(control.CONTROL_PREFIX):
            self._log.add(
                {
                    "method": request.method,
                    "path": request.path,
                    "query": redact(dict(request.query)),
                    "body": body,
                    "authorization": "Bearer <redacted>" if authorization else None,
                    "bearer_ok": bearer_ok,
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


def require_unique_routes(app: web.Application) -> None:
    """Fail when two route modules register the same method and path."""
    seen: set[tuple[str, str]] = set()
    for route in app.router.routes():
        info = route.resource.get_info() if route.resource is not None else {}
        path = info.get("path") or info.get("formatter") or ""
        key = (route.method, path)
        if key in seen:
            raise RuntimeError(f"FakeCloud route registered twice: {route.method} {path}")
        seen.add(key)
