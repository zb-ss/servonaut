"""Control plane under ``/__e2e/``: reset, scenario changes, request log.

Tests in the same process call the ``FakeCloud`` methods directly; these
routes give the same control to child processes and to manual debugging.
"""

from __future__ import annotations

from aiohttp import web

from e2e.harness.fake_cloud.log import RequestLog
from e2e.harness.fake_cloud.state import ScenarioStore

CONTROL_PREFIX = "/__e2e/"


def add_routes(app: web.Application, store: ScenarioStore, log: RequestLog) -> None:
    """Register the control routes on *app*."""

    async def reset(request: web.Request) -> web.Response:
        store.reset()
        log.clear()
        return web.json_response({"reset": True})

    async def scenario(request: web.Request) -> web.Response:
        try:
            store.configure(**(await request.json()))
        except (KeyError, ValueError, TypeError) as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response({"ok": True})

    async def requests(request: web.Request) -> web.Response:
        return web.json_response(log.entries())

    app.router.add_post(f"{CONTROL_PREFIX}reset", reset)
    app.router.add_post(f"{CONTROL_PREFIX}scenario", scenario)
    app.router.add_get(f"{CONTROL_PREFIX}requests", requests)
