"""Relay routes: subscriber token, Mercure hub, heartbeat, command results, status.

Everything a relay listener talks to except the chat tool-result reply
(``routes_ai``), plus the service's view of the relay that ``connect
--status`` and the relay tools read. Bodies are validated like the service
does (422 otherwise). State lives in
:class:`~e2e.harness.fake_cloud.relay.RelayHub`.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from typing import Any, Optional

from aiohttp import web

from e2e.harness.fake_cloud.relay import KEEPALIVE_SECONDS, Grant, RelayHub, close_marker
from e2e.harness.fake_cloud.routes_auth import (
    bearer_ok,
    json_body,
    unauthorized,
    validation_failed,
)
from e2e.harness.fake_cloud.state import ScenarioStore

MERCURE_PATH = "/.well-known/mercure"
CLIENT_ID = re.compile(r"[a-zA-Z0-9_-]{1,64}")
HEARTBEAT_TYPES = frozenset({"cli.handshake", "cli.heartbeat"})
RELEASE_CHANNELS = frozenset({"stable", "beta", "dev"})
COMMAND_STATUSES = frozenset({"success", "error", "timeout", "rejected"})


def heartbeat_problem(body: dict[str, Any]) -> Optional[str]:
    """Why the service would refuse this heartbeat or handshake, or None."""
    kind = body.get("type")
    if kind not in HEARTBEAT_TYPES:
        return f"type must be one of {sorted(HEARTBEAT_TYPES)}"
    client_id = body.get("client_id")
    if not isinstance(client_id, str) or not CLIENT_ID.fullmatch(client_id):
        return "client_id must be 1-64 characters of [a-zA-Z0-9_-]"
    providers = body.get("providers_configured")
    if not isinstance(providers, list) or not all(isinstance(p, str) for p in providers):
        return "providers_configured must be a list of strings"
    if kind == "cli.handshake":
        if not isinstance(body.get("version"), str) or not body["version"]:
            return "version is required"
        if body.get("cli_release_channel") not in RELEASE_CHANNELS:
            return f"cli_release_channel must be one of {sorted(RELEASE_CHANNELS)}"
        if not isinstance(body.get("capabilities"), dict):
            return "capabilities must be an object"
    return None


def command_result_problem(request_id: str, body: dict[str, Any]) -> Optional[str]:
    """Why the service would refuse this command result, or None."""
    if body.get("request_id") != request_id:
        return "request_id must match the path"
    if body.get("status") not in COMMAND_STATUSES:
        return f"status must be one of {sorted(COMMAND_STATUSES)}"
    for key in ("output", "error_message"):
        if not isinstance(body.get(key), str):
            return f"{key} must be a string"
    elapsed = body.get("execution_time_ms")
    if not isinstance(elapsed, int) or isinstance(elapsed, bool) or elapsed < 0:
        return "execution_time_ms must be a non-negative integer"
    return None


def add_routes(app: web.Application, store: ScenarioStore, hub: RelayHub) -> None:
    """Register the relay routes on *app*."""

    def authorized(request: web.Request) -> bool:
        return bearer_ok(request, store)

    async def mercure_token(request: web.Request) -> web.Response:
        if not authorized(request):
            return unauthorized()
        return web.json_response({"token": hub.mint_token(store.snapshot().user_id)})

    async def heartbeat(request: web.Request) -> web.Response:
        if not authorized(request):
            return unauthorized()
        body = await json_body(request)
        problem = heartbeat_problem(body)
        if problem:
            return validation_failed(problem)
        hub.record_heartbeat(body, store.session.view().generation)
        return web.json_response({"ok": True})

    async def command_result(request: web.Request) -> web.Response:
        if not authorized(request):
            return unauthorized()
        request_id = request.match_info["request_id"]
        body = await json_body(request)
        problem = command_result_problem(request_id, body)
        if problem:
            return validation_failed(problem)
        hub.record_command_result(request_id, body)
        return web.json_response({"ok": True})

    async def cli_status(request: web.Request) -> web.Response:
        if not authorized(request):
            return unauthorized()
        return web.json_response(hub.status_payload())

    async def subscribe(request: web.Request) -> web.StreamResponse:
        failure = hub.next_hub_failure()
        if failure is not None:
            return web.json_response({"error": "hub unavailable"}, status=failure)
        grant = hub.grant_for(request.query.get("authorization"))
        if grant is None:
            return web.json_response({"error": "invalid subscriber token"}, status=401)
        return await _stream(request, hub, grant)

    app.router.add_get("/api/cli/mercure-token", mercure_token)
    app.router.add_post("/api/cli/heartbeat", heartbeat)
    app.router.add_post("/api/cli/command-result/{request_id}", command_result)
    app.router.add_get("/api/cli/status", cli_status)
    app.router.add_get(MERCURE_PATH, subscribe)


async def _stream(request: web.Request, hub: RelayHub, grant: Grant) -> web.StreamResponse:
    """Serve one SSE subscription until the client leaves or the hub drops it.

    A cancellation (the server shutting down) still closes the subscription
    and is then re-raised.
    """
    subscription, replay = hub.open_subscription(
        tuple(request.query.getall("topic", [])),
        request.headers.get("Last-Event-ID"),
        grant,
        asyncio.get_running_loop(),
    )
    response = web.StreamResponse(
        headers={"Content-Type": "text/event-stream", "Cache-Control": "no-store"}
    )
    closing = close_marker()
    try:
        await response.prepare(request)
        for event in replay:
            hub.record_sent(subscription, event, replayed=True)
            await response.write(event.frame())
        while True:
            try:
                item = await asyncio.wait_for(subscription.queue.get(), KEEPALIVE_SECONDS)
            except asyncio.TimeoutError:
                if request.transport is None or request.transport.is_closing():
                    break
                await response.write(b": keepalive\n\n")
                continue
            if item is closing:
                break
            hub.record_sent(subscription, item, replayed=False)
            await response.write(item.frame())
    except ConnectionError:
        pass  # the client went away
    finally:
        hub.close_subscription(subscription)
    with contextlib.suppress(ConnectionError, RuntimeError):
        await response.write_eof()
    return response
