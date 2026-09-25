"""Relay routes: subscriber token, Mercure hub, heartbeat, results, status.

Everything a relay listener talks to, plus the backend status the relay
tools read and the hosted-MCP message endpoint. State lives in
:class:`~e2e.harness.fake_cloud.relay.RelayHub`.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any, Awaitable, Callable

from aiohttp import web

from e2e.harness.fake_cloud.relay import KEEPALIVE_SECONDS, RelayHub, close_marker
from e2e.harness.fake_cloud.routes_auth import bearer_ok, unauthorized
from e2e.harness.fake_cloud.state import ScenarioStore

MERCURE_PATH = "/.well-known/mercure"
TOOL_RESULT_PATH = "/api/ai/chat/tool-result"
HOSTED_MCP_PATH = "/mcp/message"
# Tools the fake hosted MCP server answers; any other name is an error.
HOSTED_TOOLS = frozenset({"fleet_summary"})

Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]


def add_route_once(app: web.Application, method: str, path: str, handler: Handler) -> None:
    """Register *handler* unless another FakeCloud module already serves it."""
    for route in app.router.routes():
        info = route.resource.get_info() if route.resource is not None else {}
        if route.method == method and info.get("path") == path:
            return
    app.router.add_route(method, path, handler)


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
        hub.record_heartbeat(await _json_body(request), store.session.view().generation)
        return web.json_response({"ok": True})

    async def command_result(request: web.Request) -> web.Response:
        if not authorized(request):
            return unauthorized()
        hub.record_command_result(request.match_info["request_id"], await _json_body(request))
        return web.json_response({"ok": True})

    async def tool_result(request: web.Request) -> web.Response:
        if not authorized(request):
            return unauthorized()
        hub.record_tool_result(await _json_body(request))
        return web.json_response({"ok": True})

    async def cli_status(request: web.Request) -> web.Response:
        if not authorized(request):
            return unauthorized()
        return web.json_response(hub.status_payload())

    async def hosted_mcp(request: web.Request) -> web.Response:
        if not authorized(request):
            return unauthorized()
        return web.json_response(_hosted_answer(hub, await _json_body(request)))

    async def subscribe(request: web.Request) -> web.StreamResponse:
        failure = hub.next_hub_failure()
        if failure is not None:
            return web.json_response({"error": "hub unavailable"}, status=failure)
        token_number = hub.token_number(request.query.get("authorization"))
        if token_number is None:
            return web.json_response({"error": "invalid subscriber token"}, status=401)
        return await _stream(request, hub, token_number)

    app.router.add_get("/api/cli/mercure-token", mercure_token)
    app.router.add_post("/api/cli/heartbeat", heartbeat)
    app.router.add_post("/api/cli/command-result/{request_id}", command_result)
    app.router.add_get("/api/cli/status", cli_status)
    app.router.add_get(MERCURE_PATH, subscribe)
    add_route_once(app, "POST", TOOL_RESULT_PATH, tool_result)
    add_route_once(app, "POST", HOSTED_MCP_PATH, hosted_mcp)


async def _stream(request: web.Request, hub: RelayHub, token_number: int) -> web.StreamResponse:
    """Serve one SSE subscription until the client leaves or the hub drops it."""
    topics = tuple(request.query.getall("topic", []))
    subscription, replay = hub.open_subscription(
        topics, request.headers.get("Last-Event-ID"), token_number, asyncio.get_running_loop()
    )
    response = web.StreamResponse(
        headers={"Content-Type": "text/event-stream", "Cache-Control": "no-store"}
    )
    closing = close_marker()
    try:
        await response.prepare(request)
        for event in replay:
            hub.record_sent(subscription, event)
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
            hub.record_sent(subscription, item)
            await response.write(item.frame())
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        hub.close_subscription(subscription)
    with contextlib.suppress(ConnectionError, RuntimeError):
        await response.write_eof()
    return response


def _hosted_answer(hub: RelayHub, envelope: dict[str, Any]) -> dict[str, Any]:
    """A JSON-RPC 2.0 answer from the fake hosted MCP server."""
    hub.record_hosted_call({**envelope, "at": time.time()})
    request_id = envelope.get("id")
    params = envelope.get("params") if isinstance(envelope.get("params"), dict) else {}
    name = params.get("name")
    if envelope.get("method") != "tools/call":
        return _rpc_error(request_id, -32601, "Method not found")
    if name not in HOSTED_TOOLS:
        return _rpc_error(request_id, -32602, f"Unknown tool: {name}")
    arguments = params.get("arguments") or {}
    text = f"hosted {name}: {len(arguments)} argument(s)"
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    }


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


async def _json_body(request: web.Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
