"""The hosted MCP server, speaking MCP's HTTP+SSE transport like the service.

The service's contract (protocol ``2024-11-05``) is enforced here, so a
client that skips a step fails against the fake as it would for real:

* ``GET /mcp/sse`` needs the account's current access token (401 otherwise)
  and opens an event stream. Its first event is ``endpoint``, carrying the
  relative URI ``/mcp/message?connection_id=<id>``; ``: ping`` comments
  follow as heartbeats;
* the account may hold :data:`STREAM_LIMIT` streams; a GET beyond that
  answers 429. Like the service, the fake frees a closed stream's slot only
  a moment after the client left (:meth:`HostedMcpState.hold_slots`), so a
  call made right after another one is refused at first;
* ``POST /mcp/message?connection_id=<id>`` takes one JSON-RPC message and
  answers 200 ``{"status": "accepted"}``. Without the id of an open stream
  it answers 400 ``{"error": "Invalid connection"}``. A reply is never in
  the POST response: it goes out on the stream as a ``message`` event;
* ``initialize``, ``ping``, ``tools/list`` and ``tools/call`` are answered,
  notifications are not, and any other method gets ``-32601``.
  ``tools/call`` answers the tools in :data:`HOSTED_TOOLS`, and any other
  name with an ``isError`` result ("Unknown tool: …") as the service does,
  unless :meth:`HostedMcpState.refuse` queued a refusal, such as the
  service's ``-32050`` capacity refusal.

:class:`HostedMcpState` (``FakeCloud.hosted_mcp``) records every stream with
the messages it received and whether it has closed, so a journey can check
both what the client sent and that it let the stream go.
"""

from __future__ import annotations

import asyncio
import copy
import itertools
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from aiohttp import web

from e2e.harness.fake_cloud.routes_auth import bearer_ok, unauthorized
from e2e.harness.fake_cloud.sse import comment, frame
from e2e.harness.fake_cloud.state import ScenarioStore

SSE_PATH = "/mcp/sse"
MESSAGE_PATH = "/mcp/message"
PROTOCOL_VERSION = "2024-11-05"
# Tools the fake hosted server answers; any other name is a JSON-RPC error.
HOSTED_TOOLS = frozenset({"fleet_summary"})
# The service's JSON-RPC code for a call refused for capacity or rate.
CAPACITY_REFUSED = -32050
# Short, so every journey's stream carries heartbeats the client must skip.
HEARTBEAT_SECONDS = 0.2
# Open streams one account may hold: the Solo plan's grant.
STREAM_LIMIT = 1
# How long a closed stream keeps its slot by default. The service takes
# about two seconds (it notices the client left only on its own schedule);
# journeys keep it short unless they test the wait (hold_slots).
SLOT_HOLD_SECONDS = 0.3


@dataclass
class _Connection:
    """One open event stream: its replies wait in ``outbox``."""

    connection_id: str
    record: dict[str, Any]
    outbox: asyncio.Queue = field(default_factory=asyncio.Queue)


class HostedMcpState:
    """Thread-safe record of the hosted MCP streams and scripted refusals."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._generation = 0  # bumped to end every open stream
        self.reset()

    def reset(self) -> None:
        """Forget every stream (ending those still open) and refusal."""
        with self._lock:
            self._generation += 1
            self._connections: dict[str, _Connection] = {}
            self._streams: list[dict[str, Any]] = []
            self._refusals: deque[dict[str, Any]] = deque()
            self._numbers = itertools.count(1)
            self._held_until: list[float] = []  # closed streams still holding a slot
            self._slot_hold = SLOT_HOLD_SECONDS
            self._refused_streams = 0

    def hold_slots(self, seconds: float) -> None:
        """Keep a closed stream's slot for *seconds* after it closes (from the next close on)."""
        with self._lock:
            self._slot_hold = seconds

    def refused_streams(self) -> int:
        """How many GETs were refused because every slot was taken."""
        with self._lock:
            return self._refused_streams

    def drop_streams(self) -> None:
        """End every open stream (they check between heartbeats)."""
        with self._lock:
            self._generation += 1

    def refuse(self, code: int = CAPACITY_REFUSED,
               message: str = "Capacity exceeded, try again later") -> None:
        """Answer the next ``tools/call`` with this JSON-RPC error."""
        with self._lock:
            self._refusals.append({"code": code, "message": message})

    def streams(self) -> list[dict[str, Any]]:
        """One row per stream, oldest first: its connection id, the
        messages it received and whether it has closed."""
        with self._lock:
            return copy.deepcopy(self._streams)

    def messages(self, method: Optional[str] = None) -> list[dict[str, Any]]:
        """Every JSON-RPC message received, oldest first, optionally of one method."""
        rows = [m for stream in self.streams() for m in stream["messages"]]
        return [m for m in rows if method is None or m.get("method") == method]

    # ------------------------------------------------------------------
    # Route API (server loop)
    # ------------------------------------------------------------------

    def generation(self) -> int:
        with self._lock:
            return self._generation

    def open_connection(self) -> Optional[_Connection]:
        """Open a stream, or None when the account's slots are all taken."""
        with self._lock:
            now = time.monotonic()
            self._held_until = [until for until in self._held_until if until > now]
            if len(self._connections) + len(self._held_until) >= STREAM_LIMIT:
                self._refused_streams += 1
                return None
            connection_id = f"conn-e2e-{next(self._numbers)}"
            record = {"connection_id": connection_id, "messages": [], "closed": False,
                      "opened_at": time.time()}
            connection = _Connection(connection_id, record)
            self._connections[connection_id] = connection
            self._streams.append(record)
            return connection

    def close_connection(self, connection: _Connection) -> None:
        with self._lock:
            if self._connections.pop(connection.connection_id, None) is not None:
                self._held_until.append(time.monotonic() + self._slot_hold)
            connection.record["closed"] = True

    def connection(self, connection_id: Optional[str]) -> Optional[_Connection]:
        with self._lock:
            return self._connections.get(connection_id or "")

    def receive(self, connection: _Connection, message: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Record *message*; return the reply to stream, or None for a notification."""
        with self._lock:
            connection.record["messages"].append(copy.deepcopy(message))
            refusal = (
                self._refusals.popleft()
                if message.get("method") == "tools/call" and self._refusals else None
            )
        if "id" not in message:
            return None
        if refusal is not None:
            return _rpc_error(message["id"], refusal["code"], refusal["message"])
        return _answer(message)


def add_routes(app: web.Application, store: ScenarioStore, state: HostedMcpState) -> None:
    """Register the hosted MCP routes on *app*."""

    async def sse(request: web.Request) -> web.StreamResponse:
        if not bearer_ok(request, store):
            return unauthorized()
        generation = state.generation()
        connection = state.open_connection()
        if connection is None:
            return web.Response(
                status=429, content_type="text/event-stream",
                body=frame(json.dumps({"error": "Connection limit exceeded"}), event="error"),
            )
        response = web.StreamResponse(
            headers={"Content-Type": "text/event-stream", "Cache-Control": "no-store"}
        )

        def gone() -> bool:
            transport = request.transport
            return (
                transport is None
                or transport.is_closing()
                or state.generation() != generation
            )

        try:
            await response.prepare(request)
            endpoint = f"{MESSAGE_PATH}?connection_id={connection.connection_id}"
            await response.write(frame(endpoint, event="endpoint"))
            while not gone():
                try:
                    reply = await asyncio.wait_for(connection.outbox.get(), HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    await response.write(comment("ping"))
                    continue
                await response.write(frame(json.dumps(reply), event="message"))
        except ConnectionError:
            pass  # the client left
        finally:
            state.close_connection(connection)
        return response

    async def message(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        connection = state.connection(request.query.get("connection_id"))
        if connection is None:
            return web.json_response({"error": "Invalid connection"}, status=400)
        try:
            body = await request.json()
        except ValueError:
            body = None
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
            return web.json_response({"error": "Invalid JSON-RPC message"}, status=400)
        reply = state.receive(connection, body)
        if reply is not None:
            connection.outbox.put_nowait(reply)
        return web.json_response({"status": "accepted"})

    app.router.add_get(SSE_PATH, sse)
    app.router.add_post(MESSAGE_PATH, message)


# ---------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------


def _answer(message: dict[str, Any]) -> dict[str, Any]:
    """The JSON-RPC reply to a request (a message with an id)."""
    request_id = message["id"]
    method = message.get("method")
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    if method == "initialize":
        return _rpc_result(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "servonaut-hosted-fake", "version": "0"},
        })
    if method == "ping":
        return _rpc_result(request_id, {})
    if method == "tools/list":
        tools = [{"name": name, "description": f"Hosted {name}.", "inputSchema": {}}
                 for name in sorted(HOSTED_TOOLS)]
        return _rpc_result(request_id, {"tools": tools})
    if method == "tools/call":
        name = params.get("name")
        if name not in HOSTED_TOOLS:
            return _rpc_result(request_id, {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True,
            })
        arguments = params.get("arguments") or {}
        text = f"hosted {name}: {len(arguments)} argument(s)"
        return _rpc_result(
            request_id, {"content": [{"type": "text", "text": text}], "isError": False},
        )
    return _rpc_error(request_id, -32601, "Method not found")


def _rpc_result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
