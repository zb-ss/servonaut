"""AI routes: everything under ``/api/ai/`` plus the hosted-MCP endpoint.

This module owns those paths. :class:`AiState` (``FakeCloud.ai``) records
what clients sent and holds the scripted answers:

* ``POST /api/ai/chat/tool-result``: a tool result for a chat turn,
  validated like the service (422 on a malformed body); read back with
  :meth:`AiState.tool_results`;
* ``GET /api/ai/conversations``: the chat history, set with
  :meth:`AiState.configure`;
* ``POST /mcp/message``: a JSON-RPC 2.0 ``tools/call`` for the hosted MCP
  server, which answers the tools in :data:`HOSTED_TOOLS`; read back with
  :meth:`AiState.hosted_calls`.

Every route needs the account's current access token.
"""

from __future__ import annotations

import copy
import threading
import time
from typing import Any, Optional

from aiohttp import web

from e2e.harness.fake_cloud.routes_auth import (
    bearer_ok,
    json_body,
    unauthorized,
    validation_failed,
)
from e2e.harness.fake_cloud.state import ScenarioStore

TOOL_RESULT_PATH = "/api/ai/chat/tool-result"
CONVERSATIONS_PATH = "/api/ai/conversations"
HOSTED_MCP_PATH = "/mcp/message"
# Tools the fake hosted MCP server answers; any other name is an error.
HOSTED_TOOLS = frozenset({"fleet_summary"})
TOOL_RESULT_STATUSES = frozenset({"ok", "error", "timeout", "denied"})


class AiState:
    """Thread-safe records and scripted answers for the AI routes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._tool_results: list[dict[str, Any]] = []
            self._hosted_calls: list[dict[str, Any]] = []
            self._conversations: list[dict[str, Any]] = []

    def configure(self, *, conversations: Optional[list[dict[str, Any]]] = None) -> None:
        with self._lock:
            if conversations is not None:
                self._conversations = copy.deepcopy(conversations)

    def tool_results(self, tool_call_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Accepted tool results, oldest first, optionally for one call."""
        with self._lock:
            rows = [dict(r) for r in self._tool_results]
        return [r for r in rows if tool_call_id is None or r["tool_call_id"] == tool_call_id]

    def hosted_calls(self) -> list[dict[str, Any]]:
        """JSON-RPC envelopes the hosted-MCP endpoint received, oldest first."""
        with self._lock:
            return [dict(c) for c in self._hosted_calls]

    def conversations(self, status: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(c) for c in self._conversations if c.get("status", "active") == status]

    def record_tool_result(self, body: dict[str, Any]) -> None:
        with self._lock:
            self._tool_results.append({**body, "at": time.time()})

    def record_hosted_call(self, body: dict[str, Any]) -> None:
        with self._lock:
            self._hosted_calls.append({**body, "at": time.time()})


def tool_result_problem(body: dict[str, Any]) -> Optional[str]:
    """Why the service would refuse this tool result, or None."""
    for key in ("conversation_id", "tool_call_id"):
        if not isinstance(body.get(key), str) or not body[key]:
            return f"{key} is required"
    if body.get("status") not in TOOL_RESULT_STATUSES:
        return f"status must be one of {sorted(TOOL_RESULT_STATUSES)}"
    if not isinstance(body.get("result"), str):
        return "result must be a string"
    size = body.get("bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return "bytes must be a non-negative integer"
    return None


def add_routes(app: web.Application, store: ScenarioStore, state: AiState) -> None:
    """Register the AI routes on *app*."""

    def guarded(handler: Any) -> Any:
        async def wrapper(request: web.Request) -> web.StreamResponse:
            if not bearer_ok(request, store):
                return unauthorized()
            return await handler(request)

        return wrapper

    async def tool_result(request: web.Request) -> web.Response:
        body = await json_body(request)
        problem = tool_result_problem(body)
        if problem:
            return validation_failed(problem)
        state.record_tool_result(body)
        return web.Response(status=202)

    async def conversations(request: web.Request) -> web.Response:
        items = state.conversations(request.query.get("status", "active"))
        return web.json_response({"items": items, "next_before": None})

    async def hosted_mcp(request: web.Request) -> web.Response:
        envelope = await json_body(request)
        if envelope.get("jsonrpc") != "2.0" or "id" not in envelope:
            return web.json_response(_rpc_error(None, -32600, "Invalid Request"), status=400)
        state.record_hosted_call(envelope)
        return web.json_response(_hosted_answer(envelope))

    app.router.add_post(TOOL_RESULT_PATH, guarded(tool_result))
    app.router.add_get(CONVERSATIONS_PATH, guarded(conversations))
    app.router.add_post(HOSTED_MCP_PATH, guarded(hosted_mcp))


def _hosted_answer(envelope: dict[str, Any]) -> dict[str, Any]:
    """A JSON-RPC 2.0 answer from the fake hosted MCP server."""
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
