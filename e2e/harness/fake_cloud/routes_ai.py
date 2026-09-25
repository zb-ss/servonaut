"""AI routes: everything under ``/api/ai/`` plus the hosted-MCP endpoint.

This module owns those paths. :class:`AiState` (``FakeCloud.ai``) records
what clients sent and holds the scripted answers:

* ``POST /api/ai/chat``: the hosted chat, streamed as server-sent events
  (by ``chat_stream``) from the
  :class:`~e2e.harness.fake_cloud.chat_script.ChatTurn` queued with
  :meth:`AiState.script` (one per request; nothing queued answers 500).
  Each request is recorded with how its stream ended
  (:meth:`AiState.chats`);
* ``POST /api/ai/chat/tool-result``: a tool result for a chat turn,
  validated like the service (422 on a malformed body); read back with
  :meth:`AiState.tool_results`. A chat stream that sent a ``tool_call``
  waits for it;
* ``POST /api/ai/topup/checkout``: the checkout URL for a top-up pack
  (a Stripe URL unless :meth:`AiState.configure` sets another); read back
  with :meth:`AiState.topups`;
* ``/api/ai/conversations``: the chat history (list, get, archive via
  ``PATCH``, delete, Markdown/JSON export), set with :meth:`AiState.configure`;
* ``POST /mcp/message``: a JSON-RPC 2.0 ``tools/call`` for the hosted MCP
  server, which answers the tools in :data:`HOSTED_TOOLS`; read back with
  :meth:`AiState.hosted_calls`.

Every route needs the account's current access token.
"""

from __future__ import annotations

import copy
import itertools
import threading
import time
from collections import deque
from typing import Any, Iterable, Optional

from aiohttp import web

from e2e.harness.fake_cloud.chat_script import ChatTurn
from e2e.harness.fake_cloud.chat_stream import replay
from e2e.harness.fake_cloud.routes_auth import (
    bearer_ok,
    json_body,
    unauthorized,
    validation_failed,
)
from e2e.harness.fake_cloud.state import ScenarioStore

CHAT_PATH = "/api/ai/chat"
TOOL_RESULT_PATH = "/api/ai/chat/tool-result"
TOPUP_PATH = "/api/ai/topup/checkout"
CONVERSATIONS_PATH = "/api/ai/conversations"
HOSTED_MCP_PATH = "/mcp/message"
# Tools the fake hosted MCP server answers; any other name is an error.
HOSTED_TOOLS = frozenset({"fleet_summary"})
TOOL_RESULT_STATUSES = frozenset({"ok", "error", "timeout", "denied"})
TOPUP_PACKS = frozenset({"small", "medium", "large"})
STRIPE_CHECKOUT_URL = "https://checkout.stripe.com/c/pay/cs_test_e2e_0001"


class AiState:
    """Thread-safe records and scripted answers for the AI routes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._streams = 0  # bumped to end every open chat stream
        self.reset()

    def reset(self) -> None:
        """Forget everything and end the chat streams still open."""
        with self._lock:
            self._streams += 1
            self._tool_results: list[dict[str, Any]] = []
            self._hosted_calls: list[dict[str, Any]] = []
            self._conversations: list[dict[str, Any]] = []
            self._exports: dict[str, str] = {}
            self._turns: deque[ChatTurn] = deque()
            self._chats: list[dict[str, Any]] = []
            self._conversation_numbers = itertools.count(1)
            self._topup_url = STRIPE_CHECKOUT_URL
            self._topups: list[dict[str, Any]] = []

    def drop_streams(self) -> None:
        """End every open chat stream (they check between frames)."""
        with self._lock:
            self._streams += 1

    def configure(
        self,
        *,
        conversations: Optional[Iterable[dict[str, Any]]] = None,
        exports: Optional[dict[str, str]] = None,
        topup_url: Optional[str] = None,
    ) -> None:
        """Set the stored conversations (see ``chat_script.conversation_row``),
        their Markdown exports by id, and the top-up checkout URL."""
        with self._lock:
            if conversations is not None:
                self._conversations = copy.deepcopy(list(conversations))
            if exports is not None:
                self._exports = dict(exports)
            if topup_url is not None:
                self._topup_url = topup_url

    def script(self, *turns: ChatTurn) -> None:
        """Queue *turns*; each chat request consumes the next one."""
        with self._lock:
            self._turns.extend(turns)

    def chats(self) -> list[dict[str, Any]]:
        """One row per chat request: body, conversation id, frames, pings, how it ended."""
        with self._lock:
            return copy.deepcopy(self._chats)

    def open_streams(self) -> list[dict[str, Any]]:
        """Chat requests whose stream has not ended yet."""
        return [chat for chat in self.chats() if chat["ended"] == "open"]

    def tool_results(self, tool_call_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Accepted tool results, oldest first, optionally for one call."""
        with self._lock:
            rows = [dict(r) for r in self._tool_results]
        return [r for r in rows if tool_call_id is None or r["tool_call_id"] == tool_call_id]

    def hosted_calls(self) -> list[dict[str, Any]]:
        """JSON-RPC envelopes the hosted-MCP endpoint received, oldest first."""
        with self._lock:
            return [dict(c) for c in self._hosted_calls]

    def topups(self) -> list[dict[str, Any]]:
        """Top-up checkouts requested, oldest first."""
        with self._lock:
            return [dict(t) for t in self._topups]

    def conversations(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        """Conversation summaries (without their messages), optionally by status."""
        with self._lock:
            rows = [{k: v for k, v in c.items() if k != "messages"} for c in self._conversations]
        return [c for c in rows if status is None or c.get("status", "active") == status]

    # ------------------------------------------------------------------
    # Route API (server loop)
    # ------------------------------------------------------------------

    def record_tool_result(self, body: dict[str, Any]) -> None:
        with self._lock:
            self._tool_results.append({**body, "at": time.time()})

    def record_hosted_call(self, body: dict[str, Any]) -> None:
        with self._lock:
            self._hosted_calls.append({**body, "at": time.time()})

    def record_topup(self, pack: str) -> str:
        with self._lock:
            self._topups.append({"pack": pack, "at": time.time()})
            return self._topup_url

    def stream_generation(self) -> int:
        with self._lock:
            return self._streams

    def open_chat(self, body: dict[str, Any]) -> tuple[Optional[ChatTurn], dict[str, Any]]:
        """Take the next scripted turn and start the record of this chat."""
        with self._lock:
            turn = self._turns.popleft() if self._turns else None
            conversation_id = body.get("conversation_id") or (
                f"conv-e2e-{next(self._conversation_numbers)}"
            )
            record = {
                "body": copy.deepcopy(body),
                "conversation_id": conversation_id,
                "frames": 0,
                "pings": 0,
                "ended": "open",
            }
            self._chats.append(record)
            return turn, record

    def update_chat(self, record: dict[str, Any], **changes: Any) -> None:
        with self._lock:
            record.update(changes)

    def conversation(self, conversation_id: str) -> Optional[dict[str, Any]]:
        """One conversation with its messages, as ``GET .../{id}`` returns it."""
        with self._lock:
            found = next((c for c in self._conversations if c.get("id") == conversation_id), None)
            return {"messages": [], **copy.deepcopy(found)} if found else None

    def update_conversation(self, conversation_id: str, changes: dict[str, Any]) -> Optional[dict]:
        with self._lock:
            for row in self._conversations:
                if row.get("id") == conversation_id:
                    row.update(changes)
                    return {k: v for k, v in row.items() if k != "messages"}
        return None

    def delete_conversation(self, conversation_id: str) -> bool:
        with self._lock:
            before = len(self._conversations)
            self._conversations = [c for c in self._conversations if c.get("id") != conversation_id]
            return len(self._conversations) != before

    def export(self, conversation_id: str) -> Optional[str]:
        with self._lock:
            if conversation_id in self._exports:
                return self._exports[conversation_id]
            row = next((c for c in self._conversations if c.get("id") == conversation_id), None)
        if row is None:
            return None
        title = row.get("title", conversation_id)
        return f"# {title}\n\nExported conversation {conversation_id}.\n"


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

    async def chat(request: web.Request) -> web.StreamResponse:
        turn, record = state.open_chat(await json_body(request))
        if turn is None:
            state.update_chat(record, ended="unscripted")
            return _error(500, "internal_error", "no scripted chat turn")
        if turn.status != 200:
            state.update_chat(record, ended=f"refused:{turn.status}")
            return web.json_response(turn.error_body or {}, status=turn.status)
        return await replay(request, state, turn, record)

    async def tool_result(request: web.Request) -> web.Response:
        body = await json_body(request)
        problem = tool_result_problem(body)
        if problem:
            return validation_failed(problem)
        state.record_tool_result(body)
        return web.Response(status=202)

    async def topup(request: web.Request) -> web.Response:
        pack = (await json_body(request)).get("pack")
        if pack not in TOPUP_PACKS:
            return validation_failed(f"pack must be one of {sorted(TOPUP_PACKS)}")
        return web.json_response({"checkout_url": state.record_topup(pack)})

    async def conversations(request: web.Request) -> web.Response:
        items = state.conversations(request.query.get("status", "active"))
        return web.json_response({"items": items, "next_before": None})

    async def get_conversation(request: web.Request) -> web.Response:
        row = state.conversation(request.match_info["conversation_id"])
        if row is None:
            return _error(404, "not_found", "conversation not found")
        return web.json_response(row)

    async def patch_conversation(request: web.Request) -> web.Response:
        body = await json_body(request)
        changes = {k: body[k] for k in ("title", "status") if k in body}
        row = state.update_conversation(request.match_info["conversation_id"], changes)
        if row is None:
            return _error(404, "not_found", "conversation not found")
        return web.json_response(row)

    async def delete_conversation(request: web.Request) -> web.Response:
        if not state.delete_conversation(request.match_info["conversation_id"]):
            return _error(404, "not_found", "conversation not found")
        return web.Response(status=204)

    async def export(request: web.Request) -> web.Response:
        suffix = request.match_info["suffix"]
        text = state.export(request.match_info["conversation_id"])
        if text is None or suffix not in ("md", "json"):
            return _error(404, "not_found", "conversation not found")
        content_type = "text/markdown" if suffix == "md" else "application/octet-stream"
        return web.Response(body=text.encode("utf-8"), content_type=content_type)

    async def hosted_mcp(request: web.Request) -> web.Response:
        envelope = await json_body(request)
        if envelope.get("jsonrpc") != "2.0" or "id" not in envelope:
            return web.json_response(_rpc_error(None, -32600, "Invalid Request"), status=400)
        state.record_hosted_call(envelope)
        return web.json_response(_hosted_answer(envelope))

    one = f"{CONVERSATIONS_PATH}/{{conversation_id}}"
    app.router.add_post(CHAT_PATH, guarded(chat))
    app.router.add_post(TOOL_RESULT_PATH, guarded(tool_result))
    app.router.add_post(TOPUP_PATH, guarded(topup))
    app.router.add_get(CONVERSATIONS_PATH, guarded(conversations))
    app.router.add_get(f"{one}/export.{{suffix}}", guarded(export))
    app.router.add_get(one, guarded(get_conversation))
    app.router.add_patch(one, guarded(patch_conversation))
    app.router.add_delete(one, guarded(delete_conversation))
    app.router.add_post(HOSTED_MCP_PATH, guarded(hosted_mcp))


# ---------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------


def _error(status: int, code: str, message: str) -> web.Response:
    return web.json_response({"error": {"code": code, "message": message}}, status=status)


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
