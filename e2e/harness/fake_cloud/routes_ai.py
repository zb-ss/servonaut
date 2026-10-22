"""AI routes: everything under ``/api/ai/`` plus the hosted-MCP endpoint.

This module owns those paths (the hosted MCP server is
``routes_hosted_mcp``). :class:`AiState` (``FakeCloud.ai``) records
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
  waits for it, unless the turn pauses;
* ``POST /api/ai/chat/continue``: the rest of a paused turn. A continuation
  the client never got, or already used, is 404 ``continuation_not_found``;
  one whose awaited results have not all arrived is 409
  ``tool_results_pending`` (retry after 1 s); otherwise the next scripted
  turn answers it;
* ``POST /api/ai/topup/checkout``: the checkout URL for a top-up pack
  (a Stripe URL unless :meth:`AiState.configure` sets another); read back
  with :meth:`AiState.topups`;
* ``/api/ai/conversations``: the chat history (list, get, archive via
  ``PATCH``, delete, Markdown/JSON export), set with :meth:`AiState.configure`.

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
CONTINUE_PATH = "/api/ai/chat/continue"
TOOL_RESULT_PATH = "/api/ai/chat/tool-result"
TOPUP_PATH = "/api/ai/topup/checkout"
TOPUP_PACKS_PATH = "/api/ai/topup/packs"
CONVERSATIONS_PATH = "/api/ai/conversations"
TOOL_RESULT_STATUSES = frozenset({"ok", "error", "timeout", "denied"})
DEFAULT_TOPUP_PACKS = (
    {"key": "pack_small", "label": "Starter", "price_minor": 500, "currency": "GBP", "credit_micros": 5_000_000},
    {"key": "pack_large", "label": "Extended", "price_minor": 2000, "currency": "GBP", "credit_micros": 20_000_000},
)
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
            self._conversations: list[dict[str, Any]] = []
            self._exports: dict[str, str] = {}
            self._turns: deque[ChatTurn] = deque()
            self._chats: list[dict[str, Any]] = []
            self._continuations: dict[str, dict[str, Any]] = {}
            self._conversation_numbers = itertools.count(1)
            self._topup_url = STRIPE_CHECKOUT_URL
            self._topups: list[dict[str, Any]] = []
            self._topup_packs: list[dict[str, Any]] = copy.deepcopy(list(DEFAULT_TOPUP_PACKS))

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
        topup_packs: Optional[Iterable[dict[str, Any]]] = None,
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
            if topup_packs is not None:
                self._topup_packs = copy.deepcopy(list(topup_packs))

    def script(self, *turns: ChatTurn) -> None:
        """Queue *turns*; each chat request consumes the next one."""
        with self._lock:
            self._turns.extend(turns)

    def chats(self) -> list[dict[str, Any]]:
        """One row per chat or continue request: its path, body, conversation id,
        frames, pings and how it ended."""
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

    def topups(self) -> list[dict[str, Any]]:
        """Top-up checkouts requested, oldest first."""
        with self._lock:
            return [dict(t) for t in self._topups]

    def topup_packs(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._topup_packs)

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

    def record_topup(self, pack: str) -> str:
        with self._lock:
            self._topups.append({"pack": pack, "at": time.time()})
            return self._topup_url

    def stream_generation(self) -> int:
        with self._lock:
            return self._streams

    def suspend(self, payload: dict[str, Any], conversation_id: str) -> None:
        """Keep a paused turn until the client continues it."""
        with self._lock:
            self._continuations[str(payload.get("continuation_id"))] = {
                "conversation_id": conversation_id,
                "awaited": list(payload.get("tool_call_ids") or []),
            }

    def continuation(self, continuation_id: str) -> Optional[dict[str, Any]]:
        """A paused turn (its conversation, awaited calls and whether all their
        results arrived), or ``None`` when there is no such paused turn."""
        with self._lock:
            found = self._continuations.get(continuation_id)
            if found is None:
                return None
            posted = {r["tool_call_id"] for r in self._tool_results}
            return {**copy.deepcopy(found), "ready": set(found["awaited"]) <= posted}

    def take_continuation(self, continuation_id: str) -> None:
        """Use up a paused turn: it can be continued once."""
        with self._lock:
            self._continuations.pop(continuation_id, None)

    def open_chat(
        self,
        body: dict[str, Any],
        *,
        path: str = CHAT_PATH,
        conversation_id: Optional[str] = None,
    ) -> tuple[Optional[ChatTurn], dict[str, Any]]:
        """Take the next scripted turn and start the record of this request."""
        with self._lock:
            turn = self._turns.popleft() if self._turns else None
            conversation_id = conversation_id or body.get("conversation_id") or (
                f"conv-e2e-{next(self._conversation_numbers)}"
            )
            record = {
                "path": path,
                # A paused turn exists only because its chat asked to split.
                "split_turns": path == CONTINUE_PATH or body.get("split_turns") is True,
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

    async def answer(
        request: web.Request, turn: Optional[ChatTurn], record: dict[str, Any]
    ) -> web.StreamResponse:
        if turn is None:
            state.update_chat(record, ended="unscripted")
            return _error(500, "internal_error", "no scripted chat turn")
        if turn.status != 200:
            state.update_chat(record, ended=f"refused:{turn.status}")
            headers = {} if turn.retry_after is None else {"Retry-After": str(turn.retry_after)}
            return web.json_response(turn.error_body or {}, status=turn.status, headers=headers)
        return await replay(request, state, turn, record)

    async def chat(request: web.Request) -> web.StreamResponse:
        turn, record = state.open_chat(await json_body(request))
        return await answer(request, turn, record)

    async def continue_chat(request: web.Request) -> web.StreamResponse:
        continuation_id = str((await json_body(request)).get("continuation_id") or "")
        paused = state.continuation(continuation_id)
        if paused is None:
            return _error(404, "continuation_not_found", "no such paused turn")
        if not paused["ready"]:
            return web.json_response(
                {"error": {"code": "tool_results_pending", "message": "results pending",
                           "details": {"retry_after": 1}}},
                status=409,
                headers={"Retry-After": "1"},
            )
        turn, record = state.open_chat(
            {"continuation_id": continuation_id},
            path=CONTINUE_PATH,
            conversation_id=paused["conversation_id"],
        )
        if turn is not None and turn.status == 200:
            # Refusals leave the paused turn for a retry, as the service does.
            state.take_continuation(continuation_id)
        return await answer(request, turn, record)

    async def tool_result(request: web.Request) -> web.Response:
        body = await json_body(request)
        problem = tool_result_problem(body)
        if problem:
            return validation_failed(problem)
        state.record_tool_result(body)
        return web.Response(status=202)

    async def topup(request: web.Request) -> web.Response:
        pack = (await json_body(request)).get("pack")
        available = {item.get("key") for item in state.topup_packs()}
        if pack not in available:
            return validation_failed("pack is not in the current top-up catalog")
        return web.json_response({"checkout_url": state.record_topup(pack)})

    async def topup_packs(request: web.Request) -> web.Response:
        return web.json_response({"packs": state.topup_packs()})

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

    one = f"{CONVERSATIONS_PATH}/{{conversation_id}}"
    app.router.add_post(CHAT_PATH, guarded(chat))
    app.router.add_post(CONTINUE_PATH, guarded(continue_chat))
    app.router.add_post(TOOL_RESULT_PATH, guarded(tool_result))
    app.router.add_post(TOPUP_PATH, guarded(topup))
    app.router.add_get(TOPUP_PACKS_PATH, guarded(topup_packs))
    app.router.add_get(CONVERSATIONS_PATH, guarded(conversations))
    app.router.add_get(f"{one}/export.{{suffix}}", guarded(export))
    app.router.add_get(one, guarded(get_conversation))
    app.router.add_patch(one, guarded(patch_conversation))
    app.router.add_delete(one, guarded(delete_conversation))


# ---------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------


def _error(status: int, code: str, message: str) -> web.Response:
    return web.json_response({"error": {"code": code, "message": message}}, status=status)
