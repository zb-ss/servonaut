"""Headless executor for AI tool calls dispatched over the Mercure relay.

The hosted AI's ``ToolDispatcher`` publishes every CLI-bound tool call to
``/cli/{user_id}/ai-tool-calls`` (mirrored on ``/cli/{user_id}/commands``
during the dual-publish transition window). In the TUI those calls are
executed by the chat panel from the chat-stream ``tool_call`` SSE event;
a headless ``servonaut connect`` session has no chat panel, so until this
module existed the dispatch sat unanswered for the full 60s tool-await
TTL and the model resumed tool-less.

This executor closes that gap: :class:`RelayListener` hands it any
relay event that is not a :class:`CommandType` verb but carries a
``tool_call_id``; it adapts the envelope into an
:class:`~servonaut.services.ai_tool_bridge.ToolCall`, drives the shared
:class:`~servonaut.services.ai_tool_bridge.AIToolBridge` (guard
escalation, dangerous floor, entitlement gate, audit trail with
``source="ai_chat"``), and POSTs the result back to
``/api/ai/chat/tool-result``.

Headless approval policy
------------------------

There is no human present to confirm. ``relay.ai_tool_auto_approve``
(``~/.servonaut/config.json``) sets the maximum guard tier the listener
may approve on its own:

- ``"readonly"``  → only read-only tools execute; everything else is denied.
- ``"standard"``  → (default) read-only + standard tools execute. This is
  the same trust model as the relayed web-console commands the listener
  already executes without local confirmation.
- ``"dangerous"`` → everything the server dispatches executes, PROVIDED
  the account also has the ``allow_dangerous_ai_tools`` entitlement —
  the bridge's entitlement gate runs first and is not bypassed.

Denied calls return ``status="denied"`` with an actionable message, so
the model can tell the user how to enable the tool instead of stalling.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

from servonaut.services.ai_tool_bridge import (
    AIToolBridge,
    ToolCall,
    ToolConfirmDenied,
    ToolResult,
    # Relay-bound tool names — used to decide whether CommandRequest-style
    # top-level fields (target_server_id) should be folded into args.
    _RELAY_TOOL_TO_TYPE,
)

if TYPE_CHECKING:
    from servonaut.services.config_manager import ConfigManager

logger = logging.getLogger(__name__)

_GUARD_RANK: Dict[str, int] = {"readonly": 0, "standard": 1, "dangerous": 2}

_VALID_AUTO_APPROVE = frozenset(_GUARD_RANK)

# Keys the bridge's _build_command_request reads to resolve the relay target.
_TARGET_ARG_KEYS = ("instance_id", "server_id", "target_server_id")


def is_ai_tool_call_event(raw: Dict[str, Any]) -> bool:
    """True when a relay event is an AI chat tool call.

    Callers only invoke this for events whose ``type`` is NOT one of the
    8 :class:`CommandType` web-console verbs, so the check here is "does
    this look like a dispatched tool call at all":

    - ``tool_call_id`` (top-level or nested in ``payload``) — the
      forward-looking marker; or
    - ``id`` + a ``type`` string — the envelope observed on the wire
      today (staging, 2026-06-11): ``{id, user_id, type=<tool name>,
      target_server_id, payload, created_at, ttl_seconds}`` with NO
      tool_call_id. The ``id`` doubles as the idempotency key.

    Unknown tool names are safe to route: the bridge synthesises a
    structured ``tool_unavailable`` error instead of executing anything.
    """
    if isinstance(raw.get("tool_call_id"), str) and raw["tool_call_id"]:
        return True
    payload = raw.get("payload")
    if isinstance(payload, dict):
        nested = payload.get("tool_call_id")
        if isinstance(nested, str) and nested:
            return True
    return (
        isinstance(raw.get("id"), str) and bool(raw["id"])
        and isinstance(raw.get("type"), str) and bool(raw["type"])
    )


def parse_mercure_tool_call(raw: Dict[str, Any]) -> Optional[ToolCall]:
    """Adapt a Mercure AI-tool-call envelope into a :class:`ToolCall`.

    Tolerates both wire shapes in the field today:

    - SSE-style 4-key dict: ``{tool_call_id, tool, args, guard_level}``
      (+ ``user_id``/``conversation_id`` added for the Mercure publish).
    - CommandRequest-style: ``{id, user_id, type=<tool name>,
      target_server_id, payload=<args>, ttl_seconds, tool_call_id}`` —
      the shape ``ToolDispatcher`` historically published to
      ``/cli/{uid}/commands``.

    Returns ``None`` when no tool name or no ``tool_call_id`` can be
    resolved — the caller logs and skips (never guess an execution).

    Note: the server serialises an empty args payload as a JSON array
    (PHP ``[]``), not an object — observed on the wire 2026-06-11.
    Anything that isn't a dict is treated as "no args".
    """
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}

    tool = raw.get("tool") or raw.get("type") or ""
    if not isinstance(tool, str) or not tool:
        return None

    tool_call_id = (
        raw.get("tool_call_id")
        or payload.get("tool_call_id")
        or raw.get("id")
        or ""
    )
    if not isinstance(tool_call_id, str) or not tool_call_id:
        return None

    # Args: SSE shape puts them in ``args``; CommandRequest shape in
    # ``payload``. A payload that only wrapped metadata (tool_call_id,
    # conversation_id) still passes through — the bridge's per-tool arg
    # handling tolerates extras for relay tools and TypeErrors cleanly
    # (reason="bad_args") for local handlers.
    raw_args = raw.get("args")
    if isinstance(raw_args, dict):
        args = dict(raw_args)
    elif isinstance(raw_args, str) and raw_args.strip():
        try:
            decoded = json.loads(raw_args)
            args = decoded if isinstance(decoded, dict) else {}
        except (ValueError, TypeError):
            logger.warning(
                "ai-tool-call args was a non-JSON string for tool=%s call=%s",
                tool, tool_call_id,
            )
            args = {}
    elif payload:
        args = {
            k: v for k, v in payload.items()
            if k not in ("tool_call_id", "conversation_id", "guard_level")
        }
    else:
        args = {}

    # CommandRequest-style target: fold into args for relay-bound tools so
    # the bridge's target resolution finds it. Local ServonautTools
    # handlers get their args untouched (an unexpected kwarg would
    # TypeError as reason="bad_args").
    target = raw.get("target_server_id")
    if (
        tool in _RELAY_TOOL_TO_TYPE
        and isinstance(target, str) and target
        and not any(k in args for k in _TARGET_ARG_KEYS)
    ):
        args["target_server_id"] = target

    conversation_id = (
        raw.get("conversation_id")
        or payload.get("conversation_id")
        or ""
    )
    if not conversation_id and raw.get("source") != "proactive":
        # Proactive probe envelopes legitimately carry no
        # conversation_id — their results go to the command-result
        # route, not the chat tool-result route.
        logger.warning(
            "ai-tool-call %s arrived without conversation_id — the "
            "tool-result POST will be rejected with validation_failed",
            tool_call_id,
        )

    # Guard: prefer the server-supplied level; fall back to the client
    # mirror (NOT a blanket "standard") so a readonly tool dispatched by
    # an older server without guard_level isn't denied under a
    # readonly-only auto-approve policy. The bridge re-escalates against
    # the mirror + dangerous floor regardless, so this can never relax
    # the effective tier.
    guard_level = (
        raw.get("guard_level")
        or payload.get("guard_level")
        or AIToolBridge.guard_for(tool)
    )

    return ToolCall(
        tool_call_id=str(tool_call_id),
        tool=tool,
        args=args,
        guard_level=str(guard_level),  # type: ignore[arg-type]
        conversation_id=str(conversation_id),
    )


def build_headless_confirm(config_manager: "ConfigManager"):
    """Confirm callback for headless sessions — policy, not a prompt.

    Reads ``relay.ai_tool_auto_approve`` live on every call (config edits
    apply without restarting the listener). Approves calls at or below
    the configured tier; raises :class:`ToolConfirmDenied` above it so
    the audit row carries a distinct reason code instead of the
    interactive ``user_declined``.
    """

    async def _confirm(call: ToolCall) -> bool:
        cfg = config_manager.get().relay
        auto_approve = (cfg.ai_tool_auto_approve or "standard").strip().lower()
        if auto_approve not in _VALID_AUTO_APPROVE:
            logger.warning(
                "Invalid relay.ai_tool_auto_approve=%r — treating as 'readonly'",
                cfg.ai_tool_auto_approve,
            )
            auto_approve = "readonly"
        call_rank = _GUARD_RANK.get(call.guard_level, _GUARD_RANK["standard"])
        if call_rank <= _GUARD_RANK[auto_approve]:
            logger.info(
                "headless auto-approve: tool=%s guard=%s policy=%s call=%s",
                call.tool, call.guard_level, auto_approve, call.tool_call_id,
            )
            return True
        raise ToolConfirmDenied(
            f"Tool {call.tool!r} requires {call.guard_level!r} approval, but "
            f"this headless relay listener auto-approves up to "
            f"{auto_approve!r} only. Run the tool from the Servonaut TUI "
            f"chat (interactive confirmation), or raise "
            f"relay.ai_tool_auto_approve in ~/.servonaut/config.json.",
            reason="headless_policy_denied",
        )

    return _confirm


class RelayAIToolExecutor:
    """Executes AI tool calls received by a headless relay listener.

    Owns the parse → bridge → post-result round trip for one event. The
    listener calls :meth:`execute` from its event loop; every path POSTs
    a tool result (the server's turn stays open until it lands), and no
    exception escapes back into the listener's SSE loop.
    """

    def __init__(self, bridge: AIToolBridge) -> None:
        self._bridge = bridge

    async def execute(self, raw: Dict[str, Any]) -> Optional[ToolResult]:
        """Run one AI tool call end-to-end. Returns the posted result.

        Returns ``None`` only when the envelope is unparseable (no tool
        name / tool_call_id) — there is nothing to POST a result for.
        """
        call = parse_mercure_tool_call(raw)
        if call is None:
            logger.warning(
                "Unparseable ai-tool-call event (keys: %s) — skipping",
                sorted(raw.keys()),
            )
            return None

        logger.info(
            "relay ai-tool-call received: tool=%s call=%s guard=%s conv=%s",
            call.tool, call.tool_call_id, call.guard_level,
            call.conversation_id or "<empty>",
        )

        try:
            result = await self._bridge.handle_tool_call(call)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            # Mirror of the chat panel's C4 fallback: the bridge raised
            # before producing a ToolResult; synthesise an error envelope
            # so the server's turn closes instead of burning the await TTL.
            logger.exception(
                "AIToolBridge.handle_tool_call raised for %s", call.tool_call_id,
            )
            message = f"Tool execution failed: {exc}"
            result = ToolResult(
                tool_call_id=call.tool_call_id,
                conversation_id=call.conversation_id,
                status="error",
                result=message,
                error=str(exc),
                bytes=len(message.encode("utf-8")),
            )

        try:
            await self._bridge.post_tool_result(result)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            # post_tool_result already logged specifics; the listener loop
            # must survive (the server will time the await out gracefully).
            hint = ""
            if not result.conversation_id:
                hint = (
                    " (the dispatch envelope carried no conversation_id, "
                    "which /api/ai/chat/tool-result requires — known "
                    "server-side contract gap)"
                )
            logger.warning(
                "tool-result POST failed for %s status=%s — server will "
                "time out the await%s",
                result.tool_call_id, result.status, hint,
            )
        return result


__all__ = [
    "RelayAIToolExecutor",
    "build_headless_confirm",
    "is_ai_tool_call_event",
    "parse_mercure_tool_call",
]
