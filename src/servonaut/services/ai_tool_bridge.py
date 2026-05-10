"""Bridge between hosted AI ``tool_call`` SSE events and the local relay (T6).

Receives :class:`ToolCall` events the streaming consumer surfaces from
``POST /api/ai/chat``, drives a confirmation modal sized by the tool's
``guard_level``, executes the call via :class:`RelayExecutors`, then
posts the result back to ``POST /api/ai/chat/tool-result`` so the
server can close its turn.

Hard requirements (architect plan §T6 invariants):

- ``readonly``  → no confirm prompt, execute immediately.
- ``standard``  → ``confirm_callback`` returns y/n.
- ``dangerous`` → ``confirm_callback`` returns typed-RUN; only reachable
  when ``auth_service.has_dangerous_ai_tools`` is True.
- Local execution timeout (``asyncio.TimeoutError``) → ``status="timeout"``.
- Local exception → ``status="error"`` with populated ``error`` field.
  *Never* swallow without posting back — the server is waiting on the
  round-trip to close its turn.
- ``bytes`` = UTF-8 byte length of the *stringified* result (architect
  plan §"Critical decisions" item 10).
- Audit row tagged ``source="ai_chat"`` with ``conversation_id`` +
  ``tool_call_id`` for traceability.

This module is import-light: only the standard library plus stable
intra-package imports. Tests can construct an ``AIToolBridge`` with all
collaborators mocked.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Literal,
    Optional,
    TYPE_CHECKING,
)

from servonaut.models.relay_messages import (
    CommandRequest,
    CommandResponse,
    CommandType,
)

if TYPE_CHECKING:
    from servonaut.mcp.audit import AuditTrail
    from servonaut.mcp.tools import ServonautTools
    from servonaut.services.api_client import APIClient
    from servonaut.services.auth_service import AuthService
    from servonaut.services.config_manager import ConfigManager
    from servonaut.services.ip_ban_service import IPBanService
    from servonaut.services.relay_executors import RelayExecutors

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool guard map (mirror of the server-side authoritative table)
# ---------------------------------------------------------------------------
#
# Per architect plan §"Critical decisions" item 4: encoding the table as a
# Python dict keeps it versioned with the CLI and out of user-editable
# config surface. The server is authoritative; this mirror exists for
# UI affordance gating ("hide the dangerous-tool buttons unless the
# admin enabled the flag") and for confirm-modal sizing.
_TOOL_GUARDS: Dict[str, Literal["readonly", "standard", "dangerous"]] = {
    "list_instances": "readonly",
    "tail_log": "readonly",
    "describe_instance": "readonly",
    "cost_report": "readonly",
    "ip_ban_status": "readonly",
    "ssh_exec_readonly": "readonly",
    "run_command": "standard",
    "transfer_file": "standard",
    "deploy": "dangerous",
    "provision": "dangerous",
    "security_scan": "dangerous",
    # Hetzner Cloud — readonly catalogue queries vs. mutating lifecycle.
    "hetzner_list_servers": "readonly",
    "hetzner_list_server_types": "readonly",
    "hetzner_list_ssh_keys": "readonly",
    "hetzner_create_ssh_key": "standard",
    "hetzner_create_server": "dangerous",
    "hetzner_delete_server": "dangerous",
}

# Strict ordering of guard severity. Used by :func:`_escalate_guard` to
# enforce "client mirror is the floor" — a server-supplied guard_level
# must NEVER drop below the client-side mirror, otherwise a malicious or
# buggy server could ship ``tool="deploy", guard_level="standard"`` to
# bypass the typed-RUN modal + dangerous-entitlement gate (A3 fix).
_GUARD_ORDER: Dict[str, int] = {"readonly": 0, "standard": 1, "dangerous": 2}


def _escalate_guard(
    server_guard: str,
    client_guard: str,
) -> Literal["readonly", "standard", "dangerous"]:
    """Return ``max(server_guard, client_guard)`` by severity.

    The client mirror is authoritative as a floor: even if the server's
    payload claims a tool is ``standard``, our :data:`_TOOL_GUARDS` mapping
    keeps the client-side gate (typed-RUN + dangerous entitlement) intact
    when the canonical guard is ``dangerous``.

    Unknown guard strings on either side default to ``standard`` rather
    than ``readonly`` so a typo never relaxes confirmation.
    """
    server_rank = _GUARD_ORDER.get(server_guard, 1)
    client_rank = _GUARD_ORDER.get(client_guard, 1)
    if server_rank >= client_rank:
        # Cast — already validated via _GUARD_ORDER membership.
        return server_guard if server_guard in _GUARD_ORDER else "standard"  # type: ignore[return-value]
    return client_guard if client_guard in _GUARD_ORDER else "standard"  # type: ignore[return-value]


# Tools that flow through the local relay — the rest run server-side and
# only surface to the CLI as ``tool_result`` events. If we receive a
# ``tool_call`` for a non-relay tool, that's a server-side bug; we POST
# back ``status="error"`` so the turn doesn't hang.
_RELAY_TOOL_TO_TYPE: Dict[str, CommandType] = {
    "run_command": CommandType.RUN_COMMAND,
    "ssh_exec_readonly": CommandType.RUN_COMMAND,
    "tail_log": CommandType.GET_LOGS,
    "transfer_file": CommandType.TRANSFER_FILE,
    "deploy": CommandType.DEPLOY,
    "provision": CommandType.PROVISION_APPLY,
    "security_scan": CommandType.SECURITY_SCAN,
}

# Readonly tools that don't need the relay — they query the CLI's own
# AWS / config surface directly via :class:`ServonautTools`. The server-
# side AI catalog advertises these alongside relay tools (the model
# doesn't distinguish), so the bridge needs a parallel local dispatch
# path. Maps tool name → ``ServonautTools`` async method name.
#
# ``cost_report`` is intentionally absent: it's resolved server-side and
# should arrive as a ``tool_result`` event, not a ``tool_call``. If the
# server wrongly dispatches it to the CLI, the unmapped path handles it
# gracefully (see ``handle_tool_call`` and ``UNAVAILABLE_TOOL_HINTS``).
_LOCAL_TOOL_HANDLERS: Dict[str, str] = {
    "list_instances":    "list_instances",
    "describe_instance": "get_server_info",
}

# Tools the catalog advertises but that aren't dispatchable on this
# CLI build. The bridge synthesises a structured ``tool_result`` so the
# model knows to pick a different approach instead of stalling, and the
# chat panel surfaces a one-line note to the user.
UNAVAILABLE_TOOL_HINTS: Dict[str, str] = {
    "cost_report": (
        "cost_report runs server-side; the CLI does not dispatch it. "
        "If you see this, the hosted AI emitted a tool_call instead of "
        "a tool_result — answer from your training data or ask the user."
    ),
}

# Default cap for AI-driven tool calls (mirrors the relay clamp at 300s).
# We pick a smaller default so a misbehaving model can't hold the chat
# turn open for the whole 5 minutes; the user's original confirm is
# still held while we run the command.
_DEFAULT_TTL_SECONDS = 60

# Tool-result endpoint per plan §"Tool-result POST".
_TOOL_RESULT_PATH = "/api/ai/chat/tool-result"


# ---------------------------------------------------------------------------
# Tool-result compaction thresholds
# ---------------------------------------------------------------------------
#
# Server caps the POST body at 12 MB. Two-stage CLI-side compaction:
# stage 1 (lossless run-length collapse) triggers above
# ``_COMPACTION_THRESHOLD_BYTES``; stage 2 (head+tail truncation) only fires
# if stage 1 still leaves the body above ``_POST_THRESHOLD_BYTES``. The
# 4 MB headroom under the server cap absorbs JSON envelope overhead and
# any expansion from the truncation marker.
#
# Why deterministic, not AI-summarised: the compaction process has no
# user question in context, so it can't tell signal from noise; running
# raw log content through an LLM also opens a prompt-injection surface.
# Run-length collapse + head/tail slice is verifiable and cheap.
_COMPACTION_THRESHOLD_BYTES = 1 * 1024 * 1024     # 1 MiB — stage 1 trigger
_POST_THRESHOLD_BYTES = 8 * 1024 * 1024           # 8 MiB — stage 2 trigger
_HEAD_BYTES = 2 * 1024 * 1024                     # head slice in stage 2
_TAIL_BYTES = 2 * 1024 * 1024                     # tail slice in stage 2


def _stage1_collapse_runs(text: str) -> "tuple[str, int]":
    """Collapse runs of byte-identical consecutive lines (lossless).

    A run of ``N >= 2`` consecutive identical lines is replaced with a
    single ``[N× repeated] <line>`` marker. The marker preserves count
    + sample, so an oncall reading the result still sees what happened.

    Returns ``(compacted_text, runs_collapsed)``. Lines with no runs
    pass through unchanged. Trailing newline is preserved.
    """
    if "\n" not in text:
        return text, 0

    lines = text.split("\n")
    runs_collapsed = 0
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        j = i + 1
        while j < n and lines[j] == lines[i]:
            j += 1
        run_len = j - i
        if run_len >= 2:
            out.append(f"[{run_len}× repeated] {lines[i]}")
            runs_collapsed += 1
        else:
            out.append(lines[i])
        i = j
    return "\n".join(out), runs_collapsed


def _stage2_head_tail(
    text: str,
    head_bytes: int,
    tail_bytes: int,
) -> str:
    """Slice ``text`` to head + truncation marker + tail (lossy fallback).

    Multi-line content slices on line boundaries so the body stays
    readable. Single-line / binary content with no newlines falls back
    to UTF-8 byte slicing with ``errors="replace"`` to handle multi-byte
    boundary breaks.
    """
    encoded = text.encode("utf-8")
    total_bytes = len(encoded)

    if "\n" in text:
        lines = text.split("\n")
        n = len(lines)

        head: list[str] = []
        head_used = 0
        head_idx = n  # consumed everything if loop completes without break
        for idx, line in enumerate(lines):
            line_bytes = _utf8_len(line) + 1  # +1 for the '\n' separator
            if head_used + line_bytes > head_bytes:
                head_idx = idx
                break
            head.append(line)
            head_used += line_bytes

        tail: list[str] = []
        tail_used = 0
        tail_start = n
        for idx in range(n - 1, head_idx - 1, -1):
            line = lines[idx]
            line_bytes = _utf8_len(line) + 1
            if tail_used + line_bytes > tail_bytes:
                tail_start = idx + 1
                break
            tail.insert(0, line)
            tail_used += line_bytes
            tail_start = idx

        omitted_lines = max(0, tail_start - head_idx)
        omitted_bytes = max(0, total_bytes - head_used - tail_used)
        marker = (
            f"... [truncated: {omitted_bytes} bytes / {omitted_lines} "
            "lines omitted by Servonaut CLI to fit AI context] ..."
        )
        return "\n".join(head + [marker] + tail)

    # Single-line / binary fallback.
    head_slice = encoded[:head_bytes].decode("utf-8", errors="replace")
    tail_slice = encoded[-tail_bytes:].decode("utf-8", errors="replace")
    omitted_bytes = max(0, total_bytes - head_bytes - tail_bytes)
    marker = (
        f"... [truncated: {omitted_bytes} bytes / 0 "
        "lines omitted by Servonaut CLI to fit AI context] ..."
    )
    return head_slice + marker + tail_slice


def _compact_for_post(
    content: str,
    tool_name: str,
) -> "tuple[str, Dict[str, Any]]":
    """Compact a tool-result body for ``POST /api/ai/chat/tool-result``.

    Stage 1 (always lossless): run-length collapse of identical
    consecutive lines, only fires above ``_COMPACTION_THRESHOLD_BYTES``.
    Stage 2 (lossy fallback): head+tail slice with a single visible
    truncation marker, only fires if stage 1 leaves the body above
    ``_POST_THRESHOLD_BYTES``.

    Returns ``(compacted, stats)`` where ``stats`` is suitable for an
    INFO log line: ``{tool, original_bytes, final_bytes, runs_collapsed,
    truncated}``. Bodies under the threshold pass through unchanged with
    ``runs_collapsed=0`` and ``truncated=False``.
    """
    original_bytes = _utf8_len(content)
    stats: Dict[str, Any] = {
        "tool": tool_name,
        "original_bytes": original_bytes,
        "final_bytes": original_bytes,
        "runs_collapsed": 0,
        "truncated": False,
    }

    if original_bytes <= _COMPACTION_THRESHOLD_BYTES:
        return content, stats

    stage1, runs_collapsed = _stage1_collapse_runs(content)
    stats["runs_collapsed"] = runs_collapsed
    stage1_bytes = _utf8_len(stage1)

    if stage1_bytes <= _POST_THRESHOLD_BYTES:
        stats["final_bytes"] = stage1_bytes
        return stage1, stats

    stage2 = _stage2_head_tail(stage1, _HEAD_BYTES, _TAIL_BYTES)
    stats["final_bytes"] = _utf8_len(stage2)
    stats["truncated"] = True
    return stage2, stats


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ToolCall:
    """A ``tool_call`` SSE event the model wants the CLI to execute."""

    tool_call_id: str
    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    guard_level: Literal["readonly", "standard", "dangerous"] = "standard"
    conversation_id: str = ""


@dataclass
class ToolResult:
    """Result we POST back to ``/api/ai/chat/tool-result``.

    ``skipped`` flags results synthesised because the CLI couldn't
    dispatch the tool at all (unmapped name, missing collaborator).
    The POST happens anyway as a best-effort signal to the server, but
    a 404 from ``recordResult`` (which validates the row is still in
    ``status=pending``) is swallowed silently — the server may have
    already moved the row to a terminal state by the time we POST,
    which is expected for these refused calls and not worth surfacing
    to the user as a hard error.
    """

    tool_call_id: str
    conversation_id: str
    status: Literal["ok", "error", "timeout", "denied"]
    result: str = ""
    error: Optional[str] = None
    bytes: int = 0
    skipped: bool = False


# Type alias for the modal driver. The chat panel injects a callable
# that pushes the right confirm modal for the guard level and awaits
# the user's response; returning ``False`` denies the call.
ConfirmCallback = Callable[[ToolCall], Awaitable[bool]]


# ---------------------------------------------------------------------------
# AIToolBridge
# ---------------------------------------------------------------------------


class AIToolBridge:
    """Owns the tool_call → confirm → execute → tool-result POST flow."""

    def __init__(
        self,
        api_client: "APIClient",
        relay_executors: "RelayExecutors",
        mcp_audit: "AuditTrail",
        *,
        confirm_callback: ConfirmCallback,
        auth_service: "AuthService",
        servonaut_tools: Optional["ServonautTools"] = None,
        ip_ban_service: Optional["IPBanService"] = None,
        default_ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._api = api_client
        self._executors = relay_executors
        self._audit = mcp_audit
        self._confirm = confirm_callback
        self._auth = auth_service
        self._servonaut_tools = servonaut_tools
        self._ip_ban_service = ip_ban_service
        self._default_ttl_seconds = default_ttl_seconds

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    @staticmethod
    def guard_for(tool: str) -> Literal["readonly", "standard", "dangerous"]:
        """Return the client-side mirror of the server-side guard level.

        Unknown tools default to ``standard`` — better to over-prompt
        than under-prompt when a new tool ships server-first. The server
        remains authoritative regardless.
        """
        return _TOOL_GUARDS.get(tool, "standard")

    async def handle_tool_call(self, call: ToolCall) -> ToolResult:
        """Confirm (when needed), execute via relay, return :class:`ToolResult`.

        Caller (chat panel) MUST await :meth:`post_tool_result` with the
        return value — the server's turn stays open until that POST
        lands. ``handle_tool_call`` itself does NOT post; we keep the
        two phases separate so tests can verify each in isolation.
        """
        # 0. Defensive normalisation. A model could theoretically emit a
        # guard_level we don't recognise; downgrade to 'standard' so we
        # always require confirmation.
        if call.guard_level not in ("readonly", "standard", "dangerous"):
            logger.warning(
                "Unexpected guard_level %r on tool_call %s; coercing to 'standard'",
                call.guard_level, call.tool_call_id,
            )
            call.guard_level = "standard"

        # 0a. A3 fix — escalate the guard level to the *max* of the
        # server-supplied value and our client-side mirror. A buggy or
        # malicious server cannot downgrade ``deploy`` to ``standard``
        # to bypass the typed-RUN modal + dangerous entitlement gate.
        # The client mirror is the floor.
        client_guard = self.guard_for(call.tool)
        effective_guard = _escalate_guard(call.guard_level, client_guard)
        if effective_guard != call.guard_level:
            logger.warning(
                "Guard escalation: server sent %r for tool %r; client mirror "
                "is %r — using effective guard %r (A3)",
                call.guard_level, call.tool, client_guard, effective_guard,
            )
            call.guard_level = effective_guard

        # 1. Dangerous-tool entitlement gate (defense-in-depth — server
        # already checks ``allow_dangerous_ai_tools``, this just spares
        # the user a typed-confirm dialog they can't satisfy).
        if call.guard_level == "dangerous":
            if not self._has_dangerous_entitlement():
                return self._deny_with_audit(
                    call,
                    reason="dangerous_disallowed_client_side",
                    error_message="Dangerous tools require allow_dangerous_ai_tools.",
                )

        # 2. Confirmation modal (skipped for readonly).
        if call.guard_level != "readonly":
            try:
                allowed = await self._confirm(call)
            except Exception as exc:  # noqa: BLE001 — defensive
                logger.exception("confirm_callback raised; treating as denied")
                return self._deny_with_audit(
                    call,
                    reason=f"confirm_error:{exc.__class__.__name__}",
                    error_message=f"Confirmation prompt failed: {exc}",
                )
            if not allowed:
                return self._deny_with_audit(
                    call,
                    reason="user_declined",
                    error_message="User declined.",
                )

        # 3. Dispatch — three possible routes, in priority order:
        #    a) relay (SSH/Mercure to a managed server)
        #    b) local (CLI-side handler via ServonautTools / IPBanService)
        #    c) unavailable — synthesise a structured error result so the
        #       model can recover without stalling the conversation.
        relay_type = _RELAY_TOOL_TO_TYPE.get(call.tool)
        if relay_type is not None:
            logger.info(
                "ai bridge dispatching via relay: tool=%s type=%s call=%s",
                call.tool, relay_type.value, call.tool_call_id,
            )
            return await self._execute_relay(call, relay_type)

        if call.tool in _LOCAL_TOOL_HANDLERS or call.tool == "ip_ban_status":
            logger.info(
                "ai bridge dispatching via local handler: tool=%s call=%s",
                call.tool, call.tool_call_id,
            )
            return await self._execute_local(call)

        hint = UNAVAILABLE_TOOL_HINTS.get(
            call.tool,
            f"Tool {call.tool!r} is not available in this CLI build.",
        )
        logger.warning(
            "AI requested unmapped tool %r — synthesising error result; hint: %s",
            call.tool, hint,
        )
        return self._error_with_audit(
            call,
            reason="tool_unavailable",
            error_message=hint,
        )

    async def post_tool_result(self, result: ToolResult) -> None:
        """POST the result envelope to ``/api/ai/chat/tool-result``.

        Server returns 202 with empty body; we don't inspect the
        response. Failures bubble up as :class:`APIError` subclasses for
        the caller to surface (typically a chat panel notify).

        Skipped results (``result.skipped == True``) get one tolerated
        404: the server's ``recordResult`` validates the row is still
        ``status=pending``, but for refused calls the dispatcher may
        already have moved it to ``STATUS_ERROR`` (CLI not connected,
        relay publish failure, etc.) — making the row non-pending by
        the time our POST lands. That 404 is expected, not a bug;
        swallow it so the chat panel doesn't surface a misleading
        ValidationFailedError. All other errors (5xx, network, rate
        limit) still propagate.
        """
        # Local import to avoid pulling api_client at module load.
        from servonaut.services.api_client import (
            NotFoundError,
            ValidationFailedError,
        )

        # Compact oversized bodies before serialisation. Server caps the
        # POST at 12 MB; we compact above 1 MB for cost control on the
        # next AI turn (tool-result content is fed back to the model).
        # ``bytes`` is the *post*-compaction byte count — the original
        # is in the INFO log below for ops triage. Skipped results
        # (status="error" with no payload) and short bodies pass through
        # unchanged; we still call _compact_for_post to keep the
        # accounting in one place.
        raw_result = result.result or ""
        compacted, compact_stats = _compact_for_post(
            raw_result,
            tool_name=result.tool_call_id,
        )
        compacted_bytes = compact_stats["final_bytes"]

        body: Dict[str, Any] = {
            "conversation_id": result.conversation_id,
            "tool_call_id": result.tool_call_id,
            "status": result.status,
            "result": compacted,
            "bytes": compacted_bytes,
        }
        # Only include error when status implies one — keeps the wire
        # shape minimal for the common ok / denied paths.
        if result.status == "error" and result.error:
            body["error"] = result.error

        # One log line per POST: the compaction stats are a no-op for
        # small bodies (original==final, runs_collapsed=0, truncated=False)
        # so this is also the place ops sees consistent shipping bytes.
        if compact_stats["original_bytes"] > _COMPACTION_THRESHOLD_BYTES:
            logger.info(
                "ai bridge tool-result compacted: call=%s original=%d "
                "final=%d runs_collapsed=%d truncated=%s",
                result.tool_call_id,
                compact_stats["original_bytes"],
                compact_stats["final_bytes"],
                compact_stats["runs_collapsed"],
                compact_stats["truncated"],
            )
        logger.info(
            "ai bridge POST tool-result: call=%s status=%s bytes=%d skipped=%s",
            result.tool_call_id, result.status, compacted_bytes, result.skipped,
        )
        try:
            await self._api.post(_TOOL_RESULT_PATH, json=body)
        except (ValidationFailedError, NotFoundError) as exc:
            if result.skipped and getattr(exc, "status", None) == 404:
                logger.info(
                    "tool-result POST 404 swallowed for skipped tool_call %s "
                    "(server row likely already terminal): %s",
                    result.tool_call_id, exc,
                )
                return
            logger.warning(
                "tool-result POST failed for call=%s status=%s: %s",
                result.tool_call_id, result.status, exc,
            )
            raise
        logger.info(
            "ai bridge POST tool-result accepted: call=%s",
            result.tool_call_id,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _has_dangerous_entitlement(self) -> bool:
        """True iff the AuthToken has ``allow_dangerous_ai_tools``."""
        getter = getattr(self._auth, "has_dangerous_ai_tools", None)
        if isinstance(getter, bool):
            return getter
        # Convenience property in :class:`AuthService` is plain attribute,
        # but mocks in tests sometimes set a method instead. Be defensive.
        if callable(getter):
            try:
                return bool(getter())
            except Exception:  # noqa: BLE001
                return False
        return bool(getter)

    async def _execute_relay(
        self,
        call: ToolCall,
        relay_type: CommandType,
    ) -> ToolResult:
        """Build a :class:`CommandRequest` and dispatch via :class:`RelayExecutors`."""
        request = self._build_command_request(call, relay_type)
        try:
            response = await self._executors.execute(request)
        except asyncio.TimeoutError:
            return self._timeout_with_audit(call)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Relay execution raised for tool_call %s", call.tool_call_id,
            )
            return self._error_with_audit(
                call,
                reason=f"relay_exception:{exc.__class__.__name__}",
                error_message=str(exc),
            )
        return self._map_response_to_result(call, response)

    async def _execute_local(self, call: ToolCall) -> ToolResult:
        """Run a CLI-side readonly tool via :class:`ServonautTools` /
        :class:`IPBanService`.

        These tools (list_instances, describe_instance, ip_ban_status)
        don't dispatch to a managed server — they query the user's own
        AWS / config surface from the CLI process. The bridge wraps the
        existing async handler and produces a :class:`ToolResult` shaped
        identically to the relay path so downstream code (audit, POST,
        chat-panel render) doesn't branch.
        """
        if call.tool == "ip_ban_status":
            return await self._execute_ip_ban_status(call)

        handler_name = _LOCAL_TOOL_HANDLERS.get(call.tool)
        if handler_name is None:
            # Defensive — handle_tool_call already filters; reach here
            # only on a future bug. Fail loud, not silently.
            return self._error_with_audit(
                call,
                reason="tool_unavailable",
                error_message=f"No local handler for tool {call.tool!r}.",
            )

        if self._servonaut_tools is None:
            return self._error_with_audit(
                call,
                reason="local_tools_unavailable",
                error_message=(
                    "Local tool execution is unavailable in this CLI "
                    "session (ServonautTools not wired)."
                ),
            )

        handler = getattr(self._servonaut_tools, handler_name, None)
        if not callable(handler):
            return self._error_with_audit(
                call,
                reason="missing_handler",
                error_message=(
                    f"ServonautTools.{handler_name!r} is not callable."
                ),
            )

        try:
            output = await handler(**call.args)
        except TypeError as exc:
            # Argument shape mismatch — model emitted args the handler
            # doesn't accept. Surface as error so the model can retry.
            logger.warning(
                "Local tool %r argument mismatch: %s", call.tool, exc,
            )
            return self._error_with_audit(
                call,
                reason="bad_args",
                error_message=f"Invalid arguments for {call.tool}: {exc}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Local tool %r raised", call.tool,
            )
            return self._error_with_audit(
                call,
                reason=f"local_exception:{exc.__class__.__name__}",
                error_message=str(exc),
            )

        text = output if isinstance(output, str) else str(output)
        result = ToolResult(
            tool_call_id=call.tool_call_id,
            conversation_id=call.conversation_id,
            status="ok",
            result=text,
            bytes=_utf8_len(text),
        )
        self._audit_tool_call(call, result, allowed=True, reason="ok_local")
        return result

    async def _execute_ip_ban_status(self, call: ToolCall) -> ToolResult:
        """Minimal local handler for the ``ip_ban_status`` tool.

        Returns a structured summary of every configured ban surface
        (WAF / SG / NACL) and the IPs currently banned in each. Read-only
        — never mutates state.
        """
        if self._ip_ban_service is None:
            return self._error_with_audit(
                call,
                reason="ip_ban_unavailable",
                error_message=(
                    "IP ban service is unavailable in this CLI session."
                ),
            )

        try:
            configs = self._ip_ban_service.get_configs()
        except Exception as exc:  # noqa: BLE001
            logger.exception("ip_ban_status: get_configs failed")
            return self._error_with_audit(
                call,
                reason="ip_ban_get_configs_failed",
                error_message=str(exc),
            )

        if not configs:
            text = "No IP ban configurations are defined for this CLI."
            result = ToolResult(
                tool_call_id=call.tool_call_id,
                conversation_id=call.conversation_id,
                status="ok",
                result=text,
                bytes=_utf8_len(text),
            )
            self._audit_tool_call(call, result, allowed=True, reason="ok_local")
            return result

        # Collect per-config banned-IP lists. Some strategies may need
        # remote API calls (e.g. boto3); failures per-config are folded
        # into the result rather than aborting the whole tool call.
        lines = []
        for cfg in configs:
            try:
                banned = await self._ip_ban_service.list_banned(cfg.name)
                count = len(banned) if banned is not None else 0
                preview = ", ".join((banned or [])[:5])
                if count > 5:
                    preview += f", … ({count - 5} more)"
                lines.append(
                    f"- {cfg.name} ({cfg.method}): {count} banned"
                    + (f" — {preview}" if preview else "")
                )
            except Exception as exc:  # noqa: BLE001
                lines.append(f"- {cfg.name} ({cfg.method}): error — {exc}")

        text = "IP ban status:\n" + "\n".join(lines)
        result = ToolResult(
            tool_call_id=call.tool_call_id,
            conversation_id=call.conversation_id,
            status="ok",
            result=text,
            bytes=_utf8_len(text),
        )
        self._audit_tool_call(call, result, allowed=True, reason="ok_local")
        return result

    def _build_command_request(
        self,
        call: ToolCall,
        relay_type: CommandType,
    ) -> CommandRequest:
        """Translate ``ToolCall.args`` into the relay's payload schema.

        Per plan §"Tool guard map", relay-bound tools share a small set
        of payload shapes. The mapping below is conservative — anything
        we don't recognise is forwarded verbatim and the relay will
        reject it via blocklist or path validation.
        """
        target = (
            call.args.get("instance_id")
            or call.args.get("server_id")
            or call.args.get("target_server_id")
            or ""
        )
        ttl = int(call.args.get("ttl_seconds") or self._default_ttl_seconds)

        # Build the relay payload. Args we forward verbatim by tool:
        #   tail_log       → log_path, lines
        #   transfer_file  → local_path, remote_path, direction
        #   run_command/ssh_exec_readonly/deploy/provision/security_scan
        #                  → command (with sensible default for the verb tools)
        if relay_type == CommandType.GET_LOGS:
            payload = {
                "log_path": call.args.get("log_path", "/var/log/syslog"),
                "lines": call.args.get("lines", 100),
            }
        elif relay_type == CommandType.TRANSFER_FILE:
            payload = {
                "local_path": call.args.get("local_path", ""),
                "remote_path": call.args.get("remote_path", ""),
                "direction": call.args.get("direction", "download"),
            }
        else:
            payload = {"command": call.args.get("command", "")}

        return CommandRequest(
            id=call.tool_call_id,
            user_id=call.conversation_id,  # provenance tag for audit
            type=relay_type,
            target_server_id=str(target),
            payload=payload,
            ttl_seconds=ttl,
        )

    def _map_response_to_result(
        self,
        call: ToolCall,
        response: CommandResponse,
    ) -> ToolResult:
        """Translate a :class:`CommandResponse` to the 4-status :class:`ToolResult`.

        Relay statuses ``success``, ``timeout``, ``rejected``, ``error``
        map to ``ok``, ``timeout``, ``error``, ``error`` respectively.
        ``rejected`` (blocklist hits, validation failures) is folded
        into ``error`` because the wire protocol only has 4 statuses.
        """
        if response.status == "success":
            payload = response.output or ""
            tool_result = ToolResult(
                tool_call_id=call.tool_call_id,
                conversation_id=call.conversation_id,
                status="ok",
                result=payload,
                bytes=_utf8_len(payload),
            )
            self._audit_tool_call(call, tool_result, allowed=True, reason="ok")
            return tool_result

        if response.status == "timeout":
            return self._timeout_with_audit(
                call,
                error_message=response.error_message or "",
            )

        # rejected | error — both surface as "error" with the relay's
        # error_message. The reason code preserves the relay distinction
        # in the audit row so we can grep for blocklist trips.
        reason = "relay_rejected" if response.status == "rejected" else "relay_error"
        return self._error_with_audit(
            call,
            reason=reason,
            error_message=response.error_message or "Relay reported an error.",
        )

    # ------------------------------------------------------------------
    # Result builders that ALSO write the audit row (single-shot).
    # ------------------------------------------------------------------

    def _timeout_with_audit(
        self,
        call: ToolCall,
        *,
        error_message: str = "",
    ) -> ToolResult:
        message = error_message or "Tool execution timed out."
        result = ToolResult(
            tool_call_id=call.tool_call_id,
            conversation_id=call.conversation_id,
            status="timeout",
            result=message,
            error=None,  # plan: timeout has no separate error field
            bytes=_utf8_len(message),
        )
        self._audit_tool_call(call, result, allowed=False, reason="timeout")
        return result

    def _error_with_audit(
        self,
        call: ToolCall,
        *,
        reason: str,
        error_message: str,
    ) -> ToolResult:
        # Reasons that indicate the CLI couldn't dispatch at all (unmapped
        # tool, missing collaborator). These map to the ``skipped`` flag
        # so post_tool_result tolerates the expected 404 from a
        # non-pending server-side row.
        skipped = reason in {
            "tool_unavailable",
            "missing_handler",
            "local_tools_unavailable",
            "ip_ban_unavailable",
        }
        result = ToolResult(
            tool_call_id=call.tool_call_id,
            conversation_id=call.conversation_id,
            status="error",
            result=error_message,
            error=error_message,
            bytes=_utf8_len(error_message),
            skipped=skipped,
        )
        self._audit_tool_call(call, result, allowed=False, reason=reason)
        return result

    def _deny_with_audit(
        self,
        call: ToolCall,
        *,
        reason: str,
        error_message: str,
    ) -> ToolResult:
        result = ToolResult(
            tool_call_id=call.tool_call_id,
            conversation_id=call.conversation_id,
            status="denied",
            result=error_message,
            error=None,  # denied is not an error
            bytes=_utf8_len(error_message),
        )
        self._audit_tool_call(call, result, allowed=False, reason=reason)
        return result

    def _audit_tool_call(
        self,
        call: ToolCall,
        result: ToolResult,
        *,
        allowed: bool,
        reason: str,
    ) -> None:
        """Single audit row per :meth:`handle_tool_call` invocation.

        Tagged ``source="ai_chat"`` to satisfy Risk register §2 (must be
        distinguishable from MCP-originated rows). ``conversation_id``
        and ``tool_call_id`` are persisted as extras so an operator can
        replay the round-trip from the audit log alone.
        """
        try:
            self._audit.log(
                call.tool,
                dict(call.args),
                result.result or "",
                allowed,
                reason,
                source="ai_chat",
                conversation_id=call.conversation_id,
                tool_call_id=call.tool_call_id,
                guard_level=call.guard_level,
                status=result.status,
                bytes=int(result.bytes or 0),
            )
        except Exception:  # noqa: BLE001
            # Audit MUST NOT block the user-visible flow. Log and move on.
            logger.exception(
                "Failed to audit AI tool call %s", call.tool_call_id,
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utf8_len(value: Any) -> int:
    """UTF-8 byte length of ``str(value)``.

    Plan §"Critical decisions" item 10: we measure the *stringified*
    payload, not the raw JSON, because that's what the model sees in
    its context window for billing.
    """
    return len(str(value).encode("utf-8"))


__all__ = [
    "AIToolBridge",
    "ConfirmCallback",
    "ToolCall",
    "ToolResult",
    "_escalate_guard",
]
