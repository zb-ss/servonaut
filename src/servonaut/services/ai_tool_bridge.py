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
    from servonaut.services.api_client import APIClient
    from servonaut.services.auth_service import AuthService
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

# Default cap for AI-driven tool calls (mirrors the relay clamp at 300s).
# We pick a smaller default so a misbehaving model can't hold the chat
# turn open for the whole 5 minutes; the user's original confirm is
# still held while we run the command.
_DEFAULT_TTL_SECONDS = 60

# Tool-result endpoint per plan §"Tool-result POST".
_TOOL_RESULT_PATH = "/api/ai/chat/tool-result"


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
    """Result we POST back to ``/api/ai/chat/tool-result``."""

    tool_call_id: str
    conversation_id: str
    status: Literal["ok", "error", "timeout", "denied"]
    result: str = ""
    error: Optional[str] = None
    bytes: int = 0


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
        default_ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._api = api_client
        self._executors = relay_executors
        self._audit = mcp_audit
        self._confirm = confirm_callback
        self._auth = auth_service
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

        # 3. Execute via relay (or refuse for non-relay tools).
        relay_type = _RELAY_TOOL_TO_TYPE.get(call.tool)
        if relay_type is None:
            # The server should never ship a non-relay tool to the CLI —
            # those run server-side and only surface as ``tool_result``
            # events. If we land here something's gone wrong server-side.
            logger.warning(
                "AI requested non-relay tool %r — server-side bug; refusing",
                call.tool,
            )
            return self._error_with_audit(
                call,
                reason="not_relay_tool",
                error_message=(
                    f"Tool {call.tool!r} is not executed locally."
                ),
            )

        return await self._execute_relay(call, relay_type)

    async def post_tool_result(self, result: ToolResult) -> None:
        """POST the result envelope to ``/api/ai/chat/tool-result``.

        Server returns 202 with empty body; we don't inspect the
        response. Failures bubble up as :class:`APIError` subclasses for
        the caller to surface (typically a chat panel notify).
        """
        body: Dict[str, Any] = {
            "conversation_id": result.conversation_id,
            "tool_call_id": result.tool_call_id,
            "status": result.status,
            "result": result.result or "",
            "bytes": int(result.bytes or 0),
        }
        # Only include error when status implies one — keeps the wire
        # shape minimal for the common ok / denied paths.
        if result.status == "error" and result.error:
            body["error"] = result.error
        await self._api.post(_TOOL_RESULT_PATH, json=body)

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
        result = ToolResult(
            tool_call_id=call.tool_call_id,
            conversation_id=call.conversation_id,
            status="error",
            result=error_message,
            error=error_message,
            bytes=_utf8_len(error_message),
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
