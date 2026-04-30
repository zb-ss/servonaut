"""Tests for :class:`AIToolBridge` (T6).

Covers the architect-plan minimum (9+ cases):

1. ``readonly`` tools execute with NO confirm modal awaited.
2. ``standard`` accepted → ``status="ok"``.
3. ``standard`` declined → ``status="denied"``.
4. ``dangerous`` accepted → ``status="ok"``.
5. ``dangerous`` declined → ``status="denied"``.
6. Relay timeout → ``status="timeout"``.
7. Relay exception → ``status="error"`` with ``error`` populated.
8. ``bytes`` field is the UTF-8 byte length of the stringified payload.
9. Audit row written tagged ``source="ai_chat"``.
10. ``post_tool_result`` POSTs to the canonical endpoint with the right body.

Plus dangerous-tool entitlement gate, unknown-tool refusal, guard_for
defaulting to standard, and confirm_callback exception handling.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.mcp.audit import AuditTrail
from servonaut.models.relay_messages import (
    CommandRequest,
    CommandResponse,
    CommandType,
)
from servonaut.services.ai_tool_bridge import (
    AIToolBridge,
    ToolCall,
    ToolResult,
    _escalate_guard,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bridge(
    *,
    confirm_returns: bool = True,
    relay_response: CommandResponse | None = None,
    relay_raises: BaseException | None = None,
    has_dangerous: bool = True,
    confirm_raises: BaseException | None = None,
    audit_trail: AuditTrail | None = None,
    servonaut_tools: Any = None,
    ip_ban_service: Any = None,
):
    """Build an AIToolBridge with all collaborators mocked.

    Returns ``(bridge, api, relay, audit, confirm_mock)`` so each test
    can introspect the exact calls.
    """
    api = MagicMock()
    api.post = AsyncMock(return_value={})

    relay = MagicMock()

    async def _execute(req):
        if relay_raises is not None:
            raise relay_raises
        return relay_response or CommandResponse(
            request_id=req.id, status="success", output="ok output",
        )

    relay.execute = AsyncMock(side_effect=_execute)

    if audit_trail is None:
        audit = MagicMock()
        audit.log = MagicMock()
    else:
        audit = audit_trail

    confirm_mock = AsyncMock()
    if confirm_raises is not None:
        confirm_mock.side_effect = confirm_raises
    else:
        confirm_mock.return_value = confirm_returns

    auth = MagicMock()
    auth.has_dangerous_ai_tools = has_dangerous

    bridge = AIToolBridge(
        api_client=api,
        relay_executors=relay,
        mcp_audit=audit,
        confirm_callback=confirm_mock,
        auth_service=auth,
        servonaut_tools=servonaut_tools,
        ip_ban_service=ip_ban_service,
    )
    return bridge, api, relay, audit, confirm_mock


def _call(
    *,
    tool: str = "run_command",
    guard_level: str = "standard",
    args: Dict[str, Any] | None = None,
    conv: str = "conv-1",
    tcid: str = "tc_001",
) -> ToolCall:
    return ToolCall(
        tool_call_id=tcid,
        tool=tool,
        args=args or {"command": "uptime", "instance_id": "i-abc"},
        guard_level=guard_level,  # type: ignore[arg-type]
        conversation_id=conv,
    )


# ---------------------------------------------------------------------------
# 1. readonly skips the confirm modal entirely.
# ---------------------------------------------------------------------------


def test_readonly_no_modal_executes_immediately():
    bridge, _, relay, audit, confirm_mock = _make_bridge()
    call = _call(tool="ssh_exec_readonly", guard_level="readonly", args={
        "command": "uptime", "instance_id": "i-abc",
    })
    result = run(bridge.handle_tool_call(call))

    confirm_mock.assert_not_called()
    relay.execute.assert_awaited_once()
    assert result.status == "ok"
    assert audit.log.called


# ---------------------------------------------------------------------------
# 2. standard accepted → ok
# ---------------------------------------------------------------------------


def test_standard_accepted_returns_ok():
    bridge, _, relay, _, confirm_mock = _make_bridge(confirm_returns=True)
    call = _call(guard_level="standard")

    result = run(bridge.handle_tool_call(call))

    confirm_mock.assert_awaited_once()
    relay.execute.assert_awaited_once()
    assert result.status == "ok"
    assert result.tool_call_id == call.tool_call_id
    assert result.conversation_id == call.conversation_id


# ---------------------------------------------------------------------------
# 3. standard declined → denied
# ---------------------------------------------------------------------------


def test_standard_declined_returns_denied():
    bridge, _, relay, _, confirm_mock = _make_bridge(confirm_returns=False)
    call = _call(guard_level="standard")

    result = run(bridge.handle_tool_call(call))

    confirm_mock.assert_awaited_once()
    # Relay must NOT execute on denial.
    relay.execute.assert_not_awaited()
    assert result.status == "denied"
    # Plan invariant: error field is None on denied (denial isn't an error).
    assert result.error is None


# ---------------------------------------------------------------------------
# 4. dangerous accepted → ok (with allow_dangerous_ai_tools = True)
# ---------------------------------------------------------------------------


def test_dangerous_accepted_returns_ok():
    bridge, _, relay, _, confirm_mock = _make_bridge(
        confirm_returns=True, has_dangerous=True,
    )
    call = _call(tool="deploy", guard_level="dangerous")
    result = run(bridge.handle_tool_call(call))

    confirm_mock.assert_awaited_once()
    relay.execute.assert_awaited_once()
    assert result.status == "ok"


# ---------------------------------------------------------------------------
# 5. dangerous declined → denied
# ---------------------------------------------------------------------------


def test_dangerous_declined_returns_denied():
    bridge, _, relay, _, confirm_mock = _make_bridge(
        confirm_returns=False, has_dangerous=True,
    )
    call = _call(tool="deploy", guard_level="dangerous")
    result = run(bridge.handle_tool_call(call))

    confirm_mock.assert_awaited_once()
    relay.execute.assert_not_awaited()
    assert result.status == "denied"


# ---------------------------------------------------------------------------
# 5b. dangerous WITHOUT allow_dangerous_ai_tools → denied without prompt.
# ---------------------------------------------------------------------------


def test_dangerous_without_entitlement_denies_without_prompt():
    bridge, _, relay, audit, confirm_mock = _make_bridge(
        has_dangerous=False,
    )
    call = _call(tool="deploy", guard_level="dangerous")

    result = run(bridge.handle_tool_call(call))

    # Plan §T4 / §T6 invariant: the confirm modal NEVER renders for a
    # dangerous tool when allow_dangerous_ai_tools is false.
    confirm_mock.assert_not_called()
    relay.execute.assert_not_awaited()
    assert result.status == "denied"
    # Audit row should reflect the client-side gate.
    audit.log.assert_called()
    last_call = audit.log.call_args
    assert last_call.kwargs.get("source") == "ai_chat"
    assert "dangerous_disallowed_client_side" in last_call.args[4]


# ---------------------------------------------------------------------------
# 6. Relay timeout → status="timeout"
# ---------------------------------------------------------------------------


def test_relay_timeout_maps_to_timeout_status():
    bridge, _, relay, _, _ = _make_bridge(
        relay_raises=asyncio.TimeoutError(),
    )
    call = _call(guard_level="readonly", tool="ssh_exec_readonly")

    result = run(bridge.handle_tool_call(call))

    assert result.status == "timeout"
    # Plan: timeout has no separate error field — it's surfaced in result text.
    assert result.error is None
    assert "timed out" in result.result.lower()


# ---------------------------------------------------------------------------
# 7. Relay exception → status="error" with error field populated
# ---------------------------------------------------------------------------


def test_relay_exception_maps_to_error_status_with_error_field():
    bridge, _, relay, _, _ = _make_bridge(
        relay_raises=RuntimeError("ssh died"),
    )
    call = _call(guard_level="readonly", tool="ssh_exec_readonly")

    result = run(bridge.handle_tool_call(call))

    assert result.status == "error"
    assert result.error is not None
    assert "ssh died" in result.error


# ---------------------------------------------------------------------------
# 8. bytes count matches utf-8 length
# ---------------------------------------------------------------------------


def test_bytes_count_matches_utf8_length_of_stringified_result():
    output = "Hé!"  # 'é' is two UTF-8 bytes
    relay_response = CommandResponse(
        request_id="x", status="success", output=output,
    )
    bridge, _, _, _, _ = _make_bridge(
        confirm_returns=True, relay_response=relay_response,
    )
    call = _call(tool="run_command", guard_level="standard")
    result = run(bridge.handle_tool_call(call))

    assert result.status == "ok"
    # 'Hé!' = 4 bytes in UTF-8 (H=1 + é=2 + !=1).
    assert result.bytes == len(output.encode("utf-8"))
    assert result.bytes == 4


def test_bytes_count_for_denied_is_utf8_length_of_message():
    bridge, _, _, _, _ = _make_bridge(confirm_returns=False)
    call = _call(guard_level="standard")
    result = run(bridge.handle_tool_call(call))
    # Denied result text is the canned "User declined." string.
    assert result.bytes == len(result.result.encode("utf-8"))
    assert result.bytes > 0


# ---------------------------------------------------------------------------
# 9. Audit row written with source="ai_chat" (Risk register §2)
# ---------------------------------------------------------------------------


def test_audit_row_written_with_source_ai_chat(tmp_path):
    audit = AuditTrail(str(tmp_path / "ai_audit.jsonl"))
    bridge, _, _, _, _ = _make_bridge(audit_trail=audit)
    call = _call(tool="run_command", guard_level="standard")
    run(bridge.handle_tool_call(call))

    # Read the JSONL and verify a row exists with source="ai_chat" and
    # the conversation_id / tool_call_id metadata persisted.
    entries = audit.read_recent(10)
    assert entries, "expected at least one audit entry"
    entry = entries[-1]
    assert entry["tool"] == "run_command"
    assert entry["source"] == "ai_chat"
    assert entry["conversation_id"] == call.conversation_id
    assert entry["tool_call_id"] == call.tool_call_id
    assert entry["guard_level"] == "standard"
    assert entry["status"] == "ok"


# ---------------------------------------------------------------------------
# 10. post_tool_result POSTs to the right endpoint with the right body
# ---------------------------------------------------------------------------


def test_post_tool_result_uses_correct_endpoint_and_body():
    bridge, api, _, _, _ = _make_bridge()
    result = ToolResult(
        tool_call_id="tc_42",
        conversation_id="conv-x",
        status="ok",
        result="hello world",
        bytes=11,
    )
    run(bridge.post_tool_result(result))

    api.post.assert_awaited_once()
    args, kwargs = api.post.call_args
    # Path is the first positional arg.
    assert args[0] == "/api/ai/chat/tool-result"
    # Body always passed via keyword `json=`.
    body = kwargs["json"]
    assert body["conversation_id"] == "conv-x"
    assert body["tool_call_id"] == "tc_42"
    assert body["status"] == "ok"
    assert body["result"] == "hello world"
    assert body["bytes"] == 11
    # Plan: ``error`` only included when status implies one.
    assert "error" not in body


def test_post_tool_result_includes_error_field_when_status_error():
    bridge, api, _, _, _ = _make_bridge()
    result = ToolResult(
        tool_call_id="tc_1",
        conversation_id="conv-1",
        status="error",
        result="ssh failed",
        error="connection refused",
        bytes=10,
    )
    run(bridge.post_tool_result(result))
    body = api.post.call_args.kwargs["json"]
    assert body["status"] == "error"
    assert body["error"] == "connection refused"


# ---------------------------------------------------------------------------
# 11. Unmapped tool (no relay path, no local handler) — synthesises error.
# ---------------------------------------------------------------------------


def test_unmapped_tool_returns_error_without_relay_dispatch():
    bridge, _, relay, _, _ = _make_bridge()
    # ``cost_report`` resolves server-side — the catalog should never
    # ship it as a tool_call to the CLI. If it does (server bug), the
    # bridge synthesises a structured error so the model can recover.
    call = _call(tool="cost_report", guard_level="readonly")
    result = run(bridge.handle_tool_call(call))
    relay.execute.assert_not_awaited()
    assert result.status == "error"
    assert "cost_report" in (result.error or "")


def test_unknown_tool_returns_error_with_default_hint():
    bridge, _, relay, _, _ = _make_bridge()
    call = _call(tool="totally_made_up_tool", guard_level="readonly")
    result = run(bridge.handle_tool_call(call))
    relay.execute.assert_not_awaited()
    assert result.status == "error"
    assert "totally_made_up_tool" in (result.error or "")
    assert "not available" in (result.error or "")


# ---------------------------------------------------------------------------
# 12. confirm_callback raising is treated as denial (defensive).
# ---------------------------------------------------------------------------


def test_confirm_callback_exception_is_treated_as_denied():
    bridge, _, relay, _, _ = _make_bridge(
        confirm_raises=RuntimeError("modal crashed"),
    )
    call = _call(guard_level="standard")
    result = run(bridge.handle_tool_call(call))
    relay.execute.assert_not_awaited()
    assert result.status == "denied"


# ---------------------------------------------------------------------------
# 13. guard_for unknown tool defaults to "standard".
# ---------------------------------------------------------------------------


def test_guard_for_unknown_tool_defaults_to_standard():
    assert AIToolBridge.guard_for("totally_new_tool_2030") == "standard"
    # Mirror map is verified for the documented tools.
    assert AIToolBridge.guard_for("run_command") == "standard"
    assert AIToolBridge.guard_for("ssh_exec_readonly") == "readonly"
    assert AIToolBridge.guard_for("deploy") == "dangerous"


# ---------------------------------------------------------------------------
# 14. Bogus guard_level on the wire is coerced to standard (defensive).
# ---------------------------------------------------------------------------


def test_unknown_guard_level_coerced_to_standard():
    bridge, _, _, _, confirm_mock = _make_bridge(confirm_returns=True)
    call = _call(guard_level="totally_invalid")  # type: ignore[arg-type]
    result = run(bridge.handle_tool_call(call))
    # Confirm prompt fires (because we coerced to 'standard').
    confirm_mock.assert_awaited_once()
    assert result.status == "ok"


# ---------------------------------------------------------------------------
# A3 — server guard downgrade is escalated to client mirror
# ---------------------------------------------------------------------------


def test_escalate_guard_takes_max_severity():
    """``_escalate_guard`` returns whichever side is more severe."""
    # Server says standard, client says dangerous → dangerous wins (the FLOOR).
    assert _escalate_guard("standard", "dangerous") == "dangerous"
    # Server says dangerous, client says standard → dangerous wins (the CEILING
    # is the actual severity, not a downgrade).
    assert _escalate_guard("dangerous", "standard") == "dangerous"
    # Equal severities are stable.
    assert _escalate_guard("readonly", "readonly") == "readonly"
    assert _escalate_guard("standard", "standard") == "standard"
    # Unknown server guard collapses to standard, then takes max.
    assert _escalate_guard("nonsense", "dangerous") == "dangerous"


def test_server_guard_downgrade_escalated_to_client_no_entitlement():
    """A3 — server claims ``standard`` for ``deploy``; client mirror is
    dangerous. Without ``allow_dangerous_ai_tools`` the bridge denies
    BEFORE prompting, recording the escalation in the audit row.
    """
    bridge, _, relay, audit, confirm_mock = _make_bridge(has_dangerous=False)
    # Server payload spoofs guard_level to bypass the typed-RUN modal.
    call = _call(tool="deploy", guard_level="standard")

    result = run(bridge.handle_tool_call(call))

    # Defense-in-depth fired — no confirm prompt, no relay dispatch.
    confirm_mock.assert_not_called()
    relay.execute.assert_not_awaited()
    assert result.status == "denied"
    # Audit row carries the dangerous-disallowed reason — proves the
    # escalation took effect even though the wire said "standard".
    audit.log.assert_called()
    last = audit.log.call_args
    assert "dangerous_disallowed_client_side" in last.args[4]


def test_server_guard_downgrade_escalated_to_client_with_entitlement():
    """A3 — same downgrade, but user has the entitlement. The bridge
    must escalate to dangerous, run the typed-RUN flow, and dispatch
    only when the confirm callback returns True.
    """
    bridge, _, relay, _, confirm_mock = _make_bridge(
        confirm_returns=True, has_dangerous=True,
    )
    call = _call(tool="deploy", guard_level="standard")

    result = run(bridge.handle_tool_call(call))

    # The escalation surfaces through the ToolCall passed to the confirm
    # callback — the modal driver picks based on guard_level so this is
    # the proof point that the typed-RUN flow runs even though the wire
    # said "standard".
    confirm_mock.assert_awaited_once()
    awaited_call = confirm_mock.call_args.args[0]
    assert awaited_call.guard_level == "dangerous", (
        "Confirm callback received wire-level guard, not escalated guard"
    )
    relay.execute.assert_awaited_once()
    assert result.status == "ok"


# ---------------------------------------------------------------------------
# C4 — chat panel synthesises a tool_result on bridge exception
# ---------------------------------------------------------------------------


def test_chat_panel_synthesises_error_tool_result_on_bridge_exception():
    """C4 — when ``handle_tool_call`` raises, the chat panel posts a
    synthetic ``status="error"`` result back so the server's turn closes.

    Without this, a single unhandled bridge exception hangs the chat
    forever — the server keeps the turn open until the tool-result POST
    arrives.
    """
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    from servonaut.widgets.chat_panel import ChatPanel

    panel = ChatPanel.__new__(ChatPanel)
    panel._stale_cache = {}
    panel._upstream_failures = []
    panel._session_provider_override = None
    panel._last_fallback_used = False
    panel._last_soft_capped = False
    panel._last_hard_capped = False
    panel._remote_conversation_id = "conv-c4"
    panel._pinned_error_active = False
    panel._first_run_modal_shown = False
    panel._empty_state_modal_shown = False
    panel._thinking = False
    panel._total_tokens = 0
    panel._total_cost = 0.0
    panel._model = ""
    panel._session = None

    bridge = MagicMock()
    bridge.handle_tool_call = AsyncMock(
        side_effect=RuntimeError("bridge crashed"),
    )
    bridge.post_tool_result = AsyncMock(return_value=None)

    app = MagicMock()
    app.ai_tool_bridge = bridge
    type(panel).app = property(lambda self, _a=app: _a)  # type: ignore[assignment]

    asyncio.run(
        panel._handle_streamed_tool_call(
            {
                "tool_call_id": "tc_c4",
                "tool": "run_command",
                "args": {"command": "uptime"},
                "guard_level": "standard",
            }
        )
    )

    # Synthetic error tool_result was posted back so the server can close
    # its turn. Without C4 the server hangs.
    bridge.post_tool_result.assert_awaited_once()
    posted = bridge.post_tool_result.call_args.args[0]
    assert posted.tool_call_id == "tc_c4"
    assert posted.status == "error"
    assert posted.error and "bridge crashed" in posted.error


# ---------------------------------------------------------------------------
# 13. Local-tool dispatch — readonly tools that don't need the relay.
# ---------------------------------------------------------------------------


def test_list_instances_dispatches_to_servonaut_tools():
    """The bridge should call ServonautTools.list_instances directly,
    NOT the relay, and wrap the output as status=ok."""
    fake_tools = MagicMock()
    fake_tools.list_instances = AsyncMock(return_value="i-abc | i-def | i-ghi")
    bridge, _, relay, _, _ = _make_bridge(servonaut_tools=fake_tools)

    # NOTE: the _call() helper falls back to a default arg dict on a
    # falsy ``args``, so we pass an explicit region (which list_instances
    # accepts) to verify forwarding behaviour without that quirk.
    call = _call(
        tool="list_instances",
        guard_level="readonly",
        args={"region": "us-east-1"},
    )
    result = run(bridge.handle_tool_call(call))

    relay.execute.assert_not_awaited()
    fake_tools.list_instances.assert_awaited_once_with(region="us-east-1")
    assert result.status == "ok"
    assert "i-abc" in (result.result or "")
    # bytes is the UTF-8 length of the result string.
    assert result.bytes == len(("i-abc | i-def | i-ghi").encode("utf-8"))


def test_describe_instance_maps_to_get_server_info():
    """describe_instance is mapped onto ServonautTools.get_server_info,
    which already covers the same intent with richer output."""
    fake_tools = MagicMock()
    fake_tools.get_server_info = AsyncMock(return_value="instance: i-abc, type: t3.micro")
    bridge, _, relay, _, _ = _make_bridge(servonaut_tools=fake_tools)

    call = _call(
        tool="describe_instance",
        guard_level="readonly",
        args={"instance_id": "i-abc"},
    )
    result = run(bridge.handle_tool_call(call))

    relay.execute.assert_not_awaited()
    fake_tools.get_server_info.assert_awaited_once_with(instance_id="i-abc")
    assert result.status == "ok"
    assert "i-abc" in (result.result or "")


def test_local_tool_with_no_servonaut_tools_returns_clear_error():
    """When the bridge isn't wired to ServonautTools, dispatching a local
    tool MUST return a structured error so the model knows to recover —
    not a relay timeout / crash."""
    bridge, _, relay, _, _ = _make_bridge(servonaut_tools=None)
    call = _call(tool="list_instances", guard_level="readonly", args={})
    result = run(bridge.handle_tool_call(call))

    relay.execute.assert_not_awaited()
    assert result.status == "error"
    assert "ServonautTools" in (result.error or "")


def test_local_tool_argument_mismatch_returns_bad_args_error():
    """If the model sends args the local handler can't accept, surface a
    bad_args error instead of letting the TypeError bubble up."""
    fake_tools = MagicMock()
    # Handler doesn't accept ``foo`` — simulates a model that hallucinated
    # an argument name.
    async def _handler(instance_id):
        return f"ok {instance_id}"
    fake_tools.get_server_info = _handler
    bridge, _, relay, _, _ = _make_bridge(servonaut_tools=fake_tools)

    call = _call(
        tool="describe_instance",
        guard_level="readonly",
        args={"instance_id": "i-abc", "foo": "bar"},
    )
    result = run(bridge.handle_tool_call(call))

    relay.execute.assert_not_awaited()
    assert result.status == "error"
    assert "Invalid arguments" in (result.error or "")


def test_ip_ban_status_summarises_configured_ban_surfaces():
    """The minimal ip_ban_status handler returns a structured summary
    of every IPBanConfig and its currently-banned IPs."""
    cfg = MagicMock()
    cfg.name = "prod-waf"
    cfg.method = "waf"
    fake_ipban = MagicMock()
    fake_ipban.get_configs = MagicMock(return_value=[cfg])
    fake_ipban.list_banned = AsyncMock(return_value=["1.2.3.4", "5.6.7.8"])

    bridge, _, relay, _, _ = _make_bridge(ip_ban_service=fake_ipban)
    call = _call(tool="ip_ban_status", guard_level="readonly", args={})
    result = run(bridge.handle_tool_call(call))

    relay.execute.assert_not_awaited()
    fake_ipban.get_configs.assert_called_once()
    fake_ipban.list_banned.assert_awaited_once_with("prod-waf")
    assert result.status == "ok"
    assert "prod-waf" in (result.result or "")
    assert "1.2.3.4" in (result.result or "")


def test_ip_ban_status_with_no_configs_returns_ok_empty_summary():
    fake_ipban = MagicMock()
    fake_ipban.get_configs = MagicMock(return_value=[])

    bridge, _, _, _, _ = _make_bridge(ip_ban_service=fake_ipban)
    call = _call(tool="ip_ban_status", guard_level="readonly", args={})
    result = run(bridge.handle_tool_call(call))

    assert result.status == "ok"
    assert "No IP ban" in (result.result or "")


def test_ip_ban_status_with_no_service_returns_clear_error():
    bridge, _, _, _, _ = _make_bridge(ip_ban_service=None)
    call = _call(tool="ip_ban_status", guard_level="readonly", args={})
    result = run(bridge.handle_tool_call(call))

    assert result.status == "error"
    assert "IP ban service" in (result.error or "")


# ---------------------------------------------------------------------------
# 14. post_tool_result swallows expected 404 on skipped results.
# ---------------------------------------------------------------------------


def test_post_tool_result_swallows_404_on_skipped_result():
    """When the CLI couldn't dispatch a tool (unmapped name), the server
    may have already moved the row to STATUS_ERROR — recordResult then
    returns 404. That's not a real bug; swallow it on skipped results.
    """
    from servonaut.services.api_client import ValidationFailedError

    api = MagicMock()
    api.post = AsyncMock(side_effect=ValidationFailedError(
        code="validation_failed",
        message="No pending tool call X for user Y",
        status=404,
    ))

    relay = MagicMock()
    audit = MagicMock()
    audit.log = MagicMock()
    confirm_mock = AsyncMock(return_value=True)
    auth = MagicMock(); auth.has_dangerous_ai_tools = True

    bridge = AIToolBridge(
        api_client=api,
        relay_executors=relay,
        mcp_audit=audit,
        confirm_callback=confirm_mock,
        auth_service=auth,
    )

    skipped = ToolResult(
        tool_call_id="tc_skip",
        conversation_id="conv-1",
        status="error",
        result="cost_report not available",
        error="cost_report not available",
        bytes=24,
        skipped=True,
    )

    # Should NOT raise.
    run(bridge.post_tool_result(skipped))
    api.post.assert_awaited_once()


def test_post_tool_result_propagates_404_on_non_skipped_result():
    """A 404 on a NORMAL (non-skipped) result still surfaces — that
    would be a genuine integration bug worth raising."""
    from servonaut.services.api_client import ValidationFailedError

    api = MagicMock()
    api.post = AsyncMock(side_effect=ValidationFailedError(
        code="validation_failed",
        message="No pending tool call X",
        status=404,
    ))

    relay = MagicMock()
    audit = MagicMock(); audit.log = MagicMock()
    confirm_mock = AsyncMock(return_value=True)
    auth = MagicMock(); auth.has_dangerous_ai_tools = True

    bridge = AIToolBridge(
        api_client=api,
        relay_executors=relay,
        mcp_audit=audit,
        confirm_callback=confirm_mock,
        auth_service=auth,
    )

    normal = ToolResult(
        tool_call_id="tc_normal",
        conversation_id="conv-1",
        status="ok",
        result="ran",
        error=None,
        bytes=3,
        skipped=False,
    )

    with pytest.raises(ValidationFailedError):
        run(bridge.post_tool_result(normal))


def test_post_tool_result_propagates_5xx_on_skipped_result():
    """Skipped results only swallow 404, not server outages — the user
    deserves to know if the API is down."""
    from servonaut.services.api_client import APIError

    api = MagicMock()
    api.post = AsyncMock(side_effect=APIError(
        code="server_error",
        message="upstream",
        status=502,
    ))

    relay = MagicMock()
    audit = MagicMock(); audit.log = MagicMock()
    confirm_mock = AsyncMock(return_value=True)
    auth = MagicMock(); auth.has_dangerous_ai_tools = True

    bridge = AIToolBridge(
        api_client=api,
        relay_executors=relay,
        mcp_audit=audit,
        confirm_callback=confirm_mock,
        auth_service=auth,
    )

    skipped = ToolResult(
        tool_call_id="tc_skip",
        conversation_id="conv-1",
        status="error",
        result="x",
        error="x",
        bytes=1,
        skipped=True,
    )

    with pytest.raises(APIError):
        run(bridge.post_tool_result(skipped))


# ---------------------------------------------------------------------------
# 15. Unmapped/unavailable tools set skipped=True so the chat panel can
#     render the soft-skip row.
# ---------------------------------------------------------------------------


def test_unavailable_tool_result_carries_skipped_flag():
    bridge, _, _, _, _ = _make_bridge()
    call = _call(tool="cost_report", guard_level="readonly")
    result = run(bridge.handle_tool_call(call))

    assert result.status == "error"
    assert result.skipped is True


def test_local_tool_with_no_servonaut_tools_is_skipped():
    bridge, _, _, _, _ = _make_bridge(servonaut_tools=None)
    call = _call(tool="list_instances", guard_level="readonly", args={"region": "us-east-1"})
    result = run(bridge.handle_tool_call(call))

    assert result.status == "error"
    assert result.skipped is True


def test_relay_tool_error_is_NOT_skipped():
    """A relay tool that errored isn't a 'we couldn't dispatch' case —
    it dispatched and the server-side path failed. Don't mark skipped."""
    bridge, _, _, _, _ = _make_bridge(
        relay_raises=RuntimeError("connection refused"),
    )
    call = _call(tool="run_command", guard_level="standard")
    result = run(bridge.handle_tool_call(call))

    assert result.status == "error"
    assert result.skipped is False
