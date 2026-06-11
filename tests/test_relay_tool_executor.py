"""Tests for the headless relay AI-tool executor.

Covers:

1. Envelope classifier (``is_ai_tool_call_event``) — tool_call_id
   top-level, nested in payload, absent.
2. Envelope parser — SSE-style 4-key shape, CommandRequest-style shape,
   JSON-string args, target_server_id folding (relay tools only),
   guard_level fallback to the client mirror, unparseable → None.
3. Headless approval policy — guard × ai_tool_auto_approve matrix,
   invalid config value treated as readonly, denial raises
   ``ToolConfirmDenied`` with reason ``headless_policy_denied``.
4. Executor round trip — bridge driven, result POSTed; bridge crash →
   synthetic error result still POSTed; POST failure swallowed;
   unparseable envelope → no POST.
5. RelayListener routing — non-CommandType event with a tool_call_id
   goes to the executor when wired, is skipped when not; CommandRequest
   events never touch the executor.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.ai_tool_bridge import (
    AIToolBridge,
    ToolCall,
    ToolConfirmDenied,
    ToolResult,
)
from servonaut.services.relay_tool_executor import (
    RelayAIToolExecutor,
    build_headless_confirm,
    is_ai_tool_call_event,
    parse_mercure_tool_call,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


def test_classifier_top_level_tool_call_id():
    assert is_ai_tool_call_event({"tool_call_id": "tc-1", "type": "tail_log"})


def test_classifier_nested_tool_call_id():
    assert is_ai_tool_call_event(
        {"type": "tail_log", "payload": {"tool_call_id": "tc-1"}}
    )


def test_classifier_accepts_id_plus_type_shape():
    # The envelope observed on the wire (staging, 2026-06-11) has no
    # tool_call_id at all — id + type is the marker. (The caller only
    # consults the classifier for non-CommandType events, so a
    # CommandRequest never reaches it.)
    assert is_ai_tool_call_event({
        "id": "evt-7b17-dispatch-1",
        "user_id": 7,
        "type": "list_instances",
        "target_server_id": None,
        "payload": [],
        "created_at": "2026-06-11T10:31:06+00:00",
        "ttl_seconds": 60,
    })


def test_classifier_rejects_event_without_any_id():
    assert not is_ai_tool_call_event({"tool_call_id": "", "type": "tail_log"})
    assert not is_ai_tool_call_event({"type": "tail_log"})
    assert not is_ai_tool_call_event({"id": "x"})  # no type


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_sse_style_envelope():
    call = parse_mercure_tool_call({
        "tool_call_id": "tc-9",
        "tool": "list_instances",
        "args": {"region": "eu-west-1"},
        "guard_level": "readonly",
        "conversation_id": "conv-1",
        "user_id": 7,
    })
    assert call is not None
    assert call.tool == "list_instances"
    assert call.tool_call_id == "tc-9"
    assert call.args == {"region": "eu-west-1"}
    assert call.guard_level == "readonly"
    assert call.conversation_id == "conv-1"


def test_parse_command_request_style_envelope():
    call = parse_mercure_tool_call({
        "id": "tc-7",
        "user_id": 7,
        "type": "ssh_exec_readonly",
        "target_server_id": "web-1",
        "payload": {
            "command": "uptime",
            "tool_call_id": "tc-7",
            "conversation_id": "conv-2",
        },
        "ttl_seconds": 60,
    })
    assert call is not None
    assert call.tool == "ssh_exec_readonly"
    assert call.tool_call_id == "tc-7"
    assert call.conversation_id == "conv-2"
    assert call.args["command"] == "uptime"
    # Metadata keys are stripped from args.
    assert "tool_call_id" not in call.args
    assert "conversation_id" not in call.args
    # target_server_id folded in for relay-bound tools.
    assert call.args["target_server_id"] == "web-1"


def test_parse_json_string_args():
    call = parse_mercure_tool_call({
        "tool_call_id": "tc-2",
        "tool": "tail_log",
        "args": json.dumps({"log_path": "/var/log/nginx/error.log"}),
    })
    assert call is not None
    assert call.args == {"log_path": "/var/log/nginx/error.log"}


def test_parse_bad_json_string_args_falls_back_empty():
    call = parse_mercure_tool_call({
        "tool_call_id": "tc-3",
        "tool": "tail_log",
        "args": "{not json",
    })
    assert call is not None
    assert call.args == {}


def test_parse_target_not_folded_for_local_tools():
    # list_instances runs via ServonautTools locally; an injected
    # target_server_id kwarg would TypeError there.
    call = parse_mercure_tool_call({
        "tool_call_id": "tc-4",
        "tool": "list_instances",
        "target_server_id": "web-1",
        "args": {},
    })
    assert call is not None
    assert "target_server_id" not in call.args


def test_parse_target_not_folded_when_args_already_target():
    call = parse_mercure_tool_call({
        "tool_call_id": "tc-5",
        "tool": "run_command",
        "target_server_id": "web-1",
        "args": {"instance_id": "i-123", "command": "uptime"},
    })
    assert call is not None
    assert call.args["instance_id"] == "i-123"
    assert "target_server_id" not in call.args


def test_parse_guard_falls_back_to_client_mirror():
    # No guard_level on the wire → use the client mirror, not a blanket
    # "standard", so readonly tools stay readonly under strict policies.
    call = parse_mercure_tool_call({
        "tool_call_id": "tc-6",
        "tool": "list_instances",
        "args": {},
    })
    assert call is not None
    assert call.guard_level == AIToolBridge.guard_for("list_instances") == "readonly"


def test_parse_observed_wire_envelope():
    # Golden-master for the literal bytes captured from staging Mercure
    # on 2026-06-11 — payload is a JSON ARRAY when empty (PHP []), there
    # is no tool_call_id / conversation_id / guard_level, and id is the
    # only idempotency key.
    call = parse_mercure_tool_call({
        "id": "evt-7b17-dispatch-1",
        "user_id": 7,
        "type": "list_instances",
        "target_server_id": None,
        "payload": [],
        "created_at": "2026-06-11T10:31:06+00:00",
        "ttl_seconds": 60,
    })
    assert call is not None
    assert call.tool == "list_instances"
    assert call.tool_call_id == "evt-7b17-dispatch-1"
    assert call.args == {}
    assert call.guard_level == "readonly"  # client-mirror fallback
    assert call.conversation_id == ""


def test_parse_enriched_envelope():
    # The enriched publish (server-side fix, 2026-06-11): `id` stays the
    # relay correlation id (dedup key), `tool_call_id` is the server row
    # id that must be echoed to /api/ai/chat/tool-result, and payload is
    # always an object. The parser must prefer tool_call_id over id.
    call = parse_mercure_tool_call({
        "id": "corr-model-1",
        "tool_call_id": "row-id-1",
        "conversation_id": "conv-9",
        "guard_level": "readonly",
        "user_id": 7,
        "type": "list_instances",
        "target_server_id": None,
        "payload": {},
        "created_at": "2026-06-11T11:00:00+00:00",
        "ttl_seconds": 60,
    })
    assert call is not None
    assert call.tool == "list_instances"
    assert call.tool_call_id == "row-id-1"
    assert call.conversation_id == "conv-9"
    assert call.guard_level == "readonly"
    assert call.args == {}


def test_parse_returns_none_without_tool_name():
    assert parse_mercure_tool_call({"tool_call_id": "tc-1", "args": {}}) is None


def test_parse_returns_none_without_tool_call_id():
    assert parse_mercure_tool_call({"tool": "tail_log", "args": {}}) is None


# ---------------------------------------------------------------------------
# Headless approval policy
# ---------------------------------------------------------------------------


def _config_manager(auto_approve: str):
    cfg = SimpleNamespace(relay=SimpleNamespace(ai_tool_auto_approve=auto_approve))
    manager = MagicMock()
    manager.get.return_value = cfg
    return manager


def _call(guard: str) -> ToolCall:
    return ToolCall(
        tool_call_id="tc-1", tool="run_command", args={},
        guard_level=guard, conversation_id="conv-1",
    )


@pytest.mark.parametrize("policy,guard,approved", [
    ("readonly", "readonly", True),
    ("readonly", "standard", False),
    ("readonly", "dangerous", False),
    ("standard", "readonly", True),
    ("standard", "standard", True),
    ("standard", "dangerous", False),
    ("dangerous", "readonly", True),
    ("dangerous", "standard", True),
    ("dangerous", "dangerous", True),
])
def test_policy_matrix(policy, guard, approved):
    confirm = build_headless_confirm(_config_manager(policy))
    if approved:
        assert run(confirm(_call(guard))) is True
    else:
        with pytest.raises(ToolConfirmDenied) as exc_info:
            run(confirm(_call(guard)))
        assert exc_info.value.reason == "headless_policy_denied"
        assert "ai_tool_auto_approve" in str(exc_info.value)


def test_policy_invalid_config_treated_as_readonly():
    confirm = build_headless_confirm(_config_manager("yolo"))
    with pytest.raises(ToolConfirmDenied):
        run(confirm(_call("standard")))
    assert run(confirm(_call("readonly"))) is True


def test_policy_unknown_guard_treated_as_standard():
    confirm = build_headless_confirm(_config_manager("standard"))
    assert run(confirm(_call("weird-tier"))) is True
    confirm_ro = build_headless_confirm(_config_manager("readonly"))
    with pytest.raises(ToolConfirmDenied):
        run(confirm_ro(_call("weird-tier")))


# ---------------------------------------------------------------------------
# Bridge integration: ToolConfirmDenied → status="denied" + reason
# ---------------------------------------------------------------------------


def test_bridge_maps_confirm_denied_to_denied_status():
    api = MagicMock()
    api.post = AsyncMock(return_value={})
    audit = MagicMock()
    auth = MagicMock()
    auth.has_dangerous_ai_tools = True

    async def _confirm(call):
        raise ToolConfirmDenied("nope, policy", reason="headless_policy_denied")

    bridge = AIToolBridge(
        api_client=api,
        relay_executors=MagicMock(),
        mcp_audit=audit,
        confirm_callback=_confirm,
        auth_service=auth,
    )
    result = run(bridge.handle_tool_call(_call("standard")))
    assert result.status == "denied"
    assert "nope, policy" in result.result
    reasons = [c.args[4] for c in audit.log.call_args_list]
    assert "headless_policy_denied" in reasons


# ---------------------------------------------------------------------------
# Executor round trip
# ---------------------------------------------------------------------------


def _executor(handle_result=None, handle_raises=None, post_raises=None):
    bridge = MagicMock(spec=AIToolBridge)
    if handle_raises is not None:
        bridge.handle_tool_call = AsyncMock(side_effect=handle_raises)
    else:
        bridge.handle_tool_call = AsyncMock(
            return_value=handle_result or ToolResult(
                tool_call_id="tc-1", conversation_id="conv-1",
                status="ok", result="fine", bytes=4,
            )
        )
    if post_raises is not None:
        bridge.post_tool_result = AsyncMock(side_effect=post_raises)
    else:
        bridge.post_tool_result = AsyncMock(return_value=None)
    return RelayAIToolExecutor(bridge), bridge


_EVENT = {
    "tool_call_id": "tc-1",
    "tool": "list_instances",
    "args": {},
    "guard_level": "readonly",
    "conversation_id": "conv-1",
    "user_id": 7,
}


def test_executor_executes_and_posts():
    executor, bridge = _executor()
    result = run(executor.execute(dict(_EVENT)))
    assert result is not None and result.status == "ok"
    bridge.handle_tool_call.assert_awaited_once()
    call = bridge.handle_tool_call.await_args.args[0]
    assert isinstance(call, ToolCall)
    assert call.tool == "list_instances"
    bridge.post_tool_result.assert_awaited_once_with(result)


def test_executor_posts_synthetic_error_when_bridge_raises():
    executor, bridge = _executor(handle_raises=RuntimeError("boom"))
    result = run(executor.execute(dict(_EVENT)))
    assert result is not None
    assert result.status == "error"
    assert "boom" in (result.error or "")
    bridge.post_tool_result.assert_awaited_once_with(result)


def test_executor_swallows_post_failure():
    executor, bridge = _executor(post_raises=RuntimeError("api down"))
    result = run(executor.execute(dict(_EVENT)))
    assert result is not None and result.status == "ok"


def test_executor_skips_unparseable_event():
    executor, bridge = _executor()
    result = run(executor.execute({"something": "else"}))
    assert result is None
    bridge.handle_tool_call.assert_not_awaited()
    bridge.post_tool_result.assert_not_awaited()


# ---------------------------------------------------------------------------
# RelayListener routing
# ---------------------------------------------------------------------------

httpx = pytest.importorskip("httpx")
pytest.importorskip("httpx_sse")

from servonaut.services.relay_listener import RelayListener  # noqa: E402


def _listener(ai_tool_executor=None, user_id="7"):
    executors = MagicMock()
    executors.execute = AsyncMock()
    listener = RelayListener(
        executors=executors,
        base_url="https://app.example.com",
        mercure_url="https://hub.example.com/.well-known/mercure",
        auth_token="tok",
        user_id=user_id,
        ai_tool_executor=ai_tool_executor,
    )
    listener._client = MagicMock()
    listener._client.post = AsyncMock(
        return_value=MagicMock(status_code=200, text="")
    )
    return listener, executors


def test_listener_routes_ai_tool_call_to_executor():
    executor = MagicMock()
    executor.execute = AsyncMock(return_value=ToolResult(
        tool_call_id="tc-1", conversation_id="conv-1",
        status="ok", result="fine", bytes=4,
    ))
    listener, executors = _listener(ai_tool_executor=executor)
    event = dict(_EVENT, type="list_instances")
    run(listener._handle_event(json.dumps(event)))
    executor.execute.assert_awaited_once()
    assert executor.execute.await_args.args[0]["tool_call_id"] == "tc-1"
    executors.execute.assert_not_awaited()


def test_listener_skips_ai_tool_call_without_executor():
    listener, executors = _listener(ai_tool_executor=None)
    event = dict(_EVENT, type="list_instances")
    run(listener._handle_event(json.dumps(event)))
    executors.execute.assert_not_awaited()


def test_listener_rejects_mismatched_user_id_before_executor():
    executor = MagicMock()
    executor.execute = AsyncMock()
    listener, _ = _listener(ai_tool_executor=executor, user_id="7")
    event = dict(_EVENT, type="list_instances", user_id=42)
    run(listener._handle_event(json.dumps(event)))
    executor.execute.assert_not_awaited()


def test_listener_command_request_never_touches_executor():
    executor = MagicMock()
    executor.execute = AsyncMock()
    listener, executors = _listener(ai_tool_executor=executor)
    from servonaut.models.relay_messages import CommandResponse
    executors.execute = AsyncMock(return_value=CommandResponse(
        request_id="req-1", status="success", output="ok",
    ))
    event = {
        "id": "req-1", "user_id": 7, "type": "run_command",
        "target_server_id": "web-1", "payload": {"command": "ls"},
        "ttl_seconds": 60,
    }
    run(listener._handle_event(json.dumps(event)))
    executors.execute.assert_awaited_once()
    executor.execute.assert_not_awaited()


def test_listener_routes_colliding_tool_name_to_executor():
    # run_command is BOTH an AI tool name and a web-console CommandType
    # verb. An AI dispatch (marked by tool_call_id) must go to the
    # executor — running it down the web-console path skips the AI guard
    # policy/audit and posts the result to the wrong endpoint, so the AI
    # turn times out despite the command executing (observed live
    # 2026-06-11).
    executor = MagicMock()
    executor.execute = AsyncMock(return_value=ToolResult(
        tool_call_id="row-1", conversation_id="conv-1",
        status="ok", result="fine", bytes=4,
    ))
    listener, executors = _listener(ai_tool_executor=executor)
    event = {
        "id": "corr-1",
        "tool_call_id": "row-1",
        "conversation_id": "conv-1",
        "guard_level": "standard",
        "user_id": 7,
        "type": "run_command",
        "target_server_id": "web-1",
        "payload": {"command": "uptime"},
        "ttl_seconds": 60,
    }
    run(listener._handle_event(json.dumps(event)))
    executor.execute.assert_awaited_once()
    executors.execute.assert_not_awaited()


def test_listener_skips_colliding_ai_dispatch_without_executor():
    # The TUI's in-process listener (no executor) must NOT execute an AI
    # dispatch whose name collides with a CommandType verb — the chat
    # panel executes its own conversations from the SSE stream, and
    # running the Mercure copy too would double-execute the tool.
    listener, executors = _listener(ai_tool_executor=None)
    event = {
        "id": "corr-2",
        "tool_call_id": "row-2",
        "conversation_id": "conv-1",
        "user_id": 7,
        "type": "run_command",
        "target_server_id": "web-1",
        "payload": {"command": "uptime"},
        "ttl_seconds": 60,
    }
    run(listener._handle_event(json.dumps(event)))
    executors.execute.assert_not_awaited()


def test_listener_dedups_dual_published_tool_call():
    executor = MagicMock()
    executor.execute = AsyncMock(return_value=ToolResult(
        tool_call_id="tc-1", conversation_id="conv-1",
        status="ok", result="fine", bytes=4,
    ))
    listener, _ = _listener(ai_tool_executor=executor)
    event = json.dumps(dict(_EVENT, type="list_instances"))
    run(listener._handle_event(event))
    run(listener._handle_event(event))
    executor.execute.assert_awaited_once()
