"""Tests for proactive-monitoring probe handling in RelayListener.

Contract (§F.1): probe dispatches ride the command relay with
``source: "proactive"`` and results POST to
``/api/cli/command-result/{id}`` with the CommandResponse shape.

Pins:

- probe envelopes route to the probe bridge — never to the web-console
  executors and never to the AI chat tool-call path;
- EVERY probe is answered, including "no bridge wired" and
  "tool not permitted" (silence burns the relay TTL server-side);
- the unattended probe policy: readonly mirror + the in-DB
  introspection allowlist, nothing else;
- chat tool calls and web-console commands are untouched by the new
  routing.

Fixtures are generic — no real hosts, IPs, or customer identifiers.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

httpx = pytest.importorskip("httpx")
pytest.importorskip("httpx_sse")

from servonaut.models.relay_messages import CommandResponse
from servonaut.services.relay_listener import (
    PROBE_EXTRA_ALLOWED_TOOLS,
    RelayListener,
    build_probe_confirm,
    probe_tool_allowed,
)


def run(coro):
    return asyncio.run(coro)


def _tool_result(status="ok", result="42 facts", error=None):
    r = MagicMock()
    r.status = status
    r.result = result
    r.error = error
    return r


def make_listener(*, probe_bridge=None, ai_tool_executor=None):
    executors = MagicMock()
    executors.execute = AsyncMock()
    listener = RelayListener(
        executors=executors,
        base_url="https://app.example.com",
        mercure_url="https://hub.example.com/.well-known/mercure",
        auth_token="tok-abc",
        user_id="user-123",
        heartbeat_interval=30,
        ai_tool_executor=ai_tool_executor,
        probe_bridge=probe_bridge,
    )
    listener._post_result = AsyncMock()
    return listener


def probe_event(
    *, req_id="prb-1", tool="fleet_health_snapshot",
    target="i-0000test01", payload=None,
):
    return json.dumps({
        "id": req_id,
        "user_id": "user-123",
        "type": tool,
        "target_server_id": target,
        "payload": payload or {},
        "ttl_seconds": 60,
        "source": "proactive",
    })


class TestProbePolicy:
    def test_readonly_tools_allowed(self):
        assert probe_tool_allowed("fleet_health_snapshot")
        assert probe_tool_allowed("web_traffic_summary")
        assert probe_tool_allowed("enrich_ips")

    def test_db_introspection_allowlisted(self):
        for tool in PROBE_EXTRA_ALLOWED_TOOLS:
            assert probe_tool_allowed(tool)

    def test_mutating_and_unknown_tools_rejected(self):
        assert not probe_tool_allowed("run_command")
        assert not probe_tool_allowed("deploy")
        assert not probe_tool_allowed("block_ip")
        assert not probe_tool_allowed("some_future_tool")

    def test_probe_confirm_denies_disallowed(self):
        from servonaut.services.ai_tool_bridge import ToolConfirmDenied

        confirm = build_probe_confirm()
        call = MagicMock()
        call.tool = "deploy"
        with pytest.raises(ToolConfirmDenied):
            run(confirm(call))

    def test_probe_confirm_approves_allowed(self):
        confirm = build_probe_confirm()
        call = MagicMock()
        call.tool = "fleet_health_snapshot"
        assert run(confirm(call)) is True


class TestProbeRouting:
    def test_probe_executes_via_bridge_and_posts_success(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(return_value=_tool_result())
        listener = make_listener(probe_bridge=bridge)

        run(listener._handle_event(probe_event()))

        bridge.handle_tool_call.assert_awaited_once()
        call = bridge.handle_tool_call.await_args.args[0]
        assert call.tool == "fleet_health_snapshot"
        listener._post_result.assert_awaited_once()
        response = listener._post_result.await_args.args[0]
        assert isinstance(response, CommandResponse)
        assert response.request_id == "prb-1"
        assert response.status == "success"
        assert response.output == "42 facts"
        # Probe never touches the web-console executor path.
        listener._executors.execute.assert_not_called()

    def test_probe_bridge_error_status_posted(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(
            return_value=_tool_result(status="error", result="", error="boom"),
        )
        listener = make_listener(probe_bridge=bridge)
        run(listener._handle_event(probe_event()))
        response = listener._post_result.await_args.args[0]
        assert response.status == "error"
        assert response.error_message == "boom"

    def test_probe_without_bridge_still_answers_with_error(self):
        """TUI sessions before paid services wire up (or headless with a
        failed bridge init) must answer instead of burning the TTL."""
        listener = make_listener(probe_bridge=None)
        run(listener._handle_event(probe_event()))
        listener._post_result.assert_awaited_once()
        response = listener._post_result.await_args.args[0]
        assert response.status == "error"
        assert "cannot execute" in response.error_message

    def test_disallowed_tool_answered_with_error_without_execution(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock()
        listener = make_listener(probe_bridge=bridge)
        run(listener._handle_event(probe_event(tool="run_command")))
        bridge.handle_tool_call.assert_not_awaited()
        response = listener._post_result.await_args.args[0]
        assert response.status == "error"
        assert "not permitted" in response.error_message

    def test_bridge_exception_still_answers(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(side_effect=RuntimeError("kaput"))
        listener = make_listener(probe_bridge=bridge)
        run(listener._handle_event(probe_event()))
        response = listener._post_result.await_args.args[0]
        assert response.status == "error"
        assert "kaput" in response.error_message

    def test_mismatched_user_id_not_answered(self):
        """The existing user_id gate runs before probe routing."""
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(return_value=_tool_result())
        listener = make_listener(probe_bridge=bridge)
        raw = json.loads(probe_event())
        raw["user_id"] = "attacker-456"
        run(listener._handle_event(json.dumps(raw)))
        bridge.handle_tool_call.assert_not_awaited()
        listener._post_result.assert_not_awaited()


class TestNonProbeFlowsUntouched:
    def test_web_console_command_still_dispatches_to_executors(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(return_value=_tool_result())
        listener = make_listener(probe_bridge=bridge)
        listener._executors.execute = AsyncMock(
            return_value=CommandResponse(request_id="req-9", status="success"),
        )
        data = json.dumps({
            "id": "req-9",
            "user_id": "user-123",
            "type": "run_command",
            "target_server_id": "i-0000test01",
            "payload": {"command": "uptime"},
            "ttl_seconds": 60,
        })
        run(listener._handle_event(data))
        listener._executors.execute.assert_awaited_once()
        bridge.handle_tool_call.assert_not_awaited()

    def test_chat_tool_call_without_executor_skipped_and_unanswered(self):
        """TUI-mode chat tool calls stay skipped (chat panel owns them) —
        the probe bridge must NOT hijack conversation-carrying events."""
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(return_value=_tool_result())
        listener = make_listener(probe_bridge=bridge, ai_tool_executor=None)
        data = json.dumps({
            "id": "tc-1",
            "user_id": "user-123",
            "type": "fleet_health_snapshot",
            "target_server_id": "i-0000test01",
            "payload": {"tool_call_id": "tc-1", "conversation_id": "conv-1"},
            "ttl_seconds": 60,
        })
        run(listener._handle_event(data))
        bridge.handle_tool_call.assert_not_awaited()
        listener._post_result.assert_not_awaited()
