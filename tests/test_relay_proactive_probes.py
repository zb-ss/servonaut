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
        # Success output is JSON-enveloped per contract §F.1.
        assert json.loads(response.output) == {"text": "42 facts"}
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
        # Bridge errors are slug-prefixed for the skip-reason contract.
        assert response.error_message == "probe_failed: boom"

    def test_probe_without_bridge_still_answers_with_error(self):
        """TUI sessions before paid services wire up (or headless with a
        failed bridge init) must answer instead of burning the TTL."""
        listener = make_listener(probe_bridge=None)
        run(listener._handle_event(probe_event()))
        listener._post_result.assert_awaited_once()
        response = listener._post_result.await_args.args[0]
        assert response.status == "error"
        assert response.error_message.startswith("probe_executor_unavailable:")

    def test_disallowed_tool_answered_with_error_without_execution(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock()
        listener = make_listener(probe_bridge=bridge)
        run(listener._handle_event(probe_event(tool="run_command")))
        bridge.handle_tool_call.assert_not_awaited()
        response = listener._post_result.await_args.args[0]
        assert response.status == "error"
        assert response.error_message.startswith("not_permitted:")

    def test_bridge_exception_still_answers(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(side_effect=RuntimeError("kaput"))
        listener = make_listener(probe_bridge=bridge)
        run(listener._handle_event(probe_event()))
        response = listener._post_result.await_args.args[0]
        assert response.status == "error"
        assert response.error_message.startswith("probe_execution_failed:")
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


class TestProbeOutputContract:
    def test_prose_output_wrapped_as_json_object(self):
        from servonaut.services.relay_listener import ensure_json_probe_output
        out = ensure_json_probe_output("2 servers healthy, disk ok")
        assert json.loads(out) == {"text": "2 servers healthy, disk ok"}

    def test_json_object_passthrough(self):
        from servonaut.services.relay_listener import ensure_json_probe_output
        raw = '{"disk": {"used_percent": 91}}'
        assert ensure_json_probe_output(raw) == raw

    def test_json_scalar_wrapped(self):
        from servonaut.services.relay_listener import ensure_json_probe_output
        out = ensure_json_probe_output("42")
        assert json.loads(out) == {"text": "42"}

    def test_success_result_json_wrapped_end_to_end(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(
            return_value=_tool_result(result="host summary: all ok"),
        )
        listener = make_listener(probe_bridge=bridge)
        run(listener._handle_event(probe_event()))
        response = listener._post_result.await_args.args[0]
        assert json.loads(response.output) == {"text": "host summary: all ok"}


class TestProbeDenyList:
    def test_ssh_exec_readonly_denied_for_probes(self):
        assert not probe_tool_allowed("ssh_exec_readonly")

    def test_cloudwatch_top_ips_now_allowed(self):
        assert probe_tool_allowed("cloudwatch_top_ips")
        assert probe_tool_allowed("cloudwatch_insights")
        assert probe_tool_allowed("cloudtrail_lookup_events")


class TestProbeErrorSlugs:
    """Contract §F.1: error_message leads with a snake_case slug the
    server surfaces verbatim as the detector's skip reason."""

    def test_tool_text_mappings(self):
        from servonaut.services.relay_listener import probe_error_from_tool_text
        assert probe_error_from_tool_text(
            "Error: docker_not_available") == "docker_not_available"
        assert probe_error_from_tool_text(
            "No db_profile configured for web-1. To set one up …",
        ).startswith("db_not_configured:")
        assert probe_error_from_tool_text(
            "Instance not found: ghost").startswith("instance_not_found:")
        assert probe_error_from_tool_text(
            "Blocked: tool disabled").startswith("not_permitted:")
        assert probe_error_from_tool_text(
            "Error: ssh broke badly").startswith("probe_failed:")
        assert probe_error_from_tool_text('{"containers": []}') is None
        assert probe_error_from_tool_text("plain healthy prose") is None

    def test_errorish_ok_result_posted_as_slugged_error(self):
        """A chat-style handler failure (status=ok, prose 'Error: …')
        must reach the server as status=error with the slug leading."""
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(
            return_value=_tool_result(result="Error: docker_not_available"),
        )
        listener = make_listener(probe_bridge=bridge)
        run(listener._handle_event(probe_event(tool="docker_ps")))
        response = listener._post_result.await_args.args[0]
        assert response.status == "error"
        assert response.error_message == "docker_not_available"
        assert response.output == ""

    def test_db_not_configured_slug_end_to_end(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(return_value=_tool_result(
            result="No db_profile configured for web-1. To set one up "
                   "automatically, call db_setup_scan(instance_id='web-1')",
        ))
        listener = make_listener(probe_bridge=bridge)
        run(listener._handle_event(probe_event(tool="db_top_queries")))
        response = listener._post_result.await_args.args[0]
        assert response.status == "error"
        assert response.error_message.startswith("db_not_configured:")


class TestProbeArgDrift:
    """Playbook args can drift from the CLI tool schemas — unattended
    probes drop unknown TUNING args instead of failing the detector
    (observed live: slow_only / include_sleeping on the db probes)."""

    def test_filter_drops_unknown_args(self):
        from servonaut.services.relay_listener import filter_probe_args
        out = filter_probe_args(
            "db_top_queries",
            {"instance_id": "web-1", "limit": 20, "slow_only": True},
        )
        assert out == {"instance_id": "web-1", "limit": 20}

    def test_filter_passthrough_for_unknown_tool(self):
        from servonaut.services.relay_listener import filter_probe_args
        args = {"anything": 1}
        assert filter_probe_args("no_such_tool", args) == args

    def test_drifted_args_still_execute(self):
        bridge = MagicMock()
        bridge.handle_tool_call = AsyncMock(
            return_value=_tool_result(result='{"rows": []}'),
        )
        listener = make_listener(probe_bridge=bridge)
        run(listener._handle_event(probe_event(
            tool="db_top_queries",
            payload={"instance_id": "i-0000test01", "limit": 20,
                     "slow_only": True},
        )))
        call = bridge.handle_tool_call.await_args.args[0]
        assert "slow_only" not in call.args
        assert call.args["limit"] == 20
        response = listener._post_result.await_args.args[0]
        assert response.status == "success"

    def test_error_branch_messages_get_slugged(self):
        from servonaut.services.relay_listener import ensure_probe_error_slug
        assert ensure_probe_error_slug(
            "Invalid arguments for db_top_queries: unexpected keyword",
        ).startswith("invalid_probe_args:")
        assert ensure_probe_error_slug("something broke").startswith(
            "probe_failed:")
        assert ensure_probe_error_slug(
            "db_not_configured: no creds") == "db_not_configured: no creds"
        assert ensure_probe_error_slug("") == "probe_failed"

    def test_error_wrapped_specific_messages_get_specific_slugs(self):
        from servonaut.services.relay_listener import probe_error_from_tool_text
        assert probe_error_from_tool_text(
            "Error: Instance not found: web-1",
        ).startswith("instance_not_found:")
        assert probe_error_from_tool_text(
            "Error: No db_profile configured for web-1. To set one up …",
        ).startswith("db_not_configured:")
