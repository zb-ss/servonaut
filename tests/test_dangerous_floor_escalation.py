"""Tests for PR5' dangerous-tool name-pattern floor escalation.

Verifies that handle_tool_call escalates any tool matching
DANGEROUS_FLOOR_PATTERNS to the 'dangerous' tier and writes an
audit row with reason 'dangerous_floor_escalation', regardless of
what guard_level the server asserts.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, call

import pytest

from servonaut.services.ai_tool_bridge import (
    AIToolBridge,
    ToolCall,
    _FloorDangerousMixin,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Unit tests for _FloorDangerousMixin._floor_dangerous in isolation
# ---------------------------------------------------------------------------


class TestFloorDangerousMixinUnit:
    def setup_method(self):
        self.mixin = _FloorDangerousMixin()

    def test_aws_terminate_escalated_from_standard(self):
        tier, escalated = self.mixin._floor_dangerous("aws_terminate_instance", "standard")
        assert tier == "dangerous"
        assert escalated is True

    def test_aws_run_instances_escalated_from_readonly(self):
        tier, escalated = self.mixin._floor_dangerous("aws_run_instances", "readonly")
        assert tier == "dangerous"
        assert escalated is True

    def test_s3_delete_object_escalated(self):
        tier, escalated = self.mixin._floor_dangerous("s3_delete_object", "standard")
        assert tier == "dangerous"
        assert escalated is True

    def test_hetzner_create_server_escalated(self):
        tier, escalated = self.mixin._floor_dangerous("hetzner_create_server", "standard")
        assert tier == "dangerous"
        assert escalated is True

    def test_safe_tool_not_escalated(self):
        tier, escalated = self.mixin._floor_dangerous("aws_list_regions", "readonly")
        assert tier == "readonly"
        assert escalated is False

    def test_cloudwatch_not_escalated(self):
        tier, escalated = self.mixin._floor_dangerous("cloudwatch_top_ips", "readonly")
        assert tier == "readonly"
        assert escalated is False

    def test_already_dangerous_not_re_escalated(self):
        """A tool that IS dangerous tier already produces escalated=False."""
        tier, escalated = self.mixin._floor_dangerous("aws_run_instances", "dangerous")
        assert tier == "dangerous"
        assert escalated is False  # server already said dangerous


# ---------------------------------------------------------------------------
# Integration: escalation inside handle_tool_call writes audit row
# ---------------------------------------------------------------------------


def _make_bridge(*, has_dangerous: bool = True) -> tuple:
    """Return (bridge, audit_mock) with all external deps mocked."""
    api = MagicMock()
    api.post = AsyncMock(return_value={})

    relay = MagicMock()
    relay.execute = AsyncMock(return_value=MagicMock(status="success", output="ok"))

    audit = MagicMock()
    audit.log = MagicMock()

    confirm = AsyncMock(return_value=True)
    auth = MagicMock()
    auth.has_dangerous_ai_tools = has_dangerous

    # ServonautTools mock that handles any tool call
    tools = MagicMock()
    tools.aws_terminate_instance = AsyncMock(return_value="terminated")
    tools.aws_list_regions = AsyncMock(return_value="us-east-1")

    bridge = AIToolBridge(
        api_client=api,
        relay_executors=relay,
        mcp_audit=audit,
        confirm_callback=confirm,
        auth_service=auth,
        servonaut_tools=tools,
    )
    return bridge, audit


class TestDangerousFloorEscalationIntegration:
    def test_escalation_audit_row_written_for_destructive_tool(self):
        """aws_terminate_instance arriving as 'standard' triggers audit row."""
        bridge, audit = _make_bridge()
        call_ = ToolCall(
            tool_call_id="tc-floor-1",
            tool="aws_terminate_instance",
            args={},
            guard_level="standard",  # server under-classified
            conversation_id="conv-floor",
        )
        result = run(bridge.handle_tool_call(call_))

        # Should succeed (dangerous entitlement granted + confirm accepted)
        assert result.status == "ok"

        # Audit must have been called with reason 'dangerous_floor_escalation'
        audit_calls = audit.log.call_args_list
        reasons = [
            c.args[4] if len(c.args) > 4 else c.kwargs.get("reason", "")
            for c in audit_calls
        ]
        assert "dangerous_floor_escalation" in reasons, (
            f"Expected 'dangerous_floor_escalation' in audit reasons but got: {reasons}"
        )

    def test_escalation_sets_guard_to_dangerous(self):
        """After floor escalation the effective call.guard_level is 'dangerous'."""
        bridge, audit = _make_bridge()
        call_ = ToolCall(
            tool_call_id="tc-floor-2",
            tool="aws_run_instances",
            args={},
            guard_level="standard",
            conversation_id="conv-floor",
        )
        # Capture guard_level at audit-log time via side_effect
        captured_guard = {}

        def capture_audit(*args, **kwargs):
            captured_guard["last"] = kwargs.get("guard_level")

        audit.log.side_effect = capture_audit
        bridge._servonaut_tools.aws_run_instances = AsyncMock(return_value="launched")
        run(bridge.handle_tool_call(call_))

        # The final ok_local audit row must carry guard_level='dangerous'
        assert captured_guard.get("last") == "dangerous"

    def test_safe_tool_no_floor_escalation_audit_row(self):
        """aws_list_regions at readonly does NOT trigger floor escalation row."""
        bridge, audit = _make_bridge()
        call_ = ToolCall(
            tool_call_id="tc-floor-safe",
            tool="aws_list_regions",
            args={},
            guard_level="readonly",
            conversation_id="conv-floor",
        )
        run(bridge.handle_tool_call(call_))

        audit_calls = audit.log.call_args_list
        reasons = [
            c.args[4] if len(c.args) > 4 else c.kwargs.get("reason", "")
            for c in audit_calls
        ]
        assert "dangerous_floor_escalation" not in reasons, (
            f"Unexpected floor escalation audit row for safe tool: {reasons}"
        )

    def test_floor_escalation_denied_without_dangerous_entitlement(self):
        """Floor-escalated tool is denied if auth.has_dangerous_ai_tools is False."""
        bridge, audit = _make_bridge(has_dangerous=False)
        call_ = ToolCall(
            tool_call_id="tc-floor-deny",
            tool="aws_terminate_instance",
            args={},
            guard_level="standard",
            conversation_id="conv-floor",
        )
        result = run(bridge.handle_tool_call(call_))
        assert result.status == "denied"
