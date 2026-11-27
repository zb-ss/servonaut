"""Tests for Take A audit enrichment: origin, transport/SSM, exit code, target, security."""
from __future__ import annotations

import asyncio
import json
import os
import stat
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.mcp.audit import AuditTrail, audit_call_context
from servonaut.mcp.guards import GuardLevel
from servonaut.mcp.server import _dispatch_tool
from servonaut.services.ai_tool_bridge import AIToolBridge, ToolCall
from tests.test_mcp_tools import SAMPLE_INSTANCES, make_tools


def _run(coro):
    return asyncio.run(coro)


class TestAuditCallContextAndSecurity:
    def test_context_attaches_origin_client_session_and_duration(self, tmp_path):
        audit_file = tmp_path / "mcp_audit.jsonl"
        trail = AuditTrail(str(audit_file))

        with audit_call_context(
            origin="mcp", source="mcp", client="claude-code/1.2", session_id="sess1234",
        ):
            trail.log(
                "run_command",
                {"instance_id": "i-abc123", "command": "uptime", "transport": "auto"},
                "up 5 days",
                True,
                transport_used="ssh",
                exit_code=0,
            )

        rows = trail.read_recent(10)
        assert len(rows) == 1
        row = rows[0]
        assert row["origin"] == "mcp"
        assert row["source"] == "mcp"
        assert row["client"] == "claude-code/1.2"
        assert row["session_id"] == "sess1234"
        assert isinstance(row["duration_ms"], int) and row["duration_ms"] >= 0
        assert row["transport_used"] == "ssh"
        assert row["exit_code"] == 0
        assert row["op_class"] == "remote_command"
        assert row["remote_exec"] is True
        assert row["command_category"] == "readonly_inspect"
        assert row["command_stems"] == ["uptime"]

    def test_default_origin_marks_ui_calls(self, tmp_path):
        audit_file = tmp_path / "mcp_audit.jsonl"
        trail = AuditTrail(str(audit_file), default_origin="ui")
        trail.log("list_instances", {}, "ok", True)
        row = trail.read_recent(1)[0]
        assert row["origin"] == "ui"

    def test_file_created_with_0600_and_refuses_symlink(self, tmp_path):
        audit_file = tmp_path / "mcp_audit.jsonl"
        trail = AuditTrail(str(audit_file))
        trail.log("whoami", {}, "user", True)

        mode = stat.S_IMODE(os.stat(audit_file).st_mode)
        assert mode == 0o600

        if hasattr(os, "O_NOFOLLOW"):
            target = tmp_path / "target.txt"
            target.write_text("do-not-touch")
            symlink_path = tmp_path / "evil_audit.jsonl"
            symlink_path.symlink_to(target)
            sym_trail = AuditTrail(str(symlink_path))
            sym_trail.log("whoami", {}, "user", True)
            assert target.read_text() == "do-not-touch"


class TestDispatchBoundaryAudit:
    def test_unknown_tool_and_unhandled_exception_are_audited(self, tmp_path):
        audit_file = tmp_path / "mcp_audit.jsonl"
        tools = make_tools(guard_level=GuardLevel.STANDARD, instances=SAMPLE_INSTANCES[:1])
        tools._audit = AuditTrail(str(audit_file))

        # 1. Unknown tool
        _run(_dispatch_tool(
            tools, "nonexistent_tool", {"foo": "bar"},
            client="cursor/0.5", session_id="s-01",
        ))

        # 2. Unhandled exception inside a real tool
        async def exploding_whoami():
            raise RuntimeError("boom-network")

        tools.whoami = exploding_whoami
        _run(_dispatch_tool(
            tools, "whoami", {},
            client="cursor/0.5", session_id="s-01",
        ))

        rows = tools._audit.read_recent(10)
        assert len(rows) == 2
        assert rows[0]["tool"] == "nonexistent_tool"
        assert rows[0]["allowed"] is False
        assert rows[0]["reason"] == "unknown_tool"
        assert rows[0]["origin"] == "mcp"
        assert rows[0]["client"] == "cursor/0.5"

        assert rows[1]["tool"] == "whoami"
        assert rows[1]["allowed"] is False
        assert rows[1]["reason"].startswith("exception:RuntimeError")
        assert rows[1]["session_id"] == "s-01"


class TestRunCommandTransportAndTargetTelemetry:
    def test_ssh_run_command_records_transport_exit_code_and_target(self, tmp_path):
        audit_file = tmp_path / "mcp_audit.jsonl"
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, instances=SAMPLE_INSTANCES[:1])
        tools._audit = AuditTrail(str(audit_file))

        fake_output = MagicMock()
        fake_output.__iter__ = lambda self: iter((b"ok\n", b""))
        fake_output.returncode = 0
        fake_output.diagnostics = b""

        with patch(
            "servonaut.mcp.tools.run_ssh_subprocess",
            new=AsyncMock(return_value=fake_output),
        ):
            res = _run(_dispatch_tool(
                tools,
                "run_command",
                {"instance_id": "i-abc123", "command": "sudo systemctl restart nginx", "transport": "auto"},
                client="claude-code/2.0",
                session_id="sess-ssh",
            ))

        assert "[transport_used: ssh]" in res[0].text
        rows = tools._audit.read_recent(5)
        assert len(rows) == 1
        row = rows[0]
        assert row["origin"] == "mcp"
        assert row["transport_used"] == "ssh"
        assert row["exit_code"] == 0
        assert row["target"]["id"] == "i-abc123"
        assert row["target"]["name"] == "web-server-prod"
        assert row["command_category"] == "service_control"
        assert row["used_sudo"] is True
        assert row["command_stems"] == ["systemctl"]

    def test_ssm_fallback_records_transport_fallback_and_command_id(self, tmp_path):
        audit_file = tmp_path / "mcp_audit.jsonl"
        tools = make_tools(guard_level=GuardLevel.STANDARD, instances=SAMPLE_INSTANCES[:1])
        tools._audit = AuditTrail(str(audit_file))

        ssh_fail = MagicMock()
        ssh_fail.__iter__ = lambda self: iter((b"", b"ssh: connect to host 1.2.3.4 port 22: Connection refused"))
        ssh_fail.returncode = 255
        ssh_fail.diagnostics = b""

        ssm_result = {
            "ok": True,
            "status": "Success",
            "stdout": "load average: 12.0\n",
            "stderr": "",
            "error": "",
            "command_id": "cmd-ssm-998877",
            "exit_code": 0,
        }

        with patch(
            "servonaut.mcp.tools.run_ssh_subprocess",
            new=AsyncMock(return_value=ssh_fail),
        ), patch(
            "servonaut.services.ssm_service.SSMService.run_command",
            new=AsyncMock(return_value=ssm_result),
        ):
            res = _run(_dispatch_tool(
                tools,
                "run_command",
                {"instance_id": "i-abc123", "command": "uptime", "transport": "auto"},
                client="codex/1.0",
                session_id="sess-ssm",
            ))

        assert "[transport_used: ssm]" in res[0].text
        rows = tools._audit.read_recent(5)
        assert len(rows) == 1
        row = rows[0]
        assert row["origin"] == "mcp"
        assert row["transport_used"] == "ssm"
        assert row["ssh_fell_back"] is True
        assert row["ssm_command_id"] == "cmd-ssm-998877"
        assert row["exit_code"] == 0
        assert row["target"]["id"] == "i-abc123"
        assert row["command_category"] == "readonly_inspect"


class TestBridgeOriginAndDeduplication:
    @pytest.mark.parametrize("origin,source", [
        ("ui", "ai_chat"),
        ("relay", "ai_chat"),
        ("proactive", "proactive"),
    ])
    def test_ai_tool_bridge_tags_origin_and_writes_single_row(self, tmp_path, origin, source):
        audit_file = tmp_path / "mcp_audit.jsonl"
        trail = AuditTrail(str(audit_file))
        tools = make_tools(guard_level=GuardLevel.STANDARD, instances=SAMPLE_INSTANCES[:1])
        tools._audit = trail

        bridge = AIToolBridge(
            api_client=MagicMock(),
            relay_executors=MagicMock(),
            mcp_audit=trail,
            confirm_callback=AsyncMock(return_value=True),
            auth_service=MagicMock(),
            servonaut_tools=tools,
            audit_source=source,
            audit_origin=origin,
        )

        call = ToolCall(
            tool_call_id="tc-dedup-1",
            tool="list_instances",
            args={},
            guard_level="readonly",
            conversation_id="conv-1",
        )
        res = _run(bridge.handle_tool_call(call))
        assert res.status == "ok"

        rows = trail.read_recent(10)
        assert len(rows) == 1
        assert rows[0]["origin"] == origin
        assert rows[0]["source"] == source
        assert rows[0]["tool_call_id"] == "tc-dedup-1"
