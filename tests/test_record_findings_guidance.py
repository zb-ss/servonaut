"""Agents are told to record what they learn about a server.

The MCP server instructions and the ``remember_server_finding`` tool
description carry the same short guidance as the in-app chat: when to save
a finding, how to avoid duplicates, and what never to store. Model behaviour
itself cannot be tested deterministically; these tests pin the text the
models are given and where it is given.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from servonaut.config.schema import MCPConfig
from servonaut.mcp.agent_guidance import RECORD_FINDINGS_GUIDANCE
from servonaut.mcp.server import records_findings, server_instructions
from servonaut.mcp.tool_schemas import TOOL_SCHEMAS

_HEADING = "Record what you learn"


# ---------------------------------------------------------------------------
# The guidance text
# ---------------------------------------------------------------------------

class TestGuidanceText:
    def test_names_the_tools_and_when_to_use_them(self):
        text = RECORD_FINDINGS_GUIDANCE
        assert _HEADING in text
        assert "remember_server_finding" in text
        assert "recall_server_findings" in text
        assert "supersede_id" in text
        # When: after diagnosing or fixing something a probe will not show.
        assert "fresh probe" in text

    def test_keeps_the_secret_and_injection_rules(self):
        lowered = RECORD_FINDINGS_GUIDANCE.lower()
        assert "never store secrets" in lowered
        assert "raw server output" in lowered
        assert "verified" in lowered

    def test_stays_short(self):
        # Every agent reads this on every session; keep it brief.
        assert len(RECORD_FINDINGS_GUIDANCE) < 1200


# ---------------------------------------------------------------------------
# MCP server instructions
# ---------------------------------------------------------------------------

class TestServerInstructions:
    def test_include_the_guidance_when_findings_can_be_recorded(self):
        text = server_instructions(record_findings=True)
        assert RECORD_FINDINGS_GUIDANCE in text

    def test_leave_it_out_when_they_cannot(self):
        text = server_instructions(record_findings=False)
        assert _HEADING not in text
        assert "remember_server_finding" not in text

    def test_keep_the_existing_sections(self):
        for flag in (True, False):
            text = server_instructions(record_findings=flag)
            assert "get_server_memory(instance_id) FIRST" in text
            assert "TRUST MODEL" in text
            assert "Confirmation protocol for mutating tools" in text


class TestRecordsFindings:
    def test_memory_listed_at_standard_level(self):
        assert records_findings(True, MCPConfig(guard_level="standard")) is True

    def test_memory_listed_at_dangerous_level(self):
        assert records_findings(True, MCPConfig(guard_level="dangerous")) is True

    def test_readonly_level_blocks_the_tool(self):
        assert records_findings(True, MCPConfig(guard_level="readonly")) is False

    def test_memory_tools_not_listed(self):
        assert records_findings(False, MCPConfig(guard_level="dangerous")) is False


def test_the_server_is_created_with_the_guidance(monkeypatch):
    pytest.importorskip("mcp")
    from servonaut.mcp import server as mcp_server

    captured = {}

    class FakeServer:
        def __init__(self, name, instructions=None):
            captured["instructions"] = instructions

        def list_tools(self):
            return lambda fn: fn

        def call_tool(self):
            return lambda fn: fn

    stub_tools = SimpleNamespace(
        has_memory=True, has_ovh=False, has_hetzner=False, has_ip_ban=False,
    )
    monkeypatch.setattr(mcp_server, "build_headless_tools", lambda cm: stub_tools)
    monkeypatch.setattr("mcp.server.Server", FakeServer)

    mcp_server.create_mcp_server()

    assert RECORD_FINDINGS_GUIDANCE in captured["instructions"]


# ---------------------------------------------------------------------------
# Tool description
# ---------------------------------------------------------------------------

class TestRememberToolDescription:
    def test_says_when_to_call_it(self):
        desc = TOOL_SCHEMAS["remember_server_finding"]["description"]
        assert "after you diagnose or fix" in desc
        assert "recall_server_findings" in desc
        assert "supersede_id" in desc

    def test_still_forbids_secrets(self):
        desc = TOOL_SCHEMAS["remember_server_finding"]["description"].lower()
        assert "never include secrets" in desc
