"""Tests for MCP audit trail."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from servonaut.mcp.audit import AuditTrail


@pytest.fixture
def audit_file(tmp_path):
    return str(tmp_path / "test_audit.jsonl")


@pytest.fixture
def audit(audit_file):
    return AuditTrail(audit_file)


class TestAuditLog:
    def test_creates_file_on_log(self, audit, audit_file):
        audit.log("list_instances", {}, "result", True)
        assert Path(audit_file).exists()

    def test_writes_jsonl_format(self, audit, audit_file):
        audit.log("list_instances", {"region": "us-east-1"}, "result data", True)
        lines = Path(audit_file).read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["tool"] == "list_instances"
        assert entry["args"] == {"region": "us-east-1"}
        assert entry["allowed"] is True
        assert entry["result_length"] == len("result data")
        assert "timestamp" in entry

    def test_writes_multiple_entries(self, audit, audit_file):
        audit.log("list_instances", {}, "r1", True)
        audit.log("run_command", {"instance_id": "i-abc"}, "r2", True)
        audit.log("transfer_file", {}, "", False, "blocked")
        lines = Path(audit_file).read_text().strip().split("\n")
        assert len(lines) == 3

    def test_logs_blocked_with_reason(self, audit, audit_file):
        audit.log("run_command", {"command": "apt install"}, "", False, "not in allowlist")
        entry = json.loads(Path(audit_file).read_text().strip())
        assert entry["allowed"] is False
        assert entry["reason"] == "not in allowlist"
        assert entry["result_length"] == 0

    def test_result_length_correct(self, audit, audit_file):
        result = "a" * 100
        audit.log("list_instances", {}, result, True)
        entry = json.loads(Path(audit_file).read_text().strip())
        assert entry["result_length"] == 100

    def test_empty_result_length_zero(self, audit, audit_file):
        audit.log("list_instances", {}, "", True)
        entry = json.loads(Path(audit_file).read_text().strip())
        assert entry["result_length"] == 0

    def test_creates_parent_directories(self, tmp_path):
        deep_path = str(tmp_path / "a" / "b" / "c" / "audit.jsonl")
        trail = AuditTrail(deep_path)
        trail.log("list_instances", {}, "r", True)
        assert Path(deep_path).exists()

    def test_timestamp_is_iso_format(self, audit, audit_file):
        audit.log("check_status", {}, "ok", True)
        entry = json.loads(Path(audit_file).read_text().strip())
        ts = entry["timestamp"]
        parsed = datetime.fromisoformat(ts)
        assert parsed is not None


class TestReadRecent:
    def test_read_recent_empty_if_no_file(self, tmp_path):
        trail = AuditTrail(str(tmp_path / "nonexistent.jsonl"))
        result = trail.read_recent()
        assert result == []

    def test_read_recent_returns_entries(self, audit, audit_file):
        for i in range(5):
            audit.log(f"tool_{i}", {}, f"result_{i}", True)
        entries = audit.read_recent()
        assert len(entries) == 5

    def test_read_recent_respects_count(self, audit, audit_file):
        for i in range(20):
            audit.log("list_instances", {}, f"r{i}", True)
        entries = audit.read_recent(count=10)
        assert len(entries) == 10

    def test_read_recent_returns_last_n(self, audit, audit_file):
        for i in range(10):
            audit.log("list_instances", {"idx": i}, f"r{i}", True)
        entries = audit.read_recent(count=3)
        assert len(entries) == 3
        assert entries[0]["args"]["idx"] == 7
        assert entries[2]["args"]["idx"] == 9

    def test_read_recent_skips_corrupt_lines(self, audit_file):
        Path(audit_file).parent.mkdir(parents=True, exist_ok=True)
        with open(audit_file, "w") as f:
            f.write('{"tool": "list_instances", "args": {}, "allowed": true, "reason": "", "result_length": 0, "timestamp": "2026-01-01T00:00:00"}\n')
            f.write("NOT VALID JSON\n")
            f.write('{"tool": "check_status", "args": {}, "allowed": true, "reason": "", "result_length": 0, "timestamp": "2026-01-01T00:00:01"}\n')
        trail = AuditTrail(audit_file)
        entries = trail.read_recent()
        assert len(entries) == 2
        assert entries[0]["tool"] == "list_instances"
        assert entries[1]["tool"] == "check_status"

    def test_read_recent_default_count_50(self, audit, audit_file):
        for i in range(60):
            audit.log("list_instances", {}, f"r{i}", True)
        entries = audit.read_recent()
        assert len(entries) == 50

    def test_entries_have_correct_structure(self, audit, audit_file):
        audit.log("run_command", {"instance_id": "i-abc", "command": "ls"}, "output", True)
        entries = audit.read_recent()
        assert len(entries) == 1
        e = entries[0]
        assert "timestamp" in e
        assert "tool" in e
        assert "args" in e
        assert "allowed" in e
        assert "reason" in e
        assert "result_length" in e
