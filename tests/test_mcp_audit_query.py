"""Tests for AuditQueryService (multi-file rotation, filtering, pagination) and CLI."""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from servonaut.cli.mcp_audit import add_mcp_parser, handle_mcp_command
from servonaut.mcp.audit_query import (
    AuditFilter,
    AuditQueryService,
    format_access_line,
    format_summary_text,
    parse_since,
)


def _write_rows(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            if isinstance(row, str):
                fh.write(row + "\n")
            else:
                fh.write(json.dumps(row) + "\n")


def _row(ts: datetime, tool: str = "run_command", **kwargs):
    base = {
        "timestamp": ts.isoformat(),
        "tool": tool,
        "args": {"instance_id": "i-web1", "command": "uptime", "transport": "auto"},
        "allowed": True,
        "reason": "",
        "result_length": 32,
        "origin": "mcp",
        "source": "mcp",
        "transport_used": "ssh",
        "target": {"id": "i-web1", "name": "prod-web-1", "host": "10.0.1.5"},
        "duration_ms": 120,
        "exit_code": 0,
    }
    base.update(kwargs)
    return base


class TestParseSince:
    def test_relative_and_all(self):
        now = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)
        assert parse_since("all", now=now) is None
        assert parse_since("24h", now=now) == now - timedelta(hours=24)
        assert parse_since("7d", now=now) == now - timedelta(days=7)
        assert parse_since("30m", now=now) == now - timedelta(minutes=30)

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_since("nonsense")


class TestAuditQueryService:
    def test_multi_file_rotation_and_mtime_skip(self, tmp_path):
        now = datetime.now(timezone.utc)
        live = tmp_path / "mcp_audit.jsonl"
        rot1 = tmp_path / "mcp_audit.jsonl.1"
        rot2 = tmp_path / "mcp_audit.jsonl.2"

        _write_rows(rot2, [_row(now - timedelta(days=10), tool="whoami", args={}, transport_used="")])
        _write_rows(rot1, [
            _row(now - timedelta(hours=30), tool="list_instances", args={}, transport_used=""),
            _row(now - timedelta(hours=10), tool="run_command", transport_used="ssm", ssh_fell_back=True),
        ])
        _write_rows(live, [
            "corrupt-json-line",
            _row(now - timedelta(hours=1), tool="run_command", origin="ui", source="ai_chat"),
        ])

        # Set rot2's mtime far in the past so mtime pruning skips it cleanly.
        old_ts = (now - timedelta(days=10)).timestamp()
        os.utime(rot2, (old_ts, old_ts))

        svc = AuditQueryService(live)
        page = svc.query(AuditFilter(since=now - timedelta(hours=24)), page=0, page_size=50)

        assert page.total_matches == 2
        assert page.summary.files_skipped_mtime == 1
        assert page.summary.corrupt_lines == 1
        # Newest first
        assert page.entries[0]["origin"] == "ui"
        assert page.entries[1]["transport_used"] == "ssm"

    def test_filters_origin_scope_category_transport_host_search(self, tmp_path):
        now = datetime.now(timezone.utc)
        live = tmp_path / "mcp_audit.jsonl"
        _write_rows(live, [
            _row(
                now - timedelta(minutes=30),
                tool="run_command",
                origin="mcp",
                transport_used="ssm",
                args={"instance_id": "i-api1", "command": "sudo systemctl restart nginx", "transport": "auto"},
                target={"id": "i-api1", "name": "prod-api-1"},
            ),
            _row(
                now - timedelta(minutes=20),
                tool="run_command",
                origin="ui",
                source="ai_chat",
                allowed=False,
                reason="team_rule",
                transport_used="",
                args={"instance_id": "i-db1", "command": "rm -rf /tmp/x", "transport": "auto"},
                target={"id": "i-db1", "name": "prod-db-1"},
            ),
            _row(
                now - timedelta(minutes=10),
                tool="cloudwatch_top_ips",
                origin="proactive",
                source="proactive",
                transport_used="",
                args={"log_group": "/aws/waf"},
                target={},
            ),
        ])

        svc = AuditQueryService(live)

        # Origin filter
        p_ui = svc.query(AuditFilter(origin="ui"))
        assert p_ui.total_matches == 1
        assert p_ui.entries[0]["origin"] == "ui"

        # Transport filter (SSM)
        p_ssm = svc.query(AuditFilter(transport="ssm"))
        assert p_ssm.total_matches == 1
        assert p_ssm.entries[0]["target"]["name"] == "prod-api-1"

        # Transport = none (API / local)
        p_none = svc.query(AuditFilter(transport="none"))
        assert p_none.total_matches == 1
        assert p_none.entries[0]["tool"] == "cloudwatch_top_ips"

        # Category filter (service_control)
        p_svc = svc.query(AuditFilter(category="service_control"))
        assert p_svc.total_matches == 1

        # Scope = denied
        p_denied = svc.query(AuditFilter(scope="denied"))
        assert p_denied.total_matches == 1
        assert p_denied.entries[0]["reason"] == "team_rule"

        # Host & search filter
        p_host = svc.query(AuditFilter(host="prod-api"))
        assert p_host.total_matches == 1
        p_search = svc.query(AuditFilter(search="systemctl"))
        assert p_search.total_matches == 1

    def test_pagination(self, tmp_path):
        now = datetime.now(timezone.utc)
        live = tmp_path / "mcp_audit.jsonl"
        rows = [_row(now - timedelta(seconds=50 - i), duration_ms=i) for i in range(25)]
        _write_rows(live, rows)

        svc = AuditQueryService(live)
        p0 = svc.query(AuditFilter(), page=0, page_size=10)
        p2 = svc.query(AuditFilter(), page=2, page_size=10)

        assert p0.total_matches == 25
        assert p0.total_pages == 3
        assert len(p0.entries) == 10
        assert p0.entries[0]["duration_ms"] == 24  # newest first
        assert len(p2.entries) == 5
        assert p2.entries[-1]["duration_ms"] == 0


class TestCLIMcpAudit:
    def test_cli_text_summary_and_json_output(self, tmp_path, capsys):
        now = datetime.now(timezone.utc)
        live = tmp_path / "mcp_audit.jsonl"
        _write_rows(live, [
            _row(
                now - timedelta(minutes=5),
                origin="mcp",
                client="claude-code/1.0",
                transport_used="ssm",
                ssh_fell_back=True,
                args={"instance_id": "i-web1", "command": "uptime", "transport": "auto"},
            ),
            _row(
                now - timedelta(minutes=2),
                origin="ui",
                source="ai_chat",
                transport_used="ssh",
                args={"instance_id": "i-web2", "command": "df -h", "transport": "ssh"},
                target={"id": "i-web2", "name": "staging-web"},
            ),
        ])

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="subcommand")
        add_mcp_parser(sub)

        # Text + summary
        ns = parser.parse_args(["mcp", "audit", "--since", "24h", "--summary", "--audit-path", str(live)])
        rc = handle_mcp_command(ns)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Total calls: 2" in out
        assert "ssm(fb)" in out
        assert "ui" in out

        # JSON + origin filter
        ns_json = parser.parse_args([
            "mcp", "audit", "--origin", "ui", "--json", "--audit-path", str(live),
        ])
        rc = handle_mcp_command(ns_json)
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["total_matches"] == 1
        assert payload["entries"][0]["origin"] == "ui"

        # Formatting sanity
        line = format_access_line(payload["entries"][0])
        assert "df -h" in line
        summary_str = format_summary_text(AuditQueryService(live).query(AuditFilter()).summary)
        assert "By transport:" in summary_str
