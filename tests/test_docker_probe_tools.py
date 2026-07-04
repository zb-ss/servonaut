"""Tests for the docker_* read-only probe tools.

Pure parsers (utils/docker_probe) plus the tool-layer plumbing with a
mocked SSH seam: docker-absent / permission-denied sentinels, JSON
output shapes per the proactive-monitoring tool contract, container
name validation, and guard/audit behaviour.

Fixtures are generic (web-1, RFC1918) — no real hosts or customers.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools
from servonaut.utils.docker_probe import (
    parse_docker_ps_lines,
    parse_docker_stats_lines,
    parse_mem_bytes,
    summarize_docker_events,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------


class TestParseMemBytes:
    @pytest.mark.parametrize("raw,expected", [
        ("512B", 512),
        ("1KiB", 1024),
        ("11.3MiB", int(11.3 * 1024 ** 2)),
        ("2GiB", 2 * 1024 ** 3),
        ("1.5GB", int(1.5 * 1000 ** 3)),
        ("garbage", None),
        ("", None),
    ])
    def test_units(self, raw, expected):
        assert parse_mem_bytes(raw) == expected


class TestParseDockerPs:
    def test_full_row_with_compose_labels(self):
        line = json.dumps({
            "name": "/web-app-1",
            "image": "nginx:1.25",
            "status": "running",
            "health": "healthy",
            "restart_count": 2,
            "started_at": "2026-07-01T10:00:00Z",
            "ports": {
                "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
                "9000/tcp": None,
            },
            "labels": {
                "com.docker.compose.project": "shop",
                "com.docker.compose.service": "web",
            },
        })
        rows = parse_docker_ps_lines(line + "\ngarbage-line\n")
        assert len(rows) == 1
        row = rows[0]
        assert row["name"] == "web-app-1"
        assert row["health"] == "healthy"
        assert row["restart_count"] == 2
        assert row["ports"] == [{"host": 8080, "container": 80, "proto": "tcp"}]
        assert row["compose_project"] == "shop"
        assert row["compose_service"] == "web"

    def test_non_compose_container_has_null_compose_fields(self):
        line = json.dumps({
            "name": "/standalone", "image": "redis:7", "status": "running",
            "health": None, "restart_count": 0,
            "started_at": "2026-07-01T10:00:00Z", "ports": {}, "labels": {},
        })
        row = parse_docker_ps_lines(line)[0]
        assert row["compose_project"] is None
        assert row["compose_service"] is None
        assert row["ports"] == []


class TestParseDockerStats:
    def test_row(self):
        line = json.dumps({
            "Name": "web-app-1", "CPUPerc": "1.52%",
            "MemUsage": "11.3MiB / 957.4MiB", "MemPerc": "1.18%",
            "PIDs": "9",
        })
        row = parse_docker_stats_lines(line)[0]
        assert row["name"] == "web-app-1"
        assert row["cpu_percent"] == 1.52
        assert row["mem_used_bytes"] == int(11.3 * 1024 ** 2)
        assert row["mem_limit_bytes"] == int(957.4 * 1024 ** 2)
        assert row["pids"] == 9


class TestSummarizeEvents:
    def test_aggregation_and_filtering(self):
        lines = []
        for ts in (100, 200, 300):
            lines.append(json.dumps({
                "Type": "container", "status": "die",
                "Actor": {"ID": "abc", "Attributes": {"name": "web-app-1"}},
                "time": ts,
            }))
        lines.append(json.dumps({
            "Type": "container", "status": "oom",
            "Actor": {"ID": "abc", "Attributes": {"name": "web-app-1"}},
            "time": 250,
        }))
        lines.append(json.dumps({  # non-container → ignored
            "Type": "network", "status": "die",
            "Actor": {"ID": "n1", "Attributes": {"name": "bridge"}},
            "time": 260,
        }))
        lines.append(json.dumps({  # uninteresting status → ignored
            "Type": "container", "status": "exec_create",
            "Actor": {"ID": "abc", "Attributes": {"name": "web-app-1"}},
            "time": 270,
        }))
        events = summarize_docker_events("\n".join(lines))
        assert {(e["container"], e["event"], e["count"]) for e in events} == {
            ("web-app-1", "die", 3), ("web-app-1", "oom", 1),
        }
        die = next(e for e in events if e["event"] == "die")
        assert die["last_at"] == 300


# ---------------------------------------------------------------------------
# Tool layer (mocked SSH seam)
# ---------------------------------------------------------------------------


def _tools() -> ServonautTools:
    cfg = AppConfig()
    cm = MagicMock()
    cm.get.return_value = cfg
    tools = ServonautTools(
        config_manager=cm,
        aws_service=MagicMock(),
        custom_server_service=MagicMock(),
        cache_service=MagicMock(),
        ssh_service=MagicMock(),
        connection_service=MagicMock(),
        scp_service=MagicMock(),
        guard=CommandGuard(cfg.mcp),
        audit=MagicMock(),
    )
    tools._find_instance = AsyncMock(return_value={
        "id": "i-0000test01", "name": "web-1", "public_ip": "10.0.0.5",
    })
    return tools


class TestDockerToolLayer:
    def test_docker_ps_returns_json_object(self):
        tools = _tools()
        inspect_line = json.dumps({
            "name": "/web-app-1", "image": "nginx:1.25", "status": "running",
            "health": None, "restart_count": 0,
            "started_at": "2026-07-01T10:00:00Z", "ports": {}, "labels": {},
        })
        tools._exec_ssh = AsyncMock(return_value=(inspect_line, ""))
        out = run(tools.docker_ps("web-1"))
        payload = json.loads(out)
        assert payload["containers"][0]["name"] == "web-app-1"

    def test_docker_not_available_sentinel(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock(return_value=("DOCKER_NOT_AVAILABLE\n", ""))
        out = run(tools.docker_ps("web-1"))
        assert out == "Error: docker_not_available"
        tools._audit.log.assert_called_with(
            "docker_ps", {"instance_id": "web-1"}, "", False,
            "docker_not_available",
        )

    def test_docker_permission_denied_sentinel(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock(return_value=("DOCKER_PERMISSION_DENIED\n", ""))
        out = run(tools.docker_stats("web-1"))
        assert out == "Error: docker_permission_denied"

    def test_docker_logs_validates_container_name(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock()
        out = run(tools.docker_logs("web-1", "bad name; rm -rf /"))
        assert out.startswith("validation:")
        tools._exec_ssh.assert_not_awaited()

    def test_docker_logs_returns_bounded_lines(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock(return_value=("line1\nline2\nline3\n", ""))
        out = run(tools.docker_logs("web-1", "web-app-1", lines=2))
        payload = json.loads(out)
        assert payload["container"] == "web-app-1"
        assert payload["lines"] == ["line2", "line3"]

    def test_docker_events_summary_json(self):
        tools = _tools()
        event = json.dumps({
            "Type": "container", "status": "restart",
            "Actor": {"ID": "abc", "Attributes": {"name": "web-app-1"}},
            "time": 500,
        })
        tools._exec_ssh = AsyncMock(return_value=(event, ""))
        out = run(tools.docker_events_summary("web-1", since_minutes=60))
        payload = json.loads(out)
        assert payload["events"] == [{
            "container": "web-app-1", "event": "restart",
            "count": 1, "last_at": 500,
        }]

    def test_instance_not_found_audited(self):
        tools = _tools()
        tools._find_instance = AsyncMock(return_value=None)
        out = run(tools.docker_ps("ghost"))
        assert "Instance not found" in out
        tools._audit.log.assert_called_with(
            "docker_ps", {"instance_id": "ghost"}, "", False,
            "instance_not_found",
        )

    def test_probe_policy_allows_docker_tools(self):
        from servonaut.services.relay_listener import probe_tool_allowed
        for tool in ("docker_ps", "docker_stats", "docker_logs",
                     "docker_events_summary"):
            assert probe_tool_allowed(tool)


class TestSummarizeContainerLog:
    def test_web_kind_from_plain_access_lines(self):
        from servonaut.utils.docker_probe import summarize_container_log
        lines = []
        for _ in range(6):
            lines.append('10.0.0.5 - - [04/Jul/2026:10:00:00 +0000] '
                         '"GET /api/health HTTP/1.1" 200 12')
        lines.append('10.0.0.5 - - [04/Jul/2026:10:00:30 +0000] '
                     '"GET /checkout?step=2 HTTP/1.1" 502 0')
        out = summarize_container_log("\n".join(lines))
        assert out["kind"] == "web"
        assert out["status_mix"] == {"200": 6, "502": 1}
        assert out["error_rate_5xx"] == round(1 / 7, 4)
        assert out["top_paths"][0] == {"path": "/api/health", "requests": 6}
        # Query strings stripped so endpoints group.
        assert {"path": "/checkout", "requests": 1} in out["top_paths"]
        assert out["lines_scanned"] == 7

    def test_web_kind_from_json_access_lines(self):
        import json as _json
        from servonaut.utils.docker_probe import summarize_container_log
        lines = [
            _json.dumps({"level": "info", "status": 200,
                         "request": {"uri": "/", "method": "GET"}}),
            _json.dumps({"level": "info", "status": 404,
                         "request": {"uri": "/missing", "method": "GET"}}),
        ]
        out = summarize_container_log("\n".join(lines))
        assert out["kind"] == "web"
        assert out["status_mix"] == {"200": 1, "404": 1}
        assert out["error_rate_4xx"] == 0.5

    def test_app_kind_groups_error_patterns(self):
        from servonaut.utils.docker_probe import summarize_container_log
        lines = [
            "[2026-07-04 10:00:01] app.ERROR: Connection refused (attempt 17)",
            "[2026-07-04 10:05:44] app.ERROR: Connection refused (attempt 18)",
            "[2026-07-04 10:06:00] app.INFO: heartbeat ok",
        ]
        out = summarize_container_log("\n".join(lines))
        assert out["kind"] == "app"
        assert len(out["error_patterns"]) == 1
        assert out["error_patterns"][0]["count"] == 2
        assert "Connection refused" in out["error_patterns"][0]["sample"]

    def test_empty_stream(self):
        from servonaut.utils.docker_probe import summarize_container_log
        out = summarize_container_log("")
        assert out["kind"] == "unknown"
        assert out["lines_scanned"] == 0


class TestDockerLogSummaryToolLayer:
    def test_container_not_found_sentinel(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock(return_value=("CONTAINER_NOT_FOUND\n", ""))
        out = run(tools.docker_log_summary("web-1", "ghost"))
        assert out == "Error: container_not_found"

    def test_no_logs_slug(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock(return_value=("", ""))
        out = run(tools.docker_log_summary("web-1", "web-app-1"))
        assert out == "Error: no_logs_available"

    def test_summary_json(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock(return_value=(
            '10.0.0.5 - - [x] "GET / HTTP/1.1" 200 1\n' * 3, ""))
        payload = json.loads(run(tools.docker_log_summary("web-1", "web-app-1")))
        assert payload["kind"] == "web"
        assert payload["status_mix"] == {"200": 3}

    def test_container_name_validated(self):
        tools = _tools()
        tools._exec_ssh = AsyncMock()
        out = run(tools.docker_log_summary("web-1", "bad;name"))
        assert out.startswith("validation:")
        tools._exec_ssh.assert_not_awaited()

    def test_probe_policy_allows(self):
        from servonaut.services.relay_listener import probe_tool_allowed
        assert probe_tool_allowed("docker_log_summary")
