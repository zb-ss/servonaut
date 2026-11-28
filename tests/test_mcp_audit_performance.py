"""Structural performance tests for multi-file rotated MCP audit logs.

Asserts deterministic algorithmic properties (reverse early-stop line counts,
rotated-file ``mtime`` pruning, bounded streaming memory via ``tracemalloc``,
and paginated TUI rendering) rather than flaky wall-clock deadlines.
"""
from __future__ import annotations

import asyncio
import json
import os
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

from textual.app import App
from textual.widgets import DataTable

from servonaut.config.schema import AppConfig
from servonaut.mcp.audit_query import AuditFilter, AuditQueryService
from servonaut.screens.agent_activity import AgentActivityScreen
from servonaut.styles import CSS_FILES


def _build_rotated_log(
    tmp_path: Path,
    *,
    lines_per_old_file: int = 2000,
    live_old_lines: int = 2000,
    live_recent_lines: int = 250,
) -> tuple[Path, int]:
    """Create a realistic multi-file rotated audit log spanning 30 days (~2-3 MB)."""
    now = datetime.now(timezone.utc)
    live = tmp_path / "mcp_audit.jsonl"
    total_lines = 0

    commands = [
        ("run_command", "uptime", "ssh", True, ""),
        ("run_command", "ps aux | grep nginx", "ssh", True, ""),
        ("run_command", "sudo systemctl restart nginx", "ssm", True, ""),
        ("run_command", "sed -i 's/a/b/' /etc/app.conf", "ssh", True, ""),
        ("run_command", "rm -rf /var/tmp/bad", "", False, "team_rule"),
        ("get_server_info", "", "ssh", True, ""),
        ("cloudwatch_top_ips", "", "", True, ""),
    ]
    origins = ("mcp", "mcp", "mcp", "ui", "relay", "proactive")

    def _emit_file(path: Path, start_ts: datetime, count: int, step_sec: float, mtime_ts: datetime) -> None:
        nonlocal total_lines
        buf = []
        for i in range(count):
            ts = start_ts + timedelta(seconds=i * step_sec)
            tool, cmd, via, allowed, reason = commands[i % len(commands)]
            origin = origins[i % len(origins)]
            row = {
                "timestamp": ts.isoformat(),
                "tool": tool,
                "args": (
                    {"instance_id": f"i-0abc{i % 20:04d}", "command": cmd, "transport": "auto"}
                    if tool == "run_command"
                    else {"instance_id": f"i-0abc{i % 20:04d}"}
                ),
                "allowed": allowed,
                "reason": reason,
                "result_length": 256,
                "origin": origin,
                "source": "mcp" if origin == "mcp" else ("proactive" if origin == "proactive" else "ai_chat"),
                "client": "claude-code/1.0" if origin == "mcp" else "",
                "duration_ms": 40 + (i % 500),
            }
            if via:
                row["transport_used"] = via
                if via == "ssm":
                    row["ssh_fell_back"] = True
                    row["ssm_command_id"] = f"cmd-perf-{i}"
                row["exit_code"] = 0
                row["target"] = {
                    "id": f"i-0abc{i % 20:04d}",
                    "name": f"prod-web-{i % 20}",
                    "provider": "aws",
                    "region": "eu-west-1",
                }
            buf.append(json.dumps(row))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(buf) + "\n")
        total_lines += count
        epoch = mtime_ts.timestamp()
        os.utime(path, (epoch, epoch))

    # 4 rotated archives: 28d..4d old
    for rot_idx, days_ago in ((4, 28), (3, 21), (2, 14), (1, 7)):
        p = tmp_path / f"mcp_audit.jsonl.{rot_idx}"
        start = now - timedelta(days=days_ago)
        end = start + timedelta(days=5)
        _emit_file(p, start, lines_per_old_file, (5 * 86400) / max(1, lines_per_old_file), end)

    if live_old_lines > 0:
        live_start = now - timedelta(days=5)
        _emit_file(live, live_start, live_old_lines, (4 * 86400 - 3600) / max(1, live_old_lines), now)
    recent_start = now - timedelta(hours=23)
    _emit_file(live, recent_start, live_recent_lines, (22 * 3600) / max(1, live_recent_lines), now)

    return live, total_lines


class TestLargeAuditLogPerformance:
    def test_24h_window_stops_early_without_scanning_old_history(self, tmp_path):
        live, total_lines = _build_rotated_log(tmp_path)
        assert total_lines == 10250

        svc = AuditQueryService(live)
        since = datetime.now(timezone.utc) - timedelta(hours=24)

        page = svc.query(AuditFilter(since=since), page=0, page_size=100)

        assert page.total_matches == 250
        assert len(page.entries) == 100
        # Early-stop inside the live file means older rotated files are never opened
        # and only the recent tail (+ small early-stop streak) is scanned.
        assert page.summary.files_scanned == 1
        assert page.summary.lines_scanned <= 270

    def test_mtime_pruning_skips_old_rotated_files_when_live_is_all_recent(self, tmp_path):
        live, _ = _build_rotated_log(
            tmp_path,
            lines_per_old_file=1500,
            live_old_lines=0,
            live_recent_lines=200,
        )
        svc = AuditQueryService(live)
        since = datetime.now(timezone.utc) - timedelta(hours=24)

        page = svc.query(AuditFilter(since=since), page=0, page_size=100)

        assert page.total_matches == 200
        assert page.summary.files_scanned == 1
        assert page.summary.files_skipped_mtime == 4

    def test_full_history_scan_streams_with_bounded_memory(self, tmp_path):
        live, total_lines = _build_rotated_log(tmp_path)
        svc = AuditQueryService(live)

        tracemalloc.start()
        try:
            page = svc.query(
                AuditFilter(transport="ssm", category="service_control"),
                page=0,
                page_size=100,
            )
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert page.total_matches > 1000
        assert len(page.entries) == 100
        assert page.summary.files_scanned == 5
        assert page.summary.lines_scanned == total_lines
        # Streaming pagination keeps peak memory bounded regardless of total matches.
        assert peak_bytes < 8 * 1024 * 1024, f"Peak memory {peak_bytes / (1024*1024):.1f} MB too high"

    def test_tui_paginates_large_rotated_log_cleanly(self, tmp_path):
        live, _ = _build_rotated_log(
            tmp_path,
            lines_per_old_file=1500,
            live_old_lines=1500,
            live_recent_lines=250,
        )

        class _HostApp(App):
            CSS_PATH = CSS_FILES
            demo_mode = False
            redaction_service = None

            def __init__(self):
                super().__init__()
                cfg = AppConfig()
                cfg.mcp.audit_path = str(live)
                self.config_manager = MagicMock()
                self.config_manager.get.return_value = cfg
                self.auth_service = None
                self.aws_service = None
                self.ovh_service = None
                self.hetzner_service = None
                self.relay_state = None
                self.vault_available = False

            def provider_available(self, _provider: str) -> bool:
                return False

            def on_mount(self) -> None:
                self.push_screen(AgentActivityScreen())

        async def _exercise():
            app = _HostApp()
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                screen = app.screen
                assert isinstance(screen, AgentActivityScreen)
                table = screen.query_one("#aa_table", DataTable)
                assert table.row_count == 100
                assert screen._page_result is not None
                assert screen._page_result.total_matches == 250

                screen.action_next_page()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert screen._current_page == 1
                assert table.row_count == 100

        asyncio.run(_exercise())
