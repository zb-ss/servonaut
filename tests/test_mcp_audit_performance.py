"""Performance tests for large & rotated MCP audit logs (~20+ MB / 60k+ lines)."""
from __future__ import annotations

import asyncio
import json
import os
import time
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig
from servonaut.mcp.audit import AuditTrail
from servonaut.mcp.audit_query import AuditFilter, AuditQueryService
from servonaut.screens.agent_activity import AgentActivityScreen
from servonaut.styles import CSS_FILES
from textual.app import App
from textual.widgets import DataTable


def _build_large_rotated_log(
    tmp_path: Path,
    *,
    lines_per_old_file: int = 12000,
    live_old_lines: int = 11500,
    live_recent_lines: int = 500,
) -> tuple[Path, int]:
    """Create a realistic multi-file rotated audit log spanning 30 days.

    Default totals: 4 rotated files × 12k + 12k live = 60,000 lines (~18–22 MB),
    with 500 entries inside the last 24 hours.
    """
    now = datetime.now(timezone.utc)
    live = tmp_path / "mcp_audit.jsonl"
    total_lines = 0

    commands = [
        ("run_command", "uptime", "ssh", "readonly_inspect", True, ""),
        ("run_command", "ps aux | grep nginx", "ssh", "readonly_inspect", True, ""),
        ("run_command", "sudo systemctl restart nginx", "ssm", "service_control", True, ""),
        ("run_command", "sed -i 's/a/b/' /etc/app.conf", "ssh", "file_write", True, ""),
        ("run_command", "rm -rf /var/tmp/bad", "", "blocked", False, "team_rule"),
        ("get_server_info", "", "ssh", "remote_probe", True, ""),
        ("cloudwatch_top_ips", "", "", "cloud_api", True, ""),
    ]
    origins = ("mcp", "mcp", "mcp", "ui", "relay", "proactive")

    def _emit_file(path: Path, start_ts: datetime, count: int, step_sec: float, mtime_ts: datetime) -> None:
        nonlocal total_lines
        buf = []
        for i in range(count):
            ts = start_ts + timedelta(seconds=i * step_sec)
            tool, cmd, via, cat, allowed, reason = commands[i % len(commands)]
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
                "op_class": "remote_command" if tool == "run_command" else ("remote_probe" if tool == "get_server_info" else "cloud_api"),
                "remote_exec": tool != "cloudwatch_top_ips",
                "command_category": cat,
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
            if len(buf) >= 2000:
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write("\n".join(buf) + "\n")
                buf.clear()
        if buf:
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

    # Live file: optional older lines from 5d..25h ago + recent lines in last 24h
    if live_old_lines > 0:
        live_start = now - timedelta(days=5)
        _emit_file(live, live_start, live_old_lines, (4 * 86400 - 3600) / max(1, live_old_lines), now)
    recent_start = now - timedelta(hours=23)
    _emit_file(live, recent_start, live_recent_lines, (22 * 3600) / max(1, live_recent_lines), now)

    return live, total_lines


class TestLargeAuditLogPerformance:
    def test_24h_window_fast_path_on_60k_rotated_lines(self, tmp_path):
        live, total_lines = _build_large_rotated_log(tmp_path)
        assert total_lines == 60000
        total_bytes = sum(p.stat().st_size for p in AuditQueryService(live).log_files())
        assert total_bytes >= 15 * 1024 * 1024  # realistic >= 15 MB multi-file log

        svc = AuditQueryService(live)
        since = datetime.now(timezone.utc) - timedelta(hours=24)

        started = time.monotonic()
        page = svc.query(AuditFilter(since=since), page=0, page_size=100)
        elapsed = time.monotonic() - started

        assert page.total_matches == 500
        assert len(page.entries) == 100
        # Early-stop inside live file means older rotated archives aren't even opened.
        assert page.summary.files_scanned == 1
        # Early-exit reverse scan over 500 recent rows must be fast even on a 20MB log.
        assert elapsed < 0.75, f"24h query took {elapsed:.3f}s (expected < 0.75s)"

    def test_mtime_pruning_skips_old_rotated_files_when_live_is_all_recent(self, tmp_path):
        live, _ = _build_large_rotated_log(
            tmp_path,
            lines_per_old_file=5000,
            live_old_lines=0,
            live_recent_lines=300,
        )
        svc = AuditQueryService(live)
        since = datetime.now(timezone.utc) - timedelta(hours=24)

        started = time.monotonic()
        page = svc.query(AuditFilter(since=since), page=0, page_size=100)
        elapsed = time.monotonic() - started

        assert page.total_matches == 300
        assert page.summary.files_scanned == 1
        assert page.summary.files_skipped_mtime == 4
        assert elapsed < 0.5, f"mtime-pruned query took {elapsed:.3f}s"

    def test_full_history_scan_bounded_memory_and_speed(self, tmp_path):
        live, _ = _build_large_rotated_log(tmp_path)
        svc = AuditQueryService(live)

        # 1. Uninstrumented wall-clock speed across all 60k lines (~20 MB).
        started = time.monotonic()
        page = svc.query(
            AuditFilter(transport="ssm", category="service_control"),
            page=0,
            page_size=100,
        )
        elapsed = time.monotonic() - started

        assert page.total_matches > 5000
        assert len(page.entries) == 100
        assert page.summary.files_scanned == 5
        assert elapsed < 5.0, f"Full 60k-line scan took {elapsed:.3f}s (expected < 5.0s)"

        # 2. Separate tracemalloc pass verifies bounded streaming peak memory.
        tracemalloc.start()
        try:
            page_mem = svc.query(
                AuditFilter(transport="ssm", category="service_control"),
                page=0,
                page_size=100,
            )
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert page_mem.total_matches == page.total_matches
        # Streaming pagination must keep peak memory well below loading all 60k dicts.
        assert peak_bytes < 15 * 1024 * 1024, f"Peak memory {peak_bytes / (1024*1024):.1f} MB too high"

    def test_write_path_enrichment_overhead(self, tmp_path):
        audit_file = tmp_path / "perf_write.jsonl"
        trail = AuditTrail(str(audit_file))

        started = time.monotonic()
        for i in range(1000):
            trail.log(
                "run_command",
                {"instance_id": f"i-{i}", "command": "sudo systemctl status nginx | grep active", "transport": "auto"},
                "active (running)",
                True,
                transport_used="ssh",
                exit_code=0,
            )
        elapsed = time.monotonic() - started
        assert elapsed < 2.5, f"1000 enriched writes took {elapsed:.3f}s"

    def test_tui_stays_responsive_on_25k_line_log(self, tmp_path):
        live, _ = _build_large_rotated_log(
            tmp_path,
            lines_per_old_file=5000,
            live_old_lines=4500,
            live_recent_lines=500,
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
            t0 = time.monotonic()
            async with app.run_test(size=(150, 42)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                mount_elapsed = time.monotonic() - t0

                screen = app.screen
                assert isinstance(screen, AgentActivityScreen)
                table = screen.query_one("#aa_table", DataTable)
                assert table.row_count == 100  # paginated, never dumps 25k rows
                assert mount_elapsed < 8.0, f"TUI load took {mount_elapsed:.2f}s"

                # Paginate to page 2
                screen.action_next_page()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert screen._current_page == 1
                assert table.row_count == 100

        asyncio.run(_exercise())
