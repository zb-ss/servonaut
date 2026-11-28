"""Screenshot tests: Agent activity audit screen at 160x50 and 100x30."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from textual.widgets import DataTable

from . import _harness, _snapshot

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


def _seed_snapshot_audit(path: Path) -> None:
    now = _harness.FROZEN_NOW
    rows = [
        {
            "timestamp": (now - timedelta(hours=2)).isoformat(),
            "tool": "list_instances",
            "args": {"state": "running"},
            "allowed": True,
            "reason": "",
            "result_length": 1200,
            "origin": "mcp",
            "source": "mcp",
            "client": "claude-code/1.4",
            "session_id": "sess-snap-1",
            "duration_ms": 35,
        },
        {
            "timestamp": (now - timedelta(hours=1, minutes=15)).isoformat(),
            "tool": "run_command",
            "args": {
                "instance_id": "i-0a91f3e8c201",
                "command": "sudo systemctl restart nginx",
                "transport": "auto",
            },
            "allowed": False,
            "reason": "team_rule",
            "result_length": 0,
            "origin": "ui",
            "source": "ai_chat",
            "conversation_id": "conv-snap-1",
            "duration_ms": 4,
            "target": {
                "id": "i-0a91f3e8c201",
                "name": "web-1",
                "host": "10.0.1.10",
                "provider": "aws",
                "region": "eu-west-1",
            },
        },
        {
            "timestamp": (now - timedelta(minutes=20)).isoformat(),
            "tool": "docker_stats",
            "args": {"instance_id": "hz-101"},
            "allowed": True,
            "reason": "",
            "result_length": 540,
            "origin": "relay",
            "source": "ai_chat",
            "conversation_id": "conv-snap-2",
            "duration_ms": 310,
            "transport_used": "ssh",
            "exit_code": 0,
            "target": {
                "id": "hz-101",
                "name": "worker-1",
                "host": "10.0.2.20",
                "provider": "hetzner",
                "region": "fsn1",
            },
        },
        {
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "tool": "run_command",
            "args": {
                "instance_id": "i-0a91f3e8c201",
                "command": "uptime && free -m",
                "transport": "auto",
            },
            "allowed": True,
            "reason": "",
            "result_length": 210,
            "origin": "mcp",
            "source": "mcp",
            "client": "claude-code/1.4",
            "session_id": "sess-snap-1",
            "duration_ms": 1420,
            "transport_used": "ssm",
            "ssh_fell_back": True,
            "ssm_command_id": "cmd-snap-9911",
            "exit_code": 0,
            "target": {
                "id": "i-0a91f3e8c201",
                "name": "web-1",
                "host": "10.0.1.10",
                "provider": "aws",
                "region": "eu-west-1",
            },
        },
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


@sizes
def test_agent_activity_screen(screen_snapshot: Any, size: str) -> None:
    async def run_before(pilot: Any) -> None:
        from servonaut.screens.agent_activity import AgentActivityScreen

        await _harness.wait_for_fleet(pilot)
        app = pilot.app
        cfg = app.config_manager.get()
        audit_path = Path(cfg.mcp.audit_path).expanduser()
        _seed_snapshot_audit(audit_path)

        app.push_screen(AgentActivityScreen())
        screen = await _harness.wait_for_screen(pilot, "AgentActivityScreen")
        table = screen.query_one("#aa_table", DataTable)
        await _harness.wait_until(
            pilot, lambda: table.row_count == 4 and not table.loading,
            "the agent activity table to load",
        )
        # Keep the context latency string deterministic across machines for SVG stability.
        ctx_widget = screen.query_one("#aa_context")
        ctx_text = str(ctx_widget.render())
        if "ms" in ctx_text and " · " in ctx_text:
            ctx_widget.update(ctx_text.rsplit(" · ", 1)[0])
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], run_before)
