"""TUI tests for the read-only AgentActivityScreen under Account."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

from textual.app import App
from textual.widgets import DataTable, Input, Select, Static

from servonaut.config.schema import AppConfig
from servonaut.screens.agent_activity import AgentActivityScreen
from servonaut.styles import CSS_FILES
from servonaut.widgets.sidebar import Sidebar


class _DemoRedactor:
    def redact_text(self, text: str) -> str:
        return (
            text.replace("prod-web-1", "demo-host-1")
            .replace("10.0.1.5", "192.0.2.1")
            .replace("i-0abc1234", "i-demo0001")
        )


def _seed_audit(path: Path) -> None:
    now = datetime.now(timezone.utc)
    rows = [
        {
            "timestamp": (now - timedelta(minutes=25)).isoformat(),
            "tool": "run_command",
            "args": {"instance_id": "i-0abc1234", "command": "uptime", "transport": "auto"},
            "allowed": True,
            "reason": "",
            "result_length": 64,
            "origin": "mcp",
            "source": "mcp",
            "client": "claude-code/1.2",
            "session_id": "s-100",
            "duration_ms": 810,
            "transport_used": "ssm",
            "ssh_fell_back": True,
            "ssm_command_id": "cmd-ssm-42",
            "exit_code": 0,
            "target": {"id": "i-0abc1234", "name": "prod-web-1", "host": "10.0.1.5", "provider": "aws", "region": "eu-west-1"},
        },
        {
            "timestamp": (now - timedelta(minutes=15)).isoformat(),
            "tool": "run_command",
            "args": {"instance_id": "i-0abc1234", "command": "sudo systemctl restart nginx", "transport": "ssh"},
            "allowed": False,
            "reason": "team_rule",
            "result_length": 0,
            "origin": "ui",
            "source": "ai_chat",
            "conversation_id": "conv-99",
            "duration_ms": 4,
            "target": {"id": "i-0abc1234", "name": "prod-web-1", "host": "10.0.1.5"},
        },
        {
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "tool": "docker_stats",
            "args": {"instance_id": "i-0abc1234"},
            "allowed": True,
            "reason": "",
            "result_length": 420,
            "origin": "proactive",
            "source": "proactive",
            "duration_ms": 340,
            "transport_used": "ssh",
            "exit_code": 0,
            "target": {"id": "i-0abc1234", "name": "prod-web-1", "host": "10.0.1.5"},
        },
    ]
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


class _AuditHostApp(App):
    CSS_PATH = CSS_FILES

    def __init__(self, audit_path: Path, *, demo: bool = False) -> None:
        super().__init__()
        cfg = AppConfig()
        cfg.mcp.audit_path = str(audit_path)
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = cfg
        self.auth_service = None
        self.aws_service = None
        self.ovh_service = None
        self.hetzner_service = None
        self.relay_state = None
        self.vault_available = False
        self.demo_mode = demo
        self.redaction_service = _DemoRedactor() if demo else None
        self.copied: list[str] = []

    def provider_available(self, _provider: str) -> bool:
        return False

    def copy_to_clipboard(self, text: str) -> None:
        self.copied.append(text)

    def on_mount(self) -> None:
        self.push_screen(AgentActivityScreen())


class TestAgentActivityScreen:
    def test_sidebar_placement_and_filtering(self, tmp_path):
        audit_file = tmp_path / "mcp_audit.jsonl"
        _seed_audit(audit_file)

        async def _run_case():
            app = _AuditHostApp(audit_file)
            async with app.run_test(size=(160, 44)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                screen = app.screen
                assert isinstance(screen, AgentActivityScreen)

                # Verify sidebar places Agent activity under Account and highlights it.
                sidebar = screen.query_one(Sidebar)
                account_section = sidebar.query_one("#section_account")
                nav_btn = account_section.query_one("#nav_agent_activity")
                assert "Agent activity" in str(nav_btn.label)
                assert nav_btn.has_class("--active")

                table = screen.query_one("#aa_table", DataTable)
                assert table.row_count == 3

                # Filter Origin = UI
                screen.query_one("#aa_select_origin", Select).value = "ui"
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1
                detail_text = str(screen.query_one("#aa_detail_text", Static).render())
                assert "systemctl restart nginx" in detail_text
                assert "team_rule" in detail_text

                # Reset + filter Transport = SSM
                screen.action_clear_filters()
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 3

                screen.query_one("#aa_select_transport", Select).value = "ssm"
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1
                ssm_detail = str(screen.query_one("#aa_detail_text", Static).render())
                assert "cmd-ssm-42" in ssm_detail
                assert "fell back to SSM" in ssm_detail

                # Copy JSON shortcut works
                screen.action_copy_detail()
                assert len(app.copied) == 1
                assert "cmd-ssm-42" in app.copied[0]

                # Search input filters
                screen.action_clear_filters()
                await pilot.pause()
                await app.workers.wait_for_complete()
                inp = screen.query_one("#aa_search_input", Input)
                inp.value = "docker_stats"
                screen.on_input_submitted(Input.Submitted(inp, "docker_stats"))
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                assert table.row_count == 1

        asyncio.run(_run_case())

    def test_demo_mode_redacts_targets_and_detail(self, tmp_path):
        audit_file = tmp_path / "mcp_audit.jsonl"
        _seed_audit(audit_file)

        async def _run_case():
            app = _AuditHostApp(audit_file, demo=True)
            async with app.run_test(size=(160, 44)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                detail_text = str(app.screen.query_one("#aa_detail_text", Static).render())
                assert "prod-web-1" not in detail_text
                assert "10.0.1.5" not in detail_text
                assert "demo-host-1" in detail_text

        asyncio.run(_run_case())

    def test_empty_log_renders_gracefully(self, tmp_path):
        missing = tmp_path / "does_not_exist.jsonl"

        async def _run_case():
            app = _AuditHostApp(missing)
            async with app.run_test(size=(140, 40)) as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()

                table = app.screen.query_one("#aa_table", DataTable)
                assert table.row_count == 0
                detail = str(app.screen.query_one("#aa_detail_text", Static).render())
                assert "No MCP / agent activity" in detail

        asyncio.run(_run_case())
