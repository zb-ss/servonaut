"""Fixture data and readers shared by the AWS journeys (not pytest fixtures)."""

from __future__ import annotations

import json
from pathlib import Path

from e2e.harness import fleet
from e2e.harness.aws import waf_log_record
from e2e.harness.bootstrap import Sandbox

WAF_GROUP = "aws-waf-logs-e2e"


def waf_traffic() -> list[dict]:
    """13 WAF records: one public client with allowed and blocked requests,
    one always blocked, one always allowed, and an internal health check that
    Top IPs leaves out because its address is private."""
    return (
        [waf_log_record("9.9.9.9", "ALLOW", uri=f"/page/{n}") for n in range(5)]
        + [waf_log_record("9.9.9.9", "BLOCK", uri="/wp-login.php", status=403) for _ in range(2)]
        + [waf_log_record("1.1.1.1", "BLOCK", uri="/wp-login.php", status=403) for _ in range(3)]
        + [waf_log_record("8.8.8.8", "ALLOW", uri="/") for _ in range(2)]
        + [waf_log_record(fleet.APP_1.private_ip, "ALLOW", uri="/health")]
    )


def rows_under_rule(text: str) -> list[list[str]]:
    """The whitespace-split rows below the dashed rule of a tool's table."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().startswith("---")) + 1
    return [line.split() for line in lines[start:] if line.strip()]


def audit_text(sandbox: Sandbox) -> str:
    """The raw MCP audit file (for "never written anywhere" checks)."""
    path: Path = sandbox.home / ".servonaut" / "mcp_audit.jsonl"
    return path.read_text() if path.exists() else ""


def audit_rows(sandbox: Sandbox) -> list[dict]:
    """The MCP audit trail of a child home, oldest first."""
    return [json.loads(line) for line in audit_text(sandbox).splitlines() if line.strip()]
