"""Helpers shared by the AWS journeys (not fixtures)."""

from __future__ import annotations

import json
from pathlib import Path

from e2e.harness.bootstrap import Sandbox


def audit_rows(sandbox: Sandbox) -> list[dict]:
    """The MCP audit trail of a child home, oldest first."""
    path: Path = sandbox.home / ".servonaut" / "mcp_audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def audit_text(sandbox: Sandbox) -> str:
    """The raw MCP audit file (for "never written anywhere" checks)."""
    path: Path = sandbox.home / ".servonaut" / "mcp_audit.jsonl"
    return path.read_text() if path.exists() else ""
