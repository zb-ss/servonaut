"""Regression guard: the MCP server path must stay headless.

The MCP server (``servonaut --mcp``) runs without a terminal UI, so importing
its module tree must never pull in ``textual``. A stray Textual import in a
service module would crash or bloat headless installs where the TUI is never
used. Each check runs in a fresh subprocess so imports from other tests can't
pollute ``sys.modules``.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC_DIR = str(Path(__file__).resolve().parent.parent / "src")

_HEADLESS_IMPORT_CHECK = """
import sys
import servonaut.mcp.server
import servonaut.mcp.tools
import servonaut.mcp.guards
import servonaut.mcp.audit
import servonaut.mcp.installer
import servonaut.config.manager
assert "textual" not in sys.modules, "textual leaked into the MCP import path"
assert "servonaut.app" not in sys.modules, "TUI app leaked into the MCP import path"
print("OK")
"""


def test_mcp_import_tree_does_not_load_textual():
    result = subprocess.run(
        [sys.executable, "-c", _HEADLESS_IMPORT_CHECK],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": SRC_DIR, "PATH": ""},
        timeout=30,
    )
    assert result.returncode == 0, (
        f"headless import check failed:\n{result.stdout}\n{result.stderr}"
    )
    assert "OK" in result.stdout
