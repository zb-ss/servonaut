"""Auto-installer for Servonaut MCP server into Claude Code."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def install_mcp_server() -> None:
    """Install servonaut MCP server into ~/.claude/settings.json."""
    settings_path = Path.home() / '.claude' / 'settings.json'
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    settings = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except json.JSONDecodeError:
            print(f"Warning: Could not parse {settings_path}, starting fresh")

    if 'mcpServers' not in settings:
        settings['mcpServers'] = {}

    python_path = sys.executable

    settings['mcpServers']['servonaut'] = {
        'command': python_path,
        'args': ['-m', 'servonaut.main', '--mcp'],
    }

    settings_path.write_text(json.dumps(settings, indent=2))
    print(f"Installed servonaut MCP server in {settings_path}")
    print("Restart Claude Code to use the new MCP server.")
