"""Auto-installer for Servonaut MCP server into Claude Code."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path


def install_mcp_server() -> None:
    """Install servonaut MCP server into Claude Code config.

    Claude Code stores MCP servers in ~/.claude.json (the main state file).
    """
    config_path = Path.home() / '.claude.json'

    config = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
        except json.JSONDecodeError:
            print(f"Warning: Could not parse {config_path}, creating mcpServers entry")

    if 'mcpServers' not in config:
        config['mcpServers'] = {}

    # Prefer the installed 'servonaut' command (works with pipx, pip, etc.)
    # Fall back to the current Python + module invocation
    servonaut_bin = shutil.which("servonaut")
    if servonaut_bin:
        command = servonaut_bin
        args = ["--mcp"]
    else:
        command = sys.executable
        args = ["-m", "servonaut.main", "--mcp"]
        print(
            "Warning: 'servonaut' command not found in PATH.\n"
            "  The MCP server may not work reliably.\n"
            "  Install with: pipx install servonaut"
        )

    config['mcpServers']['servonaut'] = {
        'type': 'stdio',
        'command': command,
        'args': args,
        'env': {},
    }

    config_path.write_text(json.dumps(config, indent=2))
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    print("Restart Claude Code to use the new MCP server.")
