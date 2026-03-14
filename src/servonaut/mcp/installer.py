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

    # Ask user for MCP mode
    print("\nMCP server modes:")
    print("  1. Local (stdio) — default, all tools run locally")
    print("  2. Hybrid — free tools local + premium tools remote")
    print("  3. Remote — all tools via servonaut.dev")

    choice = input("\nSelect mode [1/2/3] (default: 1): ").strip()

    if choice == "3":
        # Remote-only mode
        config['mcpServers']['servonaut'] = {
            'type': 'stdio',
            'command': command,
            'args': args[:-1] + ["--mcp-remote"] if args else ["--mcp-remote"],
            'env': {},
        }
        print("Mode: remote (SSE via servonaut.dev)")
    elif choice == "2":
        # Hybrid mode — pass flag to local MCP to enable hybrid routing
        config['mcpServers']['servonaut'] = {
            'type': 'stdio',
            'command': command,
            'args': args,
            'env': {"SERVONAUT_MCP_MODE": "hybrid"},
        }
        print("Mode: hybrid (local free + remote premium)")
    else:
        # Local mode (default)
        config['mcpServers']['servonaut'] = {
            'type': 'stdio',
            'command': command,
            'args': args,
            'env': {},
        }
        print("Mode: local (stdio)")

    config_path.write_text(json.dumps(config, indent=2))
    print(f"\nInstalled servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(config['mcpServers']['servonaut']['args'])}")
    print("Restart Claude Code to use the new MCP server.")
