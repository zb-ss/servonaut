"""Auto-installer for Servonaut MCP server into coding agents."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

SUPPORTED_TARGETS = ['claude', 'opencode', 'cursor', 'windsurf', 'vscode']


def _resolve_mcp_command() -> tuple[str, list[str]]:
    """Resolve the servonaut MCP command and args.

    Prefers the installed 'servonaut' binary (works with pipx, pip, etc.).
    Falls back to the current Python + module invocation.

    Returns:
        Tuple of (command, args).
    """
    servonaut_bin = shutil.which("servonaut")
    if servonaut_bin:
        return servonaut_bin, ["--mcp"]

    print(
        "Warning: 'servonaut' command not found in PATH.\n"
        "  The MCP server may not work reliably.\n"
        "  Install with: pipx install servonaut"
    )
    return sys.executable, ["-m", "servonaut.main", "--mcp"]


def _get_os() -> str:
    """Return 'linux', 'darwin', or 'windows'."""
    if sys.platform.startswith('linux'):
        return 'linux'
    if sys.platform == 'darwin':
        return 'darwin'
    return 'windows'


def _appdata() -> Path:
    """Return the Windows %APPDATA% directory (or equivalent)."""
    return Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming'))


def _load_json(path: Path) -> dict:
    """Load a JSON config file, returning empty dict on missing or invalid."""
    if path.exists():
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            print(f"Warning: Could not parse {path}, will create fresh entry")
    return {}


def _save_json(path: Path, config: dict) -> None:
    """Write config dict as formatted JSON, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2) + '\n')


def _install_claude() -> None:
    """Install into Claude Code (~/.claude.json)."""
    config_path = Path.home() / '.claude.json'
    config = _load_json(config_path)

    if 'mcpServers' not in config:
        config['mcpServers'] = {}

    command, args = _resolve_mcp_command()
    config['mcpServers']['servonaut'] = {
        'type': 'stdio',
        'command': command,
        'args': args,
        'env': {},
    }

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    print("Restart Claude Code to use the new MCP server.")


def _install_opencode() -> None:
    """Install into OpenCode global config.

    Linux/macOS: ~/.config/opencode/opencode.json
    Windows:     %APPDATA%/opencode/opencode.json

    See https://opencode.ai/docs/mcp-servers/
    """
    os_type = _get_os()
    if os_type == 'windows':
        config_path = _appdata() / 'opencode' / 'opencode.json'
    else:
        config_path = Path.home() / '.config' / 'opencode' / 'opencode.json'

    config = _load_json(config_path)

    if 'mcp' not in config:
        config['mcp'] = {}

    command, args = _resolve_mcp_command()
    config['mcp']['servonaut'] = {
        'type': 'local',
        'command': [command] + args,
        'enabled': True,
    }

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {[command] + args}")
    print("Restart OpenCode to use the new MCP server.")


def _install_cursor() -> None:
    """Install into Cursor global config (~/.cursor/mcp.json).

    See https://cursor.com/docs/mcp
    """
    config_path = Path.home() / '.cursor' / 'mcp.json'
    config = _load_json(config_path)

    if 'mcpServers' not in config:
        config['mcpServers'] = {}

    command, args = _resolve_mcp_command()
    config['mcpServers']['servonaut'] = {
        'type': 'stdio',
        'command': command,
        'args': args,
        'env': {},
    }

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    print("Restart Cursor to use the new MCP server.")


def _install_windsurf() -> None:
    """Install into Windsurf global config (~/.codeium/windsurf/mcp_config.json).

    See https://docs.windsurf.com/windsurf/cascade/mcp
    """
    config_path = Path.home() / '.codeium' / 'windsurf' / 'mcp_config.json'
    config = _load_json(config_path)

    if 'mcpServers' not in config:
        config['mcpServers'] = {}

    command, args = _resolve_mcp_command()
    config['mcpServers']['servonaut'] = {
        'command': command,
        'args': args,
        'env': {},
    }

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    print("Restart Windsurf to use the new MCP server.")


def _install_vscode() -> None:
    """Install into VS Code user-level MCP config.

    Linux:   ~/.config/Code/User/mcp.json
    macOS:   ~/Library/Application Support/Code/User/mcp.json
    Windows: %APPDATA%/Code/User/mcp.json

    See https://code.visualstudio.com/docs/copilot/chat/mcp-servers
    """
    os_type = _get_os()
    if os_type == 'darwin':
        config_path = Path.home() / 'Library' / 'Application Support' / 'Code' / 'User' / 'mcp.json'
    elif os_type == 'windows':
        config_path = _appdata() / 'Code' / 'User' / 'mcp.json'
    else:
        config_path = Path.home() / '.config' / 'Code' / 'User' / 'mcp.json'

    config = _load_json(config_path)

    if 'servers' not in config:
        config['servers'] = {}

    command, args = _resolve_mcp_command()
    config['servers']['servonaut'] = {
        'command': command,
        'args': args,
    }

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    print("Restart VS Code to use the new MCP server.")


_INSTALLERS = {
    'claude': _install_claude,
    'opencode': _install_opencode,
    'cursor': _install_cursor,
    'windsurf': _install_windsurf,
    'vscode': _install_vscode,
}


def install_mcp_server(target: str) -> None:
    """Install servonaut MCP server into the specified coding agent.

    Args:
        target: One of 'claude', 'opencode', 'cursor', 'windsurf', 'vscode',
                or 'all' to install into every supported client.
    """
    if target == 'all':
        for name, installer in _INSTALLERS.items():
            print(f"\n--- {name} ---")
            installer()
        return

    installer = _INSTALLERS.get(target)
    if not installer:
        targets = ', '.join(SUPPORTED_TARGETS)
        print(f"Error: Unknown target '{target}'.")
        print(f"Supported targets: {targets}, all")
        sys.exit(1)

    installer()
