"""Auto-installer for Servonaut MCP server into coding agents."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

SUPPORTED_TARGETS = [
    'claude', 'opencode', 'cursor', 'windsurf', 'vscode', 'codex', 'agy',
]


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
        text = path.read_text()
        if not text.strip():
            return {}
        try:
            return json.loads(text)
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


def _install_agy() -> None:
    """Install into the Antigravity CLI global config.

    Path: ~/.gemini/config/mcp_config.json

    Antigravity uses the standard `mcpServers` map (command/args/env for stdio
    transport), so the JSON shape matches Claude Code and Cursor. The `agy`
    binary ships no `mcp` subcommand, so the file is written directly.
    """
    config_path = Path.home() / '.gemini' / 'config' / 'mcp_config.json'
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
    print("Restart Antigravity (agy) to use the new MCP server.")


_CODEX_TABLE = 'mcp_servers.servonaut'
_CODEX_HEADERS = (f'[{_CODEX_TABLE}]', '[mcp_servers."servonaut"]')

# Keys this installer owns. Everything else in an existing block (timeouts,
# approval mode, env) belongs to the user and is preserved verbatim.
_CODEX_MANAGED_KEYS = ('command', 'args')


def _codex_home() -> Path:
    """Return the Codex CLI home directory (honours $CODEX_HOME)."""
    return Path(os.environ.get('CODEX_HOME') or Path.home() / '.codex')


def _toml_str(value: str) -> str:
    """Render a Python string as a quoted TOML basic string."""
    escaped = (
        value.replace('\\', '\\\\')
        .replace('"', '\\"')
        .replace('\n', '\\n')
        .replace('\r', '\\r')
        .replace('\t', '\\t')
    )
    return f'"{escaped}"'


def _split_codex_block(text: str) -> tuple[list[str], list[str], list[str]]:
    """Split config text into (before, servonaut_block, after) line lists.

    The block runs from its table header to the next top-level table header
    (a line starting with '[' at column 0) or end of file.
    """
    lines = text.splitlines()

    start = next(
        (i for i, line in enumerate(lines) if line.strip() in _CODEX_HEADERS),
        None,
    )
    if start is None:
        return lines, [], []

    end = next(
        (j for j in range(start + 1, len(lines)) if lines[j].startswith('[')),
        len(lines),
    )
    return lines[:start], lines[start:end], lines[end:]


def _preserved_codex_lines(block: list[str]) -> list[str]:
    """Return the block's lines minus the header and the keys we manage.

    Multi-line values for a managed key are skipped in full by tracking
    bracket depth, so a `args = [\\n  "--mcp",\\n]` form leaves no orphans.
    """
    kept: list[str] = []
    depth = 0
    skipping = False

    for line in block[1:]:
        if skipping:
            depth += line.count('[') - line.count(']')
            skipping = depth > 0
            continue

        key, sep, value = line.partition('=')
        if sep and key.strip().strip('"') in _CODEX_MANAGED_KEYS:
            depth = value.count('[') - value.count(']')
            skipping = depth > 0
            continue

        kept.append(line)

    while kept and not kept[-1].strip():
        kept.pop()
    return kept


def _install_codex() -> None:
    """Install into the Codex CLI global config ($CODEX_HOME or ~/.codex).

    Codex uses TOML, and the Python stdlib can read TOML (3.11+) but never
    write it. The server's block is therefore rewritten textually: only
    `command` and `args` are managed here, and any other keys already set on
    the block are preserved so hand-tuned timeouts survive a re-install.

    See https://github.com/openai/codex/blob/main/docs/config.md
    """
    config_path = _codex_home() / 'config.toml'
    command, args = _resolve_mcp_command()

    text = config_path.read_text() if config_path.exists() else ''
    before, block, after = _split_codex_block(text)
    preserved = _preserved_codex_lines(block)

    new_block = [
        f'[{_CODEX_TABLE}]',
        f'command = {_toml_str(command)}',
        'args = [' + ', '.join(_toml_str(arg) for arg in args) + ']',
        *preserved,
    ]

    while before and not before[-1].strip():
        before.pop()
    if before:
        before.append('')
    if after:
        new_block.append('')

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text('\n'.join(before + new_block + after) + '\n')

    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    if preserved:
        print(f"  preserved existing settings: {len(preserved)} line(s)")
    print("Restart Codex to use the new MCP server.")


_INSTALLERS = {
    'claude': _install_claude,
    'opencode': _install_opencode,
    'cursor': _install_cursor,
    'windsurf': _install_windsurf,
    'vscode': _install_vscode,
    'codex': _install_codex,
    'agy': _install_agy,
}


def install_mcp_server(target: str) -> None:
    """Install servonaut MCP server into the specified coding agent.

    Args:
        target: One of 'claude', 'opencode', 'cursor', 'windsurf', 'vscode',
                'codex', 'agy', or 'all' to install into every supported
                client.
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
