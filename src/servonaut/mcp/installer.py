"""Auto-installer for Servonaut MCP server into coding agents."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

SUPPORTED_TARGETS = [
    "claude",
    "opencode",
    "cursor",
    "windsurf",
    "vscode",
    "codex",
    "agy",
    "gemini",
]


class MCPInstallerError(RuntimeError):
    """Raised when an existing client config cannot be updated safely."""


# Environment names are forwarded by reference, never by value. Provider SDK
# names are stable public contracts; additional $ENV_VAR references are
# discovered from the operator's Servonaut config at install time.
#
# A forwarded name that is unset when the agent starts arrives as an EMPTY
# string (the references use ``${NAME:-}`` so the agent never refuses the
# config). ``prune_empty_forwarded_env`` removes those at process start —
# botocore, for one, treats ``AWS_PROFILE=""`` as a profile named "" and
# fails every client.
_BASE_FORWARD_ENV_VARS = (
    "SSH_AUTH_SOCK",
    "BW_SESSION",
    "BWS_ACCESS_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "SERVONAUT_API_URL",
    "SERVONAUT_MCP_URL",
)
_ENV_REFERENCE_RE = re.compile(
    r"^\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}"
    r"|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))$"
)


def _version_probe_timeout() -> float:
    """Return the configured bounded client-version probe timeout."""
    try:
        timeout = float(
            os.environ.get("SERVONAUT_MCP_INSTALL_VERSION_TIMEOUT_SECONDS", "5")
        )
    except ValueError as exc:
        raise MCPInstallerError(
            "MCP installer version timeout must be numeric"
        ) from exc
    if timeout <= 0:
        raise MCPInstallerError("MCP installer version timeout must be positive")
    return timeout


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
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    return "windows"


def _appdata() -> Path:
    """Return the Windows %APPDATA% directory (or equivalent)."""
    return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))


def _load_json(path: Path) -> dict[str, Any]:
    """Load an agent config without risking replacement of invalid content."""
    if not path.exists():
        return {}

    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {}

    try:
        config = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MCPInstallerError(
            f"Refusing to overwrite invalid JSON in {path}: "
            f"line {exc.lineno}, column {exc.colno}"
        ) from exc

    if not isinstance(config, dict):
        raise MCPInstallerError(
            f"Refusing to overwrite {path}: the JSON root must be an object"
        )
    return config


def _atomic_write_text(path: Path, text: str) -> None:
    """Atomically write config text without replacing a dotfile symlink."""
    target_path = path.resolve(strict=False) if path.is_symlink() else path
    target_path.parent.mkdir(parents=True, exist_ok=True)
    mode = (
        target_path.stat().st_mode & 0o777 if target_path.exists() else 0o600
    )
    temp_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target_path.parent,
            prefix=f".{target_path.name}.",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, target_path)
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise


def _save_json(path: Path, config: Mapping[str, Any]) -> None:
    """Serialize and atomically write a JSON agent config."""
    _atomic_write_text(path, json.dumps(config, indent=2) + "\n")


def _mapping_at(
    parent: dict[str, Any],
    key: str,
    *,
    context: str,
) -> dict[str, Any]:
    """Return a nested mapping, creating it but never replacing a wrong type."""
    value = parent.get(key)
    if value is None:
        value = {}
        parent[key] = value
    if not isinstance(value, dict):
        raise MCPInstallerError(f"{context}.{key} must be a JSON object")
    return value


def _collect_env_references(value: Any, found: set[str]) -> None:
    """Collect exact $NAME/${NAME} references without retaining their values."""
    if isinstance(value, str):
        match = _ENV_REFERENCE_RE.fullmatch(value)
        if match:
            found.add(match.group("braced") or match.group("plain"))
        return
    if isinstance(value, Mapping):
        for nested in value.values():
            _collect_env_references(nested, found)
        return
    if isinstance(value, list):
        for nested in value:
            _collect_env_references(nested, found)


def _required_forward_env_vars() -> tuple[str, ...]:
    """Return runtime variables required by built-ins and local config refs."""
    found = set(_BASE_FORWARD_ENV_VARS)
    config_path = Path.home() / ".servonaut" / "config.json"
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            config = None
        _collect_env_references(config, found)
    return tuple(
        [*_BASE_FORWARD_ENV_VARS] + sorted(found.difference(_BASE_FORWARD_ENV_VARS))
    )


def prune_empty_forwarded_env() -> tuple[str, ...]:
    """Remove forwarded variables that reached this process as empty strings.

    None of the forwarded names has a meaningful empty value, and several
    break their SDK when empty (``AWS_PROFILE=""`` → ``ProfileNotFound`` on
    every boto3 client, ``AWS_SHARED_CREDENTIALS_FILE=""`` → no shared
    credentials, ``SERVONAUT_API_URL=""`` → an empty API base). Dropping
    them restores each SDK's default behaviour.

    Returns:
        The names removed, in forward-list order, so the caller can log them
        once logging is configured. Safe to call more than once.
    """
    pruned: list[str] = []
    for name in _required_forward_env_vars():
        if os.environ.get(name, None) == "":
            del os.environ[name]
            pruned.append(name)
    return tuple(pruned)


def _env_references(style: str) -> dict[str, str]:
    """Render client-native references without persisting environment values."""
    names = _required_forward_env_vars()
    if style == "claude":
        return {name: f"${{{name}:-}}" for name in names}
    if style == "env-colon":
        return {name: f"${{env:{name}}}" for name in names}
    if style == "opencode":
        return {name: f"{{env:{name}}}" for name in names}
    if style == "dollar":
        return {name: f"${name}" for name in names}
    raise ValueError(f"Unknown environment-reference style: {style}")


def _merge_server_entry(
    existing: Any,
    managed: Mapping[str, Any],
    *,
    env_references: Mapping[str, str] | None = None,
    env_key: str = "env",
) -> dict[str, Any]:
    """Update owned launch fields while retaining every user-owned setting."""
    if existing is None:
        entry: dict[str, Any] = {}
    elif isinstance(existing, dict):
        entry = dict(existing)
    else:
        raise MCPInstallerError("The existing servonaut server entry must be an object")

    entry.update(managed)
    if env_references is None:
        return entry

    existing_env = entry.get(env_key)
    if existing_env is not None and not isinstance(existing_env, dict):
        raise MCPInstallerError(
            f"The existing servonaut {env_key} setting must be an object"
        )
    merged_env = dict(env_references)
    merged_env.update(existing_env or {})
    entry[env_key] = merged_env
    return entry


def _install_claude() -> None:
    """Install into Claude Code (~/.claude.json)."""
    config_path = Path.home() / ".claude.json"
    config = _load_json(config_path)

    servers = _mapping_at(config, "mcpServers", context="Claude config")

    command, args = _resolve_mcp_command()
    servers["servonaut"] = _merge_server_entry(
        servers.get("servonaut"),
        {
            "type": "stdio",
            "command": command,
            "args": args,
        },
        env_references=_env_references("claude"),
    )

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    print("Restart Claude Code to use the new MCP server.")


def _installed_major_version(command: str) -> int | None:
    """Return an installed client's major version without invoking a shell."""
    command_path = shutil.which(command)
    if command_path is None:
        return None
    try:
        result = subprocess.run(
            [command_path, "--version"],
            capture_output=True,
            text=True,
            timeout=_version_probe_timeout(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = result.stdout or result.stderr or ""
    match = re.search(r"\b(\d+)\.\d+", output)
    return int(match.group(1)) if match else None


def _opencode_server_map(
    config: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Select classic or V2 OpenCode layout without corrupting either."""
    mcp = _mapping_at(config, "mcp", context="OpenCode config")
    existing_servers = mcp.get("servers")
    if existing_servers is not None:
        if not isinstance(existing_servers, dict):
            raise MCPInstallerError("OpenCode config.mcp.servers must be an object")
        return existing_servers, "v2"
    if "servonaut" in mcp:
        return mcp, "classic"

    classic_entries = any(
        isinstance(value, dict) and value.get("type") in {"local", "remote"}
        for key, value in mcp.items()
        if key != "timeout"
    )
    if classic_entries:
        return mcp, "classic"
    if (_installed_major_version("opencode") or 1) >= 2:
        servers: dict[str, Any] = {}
        mcp["servers"] = servers
        return servers, "v2"
    return mcp, "classic"


def _install_opencode() -> None:
    """Install into OpenCode global config.

    Linux/macOS: ~/.config/opencode/opencode.json
    Windows:     %APPDATA%/opencode/opencode.json

    See https://opencode.ai/docs/mcp-servers/
    """
    os_type = _get_os()
    if os_type == "windows":
        config_path = _appdata() / "opencode" / "opencode.json"
    else:
        config_path = Path.home() / ".config" / "opencode" / "opencode.json"

    config = _load_json(config_path)
    servers, layout = _opencode_server_map(config)

    command, args = _resolve_mcp_command()
    entry = _merge_server_entry(
        servers.get("servonaut"),
        {
            "type": "local",
            "command": [command, *args],
        },
        env_references=_env_references("opencode"),
        env_key="environment",
    )
    if layout == "classic":
        entry.setdefault("enabled", True)
    servers["servonaut"] = entry

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {[command, *args]}")
    print("Restart OpenCode to use the new MCP server.")


def _install_cursor() -> None:
    """Install into Cursor global config (~/.cursor/mcp.json).

    See https://cursor.com/docs/mcp
    """
    config_path = Path.home() / ".cursor" / "mcp.json"
    config = _load_json(config_path)

    servers = _mapping_at(config, "mcpServers", context="Cursor config")

    command, args = _resolve_mcp_command()
    # Cursor IDE and CLI releases have differed on environment interpolation.
    # Preserve explicit user env entries and rely on inherited environment
    # instead of injecting a token that some builds pass through literally.
    servers["servonaut"] = _merge_server_entry(
        servers.get("servonaut"),
        {
            "type": "stdio",
            "command": command,
            "args": args,
        },
    )

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    print("Restart Cursor to use the new MCP server.")


def _install_windsurf() -> None:
    """Install into Windsurf global config (~/.codeium/windsurf/mcp_config.json).

    See https://docs.windsurf.com/windsurf/cascade/mcp
    """
    config_path = Path.home() / ".codeium" / "windsurf" / "mcp_config.json"
    config = _load_json(config_path)

    servers = _mapping_at(config, "mcpServers", context="Windsurf config")

    command, args = _resolve_mcp_command()
    servers["servonaut"] = _merge_server_entry(
        servers.get("servonaut"),
        {
            "command": command,
            "args": args,
        },
        env_references=_env_references("env-colon"),
    )

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
    if os_type == "darwin":
        config_path = (
            Path.home()
            / "Library"
            / "Application Support"
            / "Code"
            / "User"
            / "mcp.json"
        )
    elif os_type == "windows":
        config_path = _appdata() / "Code" / "User" / "mcp.json"
    else:
        config_path = Path.home() / ".config" / "Code" / "User" / "mcp.json"

    config = _load_json(config_path)
    servers = _mapping_at(config, "servers", context="VS Code config")

    command, args = _resolve_mcp_command()
    servers["servonaut"] = _merge_server_entry(
        servers.get("servonaut"),
        {
            "type": "stdio",
            "command": command,
            "args": args,
        },
        env_references=_env_references("env-colon"),
    )

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
    config_path = Path.home() / ".gemini" / "config" / "mcp_config.json"
    config = _load_json(config_path)

    servers = _mapping_at(config, "mcpServers", context="Antigravity config")

    command, args = _resolve_mcp_command()
    # Antigravity documents this config shape but no interpolation grammar;
    # inherited environment is safer than a potentially literal placeholder.
    servers["servonaut"] = _merge_server_entry(
        servers.get("servonaut"),
        {
            "command": command,
            "args": args,
        },
    )

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    print("Restart Antigravity (agy) to use the new MCP server.")


def _enable_gemini_policy(config: dict[str, Any]) -> None:
    """Keep an explicitly installed server enabled by user-level MCP policy."""
    policy = config.get("mcp")
    if policy is None:
        return
    if not isinstance(policy, dict):
        raise MCPInstallerError("Gemini config.mcp must be an object")

    for key in ("allowed", "excluded"):
        values = policy.get(key)
        if values is None:
            continue
        if not isinstance(values, list) or not all(
            isinstance(value, str) for value in values
        ):
            raise MCPInstallerError(f"Gemini config.mcp.{key} must be a string list")
        if key == "allowed" and "servonaut" not in values:
            values.append("servonaut")
        elif key == "excluded" and "servonaut" in values:
            policy[key] = [value for value in values if value != "servonaut"]


def _install_gemini() -> None:
    """Install into Gemini CLI user settings (~/.gemini/settings.json)."""
    config_path = Path.home() / ".gemini" / "settings.json"
    config = _load_json(config_path)

    servers = _mapping_at(config, "mcpServers", context="Gemini config")
    _enable_gemini_policy(config)

    command, args = _resolve_mcp_command()
    servers["servonaut"] = _merge_server_entry(
        servers.get("servonaut"),
        {
            "command": command,
            "args": args,
        },
        env_references=_env_references("dollar"),
    )

    _save_json(config_path, config)
    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    print("Restart Gemini CLI to use the new MCP server.")


_CODEX_TABLE = "mcp_servers.servonaut"
_CODEX_HEADERS = (f"[{_CODEX_TABLE}]", '[mcp_servers."servonaut"]')

# Managed values are rewritten safely; every other user-owned line survives.
# Existing env_vars entries are merged with Servonaut's required variable names.
_CODEX_MANAGED_KEYS = ("command", "args", "env_vars")


def _codex_home() -> Path:
    """Return the Codex CLI home directory (honours $CODEX_HOME)."""
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")


def _toml_str(value: str) -> str:
    """Render a Python string as a quoted TOML basic string."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
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
        (j for j in range(start + 1, len(lines)) if lines[j].lstrip().startswith("[")),
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
            depth += _toml_bracket_delta(line)
            skipping = depth > 0
            continue

        key, sep, value = line.partition("=")
        if sep and key.strip().strip('"') in _CODEX_MANAGED_KEYS:
            depth = _toml_bracket_delta(value)
            skipping = depth > 0
            continue

        kept.append(line)

    while kept and not kept[-1].strip():
        kept.pop()
    return kept


def _toml_bracket_delta(value: str) -> int:
    """Count array brackets outside quoted strings and comments."""
    depth = 0
    quote: str | None = None
    escaped = False
    for character in value:
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\" and quote == '"':
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "#":
            break
        elif character == "[":
            depth += 1
        elif character == "]":
            depth -= 1
    return depth


def _codex_value_lines(
    block: list[str],
    wanted_key: str,
) -> list[str]:
    """Return one complete top-level TOML assignment from a server block."""
    for index, line in enumerate(block[1:], start=1):
        key, separator, value = line.partition("=")
        if not separator or key.strip().strip('"') != wanted_key:
            continue
        lines = [line]
        depth = _toml_bracket_delta(value)
        cursor = index + 1
        while depth > 0 and cursor < len(block):
            lines.append(block[cursor])
            depth += _toml_bracket_delta(block[cursor])
            cursor += 1
        if depth != 0:
            raise MCPInstallerError(f"Unclosed Codex {wanted_key} value")
        return lines
    return []


def _merged_codex_env_vars_lines(block: list[str]) -> list[str]:
    """Merge required local names into Codex env_vars without losing entries."""
    existing = _codex_value_lines(block, "env_vars")
    required = _required_forward_env_vars()
    if not existing:
        rendered = ", ".join(_toml_str(name) for name in required)
        return [f"env_vars = [{rendered}]"]

    text = "\n".join(existing)
    missing = [
        name
        for name in required
        if not re.search(
            rf"""(["']){re.escape(name)}\1""",
            text,
        )
    ]
    if not missing:
        return existing
    rendered = ", ".join(_toml_str(name) for name in missing)

    if len(existing) == 1:
        line = existing[0]
        closing = line.rfind("]")
        if closing < 0:
            raise MCPInstallerError("Codex env_vars must be a TOML array")
        prefix = line[:closing]
        opening = prefix.find("[")
        has_items = opening >= 0 and bool(prefix[opening + 1 :].strip())
        separator = ", " if has_items and not prefix.rstrip().endswith(",") else ""
        if has_items and not separator:
            separator = " "
        return [f"{prefix}{separator}{rendered}{line[closing:]}"]

    closing_index = next(
        (index for index in range(len(existing) - 1, -1, -1) if "]" in existing[index]),
        None,
    )
    if closing_index is None:
        raise MCPInstallerError("Codex env_vars must be a TOML array")
    prefix = existing[:closing_index]
    closing_line = existing[closing_index]
    if prefix and not prefix[-1].rstrip().endswith(("[", ",")):
        prefix[-1] = f"{prefix[-1]},"
    indent = re.match(r"^\s*", closing_line).group(0) + "  "
    inserted = [f"{indent}{_toml_str(name)}," for name in missing]
    return [*prefix, *inserted, closing_line]


def _install_codex() -> None:
    """Install into the Codex CLI global config ($CODEX_HOME or ~/.codex).

    Codex uses TOML, so the server block is rewritten textually. Command,
    arguments, and the merged environment allowlist are managed; all other
    settings are retained so hand-tuned timeouts survive a re-install.

    See https://github.com/openai/codex/blob/main/docs/config.md
    """
    config_path = _codex_home() / "config.toml"
    command, args = _resolve_mcp_command()

    text = config_path.read_text() if config_path.exists() else ""
    before, block, after = _split_codex_block(text)
    preserved = _preserved_codex_lines(block)

    forwarded_env = _merged_codex_env_vars_lines(block)

    new_block = [
        f"[{_CODEX_TABLE}]",
        f"command = {_toml_str(command)}",
        "args = [" + ", ".join(_toml_str(arg) for arg in args) + "]",
        *forwarded_env,
        *preserved,
    ]

    while before and not before[-1].strip():
        before.pop()
    if before:
        before.append("")
    if after:
        new_block.append("")

    rendered_config = "\n".join(before + new_block + after) + "\n"
    _atomic_write_text(config_path, rendered_config)

    print(f"Installed servonaut MCP server in {config_path}")
    print(f"  command: {command} {' '.join(args)}")
    forwarded_count = len(_required_forward_env_vars())
    print(f"  forwards {forwarded_count} runtime variables by name")
    if preserved:
        print(f"  preserved existing settings: {len(preserved)} line(s)")
    print("Restart Codex to use the new MCP server.")


_INSTALLERS = {
    "claude": _install_claude,
    "opencode": _install_opencode,
    "cursor": _install_cursor,
    "windsurf": _install_windsurf,
    "vscode": _install_vscode,
    "codex": _install_codex,
    "agy": _install_agy,
    "gemini": _install_gemini,
}


def _run_installer(name: str, installer: Callable[[], None]) -> None:
    """Run one installer with a concise, non-destructive failure surface."""
    try:
        installer()
    except (MCPInstallerError, OSError) as exc:
        print(f"Error: Could not install Servonaut for {name}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def install_mcp_server(target: str) -> None:
    """Install servonaut MCP server into the specified coding agent.

    Args:
        target: One of 'claude', 'opencode', 'cursor', 'windsurf', 'vscode',
                'codex', 'agy', 'gemini', or 'all' to install into every
                supported client.
    """
    if target == "all":
        failures: list[str] = []
        for name, installer in _INSTALLERS.items():
            print(f"\n--- {name} ---")
            try:
                _run_installer(name, installer)
            except SystemExit:
                failures.append(name)
        if failures:
            failed_names = ", ".join(failures)
            print(
                f"Error: MCP installation failed for: {failed_names}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        return

    installer = _INSTALLERS.get(target)
    if not installer:
        targets = ", ".join(SUPPORTED_TARGETS)
        print(f"Error: Unknown target '{target}'.")
        print(f"Supported targets: {targets}, all")
        sys.exit(1)

    _run_installer(target, installer)
