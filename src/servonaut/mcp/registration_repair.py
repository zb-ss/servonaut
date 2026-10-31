"""Find and repair agent MCP registrations that name a removed Servonaut install.

Changing how Servonaut is installed (pipx to the desktop package, or back)
removes the old executable, while every coding agent's MCP config still names
it, so the agent can no longer start the server. Entries in the form
``--mcp-install`` writes are repointed at the running install; only the
command and its arguments change. Hand-written shell wrappers are reported and
left alone, because rewriting one would lose what it encodes (for example a
``$HOME``-relative path shared between machines).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from servonaut.mcp import installer
from servonaut.mcp.installer import MCPInstallerError
from servonaut.runtime import (
    DistributionKind,
    RuntimeCapabilityError,
    RuntimeLayout,
    RuntimeMarkerError,
    detect_runtime,
    validate_launch_argv,
)
from servonaut.services.ssh_host_keys import home_relative

if TYPE_CHECKING:
    from servonaut.main import ShortcutRepair

logger = logging.getLogger(__name__)

SERVER_NAME = "servonaut"

# An agent may rewrite its own config while the repair runs (Claude Code
# saves ~/.claude.json often). A write only lands if the file still holds what
# was read; otherwise the repair starts again from the new content.
_MAX_WRITE_ATTEMPTS = 3

# Interpreters that run a script given inline (``sh -c '...'``). Their entries
# are hand-written wrappers, never installer output.
_SHELL_NAMES = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "fish", "cmd", "powershell", "pwsh"}
)
_HOME_PREFIX_RE = re.compile(r"^(?:\$\{HOME\}|\$HOME|~)(?=[\\/]|$)")
# A path naming servonaut inside a wrapper script. The look-behind keeps the
# tail of a URL or of a longer path from counting as a path of its own.
_WRAPPER_PATH_RE = re.compile(
    r"(?<![\w:/\\.$~])"
    r"(?:\$\{HOME\}|\$HOME|~|/|[A-Za-z]:[\\/])"
    r"[^\s'\"`;|&()<>]*servonaut[^\s'\"`;|&()<>]*"
)


class RegistrationState(str, Enum):
    """What the check found in one agent's servonaut entry."""

    OK = "ok"
    REPAIRED = "repaired"
    # A hand-written wrapper names a Servonaut path that no longer exists.
    STALE_WRAPPER = "stale_wrapper"
    FAILED = "failed"


@dataclass(frozen=True)
class RegistrationReport:
    """The outcome for one agent config."""

    client: str
    label: str
    config_path: Path
    state: RegistrationState
    # The command the entry named when it was read.
    command: str = ""
    detail: str = ""


@dataclass(frozen=True)
class _JsonClient:
    name: str
    label: str
    # The maps that may hold the servonaut entry, in the order to search.
    server_maps: Callable[[dict[str, Any]], list[dict[str, Any]]]
    # OpenCode stores ``command`` as one list; the others split command/args.
    combined_command: bool = False


def _maps_at(*keys: str) -> Callable[[dict[str, Any]], list[dict[str, Any]]]:
    def select(config: dict[str, Any]) -> list[dict[str, Any]]:
        value = config
        for key in keys:
            value = value.get(key) if isinstance(value, dict) else None
        return [value] if isinstance(value, dict) else []

    return select


def _opencode_maps(config: dict[str, Any]) -> list[dict[str, Any]]:
    """The V2 ``mcp.servers`` map and the classic ``mcp`` map."""
    return [*_maps_at("mcp", "servers")(config), *_maps_at("mcp")(config)]


_JSON_CLIENTS = (
    _JsonClient("claude", "Claude Code", _maps_at("mcpServers")),
    _JsonClient("opencode", "OpenCode", _opencode_maps, combined_command=True),
    _JsonClient("cursor", "Cursor", _maps_at("mcpServers")),
    _JsonClient("windsurf", "Windsurf", _maps_at("mcpServers")),
    _JsonClient("vscode", "VS Code", _maps_at("servers")),
    _JsonClient("agy", "Antigravity", _maps_at("mcpServers")),
    _JsonClient("gemini", "Gemini CLI", _maps_at("mcpServers")),
)
_CODEX_LABEL = "Codex"


def is_command_missing(command: str) -> bool:
    """Whether *command* no longer names an existing executable.

    A path (absolute, ``~``- or ``$HOME``-relative) is checked on disk; a bare
    name is looked up on ``PATH``. A dangling symlink counts as missing.
    """
    expanded = _expand_home(command)
    if os.path.isabs(expanded) or "/" in expanded or "\\" in expanded:
        return not os.path.exists(expanded)
    return shutil.which(expanded) is None


def repair_stale_registrations(
    command: str, args: Sequence[str]
) -> list[RegistrationReport]:
    """Repoint every installer-written servonaut entry whose command is gone.

    Args:
        command: The MCP command of the running install.
        args: Its arguments (``["--mcp"]``).

    Returns:
        One report per agent config that has a servonaut entry Servonaut can
        check. Agents without one, and entries that run something else (a
        container, a package runner), are not reported.
    """
    if is_command_missing(command):
        logger.warning("MCP registration repair skipped: its own command is missing")
        return []
    target = [command, *args]
    reports: list[RegistrationReport] = []
    for client in _JSON_CLIENTS:
        report = _repair_json_client(client, target)
        if report is not None:
            reports.append(report)
    codex = _repair_codex(target)
    if codex is not None:
        reports.append(codex)
    return reports


def _expand_home(value: str) -> str:
    return _HOME_PREFIX_RE.sub(lambda _match: str(Path.home()), value, count=1)


def _executable_name(command: str) -> str:
    name = re.split(r"[\\/]", command)[-1].lower()
    return name.removesuffix(".exe")


def _is_installer_launch(argv: Sequence[str]) -> bool:
    """Whether *argv* has a shape ``--mcp-install`` writes."""
    command, args = argv[0], list(argv[1:])
    if "--mcp" not in args:
        return False
    return _executable_name(command) == "servonaut" or args[:2] == [
        "-m",
        "servonaut.main",
    ]


def _wrapper_paths(argv: Sequence[str]) -> list[str]:
    """The servonaut paths a shell wrapper's script names."""
    if _executable_name(argv[0]) not in _SHELL_NAMES:
        return []
    return _WRAPPER_PATH_RE.findall(" ".join(argv[1:]))


@dataclass(frozen=True)
class _Verdict:
    state: RegistrationState
    detail: str = ""
    needs_repair: bool = False


def _judge(argv: Sequence[str]) -> _Verdict | None:
    """Decide what to do with one entry; None when it is not Servonaut's to check."""
    if _is_installer_launch(argv):
        if is_command_missing(argv[0]):
            return _Verdict(RegistrationState.REPAIRED, needs_repair=True)
        return _Verdict(RegistrationState.OK)
    paths = _wrapper_paths(argv)
    if not paths:
        return None
    missing = [path for path in paths if not os.path.exists(_expand_home(path))]
    if missing:
        return _Verdict(
            RegistrationState.STALE_WRAPPER,
            f"its launch script names {', '.join(missing)}, which no longer exists",
        )
    return _Verdict(RegistrationState.OK)


def _entry_argv(entry: dict[str, Any], combined: bool) -> list[str] | None:
    command = entry.get("command")
    if combined:
        if isinstance(command, list) and command and all(
            isinstance(part, str) for part in command
        ):
            return list(command)
        return None
    args = entry.get("args", [])
    if not isinstance(command, str) or not command:
        return None
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return None
    return [command, *args]


def _set_entry_argv(entry: dict[str, Any], combined: bool, argv: list[str]) -> None:
    if combined:
        entry["command"] = list(argv)
        return
    entry["command"] = argv[0]
    entry["args"] = list(argv[1:])


def _failed(
    name: str, label: str, path: Path, detail: str, command: str = ""
) -> RegistrationReport:
    return RegistrationReport(
        name, label, path, RegistrationState.FAILED, command, detail
    )


def _repair_json_client(
    client: _JsonClient, target: list[str]
) -> RegistrationReport | None:
    path = installer.client_config_path(client.name)
    if not path.is_file():
        return None
    for _attempt in range(_MAX_WRITE_ATTEMPTS):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return _failed(client.name, client.label, path, f"cannot be read: {exc}")
        if not text.strip():
            return None
        try:
            config = json.loads(text)
        except json.JSONDecodeError as exc:
            return _failed(
                client.name,
                client.label,
                path,
                f"is not valid JSON (line {exc.lineno}, column {exc.colno})",
            )
        if not isinstance(config, dict):
            return None
        found = _find_json_entry(client, config)
        if found is None:
            return None
        entry, argv = found
        verdict = _judge(argv)
        if verdict is None:
            return None
        if not verdict.needs_repair:
            return RegistrationReport(
                client.name, client.label, path, verdict.state, argv[0], verdict.detail
            )
        _set_entry_argv(entry, client.combined_command, target)
        rendered = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
        try:
            if _replace_if_unchanged(path, text, rendered):
                return RegistrationReport(
                    client.name, client.label, path, RegistrationState.REPAIRED, argv[0]
                )
        except (OSError, UnicodeDecodeError) as exc:
            return _failed(
                client.name, client.label, path, f"cannot be written: {exc}", argv[0]
            )
    return _failed(
        client.name, client.label, path, "kept changing while it was repaired"
    )


def _find_json_entry(
    client: _JsonClient, config: dict[str, Any]
) -> tuple[dict[str, Any], list[str]] | None:
    for servers in client.server_maps(config):
        entry = servers.get(SERVER_NAME)
        if not isinstance(entry, dict):
            continue
        argv = _entry_argv(entry, client.combined_command)
        if argv is not None:
            return entry, argv
    return None


def _replace_if_unchanged(path: Path, expected: str, text: str) -> bool:
    """Write *text* only while *path* still holds *expected*."""
    if path.read_text(encoding="utf-8") != expected:
        return False
    installer._atomic_write_text(path, text)
    return True


def _repair_codex(target: list[str]) -> RegistrationReport | None:
    path = installer.client_config_path("codex")
    if not path.is_file():
        return None
    for _attempt in range(_MAX_WRITE_ATTEMPTS):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return _failed("codex", _CODEX_LABEL, path, f"cannot be read: {exc}")
        before, block, after = installer._split_codex_block(text)
        if not block:
            return None
        try:
            argv = _codex_argv(block)
        except MCPInstallerError as exc:
            return _failed("codex", _CODEX_LABEL, path, f"cannot be parsed: {exc}")
        if argv is None:
            return None
        verdict = _judge(argv)
        if verdict is None:
            return None
        if not verdict.needs_repair:
            return RegistrationReport(
                "codex", _CODEX_LABEL, path, verdict.state, argv[0], verdict.detail
            )
        new_block = [
            block[0],
            f"command = {installer._toml_str(target[0])}",
            "args = [" + ", ".join(installer._toml_str(arg) for arg in target[1:]) + "]",
            *installer._codex_lines_without(block, ("command", "args")),
        ]
        rendered = "\n".join([*before, *new_block, *after]) + "\n"
        try:
            if _replace_if_unchanged(path, text, rendered):
                return RegistrationReport(
                    "codex", _CODEX_LABEL, path, RegistrationState.REPAIRED, argv[0]
                )
        except (OSError, UnicodeDecodeError) as exc:
            return _failed(
                "codex", _CODEX_LABEL, path, f"cannot be written: {exc}", argv[0]
            )
    return _failed("codex", _CODEX_LABEL, path, "kept changing while it was repaired")


def _codex_argv(block: list[str]) -> list[str] | None:
    """The ``command`` and ``args`` of a Codex server block, decoded."""
    command_lines = installer._codex_value_lines(block, "command")
    if not command_lines:
        return None
    command = _toml_strings(command_lines)
    if len(command) != 1 or not command[0]:
        raise MCPInstallerError("command must be one string")
    return [command[0], *_toml_strings(installer._codex_value_lines(block, "args"))]


def _toml_strings(lines: list[str]) -> list[str]:
    """Decode the quoted strings of one TOML assignment, in order.

    Covers what the installer and people write by hand: basic and literal
    strings, arrays of them, and comments. Multi-line strings are refused
    rather than guessed at.
    """
    if not lines:
        return []
    _key, _separator, value = "\n".join(lines).partition("=")
    strings: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character == "#":
            newline = value.find("\n", index)
            index = len(value) if newline < 0 else newline
        elif character in {'"', "'"}:
            if value.startswith(character * 3, index):
                raise MCPInstallerError("multi-line strings are not supported")
            decoded, index = _toml_string_at(value, index)
            strings.append(decoded)
            continue
        index += 1
    return strings


def _toml_string_at(value: str, start: int) -> tuple[str, int]:
    """Decode the string opening at *start*; return it and the index after it."""
    quote = value[start]
    index = start + 1
    while index < len(value):
        character = value[index]
        if character == "\n":
            break
        if quote == '"' and character == "\\":
            index += 2
            continue
        if character == quote:
            raw = value[start + 1 : index]
            if quote == "'":
                return raw, index + 1
            try:
                return json.loads(f'"{raw}"'), index + 1
            except json.JSONDecodeError as exc:
                raise MCPInstallerError("unsupported string escape") from exc
        index += 1
    raise MCPInstallerError("unterminated string")


@dataclass(frozen=True)
class InstallRepairOutcome:
    """Everything one repair run checked and changed."""

    # The MCP command repaired entries now run.
    command: list[str]
    registrations: list[RegistrationReport] = field(default_factory=list)
    shortcuts: list[ShortcutRepair] = field(default_factory=list)

    @property
    def repaired_labels(self) -> list[str]:
        return [
            report.label
            for report in self.registrations
            if report.state is RegistrationState.REPAIRED
        ]

    @property
    def has_problems(self) -> bool:
        """Whether something still points at a removed install or could not be checked."""
        return any(
            report.state in {RegistrationState.STALE_WRAPPER, RegistrationState.FAILED}
            for report in self.registrations
        ) or any(shortcut.error is not None for shortcut in self.shortcuts)


def repair_install_paths(runtime: RuntimeLayout | None = None) -> InstallRepairOutcome:
    """Repoint agent MCP entries and terminal shortcuts at the running install.

    Raises:
        MCPInstallerError: The running install's MCP command cannot be resolved.
    """
    # The shortcut repair lives beside the code that writes the shortcuts.
    from servonaut.main import repair_terminal_shortcuts

    selected = runtime or detect_runtime()
    command, args = installer._resolve_mcp_command(selected)
    registrations = repair_stale_registrations(command, args)
    try:
        app_argv = validate_launch_argv(selected.current_app_argv(), runtime=selected)
    except (OSError, RuntimeCapabilityError, RuntimeMarkerError, ValueError) as exc:
        logger.info("Terminal shortcut repair skipped: %s", exc)
        shortcuts: list[ShortcutRepair] = []
    else:
        shortcuts = repair_terminal_shortcuts(app_argv)
    return InstallRepairOutcome([command, *args], registrations, shortcuts)


def repair_on_launch(runtime: RuntimeLayout | None = None) -> str | None:
    """Run the repair as the app starts; return the toast text, or None.

    A source checkout is skipped: its MCP command runs the checkout's own
    interpreter, and agents should only be moved to that when asked
    (``--mcp-install`` or ``--mcp-repair``).
    """
    selected = runtime or detect_runtime()
    if selected.kind is DistributionKind.SOURCE:
        return None
    try:
        outcome = repair_install_paths(selected)
    except MCPInstallerError as exc:
        logger.warning("MCP registration repair skipped: %s", exc)
        return None
    _log_outcome(outcome)
    return launch_message(outcome)


def launch_message(outcome: InstallRepairOutcome) -> str | None:
    """The toast that says what the launch-time repair changed, if anything."""
    repaired = outcome.repaired_labels
    shortcut_repaired = any(shortcut.error is None for shortcut in outcome.shortcuts)
    if repaired:
        pronoun = "it" if len(repaired) == 1 else "them"
        message = (
            f"Servonaut repaired its MCP setup in {_join_names(repaired)}: it still "
            f"pointed at a Servonaut install that was removed. Restart {pronoun} "
            "to reconnect."
        )
        if shortcut_repaired:
            message += " The terminal shortcut was repaired too."
        return message
    if shortcut_repaired:
        return (
            "Servonaut repaired its terminal shortcut: it still opened a Servonaut "
            "install that was removed."
        )
    return None


def run_repair_command(runtime: RuntimeLayout | None = None) -> int:
    """Run ``servonaut --mcp-repair``: repair, print a line per finding, return the exit status."""
    try:
        outcome = repair_install_paths(runtime)
    except MCPInstallerError as exc:
        print(f"Error: Could not resolve the Servonaut MCP command: {exc}", file=sys.stderr)
        return 1
    _log_outcome(outcome)
    command = shlex.join([home_relative(outcome.command[0]), *outcome.command[1:]])
    print(f"Servonaut MCP command: {command}")
    if not outcome.registrations and not outcome.shortcuts:
        print("No coding agent has a Servonaut MCP entry to check, and no terminal "
              "shortcut needs repair.")
        return 0
    for report in outcome.registrations:
        print(_report_line(report))
    for shortcut in outcome.shortcuts:
        place = home_relative(str(shortcut.path))
        if shortcut.error is None:
            print(f"Terminal shortcut ({place}): repaired")
        else:
            print(f"Terminal shortcut ({place}): could not be repaired: {shortcut.error}")
    if outcome.repaired_labels:
        print("Restart the repaired agents to reconnect.")
    return 1 if outcome.has_problems else 0


def _report_line(report: RegistrationReport) -> str:
    where = f"{report.label} ({home_relative(str(report.config_path))})"
    if report.state is RegistrationState.OK:
        return f"{where}: ok"
    if report.state is RegistrationState.REPAIRED:
        return f"{where}: repaired (was {home_relative(report.command)})"
    if report.state is RegistrationState.STALE_WRAPPER:
        return (
            f"{where}: not changed, {report.detail}. Fix that path by hand, or run "
            f"`servonaut --mcp-install {report.client}` to replace the entry."
        )
    return f"{where}: could not be checked, the file {report.detail}"


def _log_outcome(outcome: InstallRepairOutcome) -> None:
    for report in outcome.registrations:
        if report.state is RegistrationState.OK:
            continue
        logger.info(
            "MCP registration %s in %s: %s %s",
            report.client,
            home_relative(str(report.config_path)),
            report.state.value,
            report.detail,
        )
    for shortcut in outcome.shortcuts:
        logger.info(
            "Terminal shortcut %s: %s",
            home_relative(str(shortcut.path)),
            "repaired" if shortcut.error is None else shortcut.error,
        )


def _join_names(names: Sequence[str]) -> str:
    if len(names) == 1:
        return names[0]
    return f"{', '.join(names[:-1])} and {names[-1]}"
