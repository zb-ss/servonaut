"""Tests for repointing agent MCP entries that name a removed Servonaut install."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from servonaut.mcp import installer, registration_repair
from servonaut.mcp.registration_repair import (
    InstallRepairOutcome,
    RegistrationReport,
    RegistrationState,
    is_command_missing,
    launch_message,
    repair_on_launch,
    repair_stale_registrations,
    run_repair_command,
)
from servonaut.runtime import DistributionKind


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A throwaway home directory for every agent config."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(installer, "_get_os", lambda: "linux")
    return home


@pytest.fixture
def servonaut_command(tmp_path: Path) -> str:
    """The running install's MCP command: an executable that exists."""
    command = tmp_path / "opt" / "servonaut" / "servonaut"
    command.parent.mkdir(parents=True)
    command.write_text("#!/bin/sh\n", encoding="utf-8")
    command.chmod(0o755)
    return str(command)


def _gone(home: Path) -> str:
    """A pipx console script that was uninstalled."""
    return str(home / ".local" / "bin" / "servonaut")


def _write_json(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _one(reports: list[RegistrationReport]) -> RegistrationReport:
    assert len(reports) == 1, reports
    return reports[0]


# --- installer-written JSON entries -----------------------------------------


def test_a_removed_command_is_repointed_and_everything_else_kept(
    home: Path, servonaut_command: str
) -> None:
    path = _write_json(
        home / ".claude.json",
        {
            "numStartups": 12,
            "projects": {"/work/café": {"history": ["résumé"]}},
            "mcpServers": {
                "servonaut": {
                    "type": "stdio",
                    "command": _gone(home),
                    "args": ["--mcp"],
                    "env": {"AWS_PROFILE": "${AWS_PROFILE:-}"},
                },
                "other": {"command": "/usr/bin/other", "args": []},
            },
        },
    )

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.REPAIRED
    assert report.client == "claude"
    assert report.command == _gone(home)
    config = _read_json(path)
    assert config["mcpServers"]["servonaut"] == {
        "type": "stdio",
        "command": servonaut_command,
        "args": ["--mcp"],
        "env": {"AWS_PROFILE": "${AWS_PROFILE:-}"},
    }
    assert config["mcpServers"]["other"] == {"command": "/usr/bin/other", "args": []}
    assert config["numStartups"] == 12
    # Non-ASCII text stays readable rather than turning into \\u escapes.
    assert "café" in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("client", "key"),
    [
        ("claude", "mcpServers"),
        ("cursor", "mcpServers"),
        ("windsurf", "mcpServers"),
        ("vscode", "servers"),
        ("agy", "mcpServers"),
        ("gemini", "mcpServers"),
    ],
)
def test_every_split_command_client_is_repaired(
    home: Path, servonaut_command: str, client: str, key: str
) -> None:
    path = _write_json(
        installer.client_config_path(client),
        {key: {"servonaut": {"command": _gone(home), "args": ["--mcp"]}}},
    )

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert (report.client, report.state) == (client, RegistrationState.REPAIRED)
    entry = _read_json(path)[key]["servonaut"]
    assert entry == {"command": servonaut_command, "args": ["--mcp"]}


@pytest.mark.parametrize("layout", ["classic", "v2"])
def test_opencode_keeps_its_single_command_list(
    home: Path, servonaut_command: str, layout: str
) -> None:
    entry = {
        "type": "local",
        "command": [_gone(home), "--mcp"],
        "environment": {"AWS_PROFILE": "{env:AWS_PROFILE}"},
        "enabled": True,
    }
    mcp = {"servers": {"servonaut": entry}} if layout == "v2" else {"servonaut": entry}
    path = _write_json(installer.client_config_path("opencode"), {"mcp": mcp})

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.REPAIRED
    saved = _read_json(path)["mcp"]
    saved_entry = saved["servers"]["servonaut"] if layout == "v2" else saved["servonaut"]
    assert saved_entry == {**entry, "command": [servonaut_command, "--mcp"]}


def test_a_removed_interpreter_form_is_repaired(home: Path, servonaut_command: str) -> None:
    gone_python = str(home / ".local" / "share" / "pipx" / "venvs" / "servonaut" / "bin" / "python")
    path = _write_json(
        home / ".cursor" / "mcp.json",
        {"mcpServers": {"servonaut": {"command": gone_python, "args": ["-m", "servonaut.main", "--mcp"]}}},
    )

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.REPAIRED
    assert _read_json(path)["mcpServers"]["servonaut"]["args"] == ["--mcp"]


def test_a_working_entry_of_another_install_is_left_alone(
    home: Path, tmp_path: Path, servonaut_command: str
) -> None:
    other_install = tmp_path / "other" / "servonaut"
    other_install.parent.mkdir()
    other_install.write_text("", encoding="utf-8")
    other_install.chmod(0o755)
    path = _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": str(other_install), "args": ["--mcp"]}}},
    )
    before = path.read_bytes()

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.OK
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "argv",
    [
        ["uvx", "servonaut", "--mcp"],
        ["docker", "run", "-i", "servonaut", "--mcp"],
        ["/gone/servonaut", "--version"],
    ],
)
def test_commands_that_are_not_an_installer_launch_are_ignored(
    home: Path, servonaut_command: str, argv: list[str]
) -> None:
    path = _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": argv[0], "args": argv[1:]}}},
    )
    before = path.read_bytes()

    assert repair_stale_registrations(servonaut_command, ["--mcp"]) == []
    assert path.read_bytes() == before


def test_no_agent_config_is_created(home: Path, servonaut_command: str) -> None:
    assert repair_stale_registrations(servonaut_command, ["--mcp"]) == []
    assert list(home.iterdir()) == []


def test_invalid_json_is_reported_and_untouched(home: Path, servonaut_command: str) -> None:
    path = home / ".cursor" / "mcp.json"
    path.parent.mkdir()
    path.write_text('{"mcpServers": ', encoding="utf-8")

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.FAILED
    assert "not valid JSON" in report.detail
    assert path.read_text(encoding="utf-8") == '{"mcpServers": '


def test_nothing_is_rewritten_when_the_running_command_is_missing(home: Path) -> None:
    path = _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": _gone(home), "args": ["--mcp"]}}},
    )
    before = path.read_bytes()

    assert repair_stale_registrations(str(home / "also-gone"), ["--mcp"]) == []
    assert path.read_bytes() == before


def test_a_change_made_by_the_agent_meanwhile_survives(
    home: Path, servonaut_command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": _gone(home), "args": ["--mcp"]}}},
    )
    real_replace = registration_repair._replace_if_unchanged
    calls: list[None] = []

    def agent_saves_first(target: Path, expected: str, text: str) -> bool:
        if not calls:
            config = _read_json(target)
            config["tipsHistory"] = {"seen": 1}
            _write_json(target, config)
        calls.append(None)
        return real_replace(target, expected, text)

    monkeypatch.setattr(registration_repair, "_replace_if_unchanged", agent_saves_first)

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.REPAIRED
    assert len(calls) == 2
    config = _read_json(path)
    assert config["tipsHistory"] == {"seen": 1}
    assert config["mcpServers"]["servonaut"]["command"] == servonaut_command


def test_a_config_that_never_settles_is_reported(
    home: Path, servonaut_command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": _gone(home), "args": ["--mcp"]}}},
    )
    monkeypatch.setattr(registration_repair, "_replace_if_unchanged", lambda *_args: False)

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.FAILED
    assert _read_json(path)["mcpServers"]["servonaut"]["command"] == _gone(home)


# --- Codex TOML --------------------------------------------------------------


def _codex_config(home: Path, block: str) -> Path:
    path = home / ".codex" / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        'model = "gpt"\n\n'
        f"{block}"
        "\n[mcp_servers.other]\n"
        'command = "/usr/bin/other"\n',
        encoding="utf-8",
    )
    return path


def test_codex_command_and_args_are_rewritten_in_place(
    home: Path, servonaut_command: str
) -> None:
    path = _codex_config(
        home,
        "[mcp_servers.servonaut]\n"
        f'command = "{_gone(home)}"\n'
        "args = [\n"
        '  "--mcp",  # the stdio server\n'
        "]\n"
        'env_vars = ["AWS_PROFILE", "SSH_AUTH_SOCK"]\n'
        "startup_timeout_sec = 30.0\n",
    )

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.REPAIRED
    assert report.command == _gone(home)
    assert path.read_text(encoding="utf-8") == (
        'model = "gpt"\n\n'
        "[mcp_servers.servonaut]\n"
        f'command = "{servonaut_command}"\n'
        'args = ["--mcp"]\n'
        'env_vars = ["AWS_PROFILE", "SSH_AUTH_SOCK"]\n'
        "startup_timeout_sec = 30.0\n"
        "\n[mcp_servers.other]\n"
        'command = "/usr/bin/other"\n'
    )


def test_a_symlinked_codex_config_keeps_its_link(
    home: Path, tmp_path: Path, servonaut_command: str
) -> None:
    dotfiles = tmp_path / "dotfiles" / "config.toml"
    dotfiles.parent.mkdir()
    dotfiles.write_text(
        f"[mcp_servers.servonaut]\ncommand = '{_gone(home)}'\nargs = ['--mcp']\n",
        encoding="utf-8",
    )
    link = home / ".codex" / "config.toml"
    link.parent.mkdir()
    link.symlink_to(dotfiles)

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.REPAIRED
    assert link.is_symlink()
    assert f'command = "{servonaut_command}"' in dotfiles.read_text(encoding="utf-8")


def test_a_broken_shell_wrapper_is_reported_not_rewritten(
    home: Path, servonaut_command: str
) -> None:
    path = _codex_config(
        home,
        "[mcp_servers.servonaut]\n"
        'command = "sh"\n'
        "args = [\"-c\", 'exec \"$HOME/.local/bin/servonaut\" --mcp']\n",
    )
    before = path.read_bytes()

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.STALE_WRAPPER
    assert "$HOME/.local/bin/servonaut" in report.detail
    assert path.read_bytes() == before


def test_a_working_shell_wrapper_is_ok(home: Path, servonaut_command: str) -> None:
    console = Path(_gone(home))
    console.parent.mkdir(parents=True)
    console.write_text("", encoding="utf-8")
    _codex_config(
        home,
        "[mcp_servers.servonaut]\n"
        'command = "sh"\n'
        "args = [\"-c\", 'exec \"$HOME/.local/bin/servonaut\" --mcp']\n",
    )

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.OK


def test_a_wrapper_url_is_not_mistaken_for_a_path(home: Path, servonaut_command: str) -> None:
    _write_json(
        home / ".claude.json",
        {
            "mcpServers": {
                "servonaut": {
                    "command": "bash",
                    "args": ["-c", "curl -fsS https://servonaut.dev/health && exec servonaut --mcp"],
                }
            }
        },
    )

    assert repair_stale_registrations(servonaut_command, ["--mcp"]) == []


def test_a_codex_value_it_cannot_parse_is_reported(home: Path, servonaut_command: str) -> None:
    path = _codex_config(home, '[mcp_servers.servonaut]\ncommand = """\n/x"""\n')
    before = path.read_bytes()

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.FAILED
    assert path.read_bytes() == before


def test_codex_strings_decode_both_quote_styles() -> None:
    lines = [
        r'args = ["-c", "say \"hi\"\tthere", # a "quoted" comment',
        "  'C:\\literal\\path', ]",
    ]

    assert registration_repair._toml_strings(lines) == [
        "-c",
        'say "hi"\tthere',
        "C:\\literal\\path",
    ]


# --- command checks ----------------------------------------------------------


def test_a_dangling_symlink_counts_as_missing(tmp_path: Path) -> None:
    link = tmp_path / "servonaut"
    link.symlink_to(tmp_path / "removed-target")

    assert is_command_missing(str(link))


def test_home_relative_commands_are_expanded(home: Path) -> None:
    console = home / "bin" / "servonaut"
    console.parent.mkdir()
    console.write_text("", encoding="utf-8")

    assert not is_command_missing("~/bin/servonaut")
    assert not is_command_missing("$HOME/bin/servonaut")
    assert is_command_missing("${HOME}/bin/gone")


def test_a_bare_name_is_looked_up_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registration_repair.shutil, "which", lambda name: None)
    assert is_command_missing("servonaut")
    monkeypatch.setattr(registration_repair.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert not is_command_missing("servonaut")


# --- launch and CLI ----------------------------------------------------------


def _runtime(kind: DistributionKind, command: str) -> SimpleNamespace:
    return SimpleNamespace(
        kind=kind,
        mcp_argv=lambda: [command, "--mcp"],
        current_app_argv=lambda: [command],
    )


@pytest.fixture
def no_shortcuts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("servonaut.main.repair_terminal_shortcuts", lambda _argv: [])
    monkeypatch.setattr(
        registration_repair, "validate_launch_argv", lambda argv, runtime: list(argv)
    )
    monkeypatch.setattr(
        installer, "_resolve_mcp_command", lambda runtime: (runtime.mcp_argv()[0], ["--mcp"])
    )


def test_a_source_checkout_never_repairs_at_launch(
    home: Path, servonaut_command: str, no_shortcuts: None
) -> None:
    path = _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": _gone(home), "args": ["--mcp"]}}},
    )
    before = path.read_bytes()

    assert repair_on_launch(_runtime(DistributionKind.SOURCE, servonaut_command)) is None
    assert path.read_bytes() == before


def test_the_launch_repair_names_the_agents_it_fixed(
    home: Path, servonaut_command: str, no_shortcuts: None
) -> None:
    for config in (home / ".claude.json", home / ".cursor" / "mcp.json"):
        _write_json(
            config, {"mcpServers": {"servonaut": {"command": _gone(home), "args": ["--mcp"]}}}
        )

    message = repair_on_launch(_runtime(DistributionKind.PACKAGED_DESKTOP, servonaut_command))

    assert message is not None
    assert "Claude Code and Cursor" in message
    assert "Restart them" in message
    assert _read_json(home / ".claude.json")["mcpServers"]["servonaut"]["command"] == (
        servonaut_command
    )


def test_the_launch_repair_is_silent_when_nothing_changed(
    home: Path, servonaut_command: str, no_shortcuts: None
) -> None:
    console = Path(_gone(home))
    console.parent.mkdir(parents=True)
    console.write_text("", encoding="utf-8")
    _codex_config(
        home,
        "[mcp_servers.servonaut]\n"
        'command = "sh"\n'
        "args = [\"-c\", 'exec \"$HOME/.local/bin/servonaut\" --mcp']\n",
    )
    _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": servonaut_command, "args": ["--mcp"]}}},
    )

    assert repair_on_launch(_runtime(DistributionKind.PIPX, servonaut_command)) is None


def test_the_launch_repair_points_a_broken_wrapper_at_the_repair_command(
    home: Path, servonaut_command: str, no_shortcuts: None
) -> None:
    path = _codex_config(
        home,
        "[mcp_servers.servonaut]\n"
        'command = "sh"\n'
        "args = [\"-c\", 'exec \"$HOME/.local/bin/servonaut\" --mcp']\n",
    )
    before = path.read_bytes()

    message = repair_on_launch(_runtime(DistributionKind.PIPX, servonaut_command))

    assert message == (
        "Codex runs Servonaut through a hand-written script that still names a "
        "removed install; run servonaut --mcp-repair to see which path to fix."
    )
    assert path.read_bytes() == before


def test_launch_message_for_one_agent_and_the_shortcut() -> None:
    shortcut = SimpleNamespace(path=Path("/x.desktop"), error=None)
    outcome = InstallRepairOutcome(
        ["/opt/servonaut/servonaut", "--mcp"],
        [RegistrationReport("codex", "Codex", Path("/c"), RegistrationState.REPAIRED)],
        [shortcut],
    )

    message = launch_message(outcome)

    assert message is not None
    assert "in Codex:" in message
    assert "Restart it" in message
    assert message.endswith("The terminal shortcut was repaired too.")
    only_shortcut = InstallRepairOutcome(["/opt/servonaut/servonaut", "--mcp"], [], [shortcut])
    assert "terminal shortcut" in (launch_message(only_shortcut) or "")


def test_launch_message_adds_the_wrappers_it_left_after_the_repairs() -> None:
    outcome = InstallRepairOutcome(
        ["/opt/servonaut/servonaut", "--mcp"],
        [
            RegistrationReport("claude", "Claude Code", Path("/a"), RegistrationState.REPAIRED),
            RegistrationReport("agy", "Antigravity", Path("/b"), RegistrationState.STALE_WRAPPER),
            RegistrationReport("gemini", "Gemini CLI", Path("/c"), RegistrationState.STALE_WRAPPER),
            # A config that could not be read stays a --mcp-repair finding only.
            RegistrationReport("cursor", "Cursor", Path("/d"), RegistrationState.FAILED),
        ],
    )

    message = launch_message(outcome)

    assert message is not None
    assert message.startswith("Servonaut repaired its MCP setup in Claude Code:")
    assert message.endswith(
        " Antigravity and Gemini CLI run Servonaut through hand-written scripts that "
        "still name a removed install; run servonaut --mcp-repair to see which paths "
        "to fix."
    )
    assert "Cursor" not in message


def test_the_repair_command_reports_each_agent(
    home: Path,
    servonaut_command: str,
    no_shortcuts: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": _gone(home), "args": ["--mcp"]}}},
    )
    _codex_config(
        home,
        "[mcp_servers.servonaut]\n"
        'command = "sh"\n'
        "args = [\"-c\", 'exec \"$HOME/.local/bin/servonaut\" --mcp']\n",
    )

    status = run_repair_command(_runtime(DistributionKind.PIPX, servonaut_command))

    out = capsys.readouterr().out
    assert status == 1
    assert "Claude Code (~/.claude.json): repaired (was ~/.local/bin/servonaut)" in out
    assert "Codex (~/.codex/config.toml): not changed" in out
    assert "`servonaut --mcp-install codex`" in out
    assert "Restart the repaired agents to reconnect." in out
    # Shareable output: no home directory in it.
    assert str(home) not in out


def test_the_repair_command_with_nothing_to_check(
    home: Path, servonaut_command: str, no_shortcuts: None, capsys: pytest.CaptureFixture[str]
) -> None:
    status = run_repair_command(_runtime(DistributionKind.PIPX, servonaut_command))

    assert status == 0
    assert "No coding agent has a Servonaut MCP entry" in capsys.readouterr().out


def test_the_repair_command_fails_when_the_command_cannot_be_resolved(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def unresolvable(_runtime: object) -> tuple[str, list[str]]:
        raise installer.MCPInstallerError("The runtime MCP command is unavailable or invalid.")

    monkeypatch.setattr(installer, "_resolve_mcp_command", unresolvable)

    assert run_repair_command(SimpleNamespace(kind=DistributionKind.PIPX)) == 1
    assert "Could not resolve the Servonaut MCP command" in capsys.readouterr().err


def test_file_mode_is_kept(home: Path, servonaut_command: str) -> None:
    path = _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": _gone(home), "args": ["--mcp"]}}},
    )
    os.chmod(path, 0o600)

    repair_stale_registrations(servonaut_command, ["--mcp"])

    assert path.stat().st_mode & 0o777 == 0o600
