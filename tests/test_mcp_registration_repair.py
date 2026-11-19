"""Tests for repointing agent MCP entries that name a removed Servonaut install."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from servonaut import cli_link
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


@pytest.mark.parametrize("kind", ["json", "toml"])
@pytest.mark.parametrize("redirect", [False, True], ids=["file", "retargeted-symlink"])
def test_a_save_while_the_replacement_is_staged_survives(
    home: Path, servonaut_command: str, monkeypatch: pytest.MonkeyPatch,
    kind: str, redirect: bool,
) -> None:
    if kind == "json":
        path = _write_json(
            home / ".claude.json",
            {"mcpServers": {"servonaut": {"command": _gone(home), "args": ["--mcp"]}}},
        )
        saved = json.dumps({
            "theme": "dark",
            "mcpServers": {
                "servonaut": {"command": servonaut_command, "args": ["--mcp"]},
                "other": {"command": "other-runtime"},
            },
        })
    else:
        path = _codex_config(
            home, f"[mcp_servers.servonaut]\ncommand = {json.dumps(_gone(home))}\n"
            'args = ["--mcp"]\n',
        )
        saved = (
            'theme = "dark"\n[mcp_servers.servonaut]\n'
            f"command = {json.dumps(servonaut_command)}\nargs = [\"--mcp\"]\n"
            '[mcp_servers.other]\ncommand = "other-runtime"\n'
        )
    original = path.read_text(encoding="utf-8")
    previous = path.with_name("previous-config")
    replacement = path.with_name("replacement-config")
    if redirect:
        path.rename(previous)
        path.symlink_to(previous)
        replacement.write_text(saved, encoding="utf-8")
    real_fsync = os.fsync
    saves = []

    def save_after_flush(descriptor: int) -> None:
        real_fsync(descriptor)
        if redirect:
            path.unlink()
            path.symlink_to(replacement)
        else:
            path.write_text(saved, encoding="utf-8")
        saves.append(True)

    monkeypatch.setattr(installer.os, "fsync", save_after_flush)

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert saves == [True]
    assert report.state is RegistrationState.OK
    assert path.read_text(encoding="utf-8") == saved
    if redirect:
        assert path.is_symlink() and path.resolve() == replacement
        assert previous.read_text(encoding="utf-8") == original
    assert not list(path.parent.glob(f".{path.name}.*"))


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
    console.chmod(0o755)
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
    """Agent configs only: no terminal shortcut and no command line link."""
    monkeypatch.setattr("servonaut.main.repair_terminal_shortcuts", lambda _argv: [])
    monkeypatch.setattr(registration_repair, "ensure_cli_link", lambda _runtime: None)
    monkeypatch.setattr(
        registration_repair, "validate_launch_argv", lambda argv, runtime: list(argv)
    )
    monkeypatch.setattr(cli_link, "validate_launch_argv", lambda argv, runtime: list(argv))
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
    console.chmod(0o755)
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


# --- agents without an entry -------------------------------------------------


@pytest.mark.parametrize(
    "content",
    ["", "{}\n", '{"mcpServers": {"other": {"command": "x"}}}\n'],
    ids=["empty-file", "empty-object", "other-servers-only"],
)
def test_an_agent_config_without_a_servonaut_entry_is_reported_missing(
    home: Path, servonaut_command: str, content: str
) -> None:
    path = home / ".gemini" / "config" / "mcp_config.json"
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.client == "agy"
    assert report.state is RegistrationState.MISSING
    assert path.read_text(encoding="utf-8") == content


def test_a_codex_config_without_a_servonaut_block_is_reported_missing(
    home: Path, servonaut_command: str
) -> None:
    _codex_config(home, "")

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.client == "codex"
    assert report.state is RegistrationState.MISSING


def test_a_missing_entry_is_named_by_the_repair_command_only(
    home: Path,
    servonaut_command: str,
    no_shortcuts: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_json(home / ".gemini" / "config" / "mcp_config.json", {"mcpServers": {}})
    runtime = _runtime(DistributionKind.PIPX, servonaut_command)

    assert repair_on_launch(runtime) is None
    status = run_repair_command(runtime)

    assert status == 0
    assert (
        "Antigravity (~/.gemini/config/mcp_config.json): no Servonaut entry. "
        "Run `servonaut --mcp-install agy` to add one."
    ) in capsys.readouterr().out


# --- wrappers that try several places ----------------------------------------

_LOOKUP_WRAPPER = (
    'p="$HOME/.local/bin/servonaut"; [ -x "$p" ] || p="$(command -v servonaut)"; '
    'exec "$p" --mcp'
)


def _claude_wrapper(home: Path, script: str) -> Path:
    return _write_json(
        home / ".claude.json",
        {"mcpServers": {"servonaut": {"command": "sh", "args": ["-c", script]}}},
    )


@pytest.mark.parametrize(
    "script",
    [
        'exec "$HOME/removed/servonaut" --mcp # servonaut',
        'echo servonaut; exec "$HOME/removed/servonaut" --mcp',
        'echo "command -v servonaut"; exec "$HOME/removed/servonaut" --mcp',
        "printf '%s' '$(command -v servonaut)'; exec \"$HOME/removed/servonaut\" --mcp",
        'false && exec servonaut --mcp; exec "$HOME/removed/servonaut" --mcp',
        '"p=$(command -v servonaut)"; exec "$p" --mcp; '
        'exec "$HOME/removed/servonaut" --mcp',
    ],
    ids=["comment", "argument", "quoted-command", "literal-substitution",
         "skipped-launch", "quoted-assignment"],
)
def test_wrapper_data_does_not_count_as_a_path_lookup(
    home: Path, servonaut_command: str, monkeypatch: pytest.MonkeyPatch, script: str,
) -> None:
    path = _claude_wrapper(home, script)
    before = path.read_bytes()
    monkeypatch.setattr(registration_repair.shutil, "which", lambda _name: servonaut_command)

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.STALE_WRAPPER
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX execute permissions")
def test_nonexecutable_wrapper_candidate_does_not_hide_a_missing_fallback(
    home: Path, servonaut_command: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = home / "old" / "servonaut"
    candidate.parent.mkdir()
    candidate.write_text("#!/bin/sh\n", encoding="utf-8")
    candidate.chmod(0o644)
    _claude_wrapper(
        home,
        'p="$HOME/old/servonaut"; [ -x "$p" ] || p="$HOME/removed/servonaut"; '
        'exec "$p" --mcp',
    )
    monkeypatch.setattr(registration_repair.shutil, "which", lambda _name: None)

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.STALE_WRAPPER


def test_literal_quoted_codex_header_matches_an_existing_entry(
    home: Path, servonaut_command: str,
) -> None:
    path = installer.client_config_path("codex")
    path.parent.mkdir(parents=True)
    path.write_text(
        "[mcp_servers.'servonaut']\n"
        f"command = {json.dumps(servonaut_command)}\nargs = [\"--mcp\"]\n",
        encoding="utf-8",
    )
    before = path.read_bytes()

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.OK
    assert path.read_bytes() == before


def test_install_replaces_a_literal_quoted_codex_table_in_place(
    home: Path, servonaut_command: str,
) -> None:
    path = installer.client_config_path("codex")
    path.parent.mkdir(parents=True)
    path.write_text(
        "[mcp_servers.'servonaut']\ncommand = \"/old/servonaut\"\n"
        "args = [\"--mcp\"]\nstartup_timeout_sec = 42\n",
        encoding="utf-8",
    )

    installer._install_codex(servonaut_command, ["--mcp"])

    text = path.read_text(encoding="utf-8")
    assert text.count("[mcp_servers.") == 1
    assert text.count("command =") == 1
    assert f"command = {json.dumps(servonaut_command)}" in text
    assert "startup_timeout_sec = 42" in text


def test_a_wrapper_still_runs_while_any_path_it_tries_is_there(
    home: Path, servonaut_command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(registration_repair.shutil, "which", lambda name: None)
    _claude_wrapper(
        home,
        'p="$HOME/.local/bin/servonaut"; [ -x "$p" ] || p='
        f'{servonaut_command}; exec "$p" --mcp',
    )

    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))

    assert report.state is RegistrationState.OK


def test_a_wrapper_that_looks_servonaut_up_on_path_runs_while_it_is_there(
    home: Path, servonaut_command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _claude_wrapper(home, _LOOKUP_WRAPPER)

    monkeypatch.setattr(registration_repair.shutil, "which", lambda name: "/usr/bin/servonaut")
    assert _one(repair_stale_registrations(servonaut_command, ["--mcp"])).state is (
        RegistrationState.OK
    )

    monkeypatch.setattr(registration_repair.shutil, "which", lambda name: None)
    report = _one(repair_stale_registrations(servonaut_command, ["--mcp"]))
    assert report.state is RegistrationState.STALE_WRAPPER
    assert "$HOME/.local/bin/servonaut" in report.detail


# --- the macOS desktop app ----------------------------------------------------


def _bundle_command(root: Path) -> Path:
    command = root / "Servonaut.app" / "Contents" / "MacOS" / "servonaut"
    command.parent.mkdir(parents=True)
    command.write_text("#!/bin/sh\n", encoding="utf-8")
    command.chmod(0o755)
    return command


def test_the_desktop_app_links_its_command_so_a_wrapper_works_again(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("servonaut.main.repair_terminal_shortcuts", lambda _argv: [])
    monkeypatch.setattr("servonaut.utils.platform_utils.get_os", lambda: "darwin")
    for module in (registration_repair, cli_link):
        monkeypatch.setattr(module, "validate_launch_argv", lambda argv, runtime: list(argv))
    monkeypatch.setattr(
        installer, "_resolve_mcp_command", lambda runtime: (runtime.mcp_argv()[0], ["--mcp"])
    )
    monkeypatch.setattr(registration_repair.shutil, "which", lambda name: None)
    app = _bundle_command(tmp_path / "Applications")
    path = _claude_wrapper(home, _LOOKUP_WRAPPER)
    before = path.read_bytes()

    message = repair_on_launch(_runtime(DistributionKind.PACKAGED_DESKTOP, str(app)))

    assert message == (
        "Servonaut added the servonaut command at ~/.local/bin/servonaut, so coding "
        "agents and scripts that run servonaut now use this app."
    )
    assert os.readlink(home / ".local" / "bin" / "servonaut") == str(app)
    # A wrapper someone wrote by hand works again without being rewritten.
    assert path.read_bytes() == before


def _stale_codex_wrapper(home: Path) -> None:
    _codex_config(
        home,
        "[mcp_servers.servonaut]\n"
        'command = "sh"\n'
        "args = [\"-c\", 'exec \"$HOME/old/servonaut\" --mcp']\n",
    )


@pytest.mark.parametrize("setup", ["nothing", "link", "path"])
def test_the_desktop_app_names_a_command_that_exists(
    home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_shortcuts: None,
    setup: str,
) -> None:
    import shlex

    app = _bundle_command(tmp_path / "Applications")
    _stale_codex_wrapper(home)
    found = str(app) if setup == "path" else None
    monkeypatch.setattr(registration_repair.shutil, "which", lambda name: found)
    if setup == "link":
        link = home / ".local" / "bin" / "servonaut"
        link.parent.mkdir(parents=True)
        link.symlink_to(app)
    expected = {
        "nothing": shlex.quote(str(app)),
        "link": "~/.local/bin/servonaut",
        "path": "servonaut",
    }[setup]

    message = repair_on_launch(_runtime(DistributionKind.PACKAGED_DESKTOP, str(app)))

    assert message is not None
    assert f"run {expected} --mcp-repair to see which path to fix." in message


def test_the_repair_command_reports_the_command_link(
    home: Path,
    servonaut_command: str,
    no_shortcuts: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    link = home / ".local" / "bin" / "servonaut"
    runtime = _runtime(DistributionKind.PACKAGED_DESKTOP, servonaut_command)
    created = cli_link.CliLinkResult(link, cli_link.CliLinkState.CREATED, Path(servonaut_command))
    monkeypatch.setattr(registration_repair, "ensure_cli_link", lambda _runtime: created)

    assert run_repair_command(runtime) == 0
    assert "servonaut command (~/.local/bin/servonaut): created, it runs " in (
        capsys.readouterr().out
    )

    failed = cli_link.CliLinkResult(
        link, cli_link.CliLinkState.FAILED, Path(servonaut_command), "Permission denied"
    )
    monkeypatch.setattr(registration_repair, "ensure_cli_link", lambda _runtime: failed)

    assert run_repair_command(runtime) == 1
    assert "could not be created: Permission denied" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("state", "sentence"),
    [
        ("UPDATED", "Servonaut pointed the servonaut command at ~/.local/bin/servonaut to this app."),
        ("UNCHANGED", None),
        ("OCCUPIED", None),
        ("SKIPPED", None),
    ],
)
def test_the_launch_message_mentions_a_link_only_when_it_changed(
    home: Path, state: str, sentence: str | None
) -> None:
    result = cli_link.CliLinkResult(
        home / ".local" / "bin" / "servonaut",
        cli_link.CliLinkState[state],
        Path("/Applications/Servonaut.app/Contents/MacOS/servonaut"),
    )

    message = launch_message(InstallRepairOutcome(["/x", "--mcp"], cli_link=result))

    assert message == sentence
