"""Tests for the MCP auto-installer (per-agent config writers)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.mcp import installer
from servonaut.mcp.installer import SUPPORTED_TARGETS, install_mcp_server
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)

_REAL_RESOLVE_MCP_COMMAND = installer._resolve_mcp_command


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Redirect Path.home() and $CODEX_HOME into a throwaway directory."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    return home


@pytest.fixture(autouse=True)
def stub_command(monkeypatch):
    """Pin the resolved MCP command so assertions are deterministic."""
    monkeypatch.setattr(
        installer,
        "_resolve_mcp_command",
        lambda _runtime=None: ("/usr/bin/servonaut", ["--mcp"]),
    )


def _write_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("probe helper", encoding="utf-8")
    path.chmod(path.stat().st_mode | 0o111)
    return path


def _packaged_runtime(
    helper: Path, root: Path, *, desktop_child: Path | None = None
) -> RuntimeLayout:
    return RuntimeLayout(
        kind=DistributionKind.PACKAGED_DESKTOP,
        product_version="test",
        build_revision=None,
        resource_root=root,
        executable_root=root,
        data_root=root / "data",
        executable=_helper_path(root, "servonaut-desktop"),
        python_executable=None,
        path_console=None,
        console_helper=helper,
        desktop_child=desktop_child,
        package_management=PackageManagementCapability(
            PackageManagementKind.UNSUPPORTED, (), False
        ),
        is_frozen=True,
    )


def _frozen_runtime(executable: Path, root: Path) -> RuntimeLayout:
    return RuntimeLayout(
        kind=DistributionKind.FROZEN_CLI,
        product_version="test",
        build_revision=None,
        resource_root=root,
        executable_root=root,
        data_root=root / "data",
        executable=executable,
        python_executable=None,
        path_console=None,
        console_helper=executable,
        desktop_child=None,
        package_management=PackageManagementCapability(
            PackageManagementKind.UNSUPPORTED, (), False
        ),
        is_frozen=True,
    )


def _helper_path(root: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return root / f"{name}{suffix}"


def _assert_runtime_rejection_precedes_target_config_access(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch, runtime: RuntimeLayout
) -> None:
    config_path = fake_home / ".claude.json"
    original = json.dumps({"mcpServers": {"servonaut": {"command": "/stale"}}})
    config_path.write_text(original, encoding="utf-8")
    monkeypatch.setattr(installer, "_resolve_mcp_command", _REAL_RESOLVE_MCP_COMMAND)
    monkeypatch.setattr(
        installer,
        "_load_json",
        lambda _path: pytest.fail("target config was read before command validation"),
    )
    monkeypatch.setattr(
        installer,
        "_save_json",
        lambda _path, _config: pytest.fail(
            "target config was written before command validation"
        ),
    )

    with pytest.raises(SystemExit) as error:
        install_mcp_server("claude", runtime)

    assert error.value.code == 1
    assert config_path.read_text(encoding="utf-8") == original


def test_every_supported_target_has_an_installer():
    assert set(SUPPORTED_TARGETS) == set(installer._INSTALLERS)


def test_unknown_target_exits_nonzero(capsys):
    with pytest.raises(SystemExit) as exc:
        install_mcp_server("emacs")

    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Unknown target 'emacs'" in out
    # The error must advertise every target we actually support.
    for target in SUPPORTED_TARGETS:
        assert target in out


def test_packaged_helper_path_with_spaces_and_unicode_is_one_command_field(
    fake_home, tmp_path, monkeypatch
):
    monkeypatch.setattr(installer, "_resolve_mcp_command", _REAL_RESOLVE_MCP_COMMAND)
    monkeypatch.setattr(installer, "_get_os", lambda: "linux")
    helper = _write_executable(
        _helper_path(tmp_path / "packaged runtime 日本語", "servonaut cli")
    )

    install_mcp_server("opencode", _packaged_runtime(helper, tmp_path))

    config_path = fake_home / ".config" / "opencode" / "opencode.json"
    entry = json.loads(config_path.read_text())["mcp"]["servonaut"]
    assert entry["command"] == [str(helper), "--mcp"]
    assert "-m" not in entry["command"]


def test_frozen_mcp_install_never_uses_interpreter_module_fallback(
    fake_home, tmp_path, monkeypatch
):
    monkeypatch.setattr(installer, "_resolve_mcp_command", _REAL_RESOLVE_MCP_COMMAND)
    executable = _write_executable(_helper_path(tmp_path, "servonaut"))

    install_mcp_server("claude", _frozen_runtime(executable, tmp_path))

    entry = json.loads((fake_home / ".claude.json").read_text())["mcpServers"][
        "servonaut"
    ]
    assert entry["command"] == str(executable)
    assert entry["args"] == ["--mcp"]
    assert "-m" not in entry["args"]


@pytest.mark.parametrize("helper_kind", ("missing", "directory", "not_executable"))
def test_invalid_packaged_helper_stops_before_target_config_read_or_write(
    fake_home, tmp_path, monkeypatch, helper_kind
):
    config_path = fake_home / ".claude.json"
    original = json.dumps({"mcpServers": {"servonaut": {"command": "/stale"}}})
    config_path.write_text(original)
    helper = _helper_path(tmp_path, "missing-console-helper")
    if helper_kind == "directory":
        helper.mkdir()
    elif helper_kind == "not_executable":
        if os.name == "nt":
            # Windows determines executable status by suffix rather than POSIX
            # mode bits. Use a regular, unsupported extension at this boundary.
            helper = tmp_path / "missing-console-helper.invalid"
        helper.write_text("stale helper", encoding="utf-8")
    # A valid GUI executable must not become a fallback MCP command.
    _write_executable(_helper_path(tmp_path, "servonaut-desktop"))
    runtime = _packaged_runtime(helper, tmp_path)
    monkeypatch.setattr(installer, "_resolve_mcp_command", _REAL_RESOLVE_MCP_COMMAND)
    monkeypatch.setattr(
        installer,
        "_load_json",
        lambda _path: pytest.fail("target config was read before command validation"),
    )
    monkeypatch.setattr(
        installer,
        "_save_json",
        lambda _path, _config: pytest.fail("target config was written before validation"),
    )

    with pytest.raises(SystemExit) as error:
        install_mcp_server("claude", runtime)

    assert error.value.code == 1
    assert config_path.read_text() == original


def test_outside_root_packaged_helper_symlink_stops_before_target_config_access(
    fake_home, tmp_path, monkeypatch
):
    root = tmp_path / "packaged runtime"
    helper = _helper_path(root, "console helper")
    outside = _write_executable(_helper_path(tmp_path, "outside helper"))
    _write_executable(_helper_path(root, "servonaut-desktop"))
    helper.parent.mkdir(parents=True, exist_ok=True)
    try:
        helper.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")

    _assert_runtime_rejection_precedes_target_config_access(
        fake_home, monkeypatch, _packaged_runtime(helper, root)
    )


@pytest.mark.parametrize(
    ("forbidden_kind", "alias_kind"),
    [
        ("gui", "symlink"),
        ("gui", "hardlink"),
        ("child", "symlink"),
        ("child", "hardlink"),
    ],
)
def test_gui_and_child_aliases_stop_before_target_config_access(
    fake_home, tmp_path, monkeypatch, forbidden_kind, alias_kind
):
    root = tmp_path / "packaged runtime"
    gui = _write_executable(_helper_path(root, "servonaut-desktop"))
    child = _write_executable(_helper_path(root, "desktop child"))
    helper = _helper_path(root, f"{forbidden_kind} alias")
    target = gui if forbidden_kind == "gui" else child
    try:
        if alias_kind == "hardlink":
            helper.hardlink_to(target)
        else:
            helper.symlink_to(target)
    except OSError:
        pytest.skip(f"{alias_kind}s are unavailable on this test host")

    _assert_runtime_rejection_precedes_target_config_access(
        fake_home,
        monkeypatch,
        _packaged_runtime(helper, root, desktop_child=child),
    )


def test_frozen_windows_pathext_script_stops_before_target_config_access(
    fake_home, tmp_path, monkeypatch
):
    root = tmp_path / "packaged runtime"
    executable = _write_executable(root / "servonaut.exe")
    _write_executable(root / "console helper.ps1")
    runtime = _frozen_runtime(executable, root)
    monkeypatch.setenv("PATHEXT", ".PS1;.EXE")

    with monkeypatch.context() as context:
        context.setattr(installer.os, "name", "nt")
        _assert_runtime_rejection_precedes_target_config_access(
            fake_home, context, runtime
        )


# --- agy (Antigravity CLI) -------------------------------------------------


def test_agy_writes_mcp_servers_entry(fake_home):
    install_mcp_server("agy")

    config = json.loads(
        (fake_home / ".gemini" / "config" / "mcp_config.json").read_text()
    )
    assert config["mcpServers"]["servonaut"] == {
        "command": "/usr/bin/servonaut",
        "args": ["--mcp"],
    }


def test_agy_preserves_other_servers(fake_home):
    config_path = fake_home / ".gemini" / "config" / "mcp_config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}))

    install_mcp_server("agy")

    config = json.loads(config_path.read_text())
    assert config["mcpServers"]["other"] == {"command": "x"}
    assert "servonaut" in config["mcpServers"]


def test_agy_handles_zero_byte_config(fake_home, capsys):
    """Antigravity ships an empty mcp_config.json — it must not warn or crash."""
    config_path = fake_home / ".gemini" / "config" / "mcp_config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("")

    install_mcp_server("agy")

    assert "Could not parse" not in capsys.readouterr().out
    config = json.loads(config_path.read_text())
    assert config["mcpServers"]["servonaut"]["command"] == "/usr/bin/servonaut"


# --- codex (TOML) ----------------------------------------------------------


def test_codex_creates_config(fake_home):
    install_mcp_server("codex")

    text = (fake_home / ".codex" / "config.toml").read_text()
    assert "[mcp_servers.servonaut]" in text
    assert 'command = "/usr/bin/servonaut"' in text
    assert 'args = ["--mcp"]' in text
    assert 'env_vars = ["SSH_AUTH_SOCK", "BW_SESSION", "BWS_ACCESS_TOKEN"' in text
    assert '"AWS_PROFILE"' in text


def test_codex_honours_codex_home(fake_home, tmp_path, monkeypatch):
    codex_home = tmp_path / "alt-codex"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    install_mcp_server("codex")

    assert (codex_home / "config.toml").exists()
    assert not (fake_home / ".codex").exists()


def test_codex_preserves_sibling_tables_and_leading_config(fake_home):
    config_path = fake_home / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        'model = "gpt-5"\n'
        "\n"
        "[mcp_servers.github]\n"
        'command = "gh-mcp"\n'
        "\n"
        "[mcp_servers.playwright]\n"
        'command = "npx"\n'
    )

    install_mcp_server("codex")

    text = config_path.read_text()
    assert 'model = "gpt-5"' in text
    assert '[mcp_servers.github]\ncommand = "gh-mcp"' in text
    assert '[mcp_servers.playwright]\ncommand = "npx"' in text
    assert "[mcp_servers.servonaut]" in text


def test_codex_reinstall_preserves_user_tuning(fake_home):
    """Re-installing must not wipe hand-set timeouts on our own block."""
    config_path = fake_home / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[mcp_servers.servonaut]\n"
        'command = "/old/path/servonaut"\n'
        'args = ["--mcp"]\n'
        "startup_timeout_sec = 30\n"
        "tool_timeout_sec = 180\n"
        'default_tools_approval_mode = "prompt"\n'
        "\n"
        "[mcp_servers.github]\n"
        'command = "gh-mcp"\n'
    )

    install_mcp_server("codex")

    text = config_path.read_text()
    assert 'command = "/usr/bin/servonaut"' in text
    assert "/old/path/servonaut" not in text
    assert "startup_timeout_sec = 30" in text
    assert "tool_timeout_sec = 180" in text
    assert 'default_tools_approval_mode = "prompt"' in text
    # The managed keys must appear exactly once — no duplicate TOML keys.
    assert text.count('command = "/usr/bin/servonaut"') == 1
    assert text.count("args = ") == 1
    assert text.count("[mcp_servers.servonaut]") == 1


def test_codex_preserves_existing_env_vars(fake_home):
    """A user's broader forwarding policy must not be overwritten."""
    config_path = fake_home / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[mcp_servers.servonaut]\n"
        'command = "/old/servonaut"\n'
        'args = ["--mcp"]\n'
        'env_vars = ["CUSTOM_AGENT_SOCKET"]\n'
    )

    install_mcp_server("codex")

    text = config_path.read_text()
    assert 'env_vars = ["CUSTOM_AGENT_SOCKET", "SSH_AUTH_SOCK"' in text
    assert text.count("env_vars = ") == 1
    assert text.count('"CUSTOM_AGENT_SOCKET"') == 1
    assert text.count('"SSH_AUTH_SOCK"') == 1


def test_codex_replaces_multiline_args_without_orphans(fake_home):
    config_path = fake_home / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[mcp_servers.servonaut]\n"
        'command = "/old/servonaut"\n'
        "args = [\n"
        '  "--mcp",\n'
        '  "--verbose",\n'
        "]\n"
        "tool_timeout_sec = 180\n"
    )

    install_mcp_server("codex")

    lines = config_path.read_text().splitlines()
    assert 'args = ["--mcp"]' in lines
    # No orphaned continuation lines from the replaced multi-line array.
    assert '  "--verbose",' not in lines
    assert "]" not in lines
    assert "tool_timeout_sec = 180" in lines


def test_codex_matches_quoted_table_header(fake_home):
    config_path = fake_home / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        '[mcp_servers."servonaut"]\ncommand = "/old/servonaut"\ntool_timeout_sec = 99\n'
    )

    install_mcp_server("codex")

    text = config_path.read_text()
    assert "/old/servonaut" not in text
    assert "tool_timeout_sec = 99" in text
    # Rewritten under the canonical bare-key header, and only once.
    assert text.count("servonaut]") == 1


def test_codex_stops_before_indented_sibling_table(fake_home):
    config_path = fake_home / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[mcp_servers.servonaut]\n"
        'command = "/old/servonaut"\n'
        "tool_timeout_sec = 99\n"
        "  [mcp_servers.other]\n"
        'command = "other-server"\n'
    )

    install_mcp_server("codex")

    text = config_path.read_text()
    assert "tool_timeout_sec = 99" in text
    assert '  [mcp_servers.other]\ncommand = "other-server"' in text


def test_toml_str_escapes_quotes_and_backslashes():
    assert installer._toml_str(r"C:\bin\servonaut.exe") == r'"C:\\bin\\servonaut.exe"'
    assert installer._toml_str('say "hi"') == '"say \\"hi\\""'


# --- all -------------------------------------------------------------------


def test_all_runs_every_installer(fake_home):
    calls: list[str] = []
    stubs = {
        name: (lambda _command, _args, n=name: calls.append(n))
        for name in SUPPORTED_TARGETS
    }

    with patch.dict(installer._INSTALLERS, stubs, clear=True):
        install_mcp_server("all")

    assert set(calls) == set(SUPPORTED_TARGETS)


def test_all_continues_after_one_installer_fails(fake_home):
    calls: list[str] = []

    def fail(_command: str, _args: list[str]) -> None:
        calls.append("claude")
        raise installer.MCPInstallerError("invalid test config")

    stubs = {
        name: (lambda _command, _args, n=name: calls.append(n))
        for name in SUPPORTED_TARGETS
    }
    stubs["claude"] = fail

    with patch.dict(installer._INSTALLERS, stubs, clear=True), pytest.raises(
        SystemExit
    ) as exc_info:
        install_mcp_server("all")

    assert exc_info.value.code == 1
    assert set(calls) == set(SUPPORTED_TARGETS)


# --- Claude Code -----------------------------------------------------------


def test_claude_uses_native_environment_references(fake_home):
    install_mcp_server("claude")

    config = json.loads((fake_home / ".claude.json").read_text())
    entry = config["mcpServers"]["servonaut"]
    assert entry["type"] == "stdio"
    assert entry["command"] == "/usr/bin/servonaut"
    assert entry["args"] == ["--mcp"]
    assert entry["env"]["SSH_AUTH_SOCK"] == "${SSH_AUTH_SOCK:-}"
    assert entry["env"]["BWS_ACCESS_TOKEN"] == "${BWS_ACCESS_TOKEN:-}"


def test_claude_reinstall_preserves_user_owned_fields(fake_home):
    config_path = fake_home / ".claude.json"
    original = {
        "mcpServers": {
            "other": {"command": "other-server"},
            "servonaut": {
                "command": "/old/servonaut",
                "timeout": 123,
                "env": {"CUSTOM_SETTING": "kept", "SSH_AUTH_SOCK": "/custom/socket"},
            },
        }
    }
    config_path.write_text(json.dumps(original))

    install_mcp_server("claude")

    config = json.loads(config_path.read_text())
    entry = config["mcpServers"]["servonaut"]
    assert entry["timeout"] == 123
    assert entry["env"]["CUSTOM_SETTING"] == "kept"
    assert entry["env"]["SSH_AUTH_SOCK"] == "/custom/socket"
    assert config["mcpServers"]["other"] == {"command": "other-server"}


# --- OpenCode --------------------------------------------------------------


def test_opencode_classic_uses_native_environment_references(fake_home, monkeypatch):
    monkeypatch.setattr(installer, "_get_os", lambda: "linux")
    monkeypatch.setattr(installer, "_installed_major_version", lambda _name: 1)
    install_mcp_server("opencode")

    config_path = fake_home / ".config" / "opencode" / "opencode.json"
    entry = json.loads(config_path.read_text())["mcp"]["servonaut"]
    assert entry["type"] == "local"
    assert entry["enabled"] is True
    assert entry["environment"]["SSH_AUTH_SOCK"] == "{env:SSH_AUTH_SOCK}"
    assert entry["environment"]["BWS_ACCESS_TOKEN"] == "{env:BWS_ACCESS_TOKEN}"


def test_opencode_v2_layout_is_detected_and_preserved(fake_home, monkeypatch):
    monkeypatch.setattr(installer, "_get_os", lambda: "linux")
    config_path = fake_home / ".config" / "opencode" / "opencode.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        json.dumps({"mcp": {"timeout": {"connect": 9000}, "servers": {}}})
    )
    monkeypatch.setattr(installer, "_installed_major_version", lambda _name: 2)

    install_mcp_server("opencode")

    config = json.loads(config_path.read_text())
    assert config["mcp"]["timeout"] == {"connect": 9000}
    entry = config["mcp"]["servers"]["servonaut"]
    assert "enabled" not in entry
    assert entry["command"] == ["/usr/bin/servonaut", "--mcp"]
    assert entry["environment"]["SSH_AUTH_SOCK"] == "{env:SSH_AUTH_SOCK}"


def test_opencode_v2_fresh_config_uses_servers_container(fake_home, monkeypatch):
    monkeypatch.setattr(installer, "_get_os", lambda: "linux")
    monkeypatch.setattr(installer, "_installed_major_version", lambda _name: 2)
    install_mcp_server("opencode")

    config_path = fake_home / ".config" / "opencode" / "opencode.json"
    config = json.loads(config_path.read_text())
    assert "servonaut" in config["mcp"]["servers"]
    assert "servonaut" not in config["mcp"]


@pytest.mark.parametrize(
    ("os_type", "relative_path"),
    (
        ("linux", Path(".config") / "opencode" / "opencode.json"),
        ("darwin", Path(".config") / "opencode" / "opencode.json"),
        ("windows", Path("AppData") / "opencode" / "opencode.json"),
    ),
)
def test_opencode_uses_the_expected_platform_config_path(
    fake_home, monkeypatch, os_type, relative_path
):
    monkeypatch.setattr(installer, "_get_os", lambda: os_type)
    monkeypatch.setattr(installer, "_installed_major_version", lambda _name: 1)
    if os_type == "windows":
        monkeypatch.setenv("APPDATA", str(fake_home / "AppData"))

    install_mcp_server("opencode")

    config_path = fake_home / relative_path
    assert config_path.exists()
    assert "servonaut" in json.loads(config_path.read_text())["mcp"]


# --- Cursor, Windsurf, and VS Code -----------------------------------------


def test_cursor_preserves_environment_without_unsafe_interpolation(fake_home):
    config_path = fake_home / ".cursor" / "mcp.json"
    config_path.parent.mkdir(parents=True)
    original = {"mcpServers": {"servonaut": {"timeout": 45, "env": {"CUSTOM": "ok"}}}}
    config_path.write_text(json.dumps(original))

    install_mcp_server("cursor")

    entry = json.loads(config_path.read_text())["mcpServers"]["servonaut"]
    assert entry["type"] == "stdio"
    assert entry["timeout"] == 45
    assert entry["env"] == {"CUSTOM": "ok"}


def test_windsurf_uses_documented_environment_interpolation(fake_home):
    install_mcp_server("windsurf")

    config_path = fake_home / ".codeium" / "windsurf" / "mcp_config.json"
    entry = json.loads(config_path.read_text())["mcpServers"]["servonaut"]
    assert entry["command"] == "/usr/bin/servonaut"
    assert entry["env"]["SSH_AUTH_SOCK"] == "${env:SSH_AUTH_SOCK}"
    assert entry["env"]["BW_SESSION"] == "${env:BW_SESSION}"


def test_vscode_writes_stdio_type_and_environment_references(fake_home, monkeypatch):
    monkeypatch.setattr(installer, "_get_os", lambda: "linux")
    install_mcp_server("vscode")

    config_path = fake_home / ".config" / "Code" / "User" / "mcp.json"
    entry = json.loads(config_path.read_text())["servers"]["servonaut"]
    assert entry["type"] == "stdio"
    assert entry["command"] == "/usr/bin/servonaut"
    assert entry["args"] == ["--mcp"]
    assert entry["env"]["SSH_AUTH_SOCK"] == "${env:SSH_AUTH_SOCK}"


@pytest.mark.parametrize(
    ("os_type", "relative_path"),
    (
        ("linux", Path(".config") / "Code" / "User" / "mcp.json"),
        (
            "darwin",
            Path("Library") / "Application Support" / "Code" / "User" / "mcp.json",
        ),
        ("windows", Path("AppData") / "Code" / "User" / "mcp.json"),
    ),
)
def test_vscode_uses_the_expected_platform_config_path(
    fake_home, monkeypatch, os_type, relative_path
):
    monkeypatch.setattr(installer, "_get_os", lambda: os_type)
    if os_type == "windows":
        monkeypatch.setenv("APPDATA", str(fake_home / "AppData"))

    install_mcp_server("vscode")

    config_path = fake_home / relative_path
    assert config_path.exists()
    assert "servonaut" in json.loads(config_path.read_text())["servers"]


# --- Gemini CLI ------------------------------------------------------------


def test_gemini_writes_settings_with_explicit_sensitive_env_refs(fake_home):
    install_mcp_server("gemini")

    config_path = fake_home / ".gemini" / "settings.json"
    entry = json.loads(config_path.read_text())["mcpServers"]["servonaut"]
    assert entry["command"] == "/usr/bin/servonaut"
    assert entry["args"] == ["--mcp"]
    assert entry["env"]["SSH_AUTH_SOCK"] == "$SSH_AUTH_SOCK"
    assert entry["env"]["BWS_ACCESS_TOKEN"] == "$BWS_ACCESS_TOKEN"


def test_gemini_install_updates_user_mcp_policy_without_losing_entries(fake_home):
    config_path = fake_home / ".gemini" / "settings.json"
    config_path.parent.mkdir(parents=True)
    original = {"mcp": {"allowed": ["other"], "excluded": ["servonaut", "blocked"]}}
    config_path.write_text(json.dumps(original))

    install_mcp_server("gemini")

    config = json.loads(config_path.read_text())
    assert config["mcp"]["allowed"] == ["other", "servonaut"]
    assert config["mcp"]["excluded"] == ["blocked"]
    assert "servonaut" in config["mcpServers"]


# --- Config safety and dynamic references ---------------------------------


def test_invalid_json_is_never_overwritten(fake_home, capsys):
    config_path = fake_home / ".claude.json"
    invalid = "{ this is not valid JSON"
    config_path.write_text(invalid)

    with pytest.raises(SystemExit) as exc_info:
        install_mcp_server("claude")

    assert exc_info.value.code == 1
    assert config_path.read_text() == invalid
    error = capsys.readouterr().err
    assert "Refusing to overwrite invalid JSON" in error


def test_configured_env_references_are_forwarded_by_name(fake_home):
    config_path = fake_home / ".servonaut" / "config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        json.dumps(
            {"one": "$HCLOUD_TOKEN", "two": "${OVH_KEY}", "ignored": "Bearer $NOPE"}
        )
    )

    install_mcp_server("codex")

    text = (fake_home / ".codex" / "config.toml").read_text()
    assert '"HCLOUD_TOKEN"' in text
    assert '"OVH_KEY"' in text
    assert '"NOPE"' not in text


def test_codex_multiline_env_vars_keep_object_entries(fake_home):
    config_path = fake_home / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[mcp_servers.servonaut]\n"
        'command = "/old/servonaut"\n'
        "env_vars = [\n"
        '  "CUSTOM",\n'
        '  { name = "REMOTE_TOKEN", source = "remote" },\n'
        "]\n"
        "tool_timeout_sec = 90\n"
    )

    install_mcp_server("codex")

    text = config_path.read_text()
    assert '{ name = "REMOTE_TOKEN", source = "remote" },' in text
    assert text.count('"CUSTOM"') == 1
    assert text.count('"SSH_AUTH_SOCK"') == 1
    assert "tool_timeout_sec = 90" in text
    assert text.count("env_vars = ") == 1


def test_wrong_nested_config_type_is_not_replaced(fake_home):
    config_path = fake_home / ".claude.json"
    original = json.dumps({"mcpServers": []})
    config_path.write_text(original)

    with pytest.raises(SystemExit):
        install_mcp_server("claude")

    assert config_path.read_text() == original


@pytest.mark.skipif(
    os.name == "nt", reason="Windows permissions use ACLs, not POSIX modes"
)
def test_atomic_reinstall_preserves_config_permissions(fake_home):
    config_path = fake_home / ".claude.json"
    config_path.write_text(json.dumps({"mcpServers": {}}))
    config_path.chmod(0o640)

    install_mcp_server("claude")

    assert config_path.stat().st_mode & 0o777 == 0o640


@pytest.mark.skipif(os.name == "nt", reason="symlink creation may need privileges")
def test_atomic_reinstall_preserves_config_symlink(fake_home):
    target_path = fake_home / "dotfiles" / "claude.json"
    target_path.parent.mkdir()
    target_path.write_text(json.dumps({"mcpServers": {}}))
    config_path = fake_home / ".claude.json"
    config_path.symlink_to(target_path)

    install_mcp_server("claude")

    assert config_path.is_symlink()
    config = json.loads(target_path.read_text())
    assert config["mcpServers"]["servonaut"]["command"] == "/usr/bin/servonaut"


def test_opencode_reinstall_preserves_disabled_state_and_custom_env(
    fake_home, monkeypatch
):
    monkeypatch.setattr(installer, "_get_os", lambda: "linux")
    config_path = fake_home / ".config" / "opencode" / "opencode.json"
    config_path.parent.mkdir(parents=True)
    original = {
        "mcp": {
            "servonaut": {
                "type": "local",
                "enabled": False,
                "environment": {"CUSTOM": "kept"},
            }
        }
    }
    config_path.write_text(json.dumps(original))
    monkeypatch.setattr(installer, "_installed_major_version", lambda _name: 1)

    install_mcp_server("opencode")

    entry = json.loads(config_path.read_text())["mcp"]["servonaut"]
    assert entry["enabled"] is False
    assert entry["environment"]["CUSTOM"] == "kept"
    assert entry["environment"]["SSH_AUTH_SOCK"] == "{env:SSH_AUTH_SOCK}"
