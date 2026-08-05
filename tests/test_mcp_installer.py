"""Tests for the MCP auto-installer (per-agent config writers)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.mcp import installer
from servonaut.mcp.installer import SUPPORTED_TARGETS, install_mcp_server


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Redirect Path.home() and $CODEX_HOME into a throwaway directory."""
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))
    monkeypatch.delenv('CODEX_HOME', raising=False)
    return home


@pytest.fixture(autouse=True)
def stub_command(monkeypatch):
    """Pin the resolved MCP command so assertions are deterministic."""
    monkeypatch.setattr(
        installer, '_resolve_mcp_command', lambda: ('/usr/bin/servonaut', ['--mcp'])
    )


def test_every_supported_target_has_an_installer():
    assert set(SUPPORTED_TARGETS) == set(installer._INSTALLERS)


def test_unknown_target_exits_nonzero(capsys):
    with pytest.raises(SystemExit) as exc:
        install_mcp_server('emacs')

    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Unknown target 'emacs'" in out
    # The error must advertise every target we actually support.
    for target in SUPPORTED_TARGETS:
        assert target in out


# --- agy (Antigravity CLI) -------------------------------------------------


def test_agy_writes_mcp_servers_entry(fake_home):
    install_mcp_server('agy')

    config = json.loads((fake_home / '.gemini' / 'config' / 'mcp_config.json').read_text())
    assert config['mcpServers']['servonaut'] == {
        'command': '/usr/bin/servonaut',
        'args': ['--mcp'],
        'env': {},
    }


def test_agy_preserves_other_servers(fake_home):
    config_path = fake_home / '.gemini' / 'config' / 'mcp_config.json'
    config_path.parent.mkdir(parents=True)
    config_path.write_text(json.dumps({'mcpServers': {'other': {'command': 'x'}}}))

    install_mcp_server('agy')

    config = json.loads(config_path.read_text())
    assert config['mcpServers']['other'] == {'command': 'x'}
    assert 'servonaut' in config['mcpServers']


def test_agy_handles_zero_byte_config(fake_home, capsys):
    """Antigravity ships an empty mcp_config.json — it must not warn or crash."""
    config_path = fake_home / '.gemini' / 'config' / 'mcp_config.json'
    config_path.parent.mkdir(parents=True)
    config_path.write_text('')

    install_mcp_server('agy')

    assert 'Could not parse' not in capsys.readouterr().out
    config = json.loads(config_path.read_text())
    assert config['mcpServers']['servonaut']['command'] == '/usr/bin/servonaut'


# --- codex (TOML) ----------------------------------------------------------


def test_codex_creates_config(fake_home):
    install_mcp_server('codex')

    text = (fake_home / '.codex' / 'config.toml').read_text()
    assert '[mcp_servers.servonaut]' in text
    assert 'command = "/usr/bin/servonaut"' in text
    assert 'args = ["--mcp"]' in text


def test_codex_honours_codex_home(fake_home, tmp_path, monkeypatch):
    codex_home = tmp_path / 'alt-codex'
    monkeypatch.setenv('CODEX_HOME', str(codex_home))

    install_mcp_server('codex')

    assert (codex_home / 'config.toml').exists()
    assert not (fake_home / '.codex').exists()


def test_codex_preserves_sibling_tables_and_leading_config(fake_home):
    config_path = fake_home / '.codex' / 'config.toml'
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        'model = "gpt-5"\n'
        '\n'
        '[mcp_servers.github]\n'
        'command = "gh-mcp"\n'
        '\n'
        '[mcp_servers.playwright]\n'
        'command = "npx"\n'
    )

    install_mcp_server('codex')

    text = config_path.read_text()
    assert 'model = "gpt-5"' in text
    assert '[mcp_servers.github]\ncommand = "gh-mcp"' in text
    assert '[mcp_servers.playwright]\ncommand = "npx"' in text
    assert '[mcp_servers.servonaut]' in text


def test_codex_reinstall_preserves_user_tuning(fake_home):
    """Re-installing must not wipe hand-set timeouts on our own block."""
    config_path = fake_home / '.codex' / 'config.toml'
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        '[mcp_servers.servonaut]\n'
        'command = "/old/path/servonaut"\n'
        'args = ["--mcp"]\n'
        'startup_timeout_sec = 30\n'
        'tool_timeout_sec = 180\n'
        'default_tools_approval_mode = "prompt"\n'
        '\n'
        '[mcp_servers.github]\n'
        'command = "gh-mcp"\n'
    )

    install_mcp_server('codex')

    text = config_path.read_text()
    assert 'command = "/usr/bin/servonaut"' in text
    assert '/old/path/servonaut' not in text
    assert 'startup_timeout_sec = 30' in text
    assert 'tool_timeout_sec = 180' in text
    assert 'default_tools_approval_mode = "prompt"' in text
    # The managed keys must appear exactly once — no duplicate TOML keys.
    assert text.count('command = "/usr/bin/servonaut"') == 1
    assert text.count('args = ') == 1
    assert text.count('[mcp_servers.servonaut]') == 1


def test_codex_replaces_multiline_args_without_orphans(fake_home):
    config_path = fake_home / '.codex' / 'config.toml'
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        '[mcp_servers.servonaut]\n'
        'command = "/old/servonaut"\n'
        'args = [\n'
        '  "--mcp",\n'
        '  "--verbose",\n'
        ']\n'
        'tool_timeout_sec = 180\n'
    )

    install_mcp_server('codex')

    lines = config_path.read_text().splitlines()
    assert 'args = ["--mcp"]' in lines
    # No orphaned continuation lines from the replaced multi-line array.
    assert '  "--verbose",' not in lines
    assert ']' not in lines
    assert 'tool_timeout_sec = 180' in lines


def test_codex_matches_quoted_table_header(fake_home):
    config_path = fake_home / '.codex' / 'config.toml'
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        '[mcp_servers."servonaut"]\n'
        'command = "/old/servonaut"\n'
        'tool_timeout_sec = 99\n'
    )

    install_mcp_server('codex')

    text = config_path.read_text()
    assert '/old/servonaut' not in text
    assert 'tool_timeout_sec = 99' in text
    # Rewritten under the canonical bare-key header, and only once.
    assert text.count('servonaut]') == 1


def test_toml_str_escapes_quotes_and_backslashes():
    assert installer._toml_str(r'C:\bin\servonaut.exe') == r'"C:\\bin\\servonaut.exe"'
    assert installer._toml_str('say "hi"') == '"say \\"hi\\""'


# --- all -------------------------------------------------------------------


def test_all_runs_every_installer(fake_home):
    calls: list[str] = []
    stubs = {name: (lambda n=name: calls.append(n)) for name in SUPPORTED_TARGETS}

    with patch.dict(installer._INSTALLERS, stubs, clear=True):
        install_mcp_server('all')

    assert set(calls) == set(SUPPORTED_TARGETS)
