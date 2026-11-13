"""Where a member sees and decides about team options: the command line, Settings and the app."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Static

from servonaut.config.schema import AppConfig
from servonaut.screens.settings.panels.connections import ConnectionsPanel
from tests import test_refused_host_paths as host_paths
from tests.test_settings_panels_roundtrip import _PanelHost, _reload, _temp_config_manager

OPTION = "proxycommand=touch {marker}"


def _seed(home: Path, marker: Path, *, name: str = "web-1", allowed: bool = False) -> Path:
    config_dir = home / ".servonaut"
    config_dir.mkdir(parents=True, exist_ok=True)
    key = home / "k.pem"
    key.write_text("x")
    key.chmod(0o600)
    row = {"name": name, "host": "10.0.0.5", "username": "deploy", "port": 22,
           "extra_ssh_options": [f"ProxyCommand=touch {marker}"]}
    row["ssh_key"] = str(key)
    path = config_dir / "config.json"
    path.write_text(json.dumps({
        "version": 7,
        "custom_servers": [row],
        "default_scan_paths": ["/var/log"],
        "ssh": {
            "team_options_checked": True,
            "team_options": [{"option": OPTION.format(marker=marker), "team": "7",
                              "team_name": "Acme", "allowed": allowed}],
        },
    }))
    return path


def _cli(home: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    env = {**os.environ, "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
           "XDG_DATA_HOME": str(home / ".local" / "share")}
    exe = Path(sys.executable).with_name("servonaut")
    return subprocess.run([str(exe), *args], env=env, capture_output=True, text=True, timeout=timeout)


def test_servonaut_ssh_refuses_with_exit_4_and_never_runs_the_program(tmp_path):
    marker = tmp_path / "marker"
    _seed(tmp_path, marker)
    result = _cli(tmp_path, "ssh", "web-1", "uptime")
    assert result.returncode == 4, result.stderr
    assert (
        "Not connecting: the custom server 'web-1' came from team Acme and sets ProxyCommand"
        in result.stderr
    )
    assert not marker.exists()


def test_team_options_lists_allows_and_refuses_in_the_saved_config(tmp_path):
    marker = tmp_path / "marker"
    config_path = _seed(tmp_path, marker)
    listed = _cli(tmp_path, "team", "options")
    assert listed.returncode == 0
    assert listed.stdout.splitlines()[0] == "Team options that run programs on this computer"
    assert f"1  refused  Team Acme  proxycommand=touch {marker}" in listed.stdout
    assert 'Allow one: servonaut team options allow 1' in listed.stdout

    allowed = _cli(tmp_path, "team", "options", "allow", "1")
    assert allowed.stdout == (
        f"Allowed: proxycommand=touch {marker}. Connections that use it will run it on this computer.\n"
    )
    assert json.loads(config_path.read_text())["ssh"]["team_options"][0]["allowed"] is True
    assert "1  allowed" in _cli(tmp_path, "team", "options").stdout

    refused = _cli(tmp_path, "team", "options", "refuse", "1")
    assert refused.stdout == f"Refused: proxycommand=touch {marker}.\n"
    assert json.loads(config_path.read_text())["ssh"]["team_options"][0]["allowed"] is False

    all_ = _cli(tmp_path, "team", "options", "allow", "--all")
    assert all_.returncode == 0
    assert json.loads(config_path.read_text())["ssh"]["team_options"][0]["allowed"] is True


def test_team_options_with_nothing_recorded_and_a_bad_number(tmp_path):
    (tmp_path / ".servonaut").mkdir()
    (tmp_path / ".servonaut" / "config.json").write_text(json.dumps({"version": 7}))
    assert _cli(tmp_path, "team", "options").stdout == "No team options need your approval.\n"
    bad = _cli(tmp_path, "team", "options", "allow", "3")
    assert bad.returncode == 2
    assert bad.stderr == 'No option 3. Run "servonaut team options" to see the list.\n'


# --- Settings ---------------------------------------------------------------

async def _wait(pilot, condition, *, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        await pilot.pause()


@pytest.mark.asyncio
async def test_the_block_is_hidden_while_nothing_is_recorded(tmp_path):
    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(ConnectionsPanel, manager)
    async with app.run_test() as pilot:
        await _wait(pilot, lambda: app.panel is not None and app.panel.is_mounted)
        await pilot.pause()
        assert app.panel.query_one("#team_options_block").display is False


@pytest.mark.asyncio
async def test_allow_in_settings_flips_the_item_and_the_next_build_passes(tmp_path):
    from unittest.mock import MagicMock

    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.ssh_service import SSHService
    from servonaut.utils.ssh_option_policy import SSHOptionRefused

    config = AppConfig()
    config.ssh.team_options = [{"option": "localcommand=notify-send hi", "team": "7",
                                "team_name": "Acme", "allowed": False}]
    manager = _temp_config_manager(tmp_path, config)
    app = _PanelHost(ConnectionsPanel, manager)
    instance = {"id": "c-1", "name": "web-1", "extra_ssh_options": ["LocalCommand=notify-send hi"]}
    async with app.run_test() as pilot:
        await _wait(pilot, lambda: app.panel is not None and app.panel.is_mounted)
        panel = app.panel
        await _wait(pilot, lambda: panel.query_one("#team_options_block").display is True)
        table = panel.query_one("#conn_team_options_table", DataTable)
        await _wait(pilot, lambda: table.row_count == 1)
        assert [str(c.label) for c in table.columns.values()] == ["Option", "From", "State"]
        assert table.get_row_at(0) == ["localcommand=notify-send hi", "Team Acme", "Refused"]
        await _wait(pilot, lambda: str(panel.query_one("#conn_team_option_text", Static).render()) != "")
        assert "localcommand=notify-send hi" in str(panel.query_one("#conn_team_option_text", Static).render())

        service = ConnectionService(manager)
        ssh = SSHService(manager)
        with pytest.raises(SSHOptionRefused):
            ssh.build_ssh_command(host="10.0.0.5", username="d",
                                  extra_options=service.get_extra_options(instance, None))

        panel.query_one("#btn_team_option_allow", Button).press()
        await _wait(pilot, lambda: table.row_count == 1 and table.get_row_at(0)[2] == "Allowed")
        argv = ssh.build_ssh_command(host="10.0.0.5", username="d",
                                     extra_options=service.get_extra_options(instance, None))
        assert "LocalCommand=notify-send hi" in argv
        assert _reload(tmp_path).ssh.team_options[0]["allowed"] is True

        panel.query_one("#btn_team_option_refuse", Button).press()
        await _wait(pilot, lambda: table.get_row_at(0)[2] == "Refused")
        assert _reload(tmp_path).ssh.team_options[0]["allowed"] is False


# --- the app ------------------------------------------------------------------

def _seed_home(home: Path) -> None:
    _seed(home, home / "marker", name="bad-1")


@pytest.mark.asyncio
@pytest.mark.parametrize("path", list(host_paths.PATHS))
async def test_the_app_shows_a_refused_option_on_every_path_and_keeps_running(
    monkeypatch, tmp_path, path
) -> None:
    monkeypatch.setattr(host_paths, "_seed_home", _seed_home)
    running, errors, toasts, shown = await host_paths._drive(monkeypatch, tmp_path, host_paths.PATHS[path])
    assert running
    assert errors == []
    assert any("Not connecting" in toast and "ProxyCommand" in toast for toast in toasts) or (
        "Not connecting" in shown
    )
    assert not (tmp_path / "marker").exists()
