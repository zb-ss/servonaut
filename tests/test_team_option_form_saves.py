"""Saving a pulled entry in its form never makes it the member's own.

Each case pulls a team entry, opens the real form, changes an unrelated field,
saves, reloads, and builds the command. The forms keep every character except
that they split on line breaks and save ``str.strip()`` of each line, which
removes more than space and tab.
"""
from __future__ import annotations

import time
import webbrowser
from pathlib import Path

import pytest
from textual.app import App
from textual.widgets import Button, Input

from servonaut.config.manager import ConfigManager
from servonaut.services.connection_service import ConnectionService
from servonaut.services.custom_server_service import CustomServerService
from servonaut.services.ssh_service import SSHService
from servonaut.services.team_config_apply import apply_team_config
from servonaut.utils.ssh_option_policy import SSHOptionRefused

TEAM = {"id": 7, "slug": "acme", "name": "Acme"}
M = "/var/tmp/servonaut-sec/never-created"

SERVER_ENTRIES = {
    "multi-line": f"Compression=yes\nProxyCommand=touch {M}",
    "trailing no-break space": f"ProxyCommand=touch {M} ",
    "leading ideographic space": f"　ProxyCommand=touch {M}",
    "second line starts with a no-break space": f"Compression=yes\n ProxyCommand=touch {M}",
    "trailing unit separator": f"ProxyCommand=touch {M}\x1f",
    "CR LF": f"Compression=yes\r\nProxyCommand=touch {M}",
    "line separator": f"Compression=yes ProxyCommand=touch {M}",
    "tab inside the value": f"ProxyCommand=touch\t{M}",
    "vertical tab": f"Compression=yes\x0bProxyCommand=touch {M}",
    "form feed": f"Compression=yes\x0cProxyCommand=touch {M}",
    "file separator": f"Compression=yes\x1cProxyCommand=touch {M}",
    "next line": f"Compression=yes\x85ProxyCommand=touch {M}",
    "bare CR": f"Compression=yes\rProxyCommand=touch {M}",
    "control character in the name": f"Proxy\x01Command=touch {M}",
    "NUL in the name": f"Proxy\x00Command=touch {M}",
    "zero width space in the name": f"Proxy​Command=touch {M}",
    "two spaces in the value": f"ProxyCommand=touch  {M}",
}
# Not a line break to ssh: it reads the whole entry as one (invalid) option,
# which runs nothing. The form splits it, so what matters is the saved result.
ONE_OPTION_TO_SSH = {"line separator", "next line"}
PROFILE_ENTRIES = {
    "plain": f"ProxyCommand=touch {M}",
    "trailing no-break space": f"ProxyCommand=touch {M} ",
    "leading ideographic space": f"　ProxyCommand=touch {M}",
    "trailing unit separator": f"ProxyCommand=touch {M}\x1f",
    "inner line break": f"Compression=yes\nProxyCommand=touch {M}",
    "tab inside the value": f"ProxyCommand=touch\t{M}",
    "control character in the name": f"Proxy\x01Command=touch {M}",
    "NUL in the name": f"Proxy\x00Command=touch {M}",
    "escape in the name": f"Proxy\x1bCommand=touch {M}",
}


def _build(manager, instance, profile=None):
    conn, ssh = ConnectionService(manager), SSHService(manager)
    return ssh.build_ssh_command(
        host="127.0.0.1", username="deploy", port=1, remote_command="true",
        proxy_args=conn.get_proxy_args(profile) if profile else [],
        extra_options=conn.get_extra_options(instance, profile),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("label", list(SERVER_ENTRIES))
async def test_custom_server_form_keeps_the_entry_refused(tmp_path, monkeypatch, label):
    from servonaut.screens.custom_servers import CustomServersScreen
    from servonaut.styles import CSS_FILES

    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: False)
    manager = ConfigManager(config_path=tmp_path / "config.json")
    config = manager.load()
    apply_team_config(config, {"custom_servers": [{
        "name": "web-1", "host": "127.0.0.1", "username": "deploy",
        "extra_ssh_options": [SERVER_ENTRIES[label]],
    }]}, team=TEAM)
    manager.save(config)
    row = CustomServerService(manager).list_as_instances()[0]
    if label not in ONE_OPTION_TO_SSH:
        with pytest.raises(SSHOptionRefused):
            _build(manager, row)

    class Host(App):
        CSS_PATH = CSS_FILES

        def __init__(self) -> None:
            super().__init__()
            self.demo_mode = False
            self.redaction_service = None
            self.custom_server_service = CustomServerService(manager)
            self.instances = []

        def on_mount(self) -> None:
            self.push_screen(CustomServersScreen())

    app = Host()
    async with app.run_test(size=(166, 47)) as pilot:
        await pilot.pause()
        screen = app.screen
        screen._show_form(manager.get().custom_servers[0])
        await pilot.pause()
        screen.query_one("#input_ssh_key").value = "~/.ssh/own_key"
        screen.query_one("#btn_save_server", Button).press()
        deadline = time.monotonic() + 10
        while manager.get().custom_servers[0].ssh_key != "~/.ssh/own_key":
            assert time.monotonic() < deadline, "the form did not save"
            await pilot.pause()

    reloaded = ConfigManager(config_path=tmp_path / "config.json")
    reloaded.load()
    row = CustomServerService(reloaded).list_as_instances()[0]
    with pytest.raises(SSHOptionRefused):
        _build(reloaded, row)


@pytest.mark.asyncio
@pytest.mark.parametrize("label", list(PROFILE_ENTRIES))
async def test_profile_form_keeps_the_entry_refused(tmp_path, monkeypatch, label):
    from servonaut.screens.settings.panels.connections import ConnectionsPanel
    from tests.test_settings_panels_roundtrip import _PanelHost

    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: False)
    manager = ConfigManager(config_path=tmp_path / "config.json")
    config = manager.load()
    apply_team_config(config, {
        "connection_profiles": [{"name": "jump", "extra_ssh_options": [PROFILE_ENTRIES[label]]}],
        "connection_rules": [{"name": "all", "match_conditions": {}, "profile_name": "jump"}],
    }, team=TEAM)
    manager.save(config)
    instance = {"id": "i-1", "name": "web-1"}
    with pytest.raises(SSHOptionRefused):
        _build(manager, instance, manager.get().connection_profiles[0])

    app = _PanelHost(ConnectionsPanel, manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConnectionsPanel)
        panel._editing_profile_idx = 0
        panel._show_profile_form("Edit profile")
        panel._populate_profile_form(panel._profiles[0])
        await pilot.pause()
        await pilot.pause()
        panel.query_one("#pf_username", Input).value = "deploy"
        await pilot.pause()
        panel._handle_profile_save()
        await pilot.pause()
        panel.persist()
        await pilot.pause()

    reloaded = ConfigManager(config_path=tmp_path / "config.json")
    reloaded.load()
    profile = reloaded.get().connection_profiles[0]
    assert profile.username == "deploy"
    with pytest.raises(SSHOptionRefused):
        _build(reloaded, instance, profile)
