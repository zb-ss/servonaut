"""Options saved before 2.33.1 are recorded once, for people who can have pulled a team config."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from servonaut.config.manager import ConfigManager
from servonaut.services import auth_service
from servonaut.services.connection_service import ConnectionService
from servonaut.utils.ssh_option_policy import RefusedOption

PROXY = "ssh -W %h:%p jump"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_service, "AUTH_FILE", tmp_path / "auth.json")
    return tmp_path


def write_config(home: Path, **extra) -> Path:
    path = home / "config.json"
    path.write_text(json.dumps({
        "version": 7,
        "connection_profiles": [{"name": "jump", "proxy_command": PROXY}],
        "custom_servers": [{"name": "web-1", "host": "10.0.0.5", "username": "deploy",
                            "extra_ssh_options": ["LocalCommand=x", "Compression=yes"]}],
        **extra,
    }))
    return path


def load(path: Path) -> ConfigManager:
    manager = ConfigManager(config_path=path)
    manager.load()
    return manager


def test_a_signed_in_member_has_old_options_recorded_and_refused_with_the_saved_before_text(home):
    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 1.0, "teams_cached": [{"slug": "a"}]}))
    manager = load(write_config(home))
    ssh = manager.get().ssh
    assert [i["option"] for i in ssh.team_options] == [f"proxycommand={PROXY}", "localcommand=x"]
    assert all(i["allowed"] is False and i["saved_before"] is True for i in ssh.team_options)
    assert ssh.team_options_checked is True and manager.team_options_recorded == 2
    assert json.loads((home / "config.json").read_text())["ssh"]["team_options_checked"] is True

    config = manager.get()
    service = ConnectionService(MagicMock(get=MagicMock(return_value=config)))
    refused = service.get_proxy_args(config.connection_profiles[0])[1]
    assert isinstance(refused, RefusedOption)
    assert refused.message == (
        "Not connecting: the connection profile 'jump' sets ProxyCommand, which runs a program on "
        "this computer. It was saved before Servonaut recorded where settings come from. If you "
        'wrote it yourself, allow it: run "servonaut team options" or open Settings > Connections.'
    )


def test_without_an_account_nothing_is_recorded_and_the_options_work_as_before(home):
    manager = load(write_config(home))
    config = manager.get()
    # No sign-in file: nothing to decide on yet, so the step waits for one.
    assert config.ssh.team_options == [] and config.ssh.team_options_checked is False
    service = ConnectionService(MagicMock(get=MagicMock(return_value=config)))
    assert service.get_proxy_args(config.connection_profiles[0]) == ["-o", f"ProxyCommand={PROXY}"]


def test_a_member_of_no_team_is_not_touched_and_an_unreadable_file_counts_as_a_member(home):
    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 5.0, "teams_cached": []}))
    assert load(write_config(home)).get().ssh.team_options == []

    (home / "auth.json").write_text("{not json")
    path = write_config(home)
    assert len(load(path).get().ssh.team_options) == 2


def test_a_team_list_that_was_never_fetched_counts_as_a_member(home):
    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 0, "teams_cached": []}))
    assert len(load(write_config(home)).get().ssh.team_options) == 2


def test_the_step_runs_once(home):
    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 1.0, "teams_cached": [{"slug": "a"}]}))
    path = write_config(home, ssh={"team_options_checked": True})
    manager = load(path)
    assert manager.get().ssh.team_options == []

    path = write_config(home)
    first = load(path)
    first.get().connection_profiles[0].proxy_command = "ssh -W %h:%p added-later"
    first.save(first.get())
    second = load(path)
    assert [i["option"] for i in second.get().ssh.team_options] == [f"proxycommand={PROXY}", "localcommand=x"]
    assert second.team_options_recorded == 0


def test_a_new_install_records_nothing_even_after_the_member_signs_in(home):
    manager = ConfigManager(config_path=home / "config.json")
    manager.load()
    config = manager.get()
    assert config.ssh.team_options_checked is True
    config.connection_profiles = []
    manager.save(config)
    (home / "auth.json").write_text(json.dumps({"teams_fetched_at": 1.0, "teams_cached": [{"slug": "a"}]}))
    config.connection_profiles = []
    again = load(home / "config.json")
    assert again.get().ssh.team_options == []
