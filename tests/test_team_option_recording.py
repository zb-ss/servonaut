"""Applying a team configuration records the options that need the member's approval."""
from __future__ import annotations

import dataclasses

from servonaut.config.schema import AppConfig, ConnectionProfile, CustomServer
from servonaut.services.connection_service import ConnectionService
from servonaut.services.team_config_apply import apply_team_config
from servonaut.services.team_config_subset import diff_against_local
from servonaut.utils.ssh_option_policy import RefusedOption

TEAM = {"id": 7, "slug": "acme", "name": "Acme"}
PAYLOAD = {
    "connection_profiles": [
        {"name": "jump", "proxy_command": "ssh -W %h:%p jump",
         "extra_ssh_options": ["LocalCommand=notify-send hi", "ServerAliveInterval=60"]},
    ],
    "custom_servers": [
        {"name": "web-1", "host": "10.0.0.5", "username": "deploy",
         "extra_ssh_options": ["FooBar=1", "Compression=yes"]},
    ],
}


def texts(config):
    return [entry["option"] for entry in config.ssh.team_options]


def test_one_item_per_option_that_is_not_accepted_with_the_team_named():
    config = AppConfig()
    applied = apply_team_config(config, PAYLOAD, team=TEAM)
    assert texts(config) == [
        "proxycommand=ssh -W %h:%p jump", "localcommand=notify-send hi", "foobar=1",
    ]
    assert all(entry["allowed"] is False for entry in config.ssh.team_options)
    assert {entry["team"] for entry in config.ssh.team_options} == {"7"}
    assert {entry["team_name"] for entry in config.ssh.team_options} == {"Acme"}
    assert applied.refused_options == 3


def test_a_pull_without_a_team_records_blank_names():
    config = AppConfig()
    apply_team_config(config, PAYLOAD)
    assert {(e["team"], e["team_name"]) for e in config.ssh.team_options} == {("", "")}


def test_a_second_pull_keeps_what_was_allowed_and_a_changed_text_starts_refused():
    config = AppConfig()
    apply_team_config(config, PAYLOAD, team=TEAM)
    config.ssh.team_options[0]["allowed"] = True
    config.ssh.team_options.append(
        {"option": "pkcs11provider=/old.so", "team": "7", "team_name": "Acme", "allowed": True}
    )
    changed = {**PAYLOAD, "connection_profiles": [
        {"name": "jump", "proxy_command": "ssh -W %h:%p other"},
        {"name": "again", "proxy_command": "ssh -W %h:%p jump"},
    ]}
    apply_team_config(config, changed, team=TEAM)
    state = {e["option"]: e["allowed"] for e in config.ssh.team_options}
    assert state["proxycommand=ssh -W %h:%p jump"] is True
    assert state["proxycommand=ssh -W %h:%p other"] is False
    assert state["pkcs11provider=/old.so"] is True
    assert "localcommand=notify-send hi" not in state


def test_a_payload_cannot_allow_anything_itself():
    config = AppConfig()
    payload = {
        **PAYLOAD,
        "ssh": {"team_options": [{"option": "proxycommand=ssh -W %h:%p jump", "allowed": True}]},
        "team_options": [{"option": "proxycommand=ssh -W %h:%p jump", "allowed": True}],
    }
    apply_team_config(config, payload, team=TEAM)
    assert [(e["option"], e["allowed"]) for e in config.ssh.team_options] == [
        ("proxycommand=ssh -W %h:%p jump", False),
        ("localcommand=notify-send hi", False),
        ("foobar=1", False),
    ]


def test_editing_another_field_of_a_pulled_profile_keeps_it_refused():
    config = AppConfig()
    apply_team_config(config, PAYLOAD, team=TEAM)
    profile = config.connection_profiles[0]
    rebuilt = ConnectionProfile(**{**dataclasses.asdict(profile), "ssh_port": 2222})
    config.connection_profiles = [rebuilt]
    from unittest.mock import MagicMock

    manager = MagicMock()
    manager.get.return_value = config
    args = ConnectionService(manager).get_proxy_args(rebuilt)
    assert isinstance(args[1], RefusedOption)


def test_changing_the_text_of_a_pulled_option_makes_it_the_members_own():
    config = AppConfig()
    apply_team_config(config, PAYLOAD, team=TEAM)
    config.connection_profiles[0].proxy_command = "ssh -W %h:%p mine"
    from unittest.mock import MagicMock

    manager = MagicMock()
    manager.get.return_value = config
    args = ConnectionService(manager).get_proxy_args(config.connection_profiles[0])
    assert args == ["-o", "ProxyCommand=ssh -W %h:%p mine"]


def test_the_preview_lists_the_options_a_pull_would_carry():
    diff = diff_against_local(AppConfig(), PAYLOAD)
    assert diff["refused_options"] == [
        {"where": "profile 'jump'", "option": "proxycommand=ssh -W %h:%p jump"},
        {"where": "profile 'jump'", "option": "localcommand=notify-send hi"},
        {"where": "server 'web-1'", "option": "foobar=1"},
    ]
    assert diff_against_local(AppConfig(), {"connection_profiles": []})["refused_options"] == []
