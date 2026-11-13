"""Which SSH options a team may set: the closed table and the entry parser."""
from __future__ import annotations

import pytest

from servonaut.utils.ssh_option_policy import (
    ACCEPTED_OPTIONS,
    REFUSED_OPTION_VALUE,
    REFUSED_OPTIONS,
    RefusedOption,
    SSHOptionRefused,
    canonical,
    classify,
    judge_entries,
    raise_if_refused,
)

SWITCHES = ("permitlocalcommand", "forwardx11", "forwardx11trusted", "proxyusefdpass", "forwardagent")


def _spellings(name: str):
    return [f"{name}=v", f"{name} v", f"{name.upper()} = v", f'"{name}"=v', f'"{name}" v', f"\t{name}=v"]


@pytest.mark.parametrize("name", sorted(REFUSED_OPTIONS))
def test_every_refused_name_is_refused_in_every_spelling(name):
    for entry in _spellings(name):
        verdict = classify(entry)
        assert verdict.kind == "refused", entry
        assert verdict.phrase


def test_an_alias_of_a_library_option_is_refused():
    assert classify("SmartcardDevice=/x.so").kind == "refused"


@pytest.mark.parametrize(
    "entry", ["forwardagent=yes", "ForwardAgent /tmp/agent", "SendEnv=*", "RemoteForward=8080 localhost:80"]
)
def test_agent_forwarding_environment_and_remote_forwards_are_refused(entry):
    assert classify(entry).kind == "refused"


@pytest.mark.parametrize(
    "entry,phrase",
    [
        ("ForwardAgent=yes", "lets the server use this computer's SSH keys"),
        ("SendEnv=*", "sends this computer's environment variables to the server"),
        ("RemoteForward=1 h:2", "lets the server reach this computer's network"),
    ],
)
def test_the_amended_options_carry_their_phrase(entry, phrase):
    assert classify(entry).phrase == phrase


@pytest.mark.parametrize(
    "entry",
    ["FooBar=1"],
)
def test_an_unknown_name_is_group_c(entry):
    assert classify(entry).kind == "unknown"


@pytest.mark.parametrize(
    "entry",
    ["-oProxyCommand=x", "ProxyCommand", "", "   ", '"a\nb=c"', "a\x00b=c", "Foo\x7f=1", None, 5, ["x=y"]],
)
def test_malformed_entries_are_not_accepted(entry):
    assert classify(entry).kind == "malformed"


@pytest.mark.parametrize("name", sorted(ACCEPTED_OPTIONS))
def test_every_accepted_name_is_accepted(name):
    assert classify(f"{name}=1").kind == "accepted"


def test_the_two_tables_share_no_name():
    assert not set(REFUSED_OPTIONS) & ACCEPTED_OPTIONS


@pytest.mark.parametrize("name", SWITCHES)
@pytest.mark.parametrize("value", ["no", "NO", "false", "False"])
def test_a_switch_set_off_is_accepted(name, value):
    assert classify(f"{name}={value}").kind == "accepted"
    assert classify(f"{name}=yes").kind == "refused"


def test_canonical_text_lowercases_the_name_and_strips_the_value():
    assert canonical('  "ProxyCommand"  =  ssh -W %h:%p jump  ') == "proxycommand=ssh -W %h:%p jump"
    assert canonical("proxycommand\tx") == "proxycommand=x"


def test_a_value_may_hold_a_tab_and_an_empty_value_is_still_judged():
    assert classify("ProxyCommand=a\tb").kind == "refused"
    assert classify("ProxyCommand=").kind == "refused"


def test_the_carrier_is_an_option_ssh_rejects_and_carries_its_message():
    carrier = RefusedOption("Not connecting: x")
    assert carrier == REFUSED_OPTION_VALUE == "ServonautRefusedOption=yes"
    assert carrier.message == "Not connecting: x"


def test_raise_if_refused_reports_the_first_carrier_in_any_list():
    with pytest.raises(SSHOptionRefused, match="first"):
        raise_if_refused(["A=1"], ["-o", RefusedOption("first")], [RefusedOption("second")])
    raise_if_refused(["A=1"], None, ["-o", "B=2"])


def test_a_bare_sentinel_value_still_stops_the_command():
    with pytest.raises(SSHOptionRefused):
        raise_if_refused(["-o", REFUSED_OPTION_VALUE])


def test_only_recorded_entries_are_judged_for_a_connection_the_member_owns():
    entries = ["ProxyCommand=x", "LocalCommand=y", "ServerAliveInterval=60"]
    assert judge_entries(entries, where="w", team_options=[]) == entries
    recorded = [{"option": "localcommand=y", "team": "1", "team_name": "Acme", "allowed": False}]
    judged = judge_entries(entries, where="the connection profile 'p'", team_options=recorded)
    assert judged[0] == "ProxyCommand=x"
    assert isinstance(judged[1], RefusedOption)
    assert judged[2] == "ServerAliveInterval=60"
    assert judged[1].message == (
        "Not connecting: the connection profile 'p' came from team Acme and sets LocalCommand, "
        'which runs a program on this computer. To allow it, run "servonaut team options" '
        "or open Settings > Connections."
    )


def test_only_the_json_value_true_allows():
    for flag in ("true", 1, "yes", None):
        recorded = [{"option": "localcommand=y", "allowed": flag}]
        (judged,) = judge_entries(["LocalCommand=y"], where="w", team_options=recorded)
        assert isinstance(judged, RefusedOption), flag
    recorded = [{"option": "localcommand=y", "allowed": True}]
    assert judge_entries(["LocalCommand=y"], where="w", team_options=recorded) == ["LocalCommand=y"]


def test_a_malformed_team_options_value_counts_as_empty():
    for junk in (None, "x", 5, {"a": 1}, [1, "x", {"option": 5}]):
        assert judge_entries(["ProxyCommand=x"], where="w", team_options=junk) == ["ProxyCommand=x"]


def test_a_shared_record_is_always_the_teams_and_says_how_to_allow_it():
    (judged,) = judge_entries(
        ["ProxyCommand=x"], where="team Acme's record of the server 'web-1'",
        team_options=[], shared_team="Acme",
    )
    assert judged.message == (
        "Not connecting: team Acme's record of the server 'web-1' sets ProxyCommand, which runs "
        "a program on this computer. Ask the team to remove it, or allow it by adding it to "
        "ssh.team_options in ~/.servonaut/config.json."
    )
    allowed = [{"option": "proxycommand=x", "allowed": True}]
    assert judge_entries(
        ["ProxyCommand=x"], where="w", team_options=allowed, shared_team="Acme"
    ) == ["ProxyCommand=x"]
    assert judge_entries(
        ["ServerAliveInterval=5"], where="w", team_options=[], shared_team="Acme"
    ) == ["ServerAliveInterval=5"]


def test_an_option_saved_before_recording_says_so():
    recorded = [{"option": "proxycommand=x", "team": "", "team_name": "", "allowed": False,
                 "saved_before": True}]
    (judged,) = judge_entries(["ProxyCommand=x"], where="the connection profile 'p'",
                              team_options=recorded)
    assert judged.message == (
        "Not connecting: the connection profile 'p' sets ProxyCommand, which runs a program on "
        "this computer. It was saved before Servonaut recorded where settings come from. If you "
        'wrote it yourself, allow it: run "servonaut team options" or open Settings > Connections.'
    )


def test_unknown_and_malformed_messages():
    recorded = [
        {"option": "foobar=1", "team": "1", "team_name": "", "allowed": False},
        {"option": "-oProxyCommand=x", "team": "1", "team_name": "Acme", "allowed": False},
    ]
    unknown, bad = judge_entries(["FooBar=1", "-oProxyCommand=x"], where="the custom server 'w'",
                                 team_options=recorded)
    assert unknown.message.startswith(
        "Not connecting: the custom server 'w' came from a team and sets the SSH option FooBar, "
        "which Servonaut does not recognise."
    )
    assert bad.message.startswith(
        "Not connecting: the custom server 'w' came from team Acme and has an SSH option that "
        "is not written as Name=Value."
    )
