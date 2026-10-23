"""``servonaut team rules``: a team's agent rules, read-only."""
from __future__ import annotations

import argparse
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.cli import team
from servonaut.services.team_policy import MISSING

from tests._team_policy_fixtures import (
    agent_rules_with,
    envelope,
    response,
    team_id_for,
    trust_test_key,
)

SERVERS = [{"id": "srv-1", "name": "web-1", "hostname": "web.example.com"}]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="subcommand")
    team.add_team_parser(subparsers)
    return parser


def _team_service(agent_rules=None, *, signed=True):
    service = MagicMock()
    service.list_teams = AsyncMock(return_value=[
        {"id": team_id_for("ops-team"), "slug": "ops-team", "name": "Ops Team", "role": "member"},
    ])
    service.list_shared_servers = AsyncMock(return_value=list(SERVERS))
    signed_rules = envelope(team_id_for("ops-team"), agent_rules) if signed else None
    service.get_team_policy_with_date = AsyncMock(return_value=(response(signed_rules), None))
    return service


@pytest.fixture
def service_factory():
    trust_test_key()
    services = {}

    def use(service):
        services["current"] = service
        team.set_team_service_factory(lambda: services["current"])
        return service

    yield use
    team.set_team_service_factory(None)


def _run(*argv):
    return team.handle_team_command(_parser().parse_args(["team", "rules", *argv]))


def test_the_parser_reads_the_team_and_json():
    args = _parser().parse_args(["team", "rules", "ops-team", "--json"])
    assert (args.team_command, args.team, args.json) == ("rules", "ops-team", True)


def test_shows_the_rules_that_apply_now(service_factory, capsys):
    service_factory(_team_service(agent_rules_with(
        role_levels={"member": "readonly"},
        servers={"srv-1": {"role_levels": {"admin": "dangerous"}}},
    )))

    assert _run("ops-team") == 0
    out = capsys.readouterr().out
    assert out.startswith("What agents may do here (team ops-team)\n")
    assert "Owner: standard · Admin: standard · Member: readonly · Viewer: readonly" in out
    assert "Your role: member (readonly)" in out
    assert "  web-1: Admin dangerous" in out
    assert "Version 1 · last refreshed " in out


def test_json_carries_the_same_view(service_factory, capsys):
    service_factory(_team_service(agent_rules_with(command_allowlist=["uptime"])))

    assert _run("ops-team", "--json") == 0
    view = json.loads(capsys.readouterr().out)
    assert view["team"] == "ops-team"
    assert view["in_force"] is True
    assert view["command_allowlist"] == ["uptime"]
    assert view["role_levels"]["viewer"] == "readonly"


def test_a_team_is_found_by_its_name_too(service_factory, capsys):
    service_factory(_team_service())

    assert _run("ops team", "--json") == 0
    assert json.loads(capsys.readouterr().out)["team"] == "ops-team"


def test_a_fallback_is_shown_with_its_reason(service_factory, capsys):
    service_factory(_team_service(signed=False))

    assert _run("ops-team", "--json") == 0
    view = json.loads(capsys.readouterr().out)
    assert view["in_force"] is False
    assert view["problem"] == MISSING.code
    assert view["fallback_reason"] == MISSING.reason


def test_signed_out_says_to_sign_in(service_factory, capsys):
    team.set_team_service_factory(lambda: None)

    assert _run("ops-team") == 1
    assert "servonaut login" in capsys.readouterr().err


def test_a_team_the_user_is_not_in_is_refused(service_factory, capsys):
    service = service_factory(_team_service())

    assert _run("dev-team") == 1
    assert "You are not in a team called dev-team." in capsys.readouterr().err
    service.get_team_policy_with_date.assert_not_awaited()


def test_an_unreadable_team_list_is_an_error(service_factory, capsys):
    service = service_factory(_team_service())
    service.list_teams = AsyncMock(side_effect=RuntimeError("offline"))

    assert _run("ops-team") == 1
    assert "Your teams could not be read" in capsys.readouterr().err


def test_unreadable_servers_leave_out_only_the_per_server_levels(service_factory, capsys):
    service = service_factory(_team_service(agent_rules_with(
        servers={"srv-1": {"role_levels": {"admin": "dangerous"}}},
    )))
    service.list_shared_servers = AsyncMock(side_effect=RuntimeError("offline"))

    assert _run("ops-team", "--json") == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["servers"] == []
    assert "per-server levels are left out" in captured.err


def test_control_characters_from_the_team_never_reach_the_terminal(service_factory, capsys):
    service_factory(_team_service(agent_rules_with(command_blocklist=["evil\x1b[2Jpattern"])))

    assert _run("ops-team") == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "evil[2Jpattern" in out
