"""A team's agent rules as people read them (Teams screen, ``servonaut team rules``)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from servonaut.config.schema import MCPConfig
from servonaut.services.team_policy import EXPIRED, NOT_LOADED, TeamPolicyStatus
from servonaut.services.team_rules import TeamRules
from servonaut.services.team_rules_view import BUILTIN_COMMANDS, agent_rules_lines, agent_rules_view

from tests._team_policy_fixtures import agent_rules_with, team_id_for, trust_signed_team_rules

SERVERS = [{"id": "srv-1", "name": "web-1"}, {"id": "srv-2", "name": "db-1"}]


def view_of(agent_rules=None, *, role="member", servers=SERVERS):
    status = trust_signed_team_rules("ops-team", agent_rules, version=3)
    return agent_rules_view("ops-team", status, servers, role)


class TestInForce:
    def test_the_defaults(self):
        view = view_of()

        assert view["in_force"] is True
        assert view["fallback_reason"] is None
        assert view["version"] == 3
        assert view["role_levels"] == {
            "owner": "standard", "admin": "standard", "member": "standard", "viewer": "readonly",
        }
        assert view["command_allowlist"] is None
        assert view["command_blocklist"] == []
        assert view["servers"] == []
        assert (view["your_role"], view["your_level"]) == ("member", "standard")

    def test_lines_name_every_role_and_the_built_in_lists(self):
        lines = agent_rules_lines(view_of())

        assert "Owner: standard · Admin: standard · Member: standard · Viewer: readonly" in lines
        assert "Your role: member (standard)" in lines
        assert f"Allowed commands at the standard level: {BUILTIN_COMMANDS}" in lines
        assert "Blocked patterns the team adds to Servonaut's own: none" in lines
        assert lines[-1].startswith("Version 3 · last refreshed ")
        assert " · valid until " in lines[-1]

    def test_per_server_levels_are_named_by_server(self):
        view = view_of(agent_rules_with(servers={
            "srv-1": {"role_levels": {"member": "readonly", "admin": "dangerous"}},
            "srv-gone": {"role_levels": {"member": "dangerous"}},
        }))

        # A server the team no longer lists is left out.
        assert view["servers"] == [{
            "id": "srv-1", "name": "web-1",
            "role_levels": {"member": "readonly", "admin": "dangerous"},
        }]
        assert "  web-1: Member readonly, Admin dangerous" in agent_rules_lines(view)

    def test_the_team_s_own_command_lists(self):
        view = view_of(agent_rules_with(
            command_allowlist=["uptime", "df", "not a name"], command_blocklist=[r"\bcurl\b"],
        ))

        assert view["command_allowlist"] == ["uptime", "df"]
        assert view["command_blocklist"] == [r"\bcurl\b"]
        lines = agent_rules_lines(view)
        assert "Allowed commands at the standard level: uptime, df" in lines
        assert r"Blocked patterns the team adds to Servonaut's own: \bcurl\b" in lines

    def test_a_list_the_same_as_the_built_in_one_reads_as_built_in(self):
        builtin = list(MCPConfig().command_allowlist)
        assert view_of(agent_rules_with(command_allowlist=builtin))["command_allowlist"] is None

    def test_a_pattern_servonaut_cannot_use_is_called_out(self):
        view = view_of(agent_rules_with(command_blocklist=["(unclosed"]))

        assert view["unusable_pattern"] == "(unclosed"
        assert any(
            line.startswith("No command can run on this team's servers")
            and "'(unclosed'" in line
            for line in agent_rules_lines(view)
        )

    def test_the_view_is_json(self):
        view = view_of(agent_rules_with(servers={"srv-1": {"role_levels": {"member": "readonly"}}}))
        assert json.loads(json.dumps(view)) == view


class TestFallback:
    def test_never_fetched(self):
        view = agent_rules_view("ops-team", None, SERVERS, "owner")

        assert view["in_force"] is False
        assert view["problem"] == NOT_LOADED.code
        assert view["role_levels"] == dict.fromkeys(["owner", "admin", "member", "viewer"], "readonly")
        assert agent_rules_lines(view) == [
            "Agents run at the readonly level on this team's shared servers, owners "
            f"included, because {NOT_LOADED.reason}.",
            "not fetched yet",
        ]

    def test_says_why_and_when_it_was_last_refreshed(self):
        fetched = datetime(2026, 10, 18, 12, 30, tzinfo=timezone.utc)
        status = TeamPolicyStatus(
            slug="ops-team", team_id=team_id_for("ops-team"),
            rules=TeamRules.readonly(EXPIRED.reason), problem=EXPIRED, version=4,
            expires_at=datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc),
            fetched_at=fetched.timestamp(),
        )
        view = agent_rules_view("ops-team", status, SERVERS, "member")

        assert view["fallback_reason"] == EXPIRED.reason
        assert view["servers"] == []
        assert agent_rules_lines(view) == [
            "Agents run at the readonly level on this team's shared servers, owners "
            f"included, because {EXPIRED.reason}.",
            "Version 4 · last refreshed 2026-10-18 12:30 UTC",
        ]
