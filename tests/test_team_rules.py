"""Team rules: what agents may do on a team's shared servers."""
from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import MCPConfig
from servonaut.mcp.guards import CommandGuard
from servonaut.services import team_rules
from servonaut.services.team_rules import (
    DEFAULT_TEAM_RULES,
    TeamRules,
    credential_rules_row,
    credential_team_of,
    guard_for_target,
    guard_for_target_from,
    is_team_refusal,
    stricter,
)

from tests._team_policy_fixtures import agent_rules_with, trust_signed_team_rules

BUILTIN_ALLOWLIST = MCPConfig().command_allowlist
BUILTIN_BLOCKLIST = MCPConfig().command_blocklist


@pytest.fixture(autouse=True)
def _signed_team_rules():
    """Team ops has verified signed rules: the format 1 defaults."""
    trust_signed_team_rules("ops")


def _shared(role="member", **changes):
    row = {
        "id": "srv-1", "name": "server-1", "is_shared": True,
        "team_slug": "ops", "team_name": "Ops", "team_role": role,
    }
    row.update(changes)
    return row


def _guard(row, level="dangerous", allowlist=None, blocklist=None, rules=None):
    return guard_for_target(
        row, level,
        BUILTIN_ALLOWLIST if allowlist is None else allowlist,
        BUILTIN_BLOCKLIST if blocklist is None else blocklist,
        rules,
    )


class TestStricter:
    def test_the_most_restrictive_level_wins(self):
        assert stricter("dangerous", "standard") == "standard"
        assert stricter("standard", "readonly") == "readonly"
        assert stricter("dangerous", "dangerous") == "dangerous"

    def test_an_unknown_level_counts_as_readonly(self):
        assert stricter("Dangerous!", "dangerous") == "readonly"
        assert stricter(None, "standard") == "readonly"

    def test_case_and_spaces_do_not_matter(self):
        assert stricter(" DANGEROUS ", "dangerous") == "dangerous"


class TestTeamLevel:
    @pytest.mark.parametrize("role", ["owner", "admin", "member", "Member"])
    def test_members_who_manage_or_work_get_standard(self, role):
        assert DEFAULT_TEAM_RULES.level_for(role) == "standard"

    def test_a_viewer_gets_readonly(self):
        assert DEFAULT_TEAM_RULES.level_for("viewer") == "readonly"

    @pytest.mark.parametrize("role", [None, "", "guest", 3])
    def test_a_missing_or_unknown_role_gets_readonly(self, role):
        assert DEFAULT_TEAM_RULES.level_for(role) == "readonly"

    def test_published_rules_can_replace_the_defaults(self):
        rules = TeamRules(role_levels={"member": "dangerous"})
        guard = _guard(_shared("member"), rules=rules)
        assert guard.level == "dangerous"


class TestGuardForTarget:
    def test_own_servers_get_no_team_guard(self):
        assert _guard({"id": "i-1", "name": "web-1"}) is None
        assert _guard({"id": "i-1", "is_shared": "yes"}) is None

    def test_the_stricter_of_local_and_team_level_applies(self):
        assert _guard(_shared("member"), level="dangerous").level == "standard"
        assert _guard(_shared("member"), level="readonly").level == "readonly"
        assert _guard(_shared("viewer"), level="dangerous").level == "readonly"

    def test_a_row_without_a_role_is_readonly(self):
        row = _shared()
        del row["team_role"]
        assert _guard(row).level == "readonly"

    def test_a_command_outside_the_standard_allowlist_is_refused(self):
        refusal = _guard(_shared()).refusal("run_command", "systemctl restart nginx")
        assert refusal == (
            "Blocked: on team Ops's shared servers your agents run at the standard "
            "level (set by the team), and 'systemctl restart nginx' is not an "
            "allowed command there."
        )
        assert is_team_refusal(refusal)

    def test_an_allowlisted_command_is_allowed(self):
        assert _guard(_shared()).refusal("run_command", "uptime") is None

    def test_a_local_allowlist_addition_does_not_apply(self):
        guard = _guard(_shared(), level="standard", allowlist=[*BUILTIN_ALLOWLIST, "systemctl"])
        assert guard.refusal("run_command", "systemctl status nginx") is not None

    def test_a_command_removed_from_the_local_allowlist_stays_refused(self):
        allowlist = [command for command in BUILTIN_ALLOWLIST if command != "uptime"]
        guard = _guard(_shared(), allowlist=allowlist)
        assert guard.refusal("run_command", "uptime") is not None

    def test_a_local_blocklist_addition_applies(self):
        guard = _guard(_shared(), blocklist=[*BUILTIN_BLOCKLIST, r"\bcat\b"])
        assert guard.refusal("run_command", "cat /etc/hostname") is not None

    def test_the_builtin_blocklist_applies_when_the_local_one_is_empty(self):
        rules = TeamRules(role_levels={"member": "dangerous"})
        guard = _guard(_shared(), blocklist=[], rules=rules)
        assert guard.refusal("run_command", "rm -rf /tmp/x") is not None

    def test_readonly_refuses_run_command_but_not_read_tools(self):
        guard = _guard(_shared("viewer"))
        assert guard.refusal("run_command", "uptime") == (
            "Blocked: on team Ops's shared servers your agents run at the readonly "
            "level (set by the team), and running commands is not available there."
        )
        assert guard.refusal("check_status") is None
        assert guard.refusal("get_server_info") is None

    def test_dangerous_tools_are_never_available_at_the_team_level(self):
        assert _guard(_shared("owner")).refusal("transfer_file") is not None

    def test_a_stricter_local_level_is_named_as_the_setter(self):
        refusal = _guard(_shared("member"), level="readonly").refusal("run_command", "uptime")
        assert "(set by your MCP settings)" in refusal

    def test_the_team_slug_names_the_team_without_a_name(self):
        refusal = _guard(_shared(team_name="")).refusal("transfer_file")
        assert refusal.startswith("Blocked: on team ops's shared servers")

    def test_a_team_without_a_name_or_slug_reads_naturally(self):
        # Without a slug no signed rules can be found: the readonly fallback.
        refusal = _guard(_shared(team_name="", team_slug="")).refusal("transfer_file")
        assert refusal == (
            "Blocked: on this team's shared servers your agents run at the readonly "
            "level (because the team's agent rules have not been loaded yet), and "
            "file transfers are not available there."
        )
        assert is_team_refusal(refusal)

    def test_a_team_without_a_name_reads_naturally_with_explicit_rules(self):
        refusal = _guard(_shared(team_name="", team_slug=""), rules=DEFAULT_TEAM_RULES).refusal(
            "transfer_file",
        )
        assert refusal == (
            "Blocked: on this team's shared servers your agents run at the standard "
            "level (set by the team), and file transfers are not available there."
        )
        assert is_team_refusal(refusal)

    def test_an_option_the_standard_level_refuses_keeps_the_reason(self):
        refusal = _guard(_shared()).refusal("run_command", "find / -name x -delete")
        assert refusal.endswith(
            "and 'find / -name x -delete' is refused there: find actions that run "
            "programs, delete or write files are not allowed."
        )

    def test_an_ip_change_says_what_ip_allows(self):
        refusal = _guard(_shared()).refusal("run_command", "ip addr add 10.0.0.1/24 dev eth0")
        assert "is refused there: " in refusal
        assert "not an allowed command" not in refusal

    def test_a_command_list_is_refused_without_advice_to_raise_the_level(self):
        refusal = _guard(_shared()).refusal("run_command", "uptime; id")
        assert refusal.endswith(
            "and 'uptime; id' is refused there: only single pipes between "
            "allowlisted commands are allowed in standard mode."
        )
        assert "dangerous tier" not in refusal

    def test_a_blocklisted_command_names_the_pattern(self):
        guard = _guard(_shared(), blocklist=[*BUILTIN_BLOCKLIST, r"\bcat\b"])
        assert guard.refusal("run_command", "cat /etc/hostname").endswith(
            "and 'cat /etc/hostname' is refused there: it matches the blocked "
            "pattern \\bcat\\b."
        )

    def test_a_request_named_in_plain_words_is_refused_by_that_name(self):
        viewer = _guard(_shared("viewer"))
        assert viewer.refusal(
            "run_command", "tail -n 10 -- /var/log/syslog", requested_as="reading logs",
        ).endswith("and reading logs is not available there.")
        member = _guard(_shared())
        refusal = member.refusal(
            "run_command", "(sudo -n systemctl restart nginx); rc=$?",
            requested_as="the restart_service remediation",
        )
        assert refusal.endswith("and the restart_service remediation is not allowed there.")
        assert member.refusal("run_command", "uptime", requested_as="reading logs") is None

    def test_the_actor_names_who_runs_under_the_rule(self):
        refusal = _guard(_shared()).refusal(
            "run_command", "systemctl restart nginx", actor="relayed commands",
        )
        assert refusal.startswith(
            "Blocked: on team Ops's shared servers relayed commands run at the standard level"
        )
        assert is_team_refusal(refusal)

    def test_other_blocked_messages_are_not_team_refusals(self):
        assert not is_team_refusal("Blocked: Command matches blocklist pattern: x")
        assert not is_team_refusal("Blocked: on hold")
        assert not is_team_refusal(None)

    def test_a_long_command_is_shortened_in_the_message(self):
        command = "systemctl " + "x" * 200
        refusal = _guard(_shared()).refusal("run_command", command)
        assert command not in refusal
        assert "…" in refusal

    def test_the_standard_guard_renders_the_checked_words(self):
        guard = _guard(_shared())
        assert guard.guard.command_for_execution("ps aux | grep 'nginx'") == "ps aux | grep nginx"


class TestFromLocalGuard:
    def test_the_local_guard_is_read_not_changed(self):
        config = MCPConfig(guard_level="dangerous", command_allowlist=[*BUILTIN_ALLOWLIST, "systemctl"])
        local = CommandGuard(config)
        team = guard_for_target_from(_shared(), local)

        assert team.level == "standard"
        assert team.refusal("run_command", "systemctl status nginx") is not None
        assert local.level == "dangerous"
        assert local.check_command("systemctl status nginx") == (True, "OK")
        assert "systemctl" in config.command_allowlist

    def test_own_servers_keep_the_local_guard(self):
        local = CommandGuard(MCPConfig(guard_level="dangerous"))
        assert guard_for_target_from({"id": "i-1"}, local) is None

    def test_the_pattern_time_limit_is_passed_on(self):
        local = CommandGuard(MCPConfig(guard_level="dangerous"))
        team = guard_for_target_from(_shared(), local, pattern_timeout_ms=7)
        assert team.pattern_budget == pytest.approx(0.007)


def _dangerous_rules(*patterns):
    """Members at dangerous, so only the blocked patterns decide."""
    return TeamRules(
        role_levels={"member": "dangerous"},
        command_blocklist=(*BUILTIN_BLOCKLIST, *patterns),
    )


def _timed_guard(*patterns, timeout_ms=50):
    return guard_for_target(
        _shared(), "dangerous", BUILTIN_ALLOWLIST, BUILTIN_BLOCKLIST,
        _dangerous_rules(*patterns), pattern_timeout_ms=timeout_ms,
    )


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


class _SlowPattern:
    """A compiled pattern that takes *cost* seconds on any command, by *clock*.

    It stops at its timeout, as ``regex`` does, unless *overruns*: ``regex``
    looks at the clock only now and then, so a search can end a little late.
    """

    def __init__(self, name, cost, clock, overruns=False):
        self.pattern = name
        self._cost = cost
        self._clock = clock
        self._overruns = overruns
        self.timeouts = []

    def search(self, command, timeout=None):
        self.timeouts.append(timeout)
        if timeout < self._cost and not self._overruns:
            self._clock.now += timeout
            raise TimeoutError("regex timed out")
        self._clock.now += self._cost
        return None


class TestTeamPatternTimeLimit:
    """A team's blocked patterns cannot hang the tools that check them."""

    def test_a_catastrophic_pattern_is_refused_within_the_time_limit(self):
        guard = _timed_guard(r"^(a|aa)+$")
        command = "a" * 60 + "b"
        started = time.monotonic()
        refusal = guard.refusal("run_command", command)
        elapsed = time.monotonic() - started

        # Without a limit this one search outlasts the suite's 60 s timeout.
        assert elapsed < 1.0
        assert refusal == (
            "Blocked: on team Ops's shared servers your agents run at the dangerous "
            f"level (set by the team), and '{command}' is refused there: the team's "
            "blocked pattern '^(a|aa)+$' takes too long to check (a team owner or "
            "admin can change it)."
        )

    def test_one_time_limit_covers_all_of_the_team_s_patterns(self, monkeypatch):
        clock = _Clock()
        monkeypatch.setattr(team_rules, "time", clock)
        first, second, third = (_SlowPattern(name, 0.03, clock) for name in ("p1", "p2", "p3"))
        guard = replace(_timed_guard(), team_patterns=(first, second, third))

        refusal = guard.refusal("run_command", "uptime")

        assert first.timeouts == [pytest.approx(0.05)]
        # The second gets what the first left, not a budget of its own.
        assert second.timeouts == [pytest.approx(0.02)]
        assert third.timeouts == []
        assert "the team's blocked pattern 'p2' takes too long to check" in refusal

    def test_a_used_up_budget_refuses_without_searching_again(self, monkeypatch):
        clock = _Clock()
        monkeypatch.setattr(team_rules, "time", clock)
        first = _SlowPattern("p1", 0.06, clock, overruns=True)
        second = _SlowPattern("p2", 0.0, clock)
        guard = replace(_timed_guard(), team_patterns=(first, second))

        refusal = guard.refusal("run_command", "uptime")

        assert second.timeouts == []
        assert "the team's blocked pattern 'p2' takes too long to check" in refusal

    def test_patterns_that_do_not_match_let_the_command_run(self):
        guard = _timed_guard(r"^(a|aa)+$", r"\.env\b")
        assert guard.refusal("run_command", "uptime") is None
        assert guard.refusal("run_command", "aaaa").endswith(
            "it matches the blocked pattern ^(a|aa)+$."
        )

    def test_pcre_forms_python_s_re_cannot_read_are_used(self):
        rules = _dangerous_rules(r"\h--force\b", r"\p{Lu}{3}_TOKEN")
        assert rules.unusable_pattern() == ""
        guard = _guard(_shared(), rules=rules)
        assert guard.refusal("run_command", "git push\t--force").endswith(
            "it matches the blocked pattern \\h--force\\b."
        )
        assert guard.refusal("run_command", "echo $API_TOKEN") is not None
        assert guard.refusal("run_command", "git push origin main") is None

    @pytest.mark.parametrize("pattern", ["x(", "[z-a]", "a{99999999999}", "(" * 5000 + ")" * 5000])
    def test_a_pattern_regex_cannot_compile_still_refuses_every_command(self, pattern):
        guard = _guard(_shared(), rules=_dangerous_rules(pattern))
        assert "Servonaut cannot use the team's blocked pattern" in guard.refusal(
            "run_command", "uptime",
        )
        assert guard.guard.check_command("uptime")[0] is False

    @pytest.mark.parametrize("timeout_ms", [None, 0, -5, "100", float("nan"), True])
    def test_a_time_limit_that_is_not_a_positive_number_is_the_default(self, timeout_ms):
        guard = _timed_guard(timeout_ms=timeout_ms)
        assert guard.pattern_budget == MCPConfig().team_pattern_timeout_ms / 1000

    def test_servonaut_s_own_and_local_patterns_stay_on_the_guard(self):
        guard = _guard(
            _shared(), blocklist=[*BUILTIN_BLOCKLIST, r"\bcurl\b"],
            rules=_dangerous_rules(r"\.env\b"),
        )
        assert guard.guard.blocklist == [*BUILTIN_BLOCKLIST, r"\bcurl\b"]
        assert [pattern.pattern for pattern in guard.team_patterns] == [r"\.env\b"]


def test_only_team_refusals_are_recognised():
    assert not is_team_refusal("Blocked: Command 'x' not in allowlist for standard mode")
    assert not is_team_refusal(None)


class TestDescribeLevel:
    def test_names_the_level_and_who_set_it(self):
        assert _guard(_shared()).describe_level() == "standard (set by the team)"
        assert _guard(_shared(), level="readonly").describe_level() == (
            "readonly (set by your MCP settings)"
        )

    def test_a_fallback_says_why(self):
        rules = TeamRules.readonly("the team's agent rules expired")
        assert _guard(_shared(), rules=rules).describe_level() == (
            "readonly (because the team's agent rules expired)"
        )

    def test_a_pattern_servonaut_cannot_use_is_named(self):
        rules = TeamRules(command_blocklist=("(unclosed",))
        assert _guard(_shared(), rules=rules).describe_level().endswith(
            "no command can run there because Servonaut cannot use the team's "
            "blocked pattern '(unclosed'"
        )


def _own_row(**changes):
    row = {"id": "i-1", "name": "app-1", "public_ip": "web.example.com", "port": 22}
    row.update(changes)
    return row


def _teams(*rows, servers=()):
    service = MagicMock()
    service.list_teams = AsyncMock(return_value=list(rows))
    service.list_shared_servers = AsyncMock(return_value=list(servers))
    return service


class TestCredentialRules:
    """An own server reached with a team's vault key runs under that team's rules."""

    def test_the_team_s_shared_row_for_the_same_server_is_used(self):
        service = _teams(
            {"slug": "ops", "name": "Ops", "role": "member"},
            servers=[{"id": "srv-1", "name": "web-1", "hostname": "web.example.com"}],
        )
        row = asyncio.run(credential_rules_row(_own_row(), "ops", service))

        assert row["is_shared"] is True
        assert (row["id"], row["team_slug"], row["team_role"]) == ("srv-1", "ops", "member")

    def test_the_strictest_of_two_shared_copies_is_used(self):
        trust_signed_team_rules("ops", agent_rules_with(
            servers={"srv-2": {"role_levels": {"member": "readonly"}}},
        ), version=2)
        service = _teams(
            {"slug": "ops", "name": "Ops", "role": "member"},
            servers=[
                {"id": "srv-1", "name": "web-1", "hostname": "web.example.com"},
                {"id": "srv-2", "name": "web-1b", "instance_id": "i-1"},
            ],
        )
        row = asyncio.run(credential_rules_row(_own_row(), "ops", service))

        assert row["id"] == "srv-2"

    def test_another_team_s_copy_of_the_server_is_not_used(self):
        from servonaut.services.shared_servers import shared_row

        service = _teams({"slug": "ops", "name": "Ops", "role": "member"})
        other = shared_row(
            {"id": "srv-9", "instance_id": "i-1"}, {"slug": "dev", "name": "Dev", "role": "owner"},
        )
        row = asyncio.run(credential_rules_row(_own_row(), "ops", service, [other]))

        assert (row["id"], row["team_slug"], row["team_role"]) == ("", "ops", "member")

    def test_a_server_the_team_does_not_share_gets_the_team_wide_level(self):
        service = _teams({"slug": "ops", "name": "Ops", "role": "admin"})
        row = asyncio.run(credential_rules_row(_own_row(), "ops", service))

        assert (row["id"], row["team_slug"], row["team_role"]) == ("", "ops", "admin")
        assert _guard(row).level == "standard"

    def test_rows_already_read_are_used_instead_of_reading_the_team_s_servers(self):
        from servonaut.services.shared_servers import shared_row

        service = _teams({"slug": "ops", "name": "Ops", "role": "member"})
        shared = shared_row({"id": "srv-1", "instance_id": "i-1"}, {"slug": "ops", "role": "member"})
        row = asyncio.run(credential_rules_row(_own_row(), "ops", service, [shared]))

        assert row["id"] == "srv-1"
        service.list_shared_servers.assert_not_awaited()

    def test_a_team_the_user_is_not_in_gives_no_role(self):
        service = _teams({"slug": "dev", "name": "Dev", "role": "owner"})
        row = asyncio.run(credential_rules_row(_own_row(), "ops", service))

        assert row["team_role"] == ""
        assert _guard(row).level == "readonly"
        service.list_shared_servers.assert_not_awaited()

    def test_an_unreadable_team_list_is_raised_for_the_caller_to_refuse(self):
        service = _teams()
        service.list_teams = AsyncMock(side_effect=RuntimeError("offline"))

        with pytest.raises(RuntimeError):
            asyncio.run(credential_rules_row(_own_row(), "ops", service))


class TestCredentialTeamOf:
    def test_a_shared_server_or_no_vault_runtime_has_none(self):
        runtime = MagicMock(credential_team=AsyncMock(return_value="ops"))
        assert asyncio.run(credential_team_of(_shared(), runtime)) is None
        assert asyncio.run(credential_team_of(_own_row(), None)) is None
        runtime.credential_team.assert_not_awaited()

    def test_the_vault_runtime_names_the_team(self):
        runtime = MagicMock(credential_team=AsyncMock(return_value="ops"))
        assert asyncio.run(credential_team_of(_own_row(), runtime)) == "ops"

    def test_a_runtime_without_the_check_has_none(self):
        assert asyncio.run(credential_team_of(_own_row(), object())) is None
