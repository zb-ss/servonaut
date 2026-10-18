"""What agents may do on a team's shared servers.

When an agent (the MCP server, the AI chat's tools, the hosted AI's tool
calls relayed to this machine) acts on a server a team shares, the team's rule applies and the member's own MCP
settings can only tighten it, never loosen it:

- The guard level is the stricter of the local ``mcp.guard_level`` and the
  level the team gives the member's role.
- At the standard level only the team's command allowlist applies (today
  the built-in one): commands added to the local allowlist do not reach a
  team's server, commands removed from it stay refused.
- The team's blocklist (today the built-in one) always applies, and so do
  the patterns added to the local blocklist.

The user's own servers keep their local rules, and nothing here applies to
what a person sends: commands typed in the TUI, with ``servonaut ssh`` or in
the web console, and remediations a person approved.

``team_policy`` verifies the rules the team service signs, as
:class:`TeamRules`; :func:`rules_for` does not read them yet and returns
:data:`DEFAULT_TEAM_RULES`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Iterable, List, Mapping, Optional, Tuple

from servonaut.config.schema import MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.services.shared_servers import is_shared_row

# The audit reason code of every refusal a team rule causes.
TEAM_RULE_REASON = "team_rule"
# Every refusal message starts with one of these (a named team, or a team
# the row does not name), so a caller that only sees the message (the
# relay's response) can still tell a team refusal apart.
REFUSAL_PREFIX = "Blocked: on team "
_UNNAMED_TEAM = "this team's"
_REFUSAL_PREFIXES: Tuple[str, ...] = (
    REFUSAL_PREFIX, f"Blocked: on {_UNNAMED_TEAM} shared servers ",
)
# Who a refusal says runs under the rule.
AGENTS = "your agents"
# Plain words for the tools a team's level can take away entirely.
_UNAVAILABLE = {
    "run_command": "running commands is not available there",
    "transfer_file": "file transfers are not available there",
}
# The guard's reasons, as worded for a person's own server.
_NOT_ALLOWLISTED = "not in allowlist"
_STANDARD_PREFIX = "Not allowed in standard mode: "
_BLOCKLIST_PREFIX = "Command matches blocklist pattern: "
# On a team's server a higher local tier does not help, so the guard's
# advice to use one is left out.
_TIER_ADVICE = "; use the dangerous tier"

# Least to most permissive.
GUARD_LEVELS: Tuple[str, ...] = (
    GuardLevel.READONLY, GuardLevel.STANDARD, GuardLevel.DANGEROUS,
)
_RANK = {level: rank for rank, level in enumerate(GUARD_LEVELS)}
# The roles a team gives its members.
TEAM_ROLES: Tuple[str, ...] = ("owner", "admin", "member", "viewer")
_REPORTED_COMMAND_LIMIT = 64


def _level_rank(level: Any) -> int:
    """Rank of *level*; anything unrecognised ranks as readonly (fail closed)."""
    return _RANK.get(str(level or "").strip().lower(), 0)


def stricter(*levels: Any) -> str:
    """The most restrictive of *levels*; an unknown level counts as readonly."""
    return GUARD_LEVELS[min((_level_rank(level) for level in levels), default=0)]


def _builtin_allowlist() -> Tuple[str, ...]:
    return tuple(MCPConfig().command_allowlist)


def _builtin_blocklist() -> Tuple[str, ...]:
    return tuple(MCPConfig().command_blocklist)


@dataclass(frozen=True)
class TeamRules:
    """A team's rules for what its members' agents may do on its servers."""

    # The guard level each team role gets.
    role_levels: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({
        "owner": GuardLevel.STANDARD,
        "admin": GuardLevel.STANDARD,
        "member": GuardLevel.STANDARD,
        "viewer": GuardLevel.READONLY,
    }))
    # A missing or unknown role: the caller's rights are not known.
    unknown_role_level: str = GuardLevel.READONLY
    command_allowlist: Tuple[str, ...] = field(default_factory=_builtin_allowlist)
    command_blocklist: Tuple[str, ...] = field(default_factory=_builtin_blocklist)
    # Per shared server id: the levels that replace the team-wide ones there.
    servers: Mapping[str, Mapping[str, str]] = field(
        default_factory=lambda: MappingProxyType({}),
    )
    # Why these are the readonly rules a team falls back to, in plain words
    # that follow "because"; empty for rules the team set.
    fallback_reason: str = ""

    @classmethod
    def readonly(cls, reason: str) -> "TeamRules":
        """Every role at the readonly level, owners included, because of *reason*."""
        return cls(role_levels=MappingProxyType({}), fallback_reason=reason)

    def level_for(self, role: Any) -> str:
        """The guard level for a member with *role*."""
        key = _role_key(role)
        return self.role_levels.get(key, self.unknown_role_level)

    def level_for_server(self, server_id: Any, role: Any) -> str:
        """The guard level for a member with *role* on the server *server_id*.

        The server's override, when it names the role; else the team-wide level.
        """
        override = self.servers.get(str(server_id or ""))
        key = _role_key(role)
        if override is not None and key in override:
            return override[key]
        return self.level_for(role)

    def for_server(self, server_id: Any) -> "TeamRules":
        """These rules with the override of *server_id* applied team-wide."""
        if not self.servers:
            return self
        role_levels = dict(self.role_levels)
        role_levels.update(self.servers.get(str(server_id or "")) or {})
        return replace(
            self, role_levels=MappingProxyType(role_levels), servers=MappingProxyType({}),
        )

    def unusable_pattern(self) -> str:
        """The first blocklist pattern Servonaut cannot compile; '' if none."""
        return next(iter(_unusable_patterns(self.command_blocklist)), "")


def _role_key(role: Any) -> str:
    return role.strip().lower() if isinstance(role, str) else ""


def _unusable_patterns(patterns: Iterable[str]) -> List[str]:
    unusable = []
    for pattern in patterns:
        try:
            re.compile(pattern)
        except (re.error, TypeError, ValueError, OverflowError, RecursionError):
            unusable.append(pattern)
    return unusable


DEFAULT_TEAM_RULES = TeamRules()


def rules_for(row: Mapping[str, Any]) -> TeamRules:
    """The rules of the team that shares *row*.

    Always the defaults for now: the team service publishes no rules yet.
    """
    return DEFAULT_TEAM_RULES


def _team_label(row: Mapping[str, Any]) -> str:
    for key in ("team_name", "team_slug"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _command_reason(reason: str) -> str:
    """The guard's *reason* for refusing a command, worded for a team's server."""
    reason = reason.split(_TIER_ADVICE, 1)[0]
    if reason.startswith(_BLOCKLIST_PREFIX):
        return f"it matches the blocked pattern {reason[len(_BLOCKLIST_PREFIX):]}"
    if reason.startswith(_STANDARD_PREFIX):
        return reason[len(_STANDARD_PREFIX):]
    return reason[:1].lower() + reason[1:]


def _reported(command: str) -> str:
    text = " ".join(command.split())
    if len(text) <= _REPORTED_COMMAND_LIMIT:
        return text
    return text[:_REPORTED_COMMAND_LIMIT - 1] + "…"


@dataclass(frozen=True)
class TeamGuard:
    """The guard an agent runs under on one team shared server."""

    guard: CommandGuard
    level: str
    team_level: str
    team: str

    def refusal(
        self, tool_name: str, command: Optional[str] = None,
        *, requested_as: str = "", actor: str = AGENTS,
    ) -> Optional[str]:
        """Why *tool_name* (running *command*, if given) is refused; None if allowed.

        *requested_as* names what was asked for in plain words ("reading
        logs") when *command* is something the caller built rather than
        the words the requester wrote: the message then names that instead
        of the command. *actor* says who runs under the rule on this
        surface.
        """
        allowed, _ = self.guard.check_tool(tool_name)
        if not allowed:
            what = (
                f"{requested_as} is not available there" if requested_as
                else _UNAVAILABLE.get(tool_name, f"{tool_name} is not available there")
            )
            return self._message(actor, what)
        if command is None:
            return None
        allowed, reason = self.guard.check_command(command)
        if allowed:
            return None
        if requested_as:
            return self._message(actor, f"{requested_as} is not allowed there")
        shown = _reported(command)
        if _NOT_ALLOWLISTED in reason:
            return self._message(actor, f"'{shown}' is not an allowed command there")
        return self._message(actor, f"'{shown}' is refused there: {_command_reason(reason)}")

    def _message(self, actor: str, what: str) -> str:
        team = f"team {self.team}'s" if self.team else _UNNAMED_TEAM
        setter = (
            "set by the team" if _level_rank(self.team_level) <= _level_rank(self.level)
            else "set by your MCP settings"
        )
        return (
            f"Blocked: on {team} shared servers {actor} run at the "
            f"{self.level} level ({setter}), and {what}."
        )


def is_team_refusal(message: Any) -> bool:
    """Whether *message* is a refusal :class:`TeamGuard` wrote."""
    return isinstance(message, str) and message.startswith(_REFUSAL_PREFIXES)


def guard_for_target(
    row: Mapping[str, Any],
    local_level: str,
    local_allowlist: Iterable[str],
    local_blocklist: Iterable[str],
    rules: Optional[TeamRules] = None,
) -> Optional[TeamGuard]:
    """The guard an agent runs under on *row*; None for the user's own server.

    A team shared server gets the stricter of *local_level* and the level
    the team gives the caller's role (``team_role``). The allowlist is the
    team's, less anything the local allowlist leaves out; the blocklist is
    the team's plus the local patterns. The local settings are read, never
    changed.
    """
    if not is_shared_row(row):
        return None
    rules = rules or rules_for(row)
    team_level = rules.level_for(row.get("team_role"))
    local = set(local_allowlist)
    allowlist = [command for command in rules.command_allowlist if command in local]
    blocklist = list(rules.command_blocklist)
    blocklist += [pattern for pattern in local_blocklist if pattern not in blocklist]
    level = stricter(local_level, team_level)
    guard = CommandGuard(MCPConfig(
        guard_level=level, command_allowlist=allowlist, command_blocklist=blocklist,
    ))
    return TeamGuard(guard=guard, level=level, team_level=team_level, team=_team_label(row))


def guard_for_target_from(
    row: Mapping[str, Any], local_guard: CommandGuard, rules: Optional[TeamRules] = None,
) -> Optional[TeamGuard]:
    """:func:`guard_for_target` with the local settings of *local_guard*."""
    if not is_shared_row(row):
        return None
    return guard_for_target(
        row, local_guard.level, local_guard.allowlist, local_guard.blocklist, rules,
    )
