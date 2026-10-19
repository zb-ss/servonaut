"""What agents may do on a team's shared servers.

When an agent (the MCP server, the AI chat's tools, the hosted AI's tool
calls relayed to this machine) acts on a server a team shares, the team's rule applies and the member's own MCP
settings can only tighten it, never loosen it:

- The guard level is the stricter of the local ``mcp.guard_level`` and the
  level the team gives the member's role.
- A team can give a role a different level on one of its servers; the
  roles that override leaves out keep the team-wide level.
- At the standard level only the team's command allowlist applies (the
  built-in one unless the team names its own): commands added to the local
  allowlist do not reach a team's server, commands removed from it stay
  refused.
- The built-in blocklist always applies, and so do the patterns the team
  and the local blocklist add. A team pattern Servonaut cannot use refuses
  every command on that team's servers. The team's patterns are searched
  with the ``regex`` module under one time limit per command
  (``mcp.team_pattern_timeout_ms``): a command they take longer to check is
  refused, so a slow pattern cannot hang the tools.

The user's own servers keep their local rules, and nothing here applies to
what a person sends: commands typed in the TUI, with ``servonaut ssh`` or in
the web console, and remediations a person approved. One exception: a server
of the user's own that connects with a key from a team's vault is reached
with the team's credentials, so that team's rules apply to it too (see
:func:`credential_rules_row`).

The team service signs each team's rules; :func:`rules_for` reads the rules
``team_policy`` verified. When a team has no valid signed rules (not loaded
yet, expired, not verifiable), its shared servers run at the readonly level
for every role, and refusals say why.
"""
from __future__ import annotations

import inspect
import math
import time
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

import regex

from servonaut.config.schema import MCPConfig
from servonaut.mcp.guards import (
    CommandGuard,
    GuardLevel,
    check_standard_command,
    standard_command_names,
)
from servonaut.services.memory.provider import instance_provider
from servonaut.services.shared_servers import is_same_server, is_shared_row, shared_row

# The audit reason code of every refusal a team rule causes.
TEAM_RULE_REASON = "team_rule"
# The audit reason, and what the agent is told, when Servonaut cannot tell
# whether a server of the user's own connects with a team's vault key: the
# agent may not act on it then (a team's key is never taken for a personal one).
CREDENTIAL_CHECK_FAILED_REASON = "credential_check_failed"
CREDENTIAL_CHECK_FAILED = (
    "Error: could not check which vault key this server uses, so agents "
    "cannot act on it right now. Try again shortly."
)
# How long one such check serves the agent's next calls on the same server,
# so a tool loop does not cost several API requests per call. An internal
# coalescing window like the ssh-ref lookups', not an ops setting.
CREDENTIAL_MEMO_SECONDS = 60.0
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
# Put in a team guard's blocklist in place of a team pattern Servonaut cannot
# compile: the empty pattern matches every command, so the guard itself
# refuses them all as well as the refusal message saying so.
_MATCH_EVERY_COMMAND = ""
# What compiling a team's pattern can raise; any of them makes it unusable.
_PATTERN_ERRORS = (regex.error, TypeError, ValueError, OverflowError, RecursionError)


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


def _pattern_budget(timeout_ms: Any) -> float:
    """*timeout_ms* (``mcp.team_pattern_timeout_ms``) in seconds; the default
    when it is not a positive number."""
    if (
        isinstance(timeout_ms, bool) or not isinstance(timeout_ms, (int, float))
        or not math.isfinite(timeout_ms) or timeout_ms <= 0
    ):
        timeout_ms = MCPConfig().team_pattern_timeout_ms
    return timeout_ms / 1000


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
    """The patterns of *patterns* that ``regex`` cannot compile."""
    unusable = []
    for pattern in patterns:
        try:
            regex.compile(pattern)
        except _PATTERN_ERRORS:
            unusable.append(pattern)
    return unusable


DEFAULT_TEAM_RULES = TeamRules()


def rules_for(row: Mapping[str, Any]) -> TeamRules:
    """The rules of the team that shares *row*, for that server.

    The team's verified signed rules with the override of the row's server
    (``id``) applied; the readonly fallback, with its reason, when the team
    (``team_slug``) has no valid signed rules.
    """
    # team_policy builds TeamRules, so it is imported here, not at the top.
    from servonaut.services.team_policy import team_policy_store

    slug = row.get("team_slug")
    rules = team_policy_store().rules_for_team(slug if isinstance(slug, str) else "")
    return rules.for_server(row.get("id"))


async def credential_team_of(row: Mapping[str, Any], vault_runtime: Any) -> Optional[str]:
    """The team whose vault key the user's own server *row* connects with.

    None for a shared server, without a vault runtime, or when the key is
    not a team's (see ``VaultCommandService.credential_team``).

    Raises:
        Exception: the key could not be checked.
    """
    check = getattr(vault_runtime, "credential_team", None) if vault_runtime is not None else None
    if is_shared_row(row) or not callable(check):
        return None
    result = check(dict(row))
    slug = await result if inspect.isawaitable(result) else result
    return slug if isinstance(slug, str) else None


async def credential_rules_row(
    row: Mapping[str, Any],
    team_slug: str,
    team_service: Any,
    shared_rows: Optional[Iterable[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """The row whose team rules apply to the user's own server *row*.

    *row* connects with a key from the vault of team *team_slug*: the
    team's shared row for the same server (see ``shared_servers.fold_shared``;
    the strictest when the team shares it twice), else a row of that team
    without a server, which gets the team-wide level of the user's role.
    *shared_rows* are the shared rows the caller already holds; without them
    the team's servers are read.

    Raises:
        Exception: the team list or the team's servers could not be read;
            the caller refuses rather than apply no rule.
    """
    teams = await team_service.list_teams()
    team = next(
        (team for team in teams or [] if isinstance(team, Mapping) and team.get("slug") == team_slug),
        None,
    )
    if team is None:
        # Not (or no longer) a member: no role, so the strictest level.
        team = {"slug": team_slug}
    elif shared_rows is None:
        shared_rows = [
            shared_row(server, team)
            for server in await team_service.list_shared_servers(team_slug) or []
            if isinstance(server, Mapping)
        ]
    same = [
        dict(shared) for shared in shared_rows or []
        if is_shared_row(shared) and shared.get("team_slug") == team_slug
        and is_same_server(shared, row)
    ]
    if same:
        return min(same, key=lambda shared: _level_rank(
            rules_for(shared).level_for(shared.get("team_role")),
        ))
    # No server id: no team override can name it.
    return shared_row({"name": row.get("name") or ""}, team)


def _vault_unlocked(vault_runtime: Any) -> bool:
    return getattr(vault_runtime, "is_unlocked", False) is True


class CredentialRulesMemo:
    """Whose rules apply to the user's own servers, remembered a while.

    A server of the user's own that connects with a key from a team's vault
    runs under that team's rules (:func:`credential_rules_row`). Finding
    that out takes a few API calls, so each answer is kept for
    *ttl_seconds*. A check that failed is never kept, nor "not a team's
    key" while the vault is locked: once it unlocks, the server may connect
    with a team's key. A binding this process makes since (the vault
    runtime's ``binding_generation``) starts the server over.
    """

    def __init__(
        self,
        ttl_seconds: float = CREDENTIAL_MEMO_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        # (provider, id, name) -> (expiry, binding generation, rules row or None)
        self._entries: Dict[Tuple[str, str, str], Tuple[float, Any, Optional[Dict[str, Any]]]] = {}

    def clear(self) -> None:
        """Forget every answer (a new vault runtime, for example)."""
        self._entries.clear()

    async def rules_row(
        self,
        row: Mapping[str, Any],
        vault_runtime: Any,
        team_row: Callable[[str], Awaitable[Mapping[str, Any]]],
    ) -> Optional[Dict[str, Any]]:
        """The row whose team rules apply to *row*; None where the local rules apply.

        *team_row(slug)* builds that row (see :func:`credential_rules_row`)
        once *row* turns out to connect with team *slug*'s key.

        Raises:
            Exception: the key or the team could not be checked; the caller
                refuses rather than apply no rule.
        """
        if is_shared_row(row) or vault_runtime is None:
            return None
        key = (instance_provider(row), str(row.get("id") or ""), str(row.get("name") or ""))
        generation = getattr(vault_runtime, "binding_generation", None)
        now = self._clock()
        hit = self._entries.get(key)
        if hit is not None and hit[0] > now and hit[1] == generation:
            return dict(hit[2]) if hit[2] is not None else None
        slug = await credential_team_of(row, vault_runtime)
        if slug is None:
            if _vault_unlocked(vault_runtime):
                self._entries[key] = (now + self._ttl, generation, None)
            return None
        rules_row = dict(await team_row(slug))
        self._entries[key] = (now + self._ttl, generation, rules_row)
        return dict(rules_row)


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
    """The guard an agent runs under on one team shared server.

    ``guard`` holds the level, the allowlist and Servonaut's own and the
    local blocked patterns; the team's own patterns are searched here, with
    a time limit (see :meth:`refusal`).
    """

    guard: CommandGuard
    level: str
    team_level: str
    team: str
    # Why the team's rules fell back to readonly (see TeamRules); '' if not.
    fallback_reason: str = ""
    # A team blocklist pattern Servonaut cannot use: every command is refused.
    unusable_pattern: str = ""
    # The patterns the team adds, compiled with ``regex``.
    team_patterns: Tuple[Any, ...] = ()
    # Commands the team allows that the local allowlist leaves out.
    locally_refused: Tuple[str, ...] = ()
    # Seconds checking one command against every team pattern may take.
    pattern_budget: float = field(
        default_factory=lambda: _pattern_budget(MCPConfig().team_pattern_timeout_ms),
    )

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

        The team's patterns are searched in at most :attr:`pattern_budget`
        seconds for the whole command; one that takes longer refuses it.
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
        if self.unusable_pattern:
            return self._message(actor, self._unusable_pattern_refusal(requested_as))
        what = self._command_refusal(command)
        if what is None:
            return None
        if requested_as:
            return self._message(actor, f"{requested_as} is not allowed there")
        return self._message(actor, what)

    def _command_refusal(self, command: str) -> Optional[str]:
        """Why *command* may not run here, worded for a refusal; None if it may.

        At the standard level the command runs as the guard rebuilds it
        from its words, without their quotes, so that form is checked as
        well: quoting part of a word cannot hide it from a blocked pattern.
        """
        shown = _reported(command)
        forms = [command]
        allowed, reason = self.guard.check_command(command)
        if allowed:
            executed = self.guard.command_for_execution(command)
            if executed != command:
                forms.append(executed)
                allowed, reason = self.guard.check_command(executed)
        if not allowed:
            if _NOT_ALLOWLISTED in reason:
                return self._not_allowed(command)
            return f"'{shown}' is refused there: {_command_reason(reason)}"
        reason = self._team_pattern_reason(forms)
        return f"'{shown}' is refused there: {reason}" if reason else None

    def _not_allowed(self, command: str) -> str:
        """Why *command* is not on the allowlist here, and whose list left it out.

        When the team allows it and only the member's own allowlist does
        not, the message says so: the team cannot change that.
        """
        local_only = [
            name for name in dict.fromkeys(standard_command_names(command))
            if name in self.locally_refused
        ]
        if local_only and check_standard_command(command, [*self.guard.allowlist, *local_only])[0]:
            names = ", ".join(f"'{_reported(name)}'" for name in local_only)
            verb, pronoun = ("is", "it") if len(local_only) == 1 else ("are", "them")
            return (
                f"{names} {verb} allowed by the team but not by the command_allowlist "
                f"in your MCP settings; add {pronoun} there to use {pronoun} on this "
                "team's servers"
            )
        return f"'{_reported(command)}' is not an allowed command there"

    def _team_pattern_reason(self, forms: Iterable[str]) -> str:
        """Why the team's patterns refuse a command (its *forms*); '' if none does.

        One time budget covers every pattern and form: a pattern that is
        still searching when it runs out refuses the command.
        """
        deadline = time.monotonic() + self.pattern_budget
        for form in forms:
            for pattern in self.team_patterns:
                remaining = deadline - time.monotonic()
                try:
                    if remaining <= 0:
                        raise TimeoutError
                    matched = pattern.search(form, timeout=remaining)
                except TimeoutError:
                    return (
                        f"the team's blocked pattern '{_reported(pattern.pattern)}' takes "
                        "too long to check (a team owner or admin can change it)"
                    )
                if matched:
                    return f"it matches the blocked pattern {pattern.pattern}"
        return ""

    def describe_level(self) -> str:
        """The level agents run at here and who set it, e.g. ``standard (set by the team)``."""
        text = f"{self.level} ({self._setter()})"
        if self.unusable_pattern:
            text += (
                "; no command can run there because Servonaut cannot use the team's "
                f"blocked pattern '{_reported(self.unusable_pattern)}'"
            )
        return text

    def _unusable_pattern_refusal(self, requested_as: str) -> str:
        what = (
            f"{requested_as} is not allowed there" if requested_as
            else "no command can run there"
        )
        return (
            f"{what} because Servonaut cannot use the team's blocked pattern "
            f"'{_reported(self.unusable_pattern)}' (a team owner or admin can change it)"
        )

    def _setter(self) -> str:
        """Who set the level: the team (or why it fell back), or the local settings."""
        if _level_rank(self.team_level) > _level_rank(self.level):
            return "set by your MCP settings"
        if self.fallback_reason:
            return f"because {self.fallback_reason}"
        return "set by the team"

    def _message(self, actor: str, what: str) -> str:
        team = f"team {self.team}'s" if self.team else _UNNAMED_TEAM
        setter = self._setter()
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
    *,
    pattern_timeout_ms: Any = None,
) -> Optional[TeamGuard]:
    """The guard an agent runs under on *row*; None for the user's own server.

    A team shared server gets the stricter of *local_level* and the level
    the team gives the caller's role (``team_role``) on that server (``id``).
    The allowlist is the team's, less anything the local allowlist leaves
    out; the blocklist is the team's plus the local patterns. A team pattern
    that does not compile refuses every command instead of breaking the
    guard. *pattern_timeout_ms* (``mcp.team_pattern_timeout_ms``) limits how
    long the team's patterns may take on one command. The local settings are
    read, never changed.
    """
    if not is_shared_row(row):
        return None
    rules = rules or rules_for(row)
    team_level = rules.level_for_server(row.get("id"), row.get("team_role"))
    local = set(local_allowlist)
    allowlist = [command for command in rules.command_allowlist if command in local]
    # Servonaut's own patterns stay on the guard; the team's are searched
    # with a time limit (TeamGuard.refusal).
    builtin = set(_builtin_blocklist())
    blocklist = [pattern for pattern in rules.command_blocklist if pattern in builtin]
    team_patterns = [pattern for pattern in rules.command_blocklist if pattern not in builtin]
    unusable = _unusable_patterns(team_patterns)
    if unusable:
        blocklist.append(_MATCH_EVERY_COMMAND)
    blocklist += [pattern for pattern in local_blocklist if pattern not in blocklist]
    level = stricter(local_level, team_level)
    guard = CommandGuard(MCPConfig(
        guard_level=level, command_allowlist=allowlist, command_blocklist=blocklist,
    ))
    return TeamGuard(
        guard=guard, level=level, team_level=team_level, team=_team_label(row),
        fallback_reason=rules.fallback_reason,
        unusable_pattern=unusable[0] if unusable else "",
        team_patterns=() if unusable else tuple(regex.compile(p) for p in team_patterns),
        locally_refused=tuple(
            command for command in rules.command_allowlist if command not in local
        ),
        pattern_budget=_pattern_budget(pattern_timeout_ms),
    )


def guard_for_target_from(
    row: Mapping[str, Any], local_guard: CommandGuard, rules: Optional[TeamRules] = None,
    *, pattern_timeout_ms: Any = None,
) -> Optional[TeamGuard]:
    """:func:`guard_for_target` with the local settings of *local_guard*."""
    if not is_shared_row(row):
        return None
    return guard_for_target(
        row, local_guard.level, local_guard.allowlist, local_guard.blocklist, rules,
        pattern_timeout_ms=pattern_timeout_ms,
    )
