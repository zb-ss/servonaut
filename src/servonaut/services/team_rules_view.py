"""A team's agent rules as people read them: the Teams screen and the CLI.

Read-only: owners and admins edit the rules on the website. What is shown is
what applies now on this device (``team_policy``): the verified rules, or the
readonly fallback and its reason. A member's own MCP settings can still make
any of it stricter, never looser.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

from servonaut.services.team_policy import NOT_LOADED, TeamPolicyStatus
from servonaut.services.team_rules import DEFAULT_TEAM_RULES, TEAM_ROLES, TeamRules

TITLE = "What agents may do here"
BUILTIN_COMMANDS = "Servonaut's built-in list"
_STRICTER_NOTE = "Your own MCP settings can only make these stricter."
_TIME_FORMAT = "%Y-%m-%d %H:%M UTC"
_JSON_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utc_text(moment: Optional[datetime]) -> Optional[str]:
    if moment is None:
        return None
    return moment.astimezone(timezone.utc).strftime(_JSON_TIME_FORMAT)


def _epoch_text(epoch: Optional[float]) -> Optional[str]:
    if epoch is None:
        return None
    return _utc_text(datetime.fromtimestamp(epoch, tz=timezone.utc))


def _server_names(servers: Iterable[Mapping[str, Any]]) -> Dict[str, str]:
    names: Dict[str, str] = {}
    for server in servers:
        server_id = str(server.get("id") or "")
        if server_id:
            names[server_id] = str(server.get("name") or server.get("hostname") or server_id)
    return names


def _role(role: Any) -> str:
    return role.strip().lower() if isinstance(role, str) else ""


def agent_rules_view(
    slug: str,
    status: Optional[TeamPolicyStatus],
    servers: Iterable[Mapping[str, Any]] = (),
    role: Any = "",
) -> Dict[str, Any]:
    """What applies on team *slug*'s shared servers, as plain data (JSON-ready).

    *status* is the team's ``TeamPolicyStore.status`` (None: never fetched);
    *servers* are the team's shared servers (``id`` and ``name``), which name
    the per-server levels: a level set for a server the team does not list
    is left out. *role* is the signed-in user's role in the team.
    """
    rules: TeamRules = status.rules if status is not None else TeamRules.readonly(NOT_LOADED.reason)
    problem = status.problem if status is not None else NOT_LOADED
    names = _server_names(servers)
    role_key = _role(role)
    allowlist = rules.command_allowlist
    builtin_blocklist = set(DEFAULT_TEAM_RULES.command_blocklist)
    return {
        "team": slug,
        "team_id": status.team_id if status is not None else None,
        "in_force": problem is None,
        "problem": problem.code if problem is not None else None,
        "fallback_reason": rules.fallback_reason or None,
        "version": status.version if status is not None else None,
        "expires_at": _utc_text(status.expires_at) if status is not None else None,
        "last_refreshed": _epoch_text(status.fetched_at) if status is not None else None,
        "your_role": role_key or None,
        "your_level": rules.level_for(role_key),
        "role_levels": {name: rules.level_for(name) for name in TEAM_ROLES},
        "servers": [
            {"id": server_id, "name": names[server_id], "role_levels": dict(levels)}
            for server_id, levels in rules.servers.items() if server_id in names
        ],
        "command_allowlist": (
            None if allowlist == DEFAULT_TEAM_RULES.command_allowlist else list(allowlist)
        ),
        "command_blocklist": [
            pattern for pattern in rules.command_blocklist if pattern not in builtin_blocklist
        ],
        "unusable_pattern": rules.unusable_pattern() or None,
    }


def _shown_time(text: str) -> str:
    """A :func:`_utc_text` time as people read it."""
    return datetime.strptime(text, _JSON_TIME_FORMAT).strftime(_TIME_FORMAT)


def _time_line(view: Mapping[str, Any]) -> str:
    parts = []
    if view["version"] is not None:
        parts.append(f"Version {view['version']}")
    refreshed = view["last_refreshed"]
    parts.append(f"last refreshed {_shown_time(refreshed)}" if refreshed else "not fetched yet")
    if view["in_force"] and view["expires_at"]:
        parts.append(f"valid until {_shown_time(view['expires_at'])}")
    return " · ".join(parts)


def _levels_text(levels: Mapping[str, str]) -> str:
    return ", ".join(f"{role.title()} {level}" for role, level in levels.items())


def agent_rules_lines(view: Mapping[str, Any]) -> List[str]:
    """*view* (:func:`agent_rules_view`) in plain lines, without the title.

    The lines hold team-controlled text (server names, patterns, commands):
    escape them before putting them into markup.
    """
    if not view["in_force"]:
        return [
            "Agents run at the readonly level on this team's shared servers, "
            f"owners included, because {view['fallback_reason']}.",
            _time_line(view),
        ]
    levels = view["role_levels"]
    lines = [
        f"Agents on this team's shared servers run at these levels. {_STRICTER_NOTE}",
        " · ".join(f"{role.title()}: {level}" for role, level in levels.items()),
    ]
    if view["your_role"]:
        lines.append(f"Your role: {view['your_role']} ({view['your_level']})")
    if view["servers"]:
        lines.append("Per server:")
        lines.extend(
            f"  {server['name']}: {_levels_text(server['role_levels'])}"
            for server in view["servers"]
        )
    allowlist = view["command_allowlist"]
    lines.append(
        "Allowed commands at the standard level: "
        + (BUILTIN_COMMANDS if allowlist is None else (", ".join(allowlist) or "none"))
    )
    blocklist = view["command_blocklist"]
    lines.append(
        "Blocked patterns the team adds to Servonaut's own: "
        + (", ".join(blocklist) if blocklist else "none")
    )
    if view["unusable_pattern"]:
        lines.append(
            "No command can run on this team's servers: Servonaut cannot use the "
            f"team's blocked pattern '{view['unusable_pattern']}'. A team owner or "
            "admin can change it."
        )
    lines.append(_time_line(view))
    return lines
