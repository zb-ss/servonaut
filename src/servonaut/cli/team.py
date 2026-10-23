"""``servonaut team``: what a team's members' agents may do on its shared servers.

``servonaut team rules TEAM [--json]`` fetches the team's signed agent rules,
checks them as every agent surface does, and shows what applies on this
device now: the level of each role, per-server levels, the command lists,
or the readonly fallback and why. Read-only: owners and admins edit the rules
on the website.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Any, Callable, Dict, List, Mapping, Optional

from servonaut.services.vault.display import terminal_safe

logger = logging.getLogger(__name__)

_EXIT_OK = 0
_EXIT_ERROR = 1
_SIGN_IN = "Sign in first: servonaut login"

TeamServiceFactory = Callable[[], Any]
_service_factory: Optional[TeamServiceFactory] = None


def set_team_service_factory(factory: Optional[TeamServiceFactory]) -> None:
    """Use *factory* for the team service (None: the signed-in session's)."""
    global _service_factory
    _service_factory = factory


def add_team_parser(subparsers: Any) -> None:
    team = subparsers.add_parser("team", help="Show what your teams let agents do on their servers.")
    commands = team.add_subparsers(dest="team_command")
    commands.required = True
    rules = commands.add_parser(
        "rules",
        help="Show the agent rules that apply on a team's shared servers now (read-only).",
    )
    rules.add_argument("team", help="The team's slug or name.")
    rules.add_argument("--json", action="store_true", help="Print the rules as JSON.")


def _default_team_service() -> Any:
    """The signed-in session's team service; None when signed out."""
    # Loads the secrets file, which can point the CLI at another API.
    from servonaut.config.manager import ConfigManager
    from servonaut.services.auth_service import AuthService

    ConfigManager()
    auth_service = AuthService()
    if not auth_service.is_authenticated:
        return None
    from servonaut.services.api_client import APIClient
    from servonaut.services.team_service import TeamService

    return TeamService(APIClient(auth_service))


def _find_team(teams: Any, wanted: str) -> Optional[Dict[str, Any]]:
    """The team-list row whose slug, else name, is *wanted* (any case)."""
    rows = [dict(team) for team in teams or [] if isinstance(team, Mapping)]
    key = wanted.strip().lower()
    for field in ("slug", "name"):
        for row in rows:
            value = row.get(field)
            if isinstance(value, str) and value.strip().lower() == key:
                return row
    return None


async def _team_servers(team_service: Any, slug: str) -> List[Mapping[str, Any]]:
    """The team's shared servers, which name its per-server levels; [] if unreadable."""
    try:
        servers = await team_service.list_shared_servers(slug)
    except Exception as exc:  # noqa: BLE001 — the rules still show, only unnamed
        logger.info("Shared servers of team %s not read (%s)", slug, type(exc).__name__)
        print(
            "The team's shared servers could not be read: per-server levels are left out.",
            file=sys.stderr,
        )
        return []
    return [server for server in servers or [] if isinstance(server, Mapping)]


async def _rules_view(args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    """The team's agent rules as :func:`agent_rules_view` data; None after saying why not."""
    from servonaut.services.shared_servers import team_id_text
    from servonaut.services.team_policy import team_policy_store
    from servonaut.services.team_policy_refresh import TeamPolicyRefresher
    from servonaut.services.team_rules_view import agent_rules_view

    team_service = (_service_factory or _default_team_service)()
    if team_service is None:
        print(_SIGN_IN, file=sys.stderr)
        return None
    try:
        teams = await team_service.list_teams()
    except Exception as exc:  # noqa: BLE001 — offline, signed out on the server, no team plan
        print(f"Your teams could not be read ({type(exc).__name__}).", file=sys.stderr)
        return None
    team = _find_team(teams, args.team)
    if team is None:
        print(f"You are not in a team called {terminal_safe(args.team)}.", file=sys.stderr)
        return None
    slug = str(team.get("slug") or "")
    refresher = TeamPolicyRefresher(team_policy_store(), lambda: team_service)
    refresher.load()
    await refresher.refresh([team])
    servers = await _team_servers(team_service, slug)
    status = refresher.store.status(slug, team_id_text(team) or None)
    return agent_rules_view(slug, status, servers, team.get("role"))


def _print_view(view: Mapping[str, Any], as_json: bool) -> None:
    from servonaut.services.team_rules_view import TITLE, agent_rules_lines

    if as_json:
        print(json.dumps(view, indent=2, sort_keys=True))
        return
    print(f"{TITLE} (team {terminal_safe(view['team'])})")
    for line in agent_rules_lines(view):
        print(terminal_safe(line))


def handle_team_command(args: argparse.Namespace) -> int:
    if args.team_command != "rules":
        print(f"Unknown team command: {args.team_command}", file=sys.stderr)
        return _EXIT_ERROR
    view = asyncio.run(_rules_view(args))
    if view is None:
        return _EXIT_ERROR
    _print_view(view, bool(args.json))
    return _EXIT_OK
