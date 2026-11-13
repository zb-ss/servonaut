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
    options = commands.add_parser(
        "options",
        help="List the SSH options from a team that run programs here, and allow or refuse them.",
    )
    actions = options.add_subparsers(dest="options_action")
    allow = actions.add_parser("allow", help="Allow one option by its number, or all of them.")
    allow.add_argument("number", nargs="?", type=int, help="The option's number in the list.")
    allow.add_argument("--all", action="store_true", help="Allow every listed option.")
    refuse = actions.add_parser("refuse", help="Refuse one option by its number.")
    refuse.add_argument("number", type=int, help="The option's number in the list.")


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


_EXIT_USAGE = 2


def _handle_options(args: argparse.Namespace) -> int:
    """``servonaut team options [allow N|--all | refuse N]``."""
    import dataclasses

    from servonaut.config.manager import ConfigManager
    from servonaut.utils.ssh_option_policy import origin_label, set_allowed, team_option_rows

    manager = ConfigManager()
    config = manager.load()
    items = team_option_rows(config.ssh.team_options)
    action = getattr(args, "options_action", None)

    if action is None:
        if not items:
            print("No team options need your approval.")
            return _EXIT_OK
        print("Team options that run programs on this computer\n")
        width = max(len(origin_label(item)) for item in items)
        for number, item in enumerate(items, 1):
            state = "allowed" if item.get("allowed") is True else "refused"
            print(f"  {number}  {state}  {origin_label(item).ljust(width)}  {terminal_safe(item['option'])}")
        print("\nAllow one: servonaut team options allow 1")
        return _EXIT_OK

    if action == "allow" and args.all:
        chosen = list(range(len(items)))
    else:
        number = getattr(args, "number", None)
        if number is None or not 1 <= number <= len(items):
            label = "" if number is None else f" {number}"
            print(
                f'No option{label}. Run "servonaut team options" to see the list.',
                file=sys.stderr,
            )
            return _EXIT_USAGE
        chosen = [number - 1]

    allowed = action == "allow"
    options = [dict(item) for item in config.ssh.team_options if isinstance(item, dict)]
    texts = [items[index]["option"] for index in chosen]
    for text in texts:
        set_allowed(options, text, allowed)
    manager.update(ssh=dataclasses.replace(config.ssh, team_options=options))
    for text in texts:
        print(
            f"Allowed: {terminal_safe(text)}. Connections that use it will run it on this computer."
            if allowed else f"Refused: {terminal_safe(text)}."
        )
    return _EXIT_OK


def handle_team_command(args: argparse.Namespace) -> int:
    if args.team_command == "options":
        return _handle_options(args)
    if args.team_command != "rules":
        print(f"Unknown team command: {args.team_command}", file=sys.stderr)
        return _EXIT_ERROR
    view = asyncio.run(_rules_view(args))
    if view is None:
        return _EXIT_ERROR
    _print_view(view, bool(args.json))
    return _EXIT_OK
