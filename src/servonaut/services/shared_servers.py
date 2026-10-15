"""Team shared servers as rows of the server list.

The servers a team shares are listed beside the user's own servers: in the
TUI's server list, in the MCP ``list_instances`` tool and for
``servonaut ssh``. Every row carries ``is_shared=True`` and ``team_slug``,
the keys the connection paths (team vault keys, SSH certificates, team
Bitwarden references) already read, plus the plain fields the rest of the
app reads for any server: ``name``, ``public_ip`` (the shared hostname),
``username`` and ``port``. ``team_role`` is the signed-in user's role in the
team, which decides what their agents may do there (see ``team_rules``).

A shared server that is also one of the user's own servers is listed once:
the user's own row, marked as shared (see :func:`fold_shared`). The user's
own access wins because it is theirs; the mark says the team has it too.
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# The fleet slice the shared rows form (see ``_demo_resolve.row_source``).
SHARED = "shared"
# A shared row's state: the team list says nothing about power state.
SHARED_STATE = "shared"
_DEFAULT_SSH_PORT = 22


def is_shared_row(row: Mapping[str, Any]) -> bool:
    """Whether *row* is a team shared server."""
    return row.get("is_shared") is True


def team_label(team: Mapping[str, Any]) -> str:
    """The name to show for *team*: its name, else its slug."""
    for key in ("name", "slug"):
        value = team.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        return _DEFAULT_SSH_PORT
    return value


def shared_row(server: Mapping[str, Any], team: Mapping[str, Any]) -> Dict[str, Any]:
    """One server-list row for a server *team* shares.

    The team's record is kept whole (its signed ``credential_binding`` and
    ``ssh_ca`` state drive the connection), with the plain server fields
    filled in from it.
    """
    row: Dict[str, Any] = copy.deepcopy(dict(server))
    host = str(
        server.get("hostname") or server.get("public_ip") or server.get("host") or ""
    ).strip()
    login = server.get("login_user") or server.get("username")
    label = team_label(team)
    slug = team.get("slug") if isinstance(team.get("slug"), str) else ""
    role = team.get("role") if isinstance(team.get("role"), str) else ""
    row.update(
        {
            "id": str(server.get("id") or ""),
            "name": str(server.get("name") or host),
            "type": "shared",
            "state": SHARED_STATE,
            # Like a custom server, the host stands in for both addresses:
            # a connection rule with a bastion reaches it the same way.
            "public_ip": host,
            "private_ip": host,
            "region": str(server.get("region") or ""),
            "provider": f"Team {label}" if label else "Team",
            "username": login if isinstance(login, str) else "",
            "port": _port(server.get("port")),
            "key_name": "",
            "is_shared": True,
            "team_slug": slug,
            "team_name": label,
            # "" when the team list did not say: agents then get the
            # strictest level there.
            "team_role": role.strip().lower(),
        }
    )
    return row


def as_shared_row(target: Mapping[str, Any]) -> Dict[str, Any]:
    """A shared server record that names its team (``team_slug``) as a row.

    The vault's shared-target lookup returns the team's record with
    ``is_shared``, ``team_slug``, ``team_name`` and ``team_role`` added;
    this fills the plain fields the connection paths read (the host above
    all). A row is returned as is.
    """
    if target.get("type") == "shared" and "public_ip" in target:
        return dict(target)
    team = {
        "slug": target.get("team_slug") or "",
        "name": target.get("team_name") or "",
        "role": target.get("team_role") or "",
    }
    return shared_row(target, team)


def _own_port(row: Mapping[str, Any]) -> int:
    return _port(row.get("port"))


def fold_shared(
    rows: Sequence[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[int, List[str]]]:
    """*rows* without the shared servers that are also the user's own.

    A shared row is the user's own server when its recorded ``instance_id``
    is an own row's id, or its host and port are an own row's public
    address and port. Private addresses are never compared: the same private
    address exists in many networks.

    Returns the rows to list, in order, and the names of the teams sharing
    each own row that absorbed a shared one, keyed by ``id()`` of that row.
    """
    own = [row for row in rows if not is_shared_row(row)]
    by_id: Dict[str, Dict[str, Any]] = {}
    by_address: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for row in own:
        row_id = str(row.get("id") or "")
        if row_id:
            by_id.setdefault(row_id, row)
        address = str(row.get("public_ip") or "").strip().lower()
        if address:
            by_address.setdefault((address, _own_port(row)), row)

    shared_by: Dict[int, List[str]] = {}
    listed: List[Dict[str, Any]] = []
    for row in rows:
        if not is_shared_row(row):
            listed.append(row)
            continue
        recorded = str(row.get("instance_id") or "")
        address = (str(row.get("public_ip") or "").strip().lower(), _own_port(row))
        owner = (by_id.get(recorded) if recorded else None) or by_address.get(address)
        if owner is None:
            listed.append(row)
            continue
        teams = shared_by.setdefault(id(owner), [])
        label = str(row.get("team_name") or row.get("team_slug") or "")
        if label and label not in teams:
            teams.append(label)
    return listed, shared_by


def fold_shared_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """:func:`fold_shared`'s rows only."""
    return fold_shared(rows)[0]


@dataclass
class SharedServers:
    """What :func:`load_shared_servers` found."""

    rows: List[Dict[str, Any]] = field(default_factory=list)
    teams: List[Dict[str, Any]] = field(default_factory=list)
    # One line per team whose servers could not be read.
    problems: List[str] = field(default_factory=list)


async def load_shared_servers(
    team_service: Any, teams: Optional[Iterable[Mapping[str, Any]]] = None,
) -> SharedServers:
    """The shared servers of every team the signed-in user belongs to.

    *teams* skips the team lookup when the caller already has the list. A
    team whose servers cannot be read is skipped, with a line in
    ``problems``: the other teams' servers still list.

    Raises:
        Exception: the team list itself could not be read (not signed in,
            no network); the caller decides how loudly to say so.
    """
    if teams is None:
        teams = await team_service.list_teams()
    found = SharedServers(teams=[dict(team) for team in teams or [] if isinstance(team, Mapping)])
    for team in found.teams:
        slug = team.get("slug")
        if not isinstance(slug, str) or not slug:
            continue
        try:
            servers = await team_service.list_shared_servers(slug)
        except Exception as exc:  # noqa: BLE001 — another team may still load
            logger.warning("Could not load shared servers for team %s: %s", slug, exc)
            found.problems.append(f"team {team_label(team) or slug}: {exc}")
            continue
        found.rows.extend(
            shared_row(server, team) for server in servers or [] if isinstance(server, Mapping)
        )
    return found
