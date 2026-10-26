"""Team shared servers as rows of the server list.

The servers a team shares are listed beside the user's own servers: in the
TUI's server list, in the MCP ``list_instances`` tool and for
``servonaut ssh``. Every row carries ``is_shared=True`` and ``team_slug``,
the keys the connection paths (team vault keys, SSH certificates, team
Bitwarden references) already read, plus the plain fields the rest of the
app reads for any server: ``name``, ``public_ip`` (the shared hostname)
and ``port``. The team's ``login_user`` is the login its vault key or SSH
certificate uses (the key names it itself); with the user's own key the
user's own login applies (see :func:`shared_login`). ``team_role`` is the
signed-in user's role in the team, which decides what their agents may do
there (see ``team_rules``).

A shared server that is also one of the user's own servers is listed once:
the user's own row, marked as shared (see :func:`fold_shared`). The user's
own access wins because it is theirs; the mark says the team has it too.
Without a key of their own for it, the team's access is used instead (see
:func:`team_key_fallback`).
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


def team_id_text(team: Mapping[str, Any]) -> str:
    """The id of *team* (a team-list row) as text; '' when it has none."""
    value = team.get("id")
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    return value if isinstance(value, str) else ""


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
    # Only this client marks a row with a team's key (see with_team_key):
    # a record from the team list never carries one.
    row.pop(TEAM_KEY_ROW, None)
    host = str(
        server.get("hostname") or server.get("public_ip") or server.get("host") or ""
    ).strip()
    # Only a login the share names for any key: ``login_user`` belongs to
    # the team's own key and stays on the row as it came.
    login = server.get("username")
    label = team_label(team)
    slug = team.get("slug") if isinstance(team.get("slug"), str) else ""
    role = team.get("role") if isinstance(team.get("role"), str) else ""
    row.update(
        {
            "id": str(server.get("id") or ""),
            "name": str(server.get("name") or host),
            # The team list says nothing about the machine's size; the
            # state column already says "shared".
            "type": "",
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
            # The team's agent rules are found by its id: a slug can pass to
            # another team after a rename. '' when the team list did not say.
            "team_id": team_id_text(team),
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
    ``is_shared``, ``team_slug``, ``team_id``, ``team_name`` and
    ``team_role`` added;
    this fills the plain fields the connection paths read (the host above
    all). A row is returned as is.
    """
    if target.get("is_shared") is True and target.get("state") == SHARED_STATE:
        row = dict(target)
        row.pop(TEAM_KEY_ROW, None)
        return row
    team = {
        "id": target.get("team_id"),
        "slug": target.get("team_slug") or "",
        "name": target.get("team_name") or "",
        "role": target.get("team_role") or "",
    }
    return shared_row(target, team)


def shared_login(row: Mapping[str, Any], profile: Any, default_username: str) -> str:
    """The login for a team's shared server with the user's own key: a
    matching connection rule's, else the login the share names, else the
    configured default (the user's own access to the server).

    A team vault key or SSH certificate names its own login (the team's
    ``login_user``) and replaces this one when the session starts.
    """
    rule_login = getattr(profile, "username", None) if profile is not None else None
    return rule_login or str(row.get("username") or "") or default_username


def _own_port(row: Mapping[str, Any]) -> int:
    return _port(row.get("port"))


def _public_address(row: Mapping[str, Any]) -> Tuple[str, int]:
    return str(row.get("public_ip") or "").strip().lower(), _own_port(row)


def is_same_server(shared: Mapping[str, Any], own: Mapping[str, Any]) -> bool:
    """Whether the *shared* row is the user's own row *own* (see :func:`fold_shared`)."""
    recorded = str(shared.get("instance_id") or "")
    if recorded and recorded == str(own.get("id") or ""):
        return True
    address = _public_address(own)
    return bool(address[0]) and _public_address(shared) == address


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
        address = _public_address(row)
        if address[0]:
            by_address.setdefault(address, row)

    shared_by: Dict[int, List[str]] = {}
    listed: List[Dict[str, Any]] = []
    for row in rows:
        if not is_shared_row(row):
            listed.append(row)
            continue
        recorded = str(row.get("instance_id") or "")
        owner = (by_id.get(recorded) if recorded else None) or by_address.get(_public_address(row))
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


# Binding source of a team vault key (the same value ``ssh_credentials`` reads).
_VAULT_SOURCE = "servonaut_vault"
# The team row a user's own server is marked with when it connects with that
# team's key (see :func:`with_team_key`). A marked row only lives for one
# lookup: it is never cached or listed.
TEAM_KEY_ROW = "team_key_row"


def has_team_access(row: Mapping[str, Any]) -> bool:
    """Whether the team's row *row* brings the team's own SSH access: a team
    vault key (its signed ``credential_binding``) or an SSH certificate for
    an enrolled host."""
    binding = row.get("credential_binding")
    if isinstance(binding, Mapping) and binding.get("source") == _VAULT_SOURCE:
        return True
    ca = row.get("ssh_ca")
    return isinstance(ca, Mapping) and ca.get("enrolled") is True


def lacks_own_key(own: Mapping[str, Any], key_path: Any) -> bool:
    """Whether the user's own server *own* names a cloud key pair
    (``key_name``) they have no key for here (*key_path*, the local key its
    connection resolved, is empty).

    Such a server may connect with a team's key (:func:`team_key_fallback`).
    A server without a key pair keeps the user's own SSH setup (an agent or
    the default keys, which ssh tries by itself), and so does every server
    the user has a key for. A custom server's ``key_name`` is its key file,
    not a key pair: custom servers keep their own setup too.
    """
    return not (
        is_shared_row(own) or own.get("is_custom") is True or key_path
        or not str(own.get("key_name") or "").strip()
    )


def team_key_fallback(
    own: Mapping[str, Any], rows: Iterable[Mapping[str, Any]], key_path: Any,
) -> Optional[Dict[str, Any]]:
    """The team row whose key the user's own server *own* connects with, or None.

    A server the user lists as their own (from their own cloud account) and
    a team also shares is listed once, as their own (see :func:`fold_shared`).
    When the user has no key of their own for it (:func:`lacks_own_key`), it
    connects with the team's vault key or SSH certificate instead: the first
    row in *rows* that shares the same server with that access.
    """
    if not lacks_own_key(own, key_path):
        return None
    for row in rows:
        if (
            isinstance(row, Mapping) and is_shared_row(row)
            and has_team_access(row) and is_same_server(row, own)
        ):
            return dict(row)
    return None


def with_team_key(own: Mapping[str, Any], team: Mapping[str, Any]) -> Dict[str, Any]:
    """*own* marked to connect with *team*'s key (see :func:`team_key_target`)."""
    return {**own, TEAM_KEY_ROW: dict(team)}


def team_key_target(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """The team row :func:`with_team_key` marked *row* with, else None.

    Only a server of the user's own is ever marked: on a team's row the key
    is ignored, so data from elsewhere cannot point it at another team.
    """
    if is_shared_row(row):
        return None
    team = row.get(TEAM_KEY_ROW)
    return dict(team) if isinstance(team, Mapping) and is_shared_row(team) else None


def row_team_label(row: Mapping[str, Any]) -> str:
    """The name to show for the team of the shared *row*: its name, else its slug."""
    return str(row.get("team_name") or row.get("team_slug") or "").strip()


@dataclass
class SharedServers:
    """What :func:`load_shared_servers` found."""

    rows: List[Dict[str, Any]] = field(default_factory=list)
    teams: List[Dict[str, Any]] = field(default_factory=list)
    # One line per team whose servers could not be read.
    problems: List[str] = field(default_factory=list)
    # The slugs of the teams whose servers were read (their rows are all here).
    read: List[str] = field(default_factory=list)


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
        found.read.append(slug)
    return found
