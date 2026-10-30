"""Pure helpers for sharing an inventory without sharing it twice."""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

# The address a share form chose for a server (see share_address).
SHARE_ADDRESS = "share_address"


def server_address(server: Mapping[str, Any]) -> str:
    """The destination offered by a local server, or saved with a shared one."""
    return str(server.get("hostname") or server.get("host") or server.get("public_ip") or server.get("private_ip") or "")


def address_choices(server: Mapping[str, Any]) -> tuple[str, str]:
    """``(public, private)`` for a server of your own with two different addresses, else ``("", "")``.

    A server that names its host, and a team's server, have one address.
    """
    if server.get("is_shared") is True or server.get("hostname") or server.get("host"):
        return "", ""
    public = str(server.get("public_ip") or "").strip()
    private = str(server.get("private_ip") or "").strip()
    return (public, private) if public and private and public != private else ("", "")


def share_address(server: Mapping[str, Any]) -> str:
    """The address *server* is shared under: the one chosen for it, else :func:`server_address`."""
    return str(server.get(SHARE_ADDRESS) or "").strip() or server_address(server)


def _host_key(server: Mapping[str, Any]) -> str:
    host = server_address(server).strip().strip("[]").rstrip(".").casefold()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


def _destination(server: Mapping[str, Any]) -> tuple[str, object]:
    port = server.get("port") or 22
    return _host_key(server), str(port)


def _public_address(server: Mapping[str, Any]) -> bool:
    host = _host_key(server)
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return bool(host)


def _same_server(candidate: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    source_id = str(candidate.get("instance_id") or candidate.get("id") or "")
    shared_id = str(row.get("instance_id") or "")
    same_destination = bool(_host_key(candidate)) and _destination(candidate) == _destination(row)
    if source_id and source_id == shared_id:
        # Custom ids come from a local name, not a provider's stable identity.
        return same_destination if source_id.startswith("custom-") else True
    return same_destination and (_public_address(candidate) or not shared_id)


def already_shared(candidate: Mapping[str, Any], shared: Sequence[Mapping[str, Any]]) -> bool:
    """Match stable provider ids or unambiguous addresses, without crossing private networks."""
    return any(_same_server(candidate, row) for row in shared)


def _custom_server_row(server: Any) -> dict[str, Any]:
    """A custom server (its config entry, or the dict a team config carries) as the row sharing compares."""
    def field(key: str) -> Any:
        return server.get(key) if isinstance(server, Mapping) else getattr(server, key, None)

    name, host = str(field("name") or ""), str(field("host") or "")
    # The id and addresses CustomServerService gives the server's row.
    return {"id": f"custom-{name}", "name": name, "public_ip": host, "private_ip": host,
            "port": field("port") or 22, "username": str(field("username") or ""), "is_custom": True}


def _shares_custom_server(shared: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    """Whether the team's *shared* server is the custom server *row*, not just its address.

    Several logins on one machine share an address, so a share is this server
    when it records the server's id, or (recording none) names its login.
    """
    if not _host_key(row) or _destination(row) != _destination(shared):
        return False
    recorded = str(shared.get("instance_id") or "")
    if recorded:
        return recorded == row["id"]
    login = str(shared.get("username") or "")
    return not login or login == row["username"]


def shared_custom_servers(servers: Iterable[Any], shared: Sequence[Mapping[str, Any]]) -> list[str]:
    """Names of the custom *servers* that one of a team's *shared* servers is, in order."""
    rows = [_custom_server_row(server) for server in servers]
    return [
        row["name"] for row in rows
        if row["name"] and any(_shares_custom_server(team, row) for team in shared)
    ]


def share_candidates(
    instances: Sequence[Mapping[str, Any]], shared: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], int, int]:
    """Only own, addressed, distinct servers; counts explain the omitted ones."""
    offered: list[dict[str, Any]] = []
    omitted: list[dict[str, Any]] = []
    known = list(shared)
    missing = 0
    for instance in instances:
        if instance.get("is_shared") is True or already_shared(instance, known):
            if not already_shared(instance, omitted):
                omitted.append({**instance, "instance_id": instance.get("instance_id") or instance.get("id")})
            continue
        if not server_address(instance):
            missing += 1
        else:
            offered.append(dict(instance))
            known.append({**instance, "instance_id": instance.get("id")})
    return offered, len(omitted), missing


def share_payload(instance: Mapping[str, Any]) -> dict[str, Any]:
    """Public connection fields only: no local key paths, credentials or flags."""
    payload: dict[str, Any] = {
        "name": instance.get("name") or instance.get("id") or "",
        "hostname": share_address(instance),
    }
    for source, target in (("id", "instance_id"), ("region", "region"), ("username", "username")):
        if instance.get(source):
            payload[target] = instance[source]
    if instance.get("port") and instance["port"] != 22:
        payload["port"] = instance["port"]
    return payload
