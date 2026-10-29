"""Pure helpers for sharing an inventory without sharing it twice."""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any


def server_address(server: Mapping[str, Any]) -> str:
    """The destination offered by a local server, or saved with a shared one."""
    return str(server.get("hostname") or server.get("host") or server.get("public_ip") or server.get("private_ip") or "")


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
        "hostname": server_address(instance),
    }
    for source, target in (("id", "instance_id"), ("region", "region"), ("username", "username")):
        if instance.get(source):
            payload[target] = instance[source]
    if instance.get("port") and instance["port"] != 22:
        payload["port"] = instance["port"]
    return payload
