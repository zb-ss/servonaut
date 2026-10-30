"""Apply a pulled team-config payload over the local :class:`AppConfig`.

Apply semantics are REPLACE-WHOLE-SECTION for v1 — the team's section
overwrites the local one in its entirety. This is the simplest model that
makes the feature useful (admin pushes a baseline → members pull → they
have it). Selective per-item import is the v2 release. One exception: a
custom server the team also shares is not added (see
:func:`apply_team_config`).

Key paths are the other exception: a push never carries them (they name files
on the sender's computer), so a pulled profile's ``bastion_key`` and a pulled
custom server's ``ssh_key`` are blank. The member's own path for the entry of
the same name, still pointing at the same bastion or host, is kept
(:func:`local_key_paths`).

After application, the caller is responsible for invoking
:meth:`ConfigManager.save` so the change persists; the helper here only
mutates the in-memory dataclass instance so it stays testable without a
filesystem dependency.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Mapping, NamedTuple, Sequence

if TYPE_CHECKING:
    from servonaut.config.schema import AppConfig

logger = logging.getLogger(__name__)


class AppliedTeamConfig(NamedTuple):
    """What a pull did beyond replacing the four sections."""

    skipped_custom_servers: List[str]
    kept_key_paths: int


def apply_team_config(
    local: "AppConfig", remote_payload: dict, *, shared_servers: Sequence[Mapping[str, Any]] = (),
) -> AppliedTeamConfig:
    """Replace the four shareable sections on ``local`` with ``remote_payload``'s.

    A pulled custom server that one of the team's *shared_servers* also is,
    is left out: as the user's own server it would hide the team's row and
    connect without the team's key. Returns the names of those left out and
    how many of the user's own key paths were kept (:func:`local_key_paths`).

    The four sections (in order applied):

    * ``connection_profiles`` → :class:`ConnectionProfile`
    * ``connection_rules``    → :class:`ConnectionRule`
    * ``scan_rules``          → :class:`ScanRule`
    * ``custom_servers``      → :class:`CustomServer`

    Each remote dict is rehydrated into its dataclass. Unknown keys on the
    remote (e.g. a future-version field this CLI doesn't yet understand) are
    silently dropped — the rehydration filters to known fields per the
    dataclass signature so we forward-compat gracefully.
    """
    from servonaut.config.schema import (
        ConnectionProfile,
        ConnectionRule,
        CustomServer,
        ScanRule,
    )

    servers, skipped = team_custom_servers(remote_payload, shared_servers)
    kept = local_key_paths(local, {**remote_payload, "custom_servers": servers})
    local.connection_profiles = _rehydrate_list(
        remote_payload.get("connection_profiles", []), ConnectionProfile
    )
    local.connection_rules = _rehydrate_list(
        remote_payload.get("connection_rules", []), ConnectionRule
    )
    local.scan_rules = _rehydrate_list(
        remote_payload.get("scan_rules", []), ScanRule
    )
    local.custom_servers = _rehydrate_list(servers, CustomServer)
    for profile in local.connection_profiles:
        if profile.name in kept["bastion_key"]:
            profile.bastion_key = kept["bastion_key"][profile.name]
    for server in local.custom_servers:
        if server.name in kept["ssh_key"]:
            server.ssh_key = kept["ssh_key"][server.name]
    return AppliedTeamConfig(skipped, len(kept["bastion_key"]) + len(kept["ssh_key"]))


def team_custom_servers(
    remote_payload: dict, shared_servers: Sequence[Mapping[str, Any]],
) -> tuple[List[Any], List[str]]:
    """The pulled custom servers to add, and the names of those the team already shares."""
    from servonaut.services.team_sharing import shared_custom_servers

    servers = list(remote_payload.get("custom_servers", []) or [])
    entries = [server for server in servers if isinstance(server, dict)]
    skipped = shared_custom_servers(entries, shared_servers)
    kept = [server for server in servers if not (isinstance(server, dict) and server.get("name") in skipped)]
    return kept, skipped


def local_key_paths(local: "AppConfig", remote_payload: dict) -> Dict[str, Dict[str, str]]:
    """The user's own key paths a pull of *remote_payload* keeps, by entry name.

    ``{"bastion_key": {profile name: path}, "ssh_key": {server name: path}}``:
    a pulled entry without a key path keeps the local entry's of the same
    name, when that one still dials the same bastion (profiles) or host
    (custom servers). A key path is never carried to another machine: a key
    offered to the wrong host only fails, and tells that host the key exists.
    """
    return {
        "bastion_key": _kept(
            getattr(local, "connection_profiles", None), remote_payload.get("connection_profiles"),
            path_field="bastion_key", host_field="bastion_host",
        ),
        "ssh_key": _kept(
            getattr(local, "custom_servers", None), remote_payload.get("custom_servers"),
            path_field="ssh_key", host_field="host",
        ),
    }


def _kept(local_entries: Any, remote_entries: Any, *, path_field: str, host_field: str) -> Dict[str, str]:
    """``{name: local path}`` for each blank-path remote entry a local entry of the same name and host fills."""
    own: Dict[str, Any] = {}
    for entry in local_entries or []:
        name = getattr(entry, "name", None)
        if isinstance(name, str) and name not in own:
            own[name] = entry
    kept: Dict[str, str] = {}
    for remote in _dicts(remote_entries):
        name = remote.get("name")
        mine = own.get(name) if isinstance(name, str) else None
        path = str(getattr(mine, path_field, "") or "").strip()
        if (
            mine is None or not path or str(remote.get(path_field) or "").strip()
            or _host(getattr(mine, host_field, "")) != _host(remote.get(host_field))
        ):
            continue
        kept[name] = path
    return kept


def _dicts(entries: Any) -> Iterable[dict]:
    return [entry for entry in entries or [] if isinstance(entry, dict)] if isinstance(entries, list) else []


def _host(value: Any) -> str:
    return str(value or "").strip().casefold()


def _rehydrate_list(raw: List[dict], cls) -> list:
    """Rehydrate a list of dicts into instances of ``cls``.

    Drops keys that don't exist on the dataclass — keeps us tolerant of
    newer-version payloads being pulled by older-version clients without
    raising ``TypeError: __init__() got an unexpected keyword argument``.
    """
    import dataclasses

    field_names = {f.name for f in dataclasses.fields(cls)}
    result = []
    for d in raw or []:
        if not isinstance(d, dict):
            logger.warning("Skipping non-dict entry while rehydrating %s: %r", cls.__name__, d)
            continue
        cleaned = {k: v for k, v in d.items() if k in field_names}
        try:
            result.append(cls(**cleaned))
        except TypeError as exc:
            # A required field is missing — log and skip rather than abort
            # the whole apply.
            logger.warning("Skipping malformed %s entry %r: %s", cls.__name__, d, exc)
    return result
