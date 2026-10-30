"""Apply a pulled team-config payload over the local :class:`AppConfig`.

Apply semantics are REPLACE-WHOLE-SECTION for v1 — the team's section
overwrites the local one in its entirety. This is the simplest model that
makes the feature useful (admin pushes a baseline → members pull → they
have it). Selective per-item import is the v2 release. One exception: a
custom server the team also shares is not added (see
:func:`apply_team_config`).

After application, the caller is responsible for invoking
:meth:`ConfigManager.save` so the change persists; the helper here only
mutates the in-memory dataclass instance so it stays testable without a
filesystem dependency.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, List, Mapping, Sequence

if TYPE_CHECKING:
    from servonaut.config.schema import AppConfig

logger = logging.getLogger(__name__)


def apply_team_config(
    local: "AppConfig", remote_payload: dict, *, shared_servers: Sequence[Mapping[str, Any]] = (),
) -> List[str]:
    """Replace the four shareable sections on ``local`` with ``remote_payload``'s.

    A pulled custom server that one of the team's *shared_servers* also is,
    is left out: as the user's own server it would hide the team's row and
    connect without the team's key. Returns the names of those left out.

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

    local.connection_profiles = _rehydrate_list(
        remote_payload.get("connection_profiles", []), ConnectionProfile
    )
    local.connection_rules = _rehydrate_list(
        remote_payload.get("connection_rules", []), ConnectionRule
    )
    local.scan_rules = _rehydrate_list(
        remote_payload.get("scan_rules", []), ScanRule
    )
    servers, skipped = team_custom_servers(remote_payload, shared_servers)
    local.custom_servers = _rehydrate_list(servers, CustomServer)
    return skipped


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
