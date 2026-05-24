"""Apply a pulled team-config payload over the local :class:`AppConfig`.

Apply semantics are REPLACE-WHOLE-SECTION for v1 — the team's section
overwrites the local one in its entirety. This is the simplest model that
makes the feature useful (admin pushes a baseline → members pull → they
have it). Selective per-item import is the v2 release.

After application, the caller is responsible for invoking
:meth:`ConfigManager.save` so the change persists; the helper here only
mutates the in-memory dataclass instance so it stays testable without a
filesystem dependency.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from servonaut.config.schema import AppConfig

logger = logging.getLogger(__name__)


def apply_team_config(local: "AppConfig", remote_payload: dict) -> None:
    """Replace the four shareable sections on ``local`` with ``remote_payload``'s.

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
    local.custom_servers = _rehydrate_list(
        remote_payload.get("custom_servers", []), CustomServer
    )


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
