"""Memory status classification helpers — dependency-free service-layer module.

This module carries the STATUS_* constants, the snapshot-age helpers, and
the ``compute_memory_status`` classifier that both the fleet-scan service
and the fleet-memory screen need.  It must NOT import from any screen,
widget, or app module to keep the services layer free of presentation
dependencies.

``screens/fleet_memory`` re-exports every public symbol from here so that
existing importers (``widgets/instance_table``, tests, …) that do::

    from servonaut.screens.fleet_memory import STATUS_FRESH, compute_memory_status

continue to work without change.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from servonaut.config.schema import DEFAULT_SNAPSHOT_STALE_SECONDS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Status codes
# ---------------------------------------------------------------------------

# These string values are the stable external vocabulary — renderers in
# ``screens/fleet_memory`` and ``widgets/instance_table`` match on them.
# Never rename without a migration pass over all callers.
STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_NONE = "none"
STATUS_OPT_OUT = "opted-out"


# ---------------------------------------------------------------------------
# Age / threshold helpers
# ---------------------------------------------------------------------------


def _latest_probed_at(modules: Dict[str, Any]) -> str:
    """Return the most recent ``probed_at`` across *modules*, or ``""``."""
    latest = ""
    for mod in modules.values():
        probed_at = mod.get("probed_at", "") if isinstance(mod, dict) else ""
        if probed_at and probed_at > latest:
            latest = probed_at
    return latest


def snapshot_age_seconds(modules: Dict[str, Any]) -> Optional[float]:
    """Return the age in seconds of the most recent probe across *modules*.

    Returns ``None`` when *modules* is empty or carries no parseable
    ``probed_at`` timestamp — callers treat that as "stale / unknown".
    """
    latest = _latest_probed_at(modules)
    if not latest:
        return None
    try:
        probed_at = datetime.fromisoformat(latest.rstrip("Z"))
        if not probed_at.tzinfo:
            probed_at = probed_at.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return (datetime.now(tz=timezone.utc) - probed_at).total_seconds()


def _resolve_stale_threshold(memory_service: Any) -> float:
    """Return the server-level staleness threshold in seconds.

    Reads ``MemoryService.snapshot_stale_seconds`` and falls back to the
    schema default when the service does not expose a usable numeric value
    (e.g. lightweight test doubles).
    """
    val = getattr(memory_service, "snapshot_stale_seconds", None)
    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
        return float(val)
    return float(DEFAULT_SNAPSHOT_STALE_SECONDS)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


def compute_memory_status(
    instance: Dict[str, Any],
    memory_service: Any,
) -> str:
    """Return one of the STATUS_* codes for *instance*.

    A server's whole memory is reported ``STATUS_STALE`` once its newest
    probe is older than the server-level threshold
    (``MemoryService.snapshot_stale_seconds``).  This is deliberately
    decoupled from per-module TTLs — volatile modules (containers, disk)
    re-probe fast by design and must not drag the whole-server badge.

    Reuses the memory service's public API only — no ``_store`` reach-in.
    Defensive against missing services so callers (instance_list column,
    fleet table, fleet scan service) never raise from UI or service code
    paths.

    Opt-out check fails closed: if ``is_memory_disabled`` raises for any
    reason the instance is treated as opted-out so a broken lookup never
    accidentally triggers an SSH probe against a server.
    """
    if memory_service is None:
        return STATUS_NONE

    iid = instance.get("id") or instance.get("name", "")
    iname = instance.get("name", "")
    provider = instance.get("provider", "custom")
    if not iid:
        return STATUS_NONE

    try:
        if memory_service.is_memory_disabled(iid, iname):
            return STATUS_OPT_OUT
    except Exception:  # noqa: BLE001
        # Fail closed: if the opt-out check errors, treat the instance as
        # opted out so a broken lookup never accidentally probes a server.
        logger.warning(
            "is_memory_disabled check failed for %r — treating as opted out",
            iid,
        )
        return STATUS_OPT_OUT

    try:
        modules = memory_service.get_all_modules(iid, provider)
    except Exception:  # noqa: BLE001
        modules = {}
    if not modules:
        return STATUS_NONE

    age = snapshot_age_seconds(modules)
    threshold = _resolve_stale_threshold(memory_service)
    if age is None or age > threshold:
        return STATUS_STALE
    return STATUS_FRESH
