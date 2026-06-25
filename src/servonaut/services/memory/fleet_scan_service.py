"""Fleet-wide memory scan orchestrator.

UI-agnostic bulk-scan engine used by both the interactive
``FleetMemoryScreen`` and the background auto-scan loop in ``ServonautApp``.
Callers own presentation (progress display, demo-mode redaction, modals).

Import-cycle decision
---------------------
``screens/fleet_memory.py`` defines ``compute_memory_status`` and the STATUS_*
constants as module-level reusable helpers.  However, that module also imports
from ``servonaut.app`` (TYPE_CHECKING only) and several screen helpers.
Importing it from inside the ``services/`` package would invert the
conventional services-below-screens layering and risk import cycles that are
hard to detect at test time.

Instead, this module replicates the *minimal* status classification logic
using only the memory service's public API
(``is_memory_disabled``, ``get_all_modules``, ``snapshot_stale_seconds``).
The classification result matches the screen's ``STATUS_*`` vocabulary
exactly so callers receive the same codes, but this module has zero
dependency on ``screens/fleet_memory``.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from servonaut.config.schema import DEFAULT_SNAPSHOT_STALE_SECONDS

logger = logging.getLogger(__name__)

# Status codes — must stay in sync with ``screens/fleet_memory.STATUS_*``.
_STATUS_FRESH = "fresh"
_STATUS_STALE = "stale"
_STATUS_NONE = "none"
_STATUS_OPT_OUT = "opted-out"


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


@dataclass
class FleetScanProgress:
    """Emitted by ``FleetScanService.scan`` via *on_progress* after each probe.

    Attributes:
        instance_name: Display name / id of the instance just probed.
        succeeded: ``True`` when the probe produced at least one module.
        completed: Count of instances probed so far (including this one).
        total: Total number of eligible instances in this scan pass.
        instance_id: Raw ``id`` key from the instance dict — used by the
            screen to look up the corresponding table row for a live
            cell update.  Defaults to ``""`` so existing callers that
            construct :class:`FleetScanProgress` directly don't break.
    """

    instance_name: str
    succeeded: bool
    completed: int
    total: int
    instance_id: str = ""


@dataclass
class FleetScanResult:
    """Outcome of a ``FleetScanService.scan`` call.

    Matches the shape consumed by ``FleetScanSummaryModal`` in
    ``screens/fleet_memory``.

    Attributes:
        succeeded: Display names of instances whose scan produced at least
            one memory module.
        failed: Failure entries — each is a dict with keys
            ``"instance"`` (name), ``"reason"`` (code string), and
            ``"failures"`` (list of per-module dicts with ``module``,
            ``reason``, ``message`` keys).
    """

    succeeded: List[str] = field(default_factory=list)
    failed: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal status helpers (replicated from screens/fleet_memory)
# ---------------------------------------------------------------------------


def _snapshot_age_seconds(modules: Dict[str, Any]) -> Optional[float]:
    """Return the age of the most recent probe across *modules*, in seconds.

    Returns ``None`` when *modules* is empty or has no parseable timestamp
    — callers treat that as stale/unknown.
    """
    latest = ""
    for mod in modules.values():
        probed_at = mod.get("probed_at", "") if isinstance(mod, dict) else ""
        if probed_at and probed_at > latest:
            latest = probed_at
    if not latest:
        return None
    try:
        probed_at_dt = datetime.fromisoformat(latest.rstrip("Z"))
        if not probed_at_dt.tzinfo:
            probed_at_dt = probed_at_dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return (datetime.now(tz=timezone.utc) - probed_at_dt).total_seconds()


def _resolve_stale_threshold(memory_service: Any) -> float:
    """Return the server-level staleness threshold in seconds from the service."""
    val = getattr(memory_service, "snapshot_stale_seconds", None)
    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
        return float(val)
    return float(DEFAULT_SNAPSHOT_STALE_SECONDS)


def _compute_status(instance: Dict[str, Any], memory_service: Any) -> str:
    """Return the STATUS_* code for *instance* using the memory service API.

    This is a local reimplementation of ``screens/fleet_memory.compute_memory_status``
    that avoids a service→screen import dependency.  The logic and return
    values are identical; keep them in sync when either changes.
    """
    if memory_service is None:
        return _STATUS_NONE

    iid = instance.get("id") or instance.get("name", "")
    iname = instance.get("name", "")
    provider = instance.get("provider", "custom")
    if not iid:
        return _STATUS_NONE

    try:
        if memory_service.is_memory_disabled(iid, iname):
            return _STATUS_OPT_OUT
    except Exception:  # noqa: BLE001
        # Fail closed: if the opt-out check errors, treat the instance as
        # opted out so a broken lookup never accidentally probes a server.
        logger.warning(
            "is_memory_disabled check failed for %r — treating as opted out",
            iid,
        )
        return _STATUS_OPT_OUT

    try:
        modules = memory_service.get_all_modules(iid, provider)
    except Exception:  # noqa: BLE001
        modules = {}
    if not modules:
        return _STATUS_NONE

    age = _snapshot_age_seconds(modules)
    threshold = _resolve_stale_threshold(memory_service)
    if age is None or age > threshold:
        return _STATUS_STALE
    return _STATUS_FRESH


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class FleetScanService:
    """UI-agnostic orchestrator for fleet-wide memory scanning.

    Wraps the concurrent probe logic so both the interactive screen and the
    background auto-scan loop share one implementation.  Presentation
    (progress display, demo-mode redaction, post-scan modals) is the
    caller's responsibility.

    Args:
        memory_service: The application's ``MemoryService`` instance.
        max_parallel: Maximum number of concurrent SSH probes.  Mirrors
            ``_MAX_PARALLEL_FLEET_PROBES`` from ``screens/fleet_memory``.
    """

    def __init__(
        self,
        memory_service: Any,
        *,
        max_parallel: int = 4,
    ) -> None:
        self._memory_service = memory_service
        self._max_parallel = max_parallel

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def eligible_instances(
        self,
        instances: List[Dict[str, Any]],
        *,
        stale_only: bool,
    ) -> List[Dict[str, Any]]:
        """Return the subset of *instances* that should be probed.

        Mirrors ``FleetMemoryScreen._eligible_instances``:

        - Opted-out instances are always excluded.
        - When *stale_only* is ``True``, fresh and never-probed instances
          are excluded so the scan targets only servers that need refreshing.
        - When *stale_only* is ``False``, all non-opted-out instances are
          included for a full fleet re-probe.

        Args:
            instances: All managed instances (combined AWS + custom list).
            stale_only: When ``True`` probe only stale instances.

        Returns:
            Filtered list preserving original order.
        """
        eligible: List[Dict[str, Any]] = []
        for inst in instances:
            status = _compute_status(inst, self._memory_service)
            if status == _STATUS_OPT_OUT:
                continue
            if stale_only and status != _STATUS_STALE:
                continue
            eligible.append(inst)
        return eligible

    async def scan(
        self,
        instances: List[Dict[str, Any]],
        *,
        stale_only: bool,
        on_progress: Optional[Callable[[FleetScanProgress], None]] = None,
    ) -> FleetScanResult:
        """Probe eligible instances concurrently and return a summary result.

        Filters via :meth:`eligible_instances`, then runs probes in parallel
        capped by *max_parallel*.  Fires *on_progress* once per completed
        instance.  ``asyncio.CancelledError`` is always re-raised so worker
        cancellation propagates correctly — do NOT catch it in callers without
        re-raising.

        Args:
            instances: All managed instances to consider.  Filtering to
                eligible ones is done internally.
            stale_only: Passed through to :meth:`eligible_instances`.
            on_progress: Optional callback invoked after each probe finishes.
                Receives a :class:`FleetScanProgress` dataclass.  May be
                called from the asyncio event loop — keep it fast and
                non-blocking.

        Returns:
            :class:`FleetScanResult` with ``succeeded`` and ``failed`` lists.

        Raises:
            asyncio.CancelledError: When the surrounding worker is cancelled.
                All other exceptions are caught per-instance and collected in
                the result's ``failed`` list so a single bad SSH connection
                never aborts the whole scan.
        """
        eligible = self.eligible_instances(instances, stale_only=stale_only)
        if not eligible:
            logger.debug("FleetScanService.scan: no eligible instances, skipping")
            return FleetScanResult()

        semaphore = asyncio.Semaphore(self._max_parallel)
        result = FleetScanResult()
        total = len(eligible)
        completed = 0

        async def _probe_one(inst: Dict[str, Any]) -> None:
            nonlocal completed
            name = inst.get("name") or inst.get("id") or "unknown"
            logger.info("FleetScanService: probing %s", name)
            async with semaphore:
                ok = False
                try:
                    ms = self._memory_service
                    if hasattr(ms, "build_report"):
                        report = await ms.build_report(inst)
                        if report.has_any_success:
                            result.succeeded.append(name)
                            ok = True
                        else:
                            result.failed.append({
                                "instance": name,
                                "reason": report.overall_reason or "unknown",
                                "failures": [
                                    {
                                        "module": f.module,
                                        "reason": f.reason,
                                        "message": f.message,
                                    }
                                    for f in report.failures
                                ],
                            })
                    else:
                        # Fallback for older or stubbed service instances.
                        modules = await ms.refresh(inst)
                        if modules:
                            result.succeeded.append(name)
                            ok = True
                        else:
                            result.failed.append({
                                "instance": name,
                                "reason": "no_modules_returned",
                                "failures": [],
                            })
                except asyncio.CancelledError:
                    # Propagate so asyncio.gather unwinds cleanly.
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "FleetScanService: probe failed for %s", name
                    )
                    result.failed.append({
                        "instance": name,
                        "reason": "exception",
                        "failures": [
                            {
                                "module": "—",
                                "reason": "exception",
                                "message": str(exc)[:240],
                            }
                        ],
                    })
                finally:
                    completed += 1
                    if on_progress is not None:
                        try:
                            on_progress(
                                FleetScanProgress(
                                    instance_name=name,
                                    succeeded=ok,
                                    completed=completed,
                                    total=total,
                                    instance_id=inst.get("id") or inst.get("name", ""),
                                )
                            )
                        except Exception:  # noqa: BLE001
                            pass  # never let a progress callback crash the scan

        # CancelledError propagates out of gather and then out of this method.
        await asyncio.gather(*(_probe_one(i) for i in eligible))
        logger.info(
            "FleetScanService.scan complete: %d succeeded, %d failed",
            len(result.succeeded),
            len(result.failed),
        )
        return result
