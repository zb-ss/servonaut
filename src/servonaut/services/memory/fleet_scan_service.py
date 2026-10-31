"""Fleet-wide memory scan orchestrator.

UI-agnostic bulk-scan engine used by both the interactive
``FleetMemoryScreen`` and the background auto-scan loop in ``ServonautApp``.
Callers own presentation (progress display, demo-mode redaction, modals).

Status classification
---------------------
The STATUS_* constants and ``compute_memory_status`` classifier live in
``services/memory/status.py`` — a dependency-free module that both this
service and ``screens/fleet_memory`` import from.  That module is the
single source of truth; neither carries its own copy.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from servonaut.services.memory.status import (
    STATUS_FRESH as _STATUS_FRESH,
    STATUS_STALE as _STATUS_STALE,
    STATUS_NONE as _STATUS_NONE,
    STATUS_OPT_OUT as _STATUS_OPT_OUT,
    BUSY_BUILD_REASON,
    STOPPED_REASON,
    is_stopped_instance,
    compute_memory_status as _compute_status,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-row failure reasons
# ---------------------------------------------------------------------------

# Short row texts, keyed by the reason code of a build's first failure. No host
# names or addresses: the Fleet Memory screen also shows them in demo mode.
# ``vault_rate_limited`` is matched by value so this module does not depend on
# where that constant lives.
_ROW_REASON_TEXT: Dict[str, str] = {
    "ssh_auth_failed": "login refused",
    "ssh_unreachable": "unreachable",
    "ssh_failed": "SSH failed",
    "ssh_no_response": "no answer in time",
    "timeout": "no answer in time",
    "vault_credential_unavailable": "no usable vault key",
    "vault_rate_limited": "rate limited",
    STOPPED_REASON: "stopped (skipped)",
    BUSY_BUILD_REASON: "memory busy, try again",
}
_HOST_KEY_REASON_PREFIX = "ssh_host_key_"
_ROW_REASON_FALLBACK = "failed"


def row_reason_text(code: str) -> str:
    """Short, name-free text for a scan reason *code* (``""`` for no reason)."""
    if not code:
        return ""
    if code.startswith(_HOST_KEY_REASON_PREFIX):
        return "host key not trusted"
    return _ROW_REASON_TEXT.get(code, _ROW_REASON_FALLBACK)


def _has_unsaved(report: Any) -> bool:
    """Whether probed modules were left unstored (reports from stubs have none)."""
    unsaved = getattr(report, "unsaved", None)
    return isinstance(unsaved, dict) and bool(unsaved)


def _failure_code(report: Any) -> str:
    """The most specific reason code of a build that stored nothing or not all."""
    if _has_unsaved(report):
        return BUSY_BUILD_REASON
    failures = getattr(report, "failures", None) or []
    if failures and getattr(failures[0], "reason", ""):
        return str(failures[0].reason)
    return str(getattr(report, "overall_reason", None) or "unknown")


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
        skipped: Display names of servers that were not probed because the
            provider reports them stopped or terminated. They are neither
            succeeded nor failed.
    """

    succeeded: List[str] = field(default_factory=list)
    failed: List[Dict[str, Any]] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    def summary_text(self) -> str:
        """One-line outcome for toasts: ``3 ok, 1 failed, 2 skipped: stopped``."""
        text = f"{len(self.succeeded)} ok, {len(self.failed)} failed"
        if self.skipped:
            text += f", {len(self.skipped)} skipped: stopped"
        return text


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
        #: ``instance id → reason code`` of each row's latest scan outcome;
        #: a row keeps its entry until the next probe of that row.
        self.last_reasons: Dict[str, str] = {}

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
        - Stopped or terminated servers are excluded (see
          :func:`~servonaut.services.memory.status.is_stopped_instance`);
          :meth:`scan` reports them as skipped.
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
        return self._partition(instances, stale_only=stale_only)[0]

    def skipped_instances(
        self,
        instances: List[Dict[str, Any]],
        *,
        stale_only: bool,
    ) -> List[Dict[str, Any]]:
        """Return the subset of *instances* :meth:`scan` skips as stopped.

        Lets a caller tell an empty fleet from one whose servers are all
        stopped, which still produces a skipped summary.
        """
        return self._partition(instances, stale_only=stale_only)[1]

    def _partition(
        self,
        instances: List[Dict[str, Any]],
        *,
        stale_only: bool,
    ) -> "tuple[List[Dict[str, Any]], List[Dict[str, Any]]]":
        """Split *instances* into ``(to probe, skipped because stopped)``."""
        eligible: List[Dict[str, Any]] = []
        stopped: List[Dict[str, Any]] = []
        for inst in instances:
            status = _compute_status(inst, self._memory_service)
            if status == _STATUS_OPT_OUT:
                continue
            if stale_only and status != _STATUS_STALE:
                continue
            if is_stopped_instance(inst):
                stopped.append(inst)
                continue
            eligible.append(inst)
        return eligible, stopped

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
            :class:`FleetScanResult` with ``succeeded``, ``failed`` and ``skipped`` lists.

        Raises:
            asyncio.CancelledError: When the surrounding worker is cancelled.
                All other exceptions are caught per-instance and collected in
                the result's ``failed`` list so a single bad SSH connection
                never aborts the whole scan.
        """
        eligible, stopped = self._partition(instances, stale_only=stale_only)
        result = FleetScanResult()
        for inst in stopped:
            name = inst.get("name") or inst.get("id") or "unknown"
            result.skipped.append(name)
            self.last_reasons[inst.get("id") or inst.get("name", "")] = STOPPED_REASON
        if not eligible:
            logger.debug("FleetScanService.scan: no eligible instances, skipping")
            return result

        semaphore = asyncio.Semaphore(self._max_parallel)
        total = len(eligible)
        completed = 0

        async def _probe_one(inst: Dict[str, Any]) -> None:
            nonlocal completed
            name = inst.get("name") or inst.get("id") or "unknown"
            row_id = inst.get("id") or inst.get("name", "")
            logger.info("FleetScanService: probing %s", name)
            async with semaphore:
                ok = False
                self.last_reasons.pop(row_id, None)
                try:
                    ms = self._memory_service
                    if hasattr(ms, "build_report"):
                        report = await ms.build_report(inst)
                        if report.has_any_success and not _has_unsaved(report):
                            result.succeeded.append(name)
                            ok = True
                        else:
                            self.last_reasons[row_id] = _failure_code(report)
                            result.failed.append({
                                "instance": name,
                                "reason": report.overall_reason
                                or (BUSY_BUILD_REASON if _has_unsaved(report) else "unknown"),
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
                            self.last_reasons[row_id] = "no_modules_returned"
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
                    self.last_reasons[row_id] = "exception"
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
            "FleetScanService.scan complete: %d succeeded, %d failed, %d skipped",
            len(result.succeeded),
            len(result.failed),
            len(result.skipped),
        )
        return result
