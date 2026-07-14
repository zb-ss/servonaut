"""Fleet / bulk DB-credential scan — Layer B3 of the DB-credential vault.

UI-agnostic orchestrator that turns the one-instance human surface (B2)
into the "hundreds of boxes" enabler: fan out :meth:`ServonautTools.
db_scan_stage` across a fleet (concurrency-bounded), assemble ONE review
table with an "already-vaulted?" column, then commit per-row or all —
skipping instances that already have a ``db/<instance>`` profile and
isolating per-box failures so one bad box never aborts the batch.

Reuses the shipped engine end-to-end: ``db_scan_stage`` (read-only scan +
server-side staging) and ``db_setup_save`` (commit by token). No parsing
or secret handling is reimplemented here — this is pure orchestration.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

#: Bounded SSH fan-out — mirrors the fleet auto-scan default (decision #4).
_FLEET_SCAN_CONCURRENCY = 8


@dataclass
class FleetDbScanRow:
    """One instance's result in the fleet review table."""

    instance_id: str
    instance_name: str
    already_vaulted: bool
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def top_candidate(self) -> Optional[Dict[str, Any]]:
        return self.candidates[0] if self.candidates else None

    @property
    def status(self) -> str:
        if self.already_vaulted:
            return "vaulted"
        if self.error:
            return "error"
        if not self.candidates:
            return "none found"
        return f"{len(self.candidates)} found"


@dataclass
class FleetDbScanResult:
    rows: List[FleetDbScanRow] = field(default_factory=list)

    @property
    def committable(self) -> List[FleetDbScanRow]:
        """Rows that a bulk commit would act on (not vaulted, have a candidate)."""
        return [r for r in self.rows if not r.already_vaulted and r.candidates]


@dataclass
class FleetDbCommitSummary:
    stored: int = 0
    skipped: int = 0
    failed: int = 0
    failures: List[Tuple[str, str]] = field(default_factory=list)  # (instance, why)


class DbFleetScanService:
    """Concurrency-bounded fleet DB-credential scan + bulk commit."""

    def __init__(
        self,
        tools,
        config_manager,
        *,
        max_parallel: int = _FLEET_SCAN_CONCURRENCY,
    ) -> None:
        self._tools = tools
        self._config_manager = config_manager
        self._max_parallel = max(1, int(max_parallel))

    # ------------------------------------------------------------------
    # Coverage
    # ------------------------------------------------------------------

    def _already_vaulted(self, instance: Dict[str, Any]) -> bool:
        """True iff a DBProfile with a stored secret already exists."""
        try:
            config = self._config_manager.get()
            profile = config.db_profile_for(
                instance.get("id", ""), instance.get("name", ""),
            )
        except Exception:  # noqa: BLE001 - never let a config read abort a scan
            return False
        return profile is not None and bool(profile.password_secret)

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    async def scan(
        self,
        instances: List[Dict[str, Any]],
        *,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
    ) -> FleetDbScanResult:
        """Scan every instance concurrently (capped at ``max_parallel``).

        Already-vaulted instances are recorded WITHOUT an SSH probe (idempotent
        — no point re-reading a box we already stored). Every other box is
        probed via ``db_scan_stage``; a per-box exception or tool-reported
        error is captured on the row and never aborts the batch.
        """
        semaphore = asyncio.Semaphore(self._max_parallel)
        total = len(instances)
        results: Dict[int, FleetDbScanRow] = {}
        completed = 0

        async def _one(idx: int, instance: Dict[str, Any]) -> None:
            nonlocal completed
            iid = str(instance.get("id") or instance.get("name") or "")
            iname = str(instance.get("name") or iid or "?")
            async with semaphore:
                if self._already_vaulted(instance):
                    row = FleetDbScanRow(iid, iname, True)
                else:
                    row = await self._scan_one(iid, iname)
            results[idx] = row
            completed += 1
            if on_progress is not None:
                try:
                    on_progress(completed, total, iname)
                except Exception:  # noqa: BLE001 - progress must not break scan
                    pass

        await asyncio.gather(*(_one(i, inst) for i, inst in enumerate(instances)))
        # Preserve input order regardless of completion order.
        rows = [results[i] for i in range(total) if i in results]
        return FleetDbScanResult(rows=rows)

    async def _scan_one(self, iid: str, iname: str) -> FleetDbScanRow:
        try:
            res = await self._tools.db_scan_stage(iid)
        except Exception as exc:  # noqa: BLE001 - isolate the bad box
            logger.warning("Fleet DB scan failed for %s: %s", iname, exc)
            return FleetDbScanRow(iid, iname, False, error=str(exc))
        if isinstance(res, dict) and res.get("error"):
            return FleetDbScanRow(iid, iname, False, error=str(res["error"]))
        candidates = (res or {}).get("candidates") or []
        return FleetDbScanRow(iid, iname, False, candidates=list(candidates))

    # ------------------------------------------------------------------
    # Commit
    # ------------------------------------------------------------------

    async def commit_row(
        self, row: FleetDbScanRow, *, token: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Commit one candidate for a row via ``db_setup_save``.

        Skips an already-vaulted row (idempotent on ``db/<instance>``).
        Uses the row's top candidate unless an explicit ``token`` is given.
        """
        if row.already_vaulted:
            return False, "already vaulted (skipped)"
        tok = token or ((row.top_candidate or {}).get("token"))
        if not tok:
            return False, "no candidate to store"
        out = await self._tools.db_setup_save(tok, instance_id=row.instance_id)
        ok = isinstance(out, str) and out.startswith("Saved")
        return ok, out if isinstance(out, str) else str(out)

    async def commit_all(
        self,
        result: FleetDbScanResult,
        *,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
    ) -> FleetDbCommitSummary:
        """Commit the top candidate of every committable row, SEQUENTIALLY.

        Sequential on purpose: each commit does a read-modify-write of
        ``config.db_profiles``; committing in parallel would race the
        config write. Already-vaulted / candidate-less rows are skipped;
        a per-row failure is recorded and never aborts the batch.
        """
        summary = FleetDbCommitSummary()
        total = len(result.rows)
        for idx, row in enumerate(result.rows, 1):
            if row.already_vaulted or not row.candidates:
                summary.skipped += 1
            else:
                try:
                    ok, why = await self.commit_row(row)
                    if ok:
                        summary.stored += 1
                        # It's vaulted now — reflect it so a UI refresh (or a
                        # re-run of commit_all) treats it as done, not pending.
                        row.already_vaulted = True
                    else:
                        summary.failed += 1
                        summary.failures.append((row.instance_name, why))
                except Exception as exc:  # noqa: BLE001 - isolate one bad commit
                    summary.failed += 1
                    summary.failures.append((row.instance_name, str(exc)))
            if on_progress is not None:
                try:
                    on_progress(idx, total, row.instance_name)
                except Exception:  # noqa: BLE001
                    pass
        return summary
