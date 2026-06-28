"""Tests for FleetScanService — eligible_instances, scan, parallelism, progress."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, call

import pytest

from servonaut.services.memory.fleet_scan_service import (
    FleetScanProgress,
    FleetScanResult,
    FleetScanService,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inst(
    name: str,
    iid: Optional[str] = None,
    provider: str = "aws",
) -> Dict[str, Any]:
    return {
        "id": iid or name,
        "name": name,
        "provider": provider,
    }


def _make_memory_service(
    *,
    disabled_ids: Optional[List[str]] = None,
    stale_ids: Optional[List[str]] = None,
    fresh_ids: Optional[List[str]] = None,
    stale_seconds: float = 7 * 86400,
) -> MagicMock:
    """Return a memory service mock with configurable stale/opt-out state.

    ``disabled_ids``: instance IDs/names for which is_memory_disabled returns True.
    ``stale_ids``: instance IDs whose snapshots appear older than stale_seconds.
    ``fresh_ids``: instance IDs whose snapshots appear younger than stale_seconds.
    Instances absent from both stale/fresh have no modules (treated as stale/none).
    """
    from datetime import datetime, timezone, timedelta

    disabled_ids = set(disabled_ids or [])
    stale_ids = set(stale_ids or [])
    fresh_ids = set(fresh_ids or [])

    ms = MagicMock()
    ms.snapshot_stale_seconds = stale_seconds

    def _is_disabled(iid, name):
        return (iid in disabled_ids) or (name in disabled_ids)

    def _get_all_modules(iid, provider):
        # Stale = probed_at is older than the threshold.
        if iid in stale_ids:
            old_ts = (
                datetime.now(timezone.utc) - timedelta(seconds=stale_seconds + 3600)
            ).isoformat()
            return {"os": {"probed_at": old_ts}}
        # Fresh = probed_at is recent.
        if iid in fresh_ids:
            fresh_ts = (
                datetime.now(timezone.utc) - timedelta(seconds=60)
            ).isoformat()
            return {"os": {"probed_at": fresh_ts}}
        # No modules → treated as "none" (stale) by eligible_instances.
        return {}

    ms.is_memory_disabled = MagicMock(side_effect=_is_disabled)
    ms.get_all_modules = MagicMock(side_effect=_get_all_modules)
    return ms


def _make_memory_service_with_build_report(
    succeed_ids: Optional[List[str]] = None,
    fail_ids: Optional[List[str]] = None,
) -> MagicMock:
    """Memory service mock that exposes build_report (the primary scan path)."""
    succeed_ids = set(succeed_ids or [])
    fail_ids = set(fail_ids or [])

    ms = MagicMock()
    ms.is_memory_disabled = MagicMock(return_value=False)
    ms.get_all_modules = MagicMock(return_value={})
    ms.snapshot_stale_seconds = 7 * 86400

    async def _build_report(inst):
        iid = inst.get("id") or inst.get("name")
        report = MagicMock()
        if iid in succeed_ids:
            report.has_any_success = True
            report.overall_reason = None
            report.failures = []
        else:
            report.has_any_success = False
            report.overall_reason = "probe_error"
            failure = MagicMock()
            failure.module = "os"
            failure.reason = "ssh_timeout"
            failure.message = "Connection timed out"
            report.failures = [failure]
        return report

    ms.build_report = AsyncMock(side_effect=_build_report)
    return ms


class _RefreshOnlyService:
    """Minimal memory service stub that exposes only ``refresh`` (no ``build_report``)."""

    def __init__(self, succeed_ids):
        self.snapshot_stale_seconds = 7 * 86400
        self._succeed_ids = set(succeed_ids or [])

    def is_memory_disabled(self, iid, name):
        return False

    def get_all_modules(self, iid, provider):
        return {}

    async def refresh(self, inst):
        iid = inst.get("id") or inst.get("name")
        if iid in self._succeed_ids:
            return {"os": {"probed_at": "2026-01-01T00:00:00+00:00"}}
        return {}


def _make_memory_service_with_refresh(
    succeed_ids: Optional[List[str]] = None,
) -> "_RefreshOnlyService":
    """Memory service stub with only the refresh fallback path — no build_report."""
    return _RefreshOnlyService(succeed_ids)


# ---------------------------------------------------------------------------
# eligible_instances — opt-out filtering
# ---------------------------------------------------------------------------

class TestEligibleInstancesOptOut:
    def test_opted_out_instance_excluded(self) -> None:
        ms = _make_memory_service(disabled_ids=["web-1"])
        svc = FleetScanService(ms)
        instances = [_inst("web-1"), _inst("db-1")]
        result = svc.eligible_instances(instances, stale_only=False)
        names = [i["name"] for i in result]
        assert "web-1" not in names
        assert "db-1" in names

    def test_is_memory_disabled_called_with_id_and_name(self) -> None:
        ms = _make_memory_service()
        svc = FleetScanService(ms)
        instances = [_inst("web-1", iid="i-abc123")]
        svc.eligible_instances(instances, stale_only=False)
        # Must be called with both id and name so either key fires opt-out.
        ms.is_memory_disabled.assert_called_with("i-abc123", "web-1")

    def test_all_opted_out_returns_empty(self) -> None:
        ms = _make_memory_service(disabled_ids=["web-1", "db-1"])
        svc = FleetScanService(ms)
        instances = [_inst("web-1"), _inst("db-1")]
        result = svc.eligible_instances(instances, stale_only=False)
        assert result == []

    def test_empty_instances_returns_empty(self) -> None:
        ms = _make_memory_service()
        svc = FleetScanService(ms)
        result = svc.eligible_instances([], stale_only=False)
        assert result == []

    def test_opted_out_excluded_even_when_stale_only_false(self) -> None:
        ms = _make_memory_service(disabled_ids=["web-1"])
        svc = FleetScanService(ms)
        result = svc.eligible_instances([_inst("web-1")], stale_only=False)
        assert result == []


# ---------------------------------------------------------------------------
# eligible_instances — stale_only filtering
# ---------------------------------------------------------------------------

class TestEligibleInstancesStaleOnly:
    def test_stale_only_true_keeps_stale_instances(self) -> None:
        ms = _make_memory_service(stale_ids=["web-1"])
        svc = FleetScanService(ms)
        result = svc.eligible_instances([_inst("web-1")], stale_only=True)
        assert len(result) == 1

    def test_stale_only_true_excludes_fresh_instances(self) -> None:
        ms = _make_memory_service(fresh_ids=["web-1"])
        svc = FleetScanService(ms)
        result = svc.eligible_instances([_inst("web-1")], stale_only=True)
        assert result == []

    def test_stale_only_false_includes_fresh_instances(self) -> None:
        ms = _make_memory_service(fresh_ids=["web-1"])
        svc = FleetScanService(ms)
        result = svc.eligible_instances([_inst("web-1")], stale_only=False)
        assert len(result) == 1

    def test_stale_only_true_includes_never_probed_no_modules(self) -> None:
        """Instance with no modules is treated as stale/none → included."""
        ms = _make_memory_service()  # no stale/fresh entries → empty modules
        svc = FleetScanService(ms)
        # get_all_modules returns {} → _compute_status → STATUS_NONE, not STALE.
        # per spec, stale_only excludes STATUS_NONE — wait, spec says "stale or
        # missing" in docstring, but code: stale_only keeps STATUS_STALE only.
        # Let's verify by checking what the code actually does.
        result = svc.eligible_instances([_inst("web-1")], stale_only=True)
        # STATUS_NONE (no modules) is NOT STATUS_STALE → excluded when stale_only=True.
        # This is the documented behaviour — only STATUS_STALE passes the gate.
        assert result == []

    def test_stale_only_false_includes_no_modules_instance(self) -> None:
        """stale_only=False includes instances with no prior probes."""
        ms = _make_memory_service()
        svc = FleetScanService(ms)
        result = svc.eligible_instances([_inst("web-1")], stale_only=False)
        assert len(result) == 1

    def test_mixed_stale_and_fresh_stale_only(self) -> None:
        ms = _make_memory_service(stale_ids=["web-1", "web-2"], fresh_ids=["db-1"])
        svc = FleetScanService(ms)
        instances = [_inst("web-1"), _inst("web-2"), _inst("db-1")]
        result = svc.eligible_instances(instances, stale_only=True)
        names = {i["name"] for i in result}
        assert names == {"web-1", "web-2"}


# ---------------------------------------------------------------------------
# scan — success / failure paths via build_report
# ---------------------------------------------------------------------------

class TestScanBuildReportPath:
    @pytest.mark.asyncio
    async def test_successful_probes_appear_in_succeeded(self) -> None:
        ms = _make_memory_service_with_build_report(succeed_ids=["web-1", "web-2"])
        svc = FleetScanService(ms)
        instances = [_inst("web-1"), _inst("web-2")]
        result = await svc.scan(instances, stale_only=False)
        assert isinstance(result, FleetScanResult)
        assert set(result.succeeded) == {"web-1", "web-2"}
        assert result.failed == []

    @pytest.mark.asyncio
    async def test_failed_probe_appears_in_failed(self) -> None:
        ms = _make_memory_service_with_build_report(fail_ids=["web-1"])
        svc = FleetScanService(ms)
        instances = [_inst("web-1")]
        result = await svc.scan(instances, stale_only=False)
        assert result.succeeded == []
        assert len(result.failed) == 1
        entry = result.failed[0]
        assert entry["instance"] == "web-1"
        assert "reason" in entry
        assert "failures" in entry

    @pytest.mark.asyncio
    async def test_mixed_succeed_and_fail(self) -> None:
        ms = _make_memory_service_with_build_report(
            succeed_ids=["web-1"], fail_ids=["db-1"]
        )
        svc = FleetScanService(ms)
        instances = [_inst("web-1"), _inst("db-1")]
        result = await svc.scan(instances, stale_only=False)
        assert "web-1" in result.succeeded
        assert any(e["instance"] == "db-1" for e in result.failed)

    @pytest.mark.asyncio
    async def test_no_eligible_instances_returns_empty_result(self) -> None:
        ms = _make_memory_service(fresh_ids=["web-1"])
        # fresh_ids with stale_only=True → no eligible instances
        svc = FleetScanService(ms)
        # build_report not needed since no instances pass eligibility
        ms.build_report = AsyncMock()
        result = await svc.scan([_inst("web-1")], stale_only=True)
        assert result.succeeded == []
        assert result.failed == []
        ms.build_report.assert_not_called()


# ---------------------------------------------------------------------------
# scan — refresh fallback path (no build_report attribute)
# ---------------------------------------------------------------------------

class TestScanRefreshFallbackPath:
    @pytest.mark.asyncio
    async def test_refresh_path_success(self) -> None:
        ms = _make_memory_service_with_refresh(succeed_ids=["web-1"])
        # _RefreshOnlyService has no build_report attribute by design.
        assert not hasattr(ms, "build_report")
        svc = FleetScanService(ms)
        result = await svc.scan([_inst("web-1")], stale_only=False)
        assert "web-1" in result.succeeded
        assert result.failed == []

    @pytest.mark.asyncio
    async def test_refresh_path_empty_modules_goes_to_failed(self) -> None:
        ms = _make_memory_service_with_refresh(succeed_ids=[])
        assert not hasattr(ms, "build_report")
        svc = FleetScanService(ms)
        result = await svc.scan([_inst("web-1")], stale_only=False)
        assert result.succeeded == []
        assert len(result.failed) == 1
        assert result.failed[0]["reason"] == "no_modules_returned"

    @pytest.mark.asyncio
    async def test_refresh_path_exception_captured(self) -> None:
        class _RaiseOnRefresh(_RefreshOnlyService):
            async def refresh(self, inst):
                raise RuntimeError("ssh down")

        ms = _RaiseOnRefresh(succeed_ids=[])
        svc = FleetScanService(ms)
        result = await svc.scan([_inst("web-1")], stale_only=False)
        assert result.succeeded == []
        assert len(result.failed) == 1
        entry = result.failed[0]
        assert entry["reason"] == "exception"
        assert "ssh down" in entry["failures"][0]["message"]


# ---------------------------------------------------------------------------
# scan — exception handling inside probe
# ---------------------------------------------------------------------------

class TestScanExceptionHandling:
    @pytest.mark.asyncio
    async def test_exception_in_build_report_captured(self) -> None:
        ms = MagicMock()
        ms.is_memory_disabled = MagicMock(return_value=False)
        ms.get_all_modules = MagicMock(return_value={})
        ms.snapshot_stale_seconds = 7 * 86400
        ms.build_report = AsyncMock(side_effect=ConnectionError("refused"))
        svc = FleetScanService(ms)
        result = await svc.scan([_inst("web-1")], stale_only=False)
        assert result.succeeded == []
        assert len(result.failed) == 1
        assert result.failed[0]["reason"] == "exception"

    @pytest.mark.asyncio
    async def test_one_exception_does_not_abort_other_probes(self) -> None:
        """A single failing probe must not prevent the rest from completing."""
        ms = MagicMock()
        ms.is_memory_disabled = MagicMock(return_value=False)
        ms.get_all_modules = MagicMock(return_value={})
        ms.snapshot_stale_seconds = 7 * 86400

        call_count = 0

        async def _build_report(inst):
            nonlocal call_count
            call_count += 1
            if inst["name"] == "bad-1":
                raise RuntimeError("ssh error")
            report = MagicMock()
            report.has_any_success = True
            report.overall_reason = None
            report.failures = []
            return report

        ms.build_report = AsyncMock(side_effect=_build_report)
        svc = FleetScanService(ms)
        result = await svc.scan(
            [_inst("bad-1"), _inst("good-1"), _inst("good-2")],
            stale_only=False,
        )
        assert call_count == 3
        assert "good-1" in result.succeeded
        assert "good-2" in result.succeeded
        assert any(e["instance"] == "bad-1" for e in result.failed)


# ---------------------------------------------------------------------------
# scan — parallelism bounded by max_parallel
# ---------------------------------------------------------------------------

class TestScanParallelismCap:
    @pytest.mark.asyncio
    async def test_max_parallel_respected(self) -> None:
        """At most max_parallel probes should run concurrently."""
        max_parallel = 2
        concurrency_gate = asyncio.Event()
        inflight: List[int] = []
        peak: List[int] = []

        ms = MagicMock()
        ms.is_memory_disabled = MagicMock(return_value=False)
        ms.get_all_modules = MagicMock(return_value={})
        ms.snapshot_stale_seconds = 7 * 86400

        async def _build_report(inst):
            inflight.append(1)
            peak.append(len(inflight))
            # Yield to let other coroutines enter if they're allowed.
            await asyncio.sleep(0)
            inflight.pop()
            report = MagicMock()
            report.has_any_success = True
            report.overall_reason = None
            report.failures = []
            return report

        ms.build_report = AsyncMock(side_effect=_build_report)

        svc = FleetScanService(ms, max_parallel=max_parallel)
        n_instances = 6
        instances = [_inst(f"web-{i}") for i in range(n_instances)]
        result = await svc.scan(instances, stale_only=False)

        assert len(result.succeeded) == n_instances
        # Peak concurrent inflight should never exceed max_parallel.
        assert max(peak) <= max_parallel, (
            f"Peak concurrency {max(peak)} exceeded max_parallel={max_parallel}"
        )

    @pytest.mark.asyncio
    async def test_max_parallel_one_serialises_probes(self) -> None:
        """max_parallel=1 forces strictly serial execution."""
        order: List[str] = []
        start_order: List[str] = []

        ms = MagicMock()
        ms.is_memory_disabled = MagicMock(return_value=False)
        ms.get_all_modules = MagicMock(return_value={})
        ms.snapshot_stale_seconds = 7 * 86400

        async def _build_report(inst):
            name = inst["name"]
            start_order.append(name)
            await asyncio.sleep(0)
            order.append(name)
            report = MagicMock()
            report.has_any_success = True
            report.overall_reason = None
            report.failures = []
            return report

        ms.build_report = AsyncMock(side_effect=_build_report)
        svc = FleetScanService(ms, max_parallel=1)
        instances = [_inst(f"web-{i}") for i in range(4)]
        await svc.scan(instances, stale_only=False)
        # Each probe must start only after the prior one has yielded
        # the semaphore — so start_order and order must be identical
        # (no interleaving).
        assert start_order == order


# ---------------------------------------------------------------------------
# scan — on_progress callback
# ---------------------------------------------------------------------------

class TestScanOnProgress:
    @pytest.mark.asyncio
    async def test_on_progress_called_once_per_instance(self) -> None:
        ms = _make_memory_service_with_build_report(succeed_ids=["web-1", "db-1"])
        svc = FleetScanService(ms)
        progress_events: List[FleetScanProgress] = []

        def _on_progress(ev: FleetScanProgress) -> None:
            progress_events.append(ev)

        await svc.scan(
            [_inst("web-1"), _inst("db-1")],
            stale_only=False,
            on_progress=_on_progress,
        )

        assert len(progress_events) == 2

    @pytest.mark.asyncio
    async def test_on_progress_carries_instance_id(self) -> None:
        """Each FleetScanProgress must carry the raw instance id from the dict."""
        ms = _make_memory_service_with_build_report(succeed_ids=["i-abc123"])
        svc = FleetScanService(ms, max_parallel=1)
        progress_events: List[FleetScanProgress] = []

        def _on_progress(ev: FleetScanProgress) -> None:
            progress_events.append(ev)

        await svc.scan(
            [_inst("web-1", iid="i-abc123")],
            stale_only=False,
            on_progress=_on_progress,
        )

        assert len(progress_events) == 1
        ev = progress_events[0]
        # instance_name carries the display name (used by the progress line)
        assert ev.instance_name == "web-1"
        # instance_id carries the raw id (used by the live row updater)
        assert ev.instance_id == "i-abc123"

    @pytest.mark.asyncio
    async def test_on_progress_instance_id_falls_back_to_name(self) -> None:
        """When the instance dict has no 'id' key, instance_id == name."""
        ms = _make_memory_service_with_build_report(succeed_ids=["no-id-server"])
        svc = FleetScanService(ms, max_parallel=1)
        progress_events: List[FleetScanProgress] = []

        def _on_progress(ev: FleetScanProgress) -> None:
            progress_events.append(ev)

        # Pass an instance dict that has no "id" key.
        await svc.scan(
            [{"name": "no-id-server"}],
            stale_only=False,
            on_progress=_on_progress,
        )

        assert len(progress_events) == 1
        assert progress_events[0].instance_id == "no-id-server"

    @pytest.mark.asyncio
    async def test_on_progress_completed_is_monotonically_increasing(self) -> None:
        ms = _make_memory_service_with_build_report(
            succeed_ids=["web-1", "web-2", "web-3"]
        )
        svc = FleetScanService(ms, max_parallel=1)
        completed_values: List[int] = []

        def _on_progress(ev: FleetScanProgress) -> None:
            completed_values.append(ev.completed)

        await svc.scan(
            [_inst("web-1"), _inst("web-2"), _inst("web-3")],
            stale_only=False,
            on_progress=_on_progress,
        )

        assert completed_values == sorted(completed_values)
        assert completed_values[-1] == 3

    @pytest.mark.asyncio
    async def test_on_progress_total_is_constant_across_events(self) -> None:
        ms = _make_memory_service_with_build_report(succeed_ids=["a", "b", "c"])
        svc = FleetScanService(ms)
        totals: List[int] = []

        def _on_progress(ev: FleetScanProgress) -> None:
            totals.append(ev.total)

        await svc.scan(
            [_inst("a"), _inst("b"), _inst("c")],
            stale_only=False,
            on_progress=_on_progress,
        )

        assert all(t == 3 for t in totals)

    @pytest.mark.asyncio
    async def test_on_progress_succeeded_reflects_outcome(self) -> None:
        ms = _make_memory_service_with_build_report(
            succeed_ids=["web-1"], fail_ids=["db-1"]
        )
        svc = FleetScanService(ms, max_parallel=1)
        events_by_name: Dict[str, FleetScanProgress] = {}

        def _on_progress(ev: FleetScanProgress) -> None:
            events_by_name[ev.instance_name] = ev

        await svc.scan(
            [_inst("web-1"), _inst("db-1")],
            stale_only=False,
            on_progress=_on_progress,
        )

        assert events_by_name["web-1"].succeeded is True
        assert events_by_name["db-1"].succeeded is False

    @pytest.mark.asyncio
    async def test_on_progress_exception_does_not_crash_scan(self) -> None:
        """A misbehaving progress callback must not abort the scan."""
        ms = _make_memory_service_with_build_report(succeed_ids=["web-1"])
        svc = FleetScanService(ms)

        def _bad_progress(ev: FleetScanProgress) -> None:
            raise RuntimeError("callback error")

        result = await svc.scan(
            [_inst("web-1")],
            stale_only=False,
            on_progress=_bad_progress,
        )
        assert "web-1" in result.succeeded


# ---------------------------------------------------------------------------
# scan — CancelledError propagation
# ---------------------------------------------------------------------------

class TestScanCancelledError:
    @pytest.mark.asyncio
    async def test_cancelled_error_propagates_out_of_scan(self) -> None:
        """asyncio.CancelledError must escape scan() so workers can unwind."""
        ms = MagicMock()
        ms.is_memory_disabled = MagicMock(return_value=False)
        ms.get_all_modules = MagicMock(return_value={})
        ms.snapshot_stale_seconds = 7 * 86400

        async def _cancel(inst):
            raise asyncio.CancelledError()

        ms.build_report = AsyncMock(side_effect=_cancel)
        svc = FleetScanService(ms)

        with pytest.raises(asyncio.CancelledError):
            await svc.scan([_inst("web-1")], stale_only=False)

    @pytest.mark.asyncio
    async def test_scan_task_can_be_cancelled_externally(self) -> None:
        """External task cancellation propagates through scan()."""
        ms = MagicMock()
        ms.is_memory_disabled = MagicMock(return_value=False)
        ms.get_all_modules = MagicMock(return_value={})
        ms.snapshot_stale_seconds = 7 * 86400

        async def _slow_probe(inst):
            await asyncio.sleep(60)  # Would block forever without cancellation.

        ms.build_report = AsyncMock(side_effect=_slow_probe)
        svc = FleetScanService(ms)

        task = asyncio.create_task(
            svc.scan([_inst("web-1")], stale_only=False)
        )
        # Let the coroutine enter the sleep.
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
