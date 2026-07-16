"""Tests for the fleet auto-scan loop and memory-sync loop gate in ServonautApp.

Strategy: the Textual App is hard to instantiate headless without a full
service tree, so we use the same pattern established by
``test_app_session_expired_toast.py`` — a duck-typed object that provides
exactly the attributes the methods under test read, then bind the unbound
methods onto it to call them directly.

For the async loop body ``_fleet_auto_scan_loop``, we monkeypatch
``asyncio.sleep`` to raise or return quickly, controlling loop cycles.

Note: ``_fleet_auto_scan_loop`` imports ``asyncio`` locally with a bare
``import asyncio``, so patching must target ``asyncio.sleep`` (not
``servonaut.app.asyncio.sleep``).
"""

from __future__ import annotations

import asyncio
import types
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig, MemoryConfig


# ---------------------------------------------------------------------------
# Helpers — minimal stub
# ---------------------------------------------------------------------------

def _make_config(
    *,
    memory_enabled: bool = True,
    auto_scan_enabled: bool = True,
    auto_scan_interval_seconds: int = 300,
    auto_scan_stale_only: bool = True,
) -> AppConfig:
    import dataclasses
    mem = MemoryConfig(
        enabled=memory_enabled,
        auto_scan_enabled=auto_scan_enabled,
        auto_scan_interval_seconds=auto_scan_interval_seconds,
        auto_scan_stale_only=auto_scan_stale_only,
    )
    return AppConfig(memory=mem)


def _make_stub(
    config: Optional[AppConfig] = None,
    fleet_scan_service=None,
    memory_service=None,
    memory_sync_service=None,
    auth_service=None,
) -> SimpleNamespace:
    """Return a duck-typed stub for ServonautApp method tests.

    Includes a real ``_fleet_auto_scan_loop`` method bound from ``ServonautApp``
    so ``_start_fleet_auto_scan_loop`` can call ``self._fleet_auto_scan_loop()``.
    """
    if config is None:
        config = _make_config()

    config_manager = MagicMock()
    config_manager.get = MagicMock(return_value=config)

    # run_worker receives a coroutine object but never awaits it in tests.
    # Close it immediately so Python doesn't warn about an unawaited coroutine.
    def _run_worker_closing(coro_or_fn, *, name=None, group=None, exclusive=None):
        if asyncio.iscoroutine(coro_or_fn):
            coro_or_fn.close()

    run_worker_mock = MagicMock(side_effect=_run_worker_closing)

    stub = SimpleNamespace(
        config_manager=config_manager,
        fleet_scan_service=fleet_scan_service,
        memory_service=memory_service,
        memory_sync_service=memory_sync_service,
        auth_service=auth_service,
        instances=[],
        _fleet_auto_scan_last_run=0.0,
        run_worker=run_worker_mock,
        # Cycle collaborators — the loop-body tests mock the whole cycle, the
        # cycle tests bind the real method and use these.
        _fleet_manual_scan_progress=MagicMock(),
        _refresh_fleet_panels_after_scan=MagicMock(),
    )
    # Bind the real loop coroutine so _start_fleet_auto_scan_loop can call it.
    stub._fleet_auto_scan_loop = (
        lambda: ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
    )
    # Bind the real cycle method so loop-body tests that don't mock it work too.
    stub._run_fleet_auto_scan_cycle = (
        lambda stale_only: ServonautApp._run_fleet_auto_scan_cycle(  # type: ignore[arg-type]
            stub, stale_only
        )
    )
    return stub


# ---------------------------------------------------------------------------
# _start_fleet_auto_scan_loop — guard conditions
# ---------------------------------------------------------------------------

class TestStartFleetAutoScanLoop:
    """_start_fleet_auto_scan_loop must be a no-op unless all conditions hold."""

    def test_noop_when_auto_scan_enabled_false(self) -> None:
        config = _make_config(auto_scan_enabled=False)
        stub = _make_stub(
            config=config,
            fleet_scan_service=MagicMock(),
            memory_service=MagicMock(),
        )
        ServonautApp._start_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()

    def test_noop_when_memory_enabled_false(self) -> None:
        config = _make_config(memory_enabled=False, auto_scan_enabled=True)
        stub = _make_stub(
            config=config,
            fleet_scan_service=MagicMock(),
            memory_service=MagicMock(),
        )
        ServonautApp._start_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()

    def test_noop_when_fleet_scan_service_is_none(self) -> None:
        config = _make_config()
        stub = _make_stub(
            config=config,
            fleet_scan_service=None,
            memory_service=MagicMock(),
        )
        ServonautApp._start_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()

    def test_noop_when_memory_service_is_none(self) -> None:
        config = _make_config()
        stub = _make_stub(
            config=config,
            fleet_scan_service=MagicMock(),
            memory_service=None,
        )
        ServonautApp._start_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()

    def test_calls_run_worker_when_all_conditions_hold(self) -> None:
        config = _make_config()
        stub = _make_stub(
            config=config,
            fleet_scan_service=MagicMock(),
            memory_service=MagicMock(),
        )
        ServonautApp._start_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        stub.run_worker.assert_called_once()

    def test_run_worker_called_with_correct_group_and_flags(self) -> None:
        config = _make_config()
        stub = _make_stub(
            config=config,
            fleet_scan_service=MagicMock(),
            memory_service=MagicMock(),
        )
        ServonautApp._start_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        _, kwargs = stub.run_worker.call_args
        assert kwargs.get("group") == "memory_auto_scan"
        assert kwargs.get("exclusive") is True
        assert kwargs.get("name") == "fleet_auto_scan_loop"


# ---------------------------------------------------------------------------
# _fleet_auto_scan_loop — loop body behaviour
# ---------------------------------------------------------------------------

class TestFleetAutoScanLoopBody:
    """Drive _fleet_auto_scan_loop directly by monkeypatching asyncio.sleep.

    The loop now persists its schedule (``services/memory/scan_state``) and is
    compute-then-sleep: a startup grace first, then a catch-up scan when the
    interval has elapsed since the persisted last run, else a partial sleep.
    Loop-body tests mock ``_run_fleet_auto_scan_cycle`` to isolate scheduling
    and patch ``scan_state.read_last_run`` to control "due" vs "not due".

    ``_fleet_auto_scan_loop`` does ``import asyncio`` locally, so the correct
    patch target is ``asyncio.sleep`` (the real module attribute).
    """

    def _bind_cycle_mock(self, stub, *, ran: bool = True):
        """Replace the bound cycle with an AsyncMock returning *ran*."""
        cycle = AsyncMock(return_value=ran)
        stub._run_fleet_auto_scan_cycle = cycle
        return cycle

    @pytest.mark.asyncio
    async def test_loop_exits_when_auto_scan_disabled_before_grace(self) -> None:
        """auto_scan_enabled=False on entry → exit before even the grace sleep."""
        config = _make_config(auto_scan_enabled=False)
        stub = _make_stub(config=config)
        with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    async def test_grace_sleep_precedes_first_cycle(self) -> None:
        """The first sleep is the startup grace, not the interval."""
        from servonaut.app import _FLEET_AUTO_SCAN_STARTUP_GRACE_SECONDS

        config = _make_config(auto_scan_interval_seconds=300)
        stub = _make_stub(config=config, fleet_scan_service=MagicMock())
        cycle = self._bind_cycle_mock(stub, ran=True)

        sleep_calls: List[float] = []

        async def _fake_sleep(seconds):
            sleep_calls.append(seconds)
            # Disable after the grace so the loop exits before scanning.
            stub.config_manager.get = MagicMock(
                return_value=_make_config(auto_scan_enabled=False)
            )

        with patch("asyncio.sleep", side_effect=_fake_sleep), patch(
            "servonaut.services.memory.scan_state.read_last_run", return_value=0.0
        ):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        assert sleep_calls[0] == _FLEET_AUTO_SCAN_STARTUP_GRACE_SECONDS
        cycle.assert_not_called()  # disabled before the first cycle

    @pytest.mark.asyncio
    async def test_catch_up_scan_runs_when_overdue(self) -> None:
        """No persisted last_run → a cycle runs right after the grace."""
        config = _make_config(auto_scan_stale_only=True)
        stub = _make_stub(config=config, fleet_scan_service=MagicMock())
        cycle = self._bind_cycle_mock(stub, ran=True)

        n = 0

        async def _fake_sleep(seconds):
            nonlocal n
            n += 1
            # grace (1), then post-cycle interval sleep (2) → exit.
            if n >= 2:
                stub.config_manager.get = MagicMock(
                    return_value=_make_config(auto_scan_enabled=False)
                )

        with patch("asyncio.sleep", side_effect=_fake_sleep), patch(
            "servonaut.services.memory.scan_state.read_last_run", return_value=0.0
        ):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        cycle.assert_awaited_once_with(True)

    @pytest.mark.asyncio
    async def test_not_due_sleeps_remaining_and_skips_scan(self) -> None:
        """A recent persisted last_run → sleep the remaining time, no scan yet."""
        import time as _time

        config = _make_config(auto_scan_interval_seconds=1000)
        stub = _make_stub(config=config, fleet_scan_service=MagicMock())
        cycle = self._bind_cycle_mock(stub, ran=True)

        # last_run 200s ago, interval 1000 → ~800s remaining.
        recent = _time.time() - 200
        sleep_calls: List[float] = []

        async def _fake_sleep(seconds):
            sleep_calls.append(seconds)
            # After grace + the partial sleep, disable so the loop exits.
            if len(sleep_calls) >= 2:
                stub.config_manager.get = MagicMock(
                    return_value=_make_config(auto_scan_enabled=False)
                )

        with patch("asyncio.sleep", side_effect=_fake_sleep), patch(
            "servonaut.services.memory.scan_state.read_last_run", return_value=recent
        ):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        # Second sleep is the "remaining" partial sleep (roughly 800s), and no
        # cycle ran because the schedule wasn't due yet.
        assert 700 < sleep_calls[1] <= 800
        cycle.assert_not_called()

    @pytest.mark.asyncio
    async def test_skipped_cycle_retries_after_grace(self) -> None:
        """When a cycle is skipped (ran=False) the next sleep is the grace."""
        from servonaut.app import _FLEET_AUTO_SCAN_STARTUP_GRACE_SECONDS

        config = _make_config(auto_scan_interval_seconds=1000)
        stub = _make_stub(config=config, fleet_scan_service=MagicMock())
        cycle = self._bind_cycle_mock(stub, ran=False)  # instances not loaded

        sleep_calls: List[float] = []

        async def _fake_sleep(seconds):
            sleep_calls.append(seconds)
            if len(sleep_calls) >= 2:
                stub.config_manager.get = MagicMock(
                    return_value=_make_config(auto_scan_enabled=False)
                )

        with patch("asyncio.sleep", side_effect=_fake_sleep), patch(
            "servonaut.services.memory.scan_state.read_last_run", return_value=0.0
        ):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        # grace, then (because the cycle was skipped) another grace-length sleep.
        assert sleep_calls[0] == _FLEET_AUTO_SCAN_STARTUP_GRACE_SECONDS
        assert sleep_calls[1] == _FLEET_AUTO_SCAN_STARTUP_GRACE_SECONDS

    @pytest.mark.asyncio
    async def test_completed_cycle_sleeps_full_interval(self) -> None:
        """After a completed cycle the post-cycle sleep is the full interval."""
        config = _make_config(auto_scan_interval_seconds=222)
        stub = _make_stub(config=config, fleet_scan_service=MagicMock())
        self._bind_cycle_mock(stub, ran=True)

        sleep_calls: List[float] = []

        async def _fake_sleep(seconds):
            sleep_calls.append(seconds)
            if len(sleep_calls) >= 2:
                stub.config_manager.get = MagicMock(
                    return_value=_make_config(auto_scan_enabled=False)
                )

        with patch("asyncio.sleep", side_effect=_fake_sleep), patch(
            "servonaut.services.memory.scan_state.read_last_run", return_value=0.0
        ):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        assert sleep_calls[1] == 222  # interval, min-60 clamp not triggered

    @pytest.mark.asyncio
    async def test_interval_clamped_to_minimum_60(self) -> None:
        """Interval below 60 is clamped to 60 for the post-cycle sleep."""
        config = _make_config(auto_scan_interval_seconds=5)
        stub = _make_stub(config=config, fleet_scan_service=MagicMock())
        self._bind_cycle_mock(stub, ran=True)

        sleep_calls: List[float] = []

        async def _fake_sleep(seconds):
            sleep_calls.append(seconds)
            if len(sleep_calls) >= 2:
                stub.config_manager.get = MagicMock(
                    return_value=_make_config(auto_scan_enabled=False)
                )

        with patch("asyncio.sleep", side_effect=_fake_sleep), patch(
            "servonaut.services.memory.scan_state.read_last_run", return_value=0.0
        ):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        assert sleep_calls[1] == 60

    @pytest.mark.asyncio
    async def test_cancelled_error_during_grace_exits_loop(self) -> None:
        """CancelledError from the grace sleep causes a clean loop exit."""
        config = _make_config()
        stub = _make_stub(config=config, fleet_scan_service=MagicMock())
        cycle = self._bind_cycle_mock(stub, ran=True)

        async def _cancel(seconds):
            raise asyncio.CancelledError()

        with patch("asyncio.sleep", side_effect=_cancel):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        cycle.assert_not_called()  # cancelled before any cycle ran


# ---------------------------------------------------------------------------
# _run_fleet_auto_scan_cycle — one scan pass + persistence + panel refresh
# ---------------------------------------------------------------------------

class TestRunFleetAutoScanCycle:
    """The cycle probes eligible instances, persists last_run, refreshes panels."""

    @pytest.mark.asyncio
    async def test_skips_and_returns_false_when_no_instances(self) -> None:
        """Empty instance list → skipped (ran=False), nothing persisted."""
        scan_service = MagicMock()
        scan_service.scan = AsyncMock(return_value=MagicMock())
        stub = _make_stub(fleet_scan_service=scan_service, memory_service=MagicMock())
        stub.instances = []

        with patch(
            "servonaut.services.memory.scan_state.write_last_run"
        ) as mock_write:
            ran = await ServonautApp._run_fleet_auto_scan_cycle(stub, True)  # type: ignore[arg-type]

        assert ran is False
        scan_service.scan.assert_not_called()
        mock_write.assert_not_called()
        stub._refresh_fleet_panels_after_scan.assert_not_called()

    @pytest.mark.asyncio
    async def test_runs_scan_with_progress_and_stale_only(self) -> None:
        """scan() gets stale_only + the app's progress router as on_progress."""
        for expected_stale_only in (True, False):
            result = MagicMock()
            scan_service = MagicMock()
            scan_service.scan = AsyncMock(return_value=result)
            stub = _make_stub(
                fleet_scan_service=scan_service, memory_service=MagicMock()
            )
            stub.instances = [{"id": "web-1", "name": "web-1"}]

            with patch("servonaut.services.memory.scan_state.write_last_run"):
                ran = await ServonautApp._run_fleet_auto_scan_cycle(  # type: ignore[arg-type]
                    stub, expected_stale_only
                )

            assert ran is True
            scan_service.scan.assert_awaited_once_with(
                stub.instances,
                stale_only=expected_stale_only,
                on_progress=stub._fleet_manual_scan_progress,
            )

    @pytest.mark.asyncio
    async def test_persists_last_run_and_refreshes_panels_on_success(self) -> None:
        """A successful pass writes last_run (disk + memory) and refreshes panels."""
        result = MagicMock()
        scan_service = MagicMock()
        scan_service.scan = AsyncMock(return_value=result)
        stub = _make_stub(fleet_scan_service=scan_service, memory_service=MagicMock())
        stub.instances = [{"id": "web-1", "name": "web-1"}]
        stub._fleet_auto_scan_last_run = 0.0

        with patch(
            "servonaut.services.memory.scan_state.write_last_run"
        ) as mock_write:
            await ServonautApp._run_fleet_auto_scan_cycle(stub, True)  # type: ignore[arg-type]

        assert stub._fleet_auto_scan_last_run > 0.0
        mock_write.assert_called_once()
        # persisted value matches the in-memory marker
        assert mock_write.call_args.args[0] == stub._fleet_auto_scan_last_run
        stub._refresh_fleet_panels_after_scan.assert_called_once_with(
            result, quiet=True
        )

    @pytest.mark.asyncio
    async def test_scan_exception_does_not_persist_but_reports_ran(self) -> None:
        """A scan that raises: ran=True (back off a full interval), last_run intact."""
        scan_service = MagicMock()
        scan_service.scan = AsyncMock(side_effect=RuntimeError("ssh down"))
        stub = _make_stub(fleet_scan_service=scan_service, memory_service=MagicMock())
        stub.instances = [{"id": "web-1", "name": "web-1"}]
        stub._fleet_auto_scan_last_run = 0.0

        with patch(
            "servonaut.services.memory.scan_state.write_last_run"
        ) as mock_write:
            ran = await ServonautApp._run_fleet_auto_scan_cycle(stub, True)  # type: ignore[arg-type]

        assert ran is True
        assert stub._fleet_auto_scan_last_run == 0.0
        mock_write.assert_not_called()
        stub._refresh_fleet_panels_after_scan.assert_not_called()

    @pytest.mark.asyncio
    async def test_cancelled_error_propagates(self) -> None:
        """CancelledError from scan() propagates so the worker unwinds."""
        scan_service = MagicMock()
        scan_service.scan = AsyncMock(side_effect=asyncio.CancelledError())
        stub = _make_stub(fleet_scan_service=scan_service, memory_service=MagicMock())
        stub.instances = [{"id": "web-1", "name": "web-1"}]

        with patch("servonaut.services.memory.scan_state.write_last_run"):
            with pytest.raises(asyncio.CancelledError):
                await ServonautApp._run_fleet_auto_scan_cycle(stub, True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# scan_state — persisted last-run round-trip + fail-soft
# ---------------------------------------------------------------------------

class TestScanStatePersistence:
    """read_last_run / write_last_run survive restarts and never crash on bad data."""

    def test_missing_file_returns_zero(self, tmp_path) -> None:
        from servonaut.services.memory import scan_state
        assert scan_state.read_last_run(tmp_path) == 0.0

    def test_round_trip(self, tmp_path) -> None:
        from servonaut.services.memory import scan_state
        scan_state.write_last_run(1_700_000_000.5, tmp_path)
        assert scan_state.read_last_run(tmp_path) == 1_700_000_000.5

    def test_corrupt_file_returns_zero(self, tmp_path) -> None:
        from servonaut.services.memory import scan_state
        scan_state.state_path(tmp_path).write_text("{not json", encoding="utf-8")
        assert scan_state.read_last_run(tmp_path) == 0.0

    def test_bool_and_nonpositive_rejected(self, tmp_path) -> None:
        from servonaut.services.memory import scan_state
        p = scan_state.state_path(tmp_path)
        p.write_text('{"auto_scan_last_run_at": true}', encoding="utf-8")
        assert scan_state.read_last_run(tmp_path) == 0.0
        p.write_text('{"auto_scan_last_run_at": -5}', encoding="utf-8")
        assert scan_state.read_last_run(tmp_path) == 0.0


# ---------------------------------------------------------------------------
# _refresh_fleet_panels_after_scan — shared post-scan UI refresh
# ---------------------------------------------------------------------------

class TestRefreshFleetPanelsAfterScan:
    """Routes to the right screen hook (quiet vs manual) and the memory column."""

    def _make_app_stub(self, screen) -> SimpleNamespace:
        return SimpleNamespace(screen=screen)

    def test_quiet_uses_auto_hook(self) -> None:
        screen = MagicMock(spec=["on_fleet_auto_scan_done", "refresh_memory_status"])
        app = self._make_app_stub(screen)
        result = MagicMock()
        ServonautApp._refresh_fleet_panels_after_scan(app, result, quiet=True)  # type: ignore[arg-type]
        screen.on_fleet_auto_scan_done.assert_called_once_with(result)
        screen.refresh_memory_status.assert_called_once_with()

    def test_non_quiet_uses_manual_hook(self) -> None:
        screen = MagicMock(spec=["on_fleet_manual_scan_done", "refresh_memory_status"])
        app = self._make_app_stub(screen)
        result = MagicMock()
        ServonautApp._refresh_fleet_panels_after_scan(app, result, quiet=False)  # type: ignore[arg-type]
        screen.on_fleet_manual_scan_done.assert_called_once_with(result)

    def test_noop_when_screen_lacks_hooks(self) -> None:
        """A screen without memory hooks (e.g. some other view) → no crash."""
        screen = MagicMock(spec=[])  # no memory methods
        app = self._make_app_stub(screen)
        # Must not raise.
        ServonautApp._refresh_fleet_panels_after_scan(app, MagicMock(), quiet=True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _start_memory_sync_loop — gate conditions
# ---------------------------------------------------------------------------

class TestStartMemorySyncLoop:
    """_start_memory_sync_loop(self, auto_sync_enabled: bool) must respect the
    passed flag, the entitlement check, and the is_configured guard.

    The server-side flag is now fetched by the async caller (bootstrap_memory_cloud
    or _refresh_memory_sync_loop) and passed in as a plain bool parameter,
    so these tests drive the method directly with the flag value.
    """

    def _make_sync_service(self, is_configured: bool = True) -> MagicMock:
        svc = MagicMock()
        svc.is_configured = is_configured
        svc.start_background_loop = MagicMock(return_value=AsyncMock())
        return svc

    def _make_auth(self, has_memory_sync: bool) -> MagicMock:
        auth = MagicMock()
        auth.has_feature = MagicMock(
            side_effect=lambda feat: feat == "memory_sync" and has_memory_sync
        )
        return auth

    def test_noop_when_sync_service_is_none(self) -> None:
        """No sync service — no-op regardless of flag."""
        stub = _make_stub(
            memory_sync_service=None,
            auth_service=self._make_auth(has_memory_sync=True),
        )
        ServonautApp._start_memory_sync_loop(stub, True)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()

    def test_noop_when_not_configured(self) -> None:
        """is_configured=False — no-op even when flag is True."""
        sync = self._make_sync_service(is_configured=False)
        stub = _make_stub(
            memory_sync_service=sync,
            auth_service=self._make_auth(has_memory_sync=True),
        )
        ServonautApp._start_memory_sync_loop(stub, True)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()

    def test_noop_when_auto_sync_enabled_false(self) -> None:
        """auto_sync_enabled param=False blocks the loop even when configured."""
        sync = self._make_sync_service(is_configured=True)
        stub = _make_stub(
            memory_sync_service=sync,
            auth_service=self._make_auth(has_memory_sync=True),
        )
        ServonautApp._start_memory_sync_loop(stub, False)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()

    def test_noop_when_not_entitled(self) -> None:
        """has_feature('memory_sync')=False blocks the loop even when flag is True."""
        sync = self._make_sync_service(is_configured=True)
        stub = _make_stub(
            memory_sync_service=sync,
            auth_service=self._make_auth(has_memory_sync=False),
        )
        ServonautApp._start_memory_sync_loop(stub, True)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()

    def test_spawns_when_configured_enabled_and_entitled(self) -> None:
        """run_worker is called when all three gates pass."""
        sync = self._make_sync_service(is_configured=True)
        stub = _make_stub(
            memory_sync_service=sync,
            auth_service=self._make_auth(has_memory_sync=True),
        )
        ServonautApp._start_memory_sync_loop(stub, True)  # type: ignore[arg-type]
        stub.run_worker.assert_called_once()

    def test_run_worker_uses_memory_sync_background_group(self) -> None:
        """Worker must use the 'memory_sync_background' group with exclusive=True."""
        sync = self._make_sync_service(is_configured=True)
        stub = _make_stub(
            memory_sync_service=sync,
            auth_service=self._make_auth(has_memory_sync=True),
        )
        ServonautApp._start_memory_sync_loop(stub, True)  # type: ignore[arg-type]
        _, kwargs = stub.run_worker.call_args
        assert kwargs.get("group") == "memory_sync_background"
        assert kwargs.get("exclusive") is True

    def test_noop_when_auto_sync_enabled_true_but_auth_service_is_none(self) -> None:
        """No auth service means has_feature cannot be checked — no-op."""
        sync = self._make_sync_service(is_configured=True)
        stub = _make_stub(
            memory_sync_service=sync,
            auth_service=None,
        )
        ServonautApp._start_memory_sync_loop(stub, True)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()


# ---------------------------------------------------------------------------
# _refresh_fleet_auto_scan_loop — Fix C lifecycle helper
# ---------------------------------------------------------------------------

class TestRefreshFleetAutoScanLoop:
    """_refresh_fleet_auto_scan_loop must spawn or cancel based on config flags."""

    def _make_stub_with_workers(
        self,
        config: Optional[AppConfig] = None,
        fleet_scan_service=None,
        memory_service=None,
    ) -> SimpleNamespace:
        """Return a stub with a real workers mock that tracks cancel_group calls."""
        stub = _make_stub(
            config=config or _make_config(),
            fleet_scan_service=fleet_scan_service or MagicMock(),
            memory_service=memory_service or MagicMock(),
        )
        workers_mock = MagicMock()
        workers_mock.cancel_group = MagicMock()
        stub.workers = workers_mock
        # Bind _start_fleet_auto_scan_loop so _refresh_fleet_auto_scan_loop can call it.
        stub._start_fleet_auto_scan_loop = (
            lambda: ServonautApp._start_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        )
        return stub

    def test_spawns_loop_when_enabled(self) -> None:
        """When both enabled and auto_scan_enabled, run_worker is called."""
        config = _make_config(memory_enabled=True, auto_scan_enabled=True)
        stub = self._make_stub_with_workers(config=config)
        ServonautApp._refresh_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        stub.run_worker.assert_called_once()
        stub.workers.cancel_group.assert_not_called()

    def test_cancels_group_when_auto_scan_disabled(self) -> None:
        """When auto_scan_enabled=False, cancel_group is called and run_worker is not."""
        config = _make_config(memory_enabled=True, auto_scan_enabled=False)
        stub = self._make_stub_with_workers(config=config)
        ServonautApp._refresh_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()
        stub.workers.cancel_group.assert_called_once_with(stub, "memory_auto_scan")

    def test_cancels_group_when_memory_disabled(self) -> None:
        """When memory.enabled=False, cancel_group is called promptly."""
        config = _make_config(memory_enabled=False, auto_scan_enabled=True)
        stub = self._make_stub_with_workers(config=config)
        ServonautApp._refresh_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        stub.run_worker.assert_not_called()
        stub.workers.cancel_group.assert_called_once_with(stub, "memory_auto_scan")

    def test_cancel_group_exception_is_swallowed(self) -> None:
        """cancel_group raising must not propagate — graceful degradation."""
        config = _make_config(memory_enabled=False, auto_scan_enabled=False)
        stub = self._make_stub_with_workers(config=config)
        stub.workers.cancel_group.side_effect = RuntimeError("textual gone")
        # Must not raise.
        ServonautApp._refresh_fleet_auto_scan_loop(stub)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _auto_scan_status_text — Fix A regression
# ---------------------------------------------------------------------------

class TestAutoScanStatusText:
    """_auto_scan_status_text reads config_manager, not the non-existent .config attr."""

    def _make_fleet_screen(self, config: Optional[AppConfig] = None) -> Any:
        """Return a FleetMemoryScreen-like object with a patched app."""
        from servonaut.screens.fleet_memory import FleetMemoryScreen

        screen = object.__new__(FleetMemoryScreen)
        screen._rows = []
        screen._scanning = False

        cfg = config or _make_config(memory_enabled=True, auto_scan_enabled=True)
        config_manager = MagicMock()
        config_manager.get = MagicMock(return_value=cfg)

        app = MagicMock()
        app.config_manager = config_manager
        # _auto_scan_status_text reads _fleet_auto_scan_last_run from app (not screen).
        app._fleet_auto_scan_last_run = 0.0

        # Patch app property on the screen class shadow.
        type(screen).app = property(lambda self: app)
        return screen

    def test_returns_on_string_when_enabled(self) -> None:
        """When auto_scan_enabled=True, status text contains 'on'."""
        from servonaut.screens.fleet_memory import FleetMemoryScreen

        screen = self._make_fleet_screen(
            _make_config(memory_enabled=True, auto_scan_enabled=True)
        )
        text = FleetMemoryScreen._auto_scan_status_text(screen)
        assert "on" in text.lower()
        assert "off" not in text.lower()

    def test_returns_off_string_when_disabled(self) -> None:
        """When auto_scan_enabled=False, status text contains 'off'."""
        from servonaut.screens.fleet_memory import FleetMemoryScreen

        screen = self._make_fleet_screen(
            _make_config(memory_enabled=True, auto_scan_enabled=False)
        )
        text = FleetMemoryScreen._auto_scan_status_text(screen)
        assert "off" in text.lower()

    def test_returns_off_when_config_manager_is_none(self) -> None:
        """If config_manager is missing on app, return 'off' gracefully."""
        from servonaut.screens.fleet_memory import FleetMemoryScreen

        screen = object.__new__(FleetMemoryScreen)
        screen._rows = []

        app = MagicMock(spec=[])  # no attributes at all
        type(screen).app = property(lambda self: app)

        text = FleetMemoryScreen._auto_scan_status_text(screen)
        assert "off" in text.lower()


# ---------------------------------------------------------------------------
# action_toggle_auto_scan — Fix A regression
# ---------------------------------------------------------------------------

class TestActionToggleAutoScan:
    """action_toggle_auto_scan reads config_manager (not .config) and persists."""

    def _make_toggle_screen(self, initial_auto_scan: bool) -> Any:
        """Return a FleetMemoryScreen stub with a writable config_manager."""
        import dataclasses
        from servonaut.screens.fleet_memory import FleetMemoryScreen

        screen = object.__new__(FleetMemoryScreen)
        screen._rows = []
        screen._scanning = False

        cfg = _make_config(memory_enabled=True, auto_scan_enabled=initial_auto_scan)

        # Track config_manager.update calls.
        config_manager = MagicMock()
        config_manager.get = MagicMock(return_value=cfg)
        update_calls: List[Any] = []
        config_manager.update = MagicMock(side_effect=lambda **kw: update_calls.append(kw))

        app = MagicMock()
        app.config_manager = config_manager
        app._refresh_fleet_auto_scan_loop = MagicMock()
        app.notify = MagicMock()

        type(screen).app = property(lambda self: app)
        screen._refresh_auto_scan_status = MagicMock()

        screen._update_calls = update_calls
        screen._config_manager = config_manager
        return screen

    def test_toggle_off_to_on_persists_enabled(self) -> None:
        """Toggling from off→on writes auto_scan_enabled=True to config."""
        from servonaut.screens.fleet_memory import FleetMemoryScreen

        screen = self._make_toggle_screen(initial_auto_scan=False)
        FleetMemoryScreen.action_toggle_auto_scan(screen)

        assert len(screen._update_calls) == 1
        updated_mem = screen._update_calls[0]["memory"]
        assert updated_mem.auto_scan_enabled is True

    def test_toggle_on_to_off_persists_disabled(self) -> None:
        """Toggling from on→off writes auto_scan_enabled=False to config."""
        from servonaut.screens.fleet_memory import FleetMemoryScreen

        screen = self._make_toggle_screen(initial_auto_scan=True)
        FleetMemoryScreen.action_toggle_auto_scan(screen)

        assert len(screen._update_calls) == 1
        updated_mem = screen._update_calls[0]["memory"]
        assert updated_mem.auto_scan_enabled is False

    def test_calls_refresh_loop_after_toggle(self) -> None:
        """_refresh_fleet_auto_scan_loop must be called after persisting."""
        from servonaut.screens.fleet_memory import FleetMemoryScreen

        screen = self._make_toggle_screen(initial_auto_scan=False)
        FleetMemoryScreen.action_toggle_auto_scan(screen)

        screen.app._refresh_fleet_auto_scan_loop.assert_called_once()

    def test_status_text_on_after_enabling(self) -> None:
        """After enabling, _auto_scan_status_text returns an 'on' string."""
        from servonaut.screens.fleet_memory import FleetMemoryScreen

        # Build screen with enabled=True config (post-toggle state).
        screen = self._make_toggle_screen(initial_auto_scan=True)
        # _auto_scan_status_text reads _fleet_auto_scan_last_run from app, not screen.
        screen.app._fleet_auto_scan_last_run = 0.0
        text = FleetMemoryScreen._auto_scan_status_text(screen)
        assert "on" in text.lower()
        assert "off" not in text.lower()
