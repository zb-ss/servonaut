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
    )
    # Bind the real loop coroutine so _start_fleet_auto_scan_loop can call it.
    stub._fleet_auto_scan_loop = (
        lambda: ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
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

    ``_fleet_auto_scan_loop`` does ``import asyncio`` locally, so the correct
    patch target is ``asyncio.sleep`` (the real module attribute), not any
    ``servonaut.app.*`` path.
    """

    @pytest.mark.asyncio
    async def test_loop_exits_when_auto_scan_disabled_before_sleep(self) -> None:
        """If config has auto_scan_enabled=False on entry, exit immediately."""
        config = _make_config(auto_scan_enabled=False)
        stub = _make_stub(config=config)
        with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]
        mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    async def test_loop_uses_configured_interval(self) -> None:
        """sleep() must be called with the configured interval (min 60)."""
        config = _make_config(auto_scan_interval_seconds=180)
        scan_service = MagicMock()
        scan_service.scan = AsyncMock(return_value=MagicMock())
        stub = _make_stub(config=config, fleet_scan_service=scan_service)

        sleep_calls: List[float] = []

        async def _fake_sleep(seconds):
            sleep_calls.append(seconds)
            # After first sleep, flip the flag so the loop exits.
            off_config = _make_config(auto_scan_enabled=False)
            stub.config_manager.get = MagicMock(return_value=off_config)

        with patch("asyncio.sleep", side_effect=_fake_sleep):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        assert len(sleep_calls) >= 1
        assert sleep_calls[0] == 180

    @pytest.mark.asyncio
    async def test_loop_enforces_minimum_interval_of_60(self) -> None:
        """Interval below 60 is clamped to 60."""
        config = _make_config(auto_scan_interval_seconds=5)
        scan_service = MagicMock()
        scan_service.scan = AsyncMock(return_value=MagicMock())
        stub = _make_stub(config=config, fleet_scan_service=scan_service)

        sleep_calls: List[float] = []

        async def _fake_sleep(seconds):
            sleep_calls.append(seconds)
            off_config = _make_config(auto_scan_enabled=False)
            stub.config_manager.get = MagicMock(return_value=off_config)

        with patch("asyncio.sleep", side_effect=_fake_sleep):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        assert sleep_calls[0] == 60

    @pytest.mark.asyncio
    async def test_scan_called_with_stale_only_from_config(self) -> None:
        """scan() receives stale_only from config.memory.auto_scan_stale_only."""
        for expected_stale_only in (True, False):
            config = _make_config(auto_scan_stale_only=expected_stale_only)
            scan_service = MagicMock()
            scan_service.scan = AsyncMock(return_value=MagicMock())
            stub = _make_stub(
                config=config, fleet_scan_service=scan_service
            )
            stub.instances = [{"id": "web-1", "name": "web-1"}]

            # One sleep then exit.
            cycle_count = 0

            async def _fake_sleep_one_cycle(seconds):
                nonlocal cycle_count
                cycle_count += 1
                if cycle_count == 1:
                    # First sleep: return normally so the scan runs.
                    return
                # Second sleep: flip flag off so loop exits cleanly.
                off_config = _make_config(auto_scan_enabled=False)
                stub.config_manager.get = MagicMock(return_value=off_config)

            with patch("asyncio.sleep", side_effect=_fake_sleep_one_cycle):
                await ServonautApp._fleet_auto_scan_loop(  # type: ignore[arg-type]
                    stub
                )

            scan_service.scan.assert_called_with(
                stub.instances,
                stale_only=expected_stale_only,
            )

    @pytest.mark.asyncio
    async def test_last_run_updated_after_successful_scan(self) -> None:
        """_fleet_auto_scan_last_run is updated after a scan completes."""
        config = _make_config()
        scan_service = MagicMock()
        scan_service.scan = AsyncMock(return_value=MagicMock())
        stub = _make_stub(config=config, fleet_scan_service=scan_service)
        stub._fleet_auto_scan_last_run = 0.0

        cycle_count = 0

        async def _fake_sleep(seconds):
            nonlocal cycle_count
            cycle_count += 1
            if cycle_count >= 2:
                off_config = _make_config(auto_scan_enabled=False)
                stub.config_manager.get = MagicMock(return_value=off_config)

        with patch("asyncio.sleep", side_effect=_fake_sleep):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        assert stub._fleet_auto_scan_last_run > 0.0

    @pytest.mark.asyncio
    async def test_loop_survives_scan_exception_and_continues(self) -> None:
        """A scan() that raises must not kill the loop — it keeps iterating."""
        config = _make_config()
        scan_service = MagicMock()
        scan_calls: List[int] = []

        async def _scan(instances, *, stale_only):
            scan_calls.append(1)
            raise RuntimeError("ssh error")

        scan_service.scan = AsyncMock(side_effect=_scan)
        stub = _make_stub(config=config, fleet_scan_service=scan_service)
        stub._fleet_auto_scan_last_run = 0.0

        # Run 2 cycles then exit.
        cycle_count = 0

        async def _fake_sleep(seconds):
            nonlocal cycle_count
            cycle_count += 1
            if cycle_count >= 3:
                off_config = _make_config(auto_scan_enabled=False)
                stub.config_manager.get = MagicMock(return_value=off_config)

        with patch("asyncio.sleep", side_effect=_fake_sleep):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        # Should have attempted 2 scans despite both raising.
        assert len(scan_calls) == 2
        # last_run NOT updated on failure.
        assert stub._fleet_auto_scan_last_run == 0.0

    @pytest.mark.asyncio
    async def test_cancelled_error_during_sleep_exits_loop(self) -> None:
        """CancelledError from asyncio.sleep causes clean loop exit."""
        config = _make_config()
        stub = _make_stub(config=config, fleet_scan_service=MagicMock())

        async def _cancel(seconds):
            raise asyncio.CancelledError()

        with patch("asyncio.sleep", side_effect=_cancel):
            # _fleet_auto_scan_loop catches CancelledError during sleep and returns.
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        # Reaching here means the loop returned cleanly (did not re-raise).

    @pytest.mark.asyncio
    async def test_loop_exits_when_flag_toggled_off_after_sleep(self) -> None:
        """If auto_scan_enabled is flipped to False after the sleep, loop exits."""
        config = _make_config(auto_scan_enabled=True)
        scan_service = MagicMock()
        scan_service.scan = AsyncMock(return_value=MagicMock())
        stub = _make_stub(config=config, fleet_scan_service=scan_service)

        async def _fake_sleep(seconds):
            # After sleeping, flip the flag off so the post-sleep re-read exits.
            off_config = _make_config(auto_scan_enabled=False)
            stub.config_manager.get = MagicMock(return_value=off_config)

        with patch("asyncio.sleep", side_effect=_fake_sleep):
            await ServonautApp._fleet_auto_scan_loop(stub)  # type: ignore[arg-type]

        # Loop should have exited before calling scan.
        scan_service.scan.assert_not_called()


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
