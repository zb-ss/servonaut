"""Tests for the app-owned manual fleet scan (survives screen navigation).

The "Scan All" action is owned by ``ServonautApp`` (group ``memory_manual_scan``)
rather than by ``FleetMemoryScreen``, so a scan keeps running and finishes even
when the user leaves the panel. Progress and completion are routed to whichever
Fleet Memory screen is currently mounted via duck-typing, and are safe no-ops
when the user has navigated elsewhere.
"""

import asyncio
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from servonaut.app import ServonautApp


def _make_app():
    app = ServonautApp.__new__(ServonautApp)
    app._fleet_manual_scan_in_progress = False
    app.notify = MagicMock()
    app.fleet_scan_service = MagicMock()
    return app


def _capture_worker(app):
    """Replace run_worker with a capture that stores the coroutine + group."""
    captured = {}

    def run_worker(coro, **kwargs):
        captured["coro"] = coro
        captured["group"] = kwargs.get("group")
        captured["name"] = kwargs.get("name")
        captured["exclusive"] = kwargs.get("exclusive")
        return MagicMock()

    app.run_worker = run_worker
    return captured


def test_start_spawns_app_worker_in_dedicated_group():
    app = _make_app()
    captured = _capture_worker(app)

    started = app.start_fleet_manual_scan([{"id": "web-1"}], stale_only=False)

    assert started is True
    assert app._fleet_manual_scan_in_progress is True
    assert captured["group"] == "memory_manual_scan"
    assert captured["exclusive"] is True
    # Close the un-awaited coroutine to avoid a RuntimeWarning.
    captured["coro"].close()


def test_second_start_is_refused_while_in_progress():
    app = _make_app()
    captured = _capture_worker(app)

    assert app.start_fleet_manual_scan([{"id": "web-1"}], stale_only=False) is True
    # A second launch while one is in progress must NOT spawn another worker.
    spawned_after_first = "coro" in captured
    captured_count_before = captured.copy()
    assert app.start_fleet_manual_scan([{"id": "web-2"}], stale_only=False) is False
    # group/name unchanged — no second spawn occurred.
    assert captured["name"] == captured_count_before["name"]
    captured["coro"].close()
    assert spawned_after_first


def test_progress_routes_to_mounted_fleet_screen():
    app = _make_app()
    screen = MagicMock()  # has _on_scan_progress
    with patch.object(ServonautApp, "screen", new_callable=PropertyMock, return_value=screen):
        progress = MagicMock()
        app._fleet_manual_scan_progress(progress)
        screen._on_scan_progress.assert_called_once_with(progress)


def test_progress_is_noop_when_current_screen_lacks_hook():
    app = _make_app()
    # A screen without _on_scan_progress (user navigated away) must not raise.
    other_screen = MagicMock(spec=[])
    with patch.object(ServonautApp, "screen", new_callable=PropertyMock, return_value=other_screen):
        app._fleet_manual_scan_progress(MagicMock())  # no exception = pass


def test_scan_completes_and_clears_flag_even_without_fleet_screen():
    """The worker finishes in the background and clears the in-progress flag
    via its finally block, even when no Fleet Memory screen is mounted."""
    app = _make_app()
    captured = _capture_worker(app)

    async def fake_scan(instances, *, stale_only, on_progress=None):
        for i, inst in enumerate(instances, 1):
            await asyncio.sleep(0)
            if on_progress:
                on_progress(MagicMock(instance_id=inst["id"], completed=i,
                                      total=len(instances), succeeded=True,
                                      instance_name=inst["id"]))
        result = MagicMock()
        result.succeeded = [inst["id"] for inst in instances]
        result.failed = []
        return result

    app.fleet_scan_service.scan = fake_scan

    other_screen = MagicMock(spec=[])  # no fleet hooks -> user navigated away
    with patch.object(ServonautApp, "screen", new_callable=PropertyMock, return_value=other_screen):
        app.start_fleet_manual_scan([{"id": "web-1"}, {"id": "web-2"}], stale_only=False)
        assert app._fleet_manual_scan_in_progress is True
        asyncio.run(captured["coro"])  # drive the background worker to completion

    assert app._fleet_manual_scan_in_progress is False
    app.notify.assert_called()  # "Fleet scan done: ..." toast fired


def test_completion_hook_fires_on_mounted_fleet_screen():
    app = _make_app()
    captured = _capture_worker(app)

    async def fake_scan(instances, *, stale_only, on_progress=None):
        result = MagicMock()
        result.succeeded = ["web-1"]
        result.failed = []
        return result

    app.fleet_scan_service.scan = fake_scan

    screen = MagicMock()  # has on_fleet_manual_scan_done + _set_progress
    with patch.object(ServonautApp, "screen", new_callable=PropertyMock, return_value=screen):
        app.start_fleet_manual_scan([{"id": "web-1"}], stale_only=False)
        asyncio.run(captured["coro"])
        screen.on_fleet_manual_scan_done.assert_called_once()
