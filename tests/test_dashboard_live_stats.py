"""Exercise the dashboard's compact SSH metrics in a real Textual application."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual.app import App
from textual.screen import Screen
from textual.widgets import Button, Static

from servonaut.config.schema import AppConfig
from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.services.connection_service import ConnectionService
from servonaut.services.live_stats_service import LiveStatsService
from servonaut.styles import CSS_FILES


class MonitoringApp(App):
    CSS_PATH = CSS_FILES
    demo_mode = False
    memory_service = None
    redaction_service = None

    def __init__(self, runner: AsyncMock) -> None:
        super().__init__()
        self.config = AppConfig()
        self.config.ssh.live_stats_interval_seconds = 0.05
        self.config_manager = Mock()
        self.config_manager.get.return_value = self.config
        self.connection_service = ConnectionService(self.config_manager)
        self.live_stats_service = LiveStatsService(lambda row: runner, self.config.ssh)
        self.ovh_snapshot_service = SimpleNamespace(
            list_vps_snapshots=AsyncMock(return_value=[]),
            get_vps_backup_options=AsyncMock(return_value={}),
        )

    def connection_instance(self, instance: dict) -> dict:
        return instance

    def real_instance_id(self, instance_id: str) -> str:
        return instance_id


def panel_text(screen: Screen) -> str:
    return str(screen.query_one("#live_stats", Static).content)


async def wait_for(pilot, predicate) -> None:
    for _ in range(100):
        if predicate():
            return
        await pilot.pause(0.01)
    raise AssertionError("Monitoring did not reach the expected state")


@pytest.mark.asyncio
async def test_live_controls_failure_retry_and_navigation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A denied connection must stop, then recover when the user fixes access.
    runner = AsyncMock(return_value=("", "Permission denied (publickey)", 255))
    app = MonitoringApp(runner)
    monkeypatch.setattr(ServerActionsScreen, "_fetch_rdns", AsyncMock())
    instance = {"id": "vps-web-1", "name": "web-1", "provider_type": "vps", "is_ovh": True, "public_ip": "192.0.2.1"}
    async with app.run_test(size=(155, 47)) as pilot:
        screen = ServerActionsScreen(instance)
        await app.push_screen(screen)
        assert not screen.query("#btn_ovh_monitoring")
        await pilot.press("l")
        await wait_for(pilot, lambda: "authentication failed" in panel_text(screen))
        assert not screen._live_on
        assert "retry" in panel_text(screen)
        await pilot.pause(0.1)
        assert runner.await_count == 1

        runner.return_value = ("SVN_MEM\nMem: 1000 250 750\n", "", 0)
        await pilot.press("L")
        await wait_for(pilot, lambda: "25%" in panel_text(screen))
        assert screen._live_on
        await pilot.press("l")
        assert not screen._live_on
        calls = runner.await_count
        await pilot.pause(0.1)
        assert runner.await_count == calls

        await pilot.press("l")
        await wait_for(pilot, lambda: runner.await_count > calls)
        await app.push_screen(Screen())
        assert not screen._live_on
        calls = runner.await_count
        await pilot.pause(0.1)
        assert runner.await_count == calls


@pytest.mark.asyncio
async def test_snapshots_remain_accessible_without_starting_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = AsyncMock()
    app = MonitoringApp(runner)
    monkeypatch.setattr(ServerActionsScreen, "_fetch_rdns", AsyncMock())
    async with app.run_test(size=(155, 47)) as pilot:
        screen = ServerActionsScreen({"id": "vps-web-1", "name": "web-1", "provider_type": "vps", "is_ovh": True, "public_ip": "192.0.2.1"})
        await app.push_screen(screen)
        screen.query_one("#btn_ovh_snapshots", Button).focus()
        await pilot.press("enter")
        await wait_for(pilot, lambda: isinstance(app.screen, OVHSnapshotsScreen))
        await wait_for(pilot, lambda: app.ovh_snapshot_service.list_vps_snapshots.await_count == 1)
        app.ovh_snapshot_service.list_vps_snapshots.assert_awaited_once_with("vps-web-1")
        await pilot.press("escape")
        assert app.screen is screen
        runner.assert_not_called()


@pytest.mark.asyncio
async def test_leaving_during_connect_cancels_pending_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def pending(command: str) -> tuple[str, str, int]:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    app = MonitoringApp(AsyncMock(side_effect=pending))
    monkeypatch.setattr(ServerActionsScreen, "_fetch_rdns", AsyncMock())
    async with app.run_test(size=(155, 47)) as pilot:
        await app.push_screen(ServerActionsScreen({"id": "vps-web-1", "name": "web-1", "provider_type": "vps", "is_ovh": True, "public_ip": "192.0.2.1"}))
        await pilot.press("l")
        await asyncio.wait_for(started.wait(), timeout=5)
        await pilot.press("escape")
        await asyncio.wait_for(cancelled.wait(), timeout=5)
