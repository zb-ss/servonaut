"""Regression tests for the instance-dashboard Memory screen."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Static

from servonaut.screens.memory import MemoryScreen


_INSTANCE = {
    "id": "server-1",
    "name": "Example server",
    "provider": "custom",
}


def _module(module_name: str) -> dict[str, object]:
    """Return a freshly probed memory module."""
    return {
        "module": module_name,
        "instance_id": _INSTANCE["id"],
        "observed": {"version": "1.0"},
        "declared": {},
        "probed_at": datetime.now(tz=timezone.utc).isoformat(),
        "ttl_seconds": 86400,
    }


def _memory_service(modules: dict[str, dict[str, object]]) -> MagicMock:
    """Return a memory service whose store can change while mounted."""
    service = MagicMock()
    service.snapshot_stale_seconds = 86400
    service.is_memory_disabled.return_value = False
    service.get_all_modules.side_effect = lambda *_args: dict(modules)
    service.stale_modules.return_value = []
    return service


def _never_synced_service() -> MagicMock:
    """Return an active cloud-sync service with no completed sync."""
    service = MagicMock()
    service.is_configured = True
    service.status = SimpleNamespace(
        state="idle",
        pending_envelopes=0,
        last_sync_at=None,
        halted_reason=None,
    )
    return service


class _PerServerSyncStub:
    is_configured = True

    def __init__(self) -> None:
        self.pending = 0
        self.last_sync_at = None
        self.backfill_instance_ids: list[str] = []
        self.drain_instance_ids: list[str] = []

    @property
    def status(self) -> SimpleNamespace:
        return SimpleNamespace(
            state="idle",
            pending_envelopes=self.pending,
            last_sync_at=self.last_sync_at,
            last_error=None,
            halted_reason=None,
        )

    def backfill_from_local_store(self, instance_id: str | None = None) -> int:
        self.backfill_instance_ids.append(instance_id or "")
        self.pending = 1
        return 1

    def pending_count(self, instance_id: str | None = None) -> int:
        return self.pending

    async def drain_now(self, *, instance_id: str | None = None) -> SimpleNamespace:
        self.drain_instance_ids.append(instance_id or "")
        if self.pending:
            self.pending = 0
            self.last_sync_at = datetime.now(tz=timezone.utc).isoformat()
            return SimpleNamespace(accepted=["os"], rejected=[])
        return SimpleNamespace(accepted=[], rejected=[])

    @staticmethod
    async def pull_annotations(instance_id: str, name: str, provider: str) -> str:
        return "unchanged"

    @staticmethod
    async def pull_findings(instance_id: str, name: str, provider: str) -> str:
        return "unchanged"


class _MemoryApp(App):
    """Minimal host app for the per-instance Memory screen."""

    def __init__(
        self,
        modules: dict[str, dict[str, object]],
        *,
        auth_service: MagicMock | None = None,
        sync_service: MagicMock | None = None,
    ) -> None:
        super().__init__()
        self.demo_mode = False
        self.redaction_service = None
        self.memory_service = _memory_service(modules)
        self.memory_sync_service = sync_service
        self.auth_service = auth_service
        self.ai_summary_service = MagicMock()

    def on_mount(self) -> None:
        self.push_screen(MemoryScreen(dict(_INSTANCE)))


@pytest.mark.asyncio
async def test_fresh_scan_is_distinct_from_never_synced_cloud_state() -> None:
    """Fresh local memory must not be presented as an unsynchronised scan."""
    modules = {"os": _module("os"), "services": _module("services")}
    app = _MemoryApp(modules, sync_service=_never_synced_service())

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)

        local_status = app.screen.query_one("#memory-local-status", Static)
        cloud_status = app.screen.query_one("#memory-sync-status", Static)

        local_text = str(local_status.render())
        cloud_text = str(cloud_status.render())
        assert "Memory scan: ● Fresh" in local_text
        assert "2 modules" in local_text
        assert "last probe" in local_text
        assert "Cloud sync: idle" in cloud_text
        assert "last: never" in cloud_text


@pytest.mark.asyncio
async def test_sync_this_server_backfills_and_drains_only_that_server() -> None:
    modules = {"os": _module("os")}
    sync = _PerServerSyncStub()
    app = _MemoryApp(modules, sync_service=sync)

    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await pilot.pause(0.2)
        button = app.screen.query_one("#btn_sync_now", Button)
        assert str(button.label) == "S. Sync This Server"

        await pilot.click("#btn_sync_now")
        for _ in range(20):
            if not getattr(app, "_memory_manual_sync_in_progress", False):
                break
            await pilot.pause(0.05)

        assert sync.backfill_instance_ids == [_INSTANCE["id"]]
        assert sync.drain_instance_ids == [
            _INSTANCE["id"],
            _INSTANCE["id"],
        ]
        cloud_status = (
            app.screen.query_one("#memory-sync-status", Static).render().plain
        )
        assert "last: never" not in cloud_status
        assert "0 pending" in cloud_status


@pytest.mark.asyncio
async def test_fleet_scan_refresh_hook_reloads_status_and_module_rows() -> None:
    """The app-owned fleet scan hook must update an already-mounted screen."""
    modules: dict[str, dict[str, object]] = {}
    app = _MemoryApp(modules)

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        table = screen.query_one("#memory-table", DataTable)
        status = screen.query_one("#memory-local-status", Static)

        assert "Not probed" in str(status.render())
        assert table.row_count == 0

        modules["os"] = _module("os")
        screen.refresh_memory_status()
        await pilot.pause()

        assert "Fresh" in str(status.render())
        assert "1 module" in str(status.render())
        assert table.row_count == 1


@pytest.mark.asyncio
async def test_ai_summary_rechecks_account_override_before_upsell() -> None:
    """A freshly returned test-account override must unlock the summary flow."""
    entitlement = {"enabled": False}
    auth = MagicMock()
    auth.is_authenticated = True
    auth.plan = "solo"
    auth.has_feature.side_effect = lambda feature: (
        feature == "memory_ai_summary" and entitlement["enabled"]
    )

    async def _fetch_entitlements() -> dict[str, bool]:
        entitlement["enabled"] = True
        return {"memory_ai_summary": True}

    auth.fetch_entitlements = AsyncMock(side_effect=_fetch_entitlements)
    app = _MemoryApp({}, auth_service=auth)

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        flow = AsyncMock()
        screen._do_ai_summary_flow = flow

        screen.action_build_ai_summary()
        for _ in range(20):
            await pilot.pause(0.01)
            if flow.await_count:
                break

        auth.fetch_entitlements.assert_awaited_once_with()
        flow.assert_awaited_once_with("server-1")
        assert app.screen is screen


@pytest.mark.asyncio
async def test_ai_summary_still_upsells_unentitled_solo_after_refresh() -> None:
    """Refreshing entitlements must not unlock an ordinary Solo account."""
    from servonaut.widgets.upsell_modal import UpsellModal

    auth = MagicMock()
    auth.is_authenticated = True
    auth.plan = "solo"
    auth.has_feature.return_value = False
    auth.fetch_entitlements = AsyncMock(return_value={"memory_ai_summary": False})
    app = _MemoryApp({}, auth_service=auth)

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        app.screen.action_build_ai_summary()
        for _ in range(20):
            await pilot.pause(0.01)
            if isinstance(app.screen, UpsellModal):
                break

        auth.fetch_entitlements.assert_awaited_once_with()
        assert isinstance(app.screen, UpsellModal)


@pytest.mark.asyncio
async def test_ai_summary_rechecks_cached_access_before_proceeding() -> None:
    """A removed override must take effect before the summary flow starts."""
    from servonaut.widgets.upsell_modal import UpsellModal

    entitlement = {"enabled": True}
    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature.side_effect = lambda feature: (
        feature == "memory_ai_summary" and entitlement["enabled"]
    )

    async def _fetch_entitlements() -> dict[str, bool]:
        entitlement["enabled"] = False
        return {"memory_ai_summary": False}

    auth.fetch_entitlements = AsyncMock(side_effect=_fetch_entitlements)
    app = _MemoryApp({}, auth_service=auth)

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        app.screen.action_build_ai_summary()
        for _ in range(20):
            await pilot.pause(0.01)
            if isinstance(app.screen, UpsellModal):
                break

        auth.fetch_entitlements.assert_awaited_once_with()
        assert isinstance(app.screen, UpsellModal)


@pytest.mark.asyncio
async def test_ai_summary_refresh_failure_does_not_show_false_upsell() -> None:
    """An unverifiable entitlement must produce a retry warning, not an upsell."""
    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature.return_value = False
    auth.fetch_entitlements = AsyncMock(return_value=None)
    app = _MemoryApp({}, auth_service=auth)
    app.notify = MagicMock()

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        await screen._start_ai_summary_flow()

        auth.fetch_entitlements.assert_awaited_once_with()
        app.notify.assert_called_once_with(
            "Could not verify AI summary access. Check your connection and retry.",
            severity="warning",
        )
        assert app.screen is screen


@pytest.mark.asyncio
async def test_ai_summary_server_denial_explains_entitlement_projection() -> None:
    """A backend 403 after local access must not be presented as a generic error."""
    from servonaut.services.memory.interfaces import UpsellRequired

    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature.return_value = True
    auth.fetch_entitlements = AsyncMock(return_value={"memory_ai_summary": True})
    app = _MemoryApp({}, auth_service=auth)
    app.ai_summary_service.get_provider_info = AsyncMock(
        side_effect=UpsellRequired("memory_ai_summary")
    )
    app.notify = MagicMock()

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        await app.screen._start_ai_summary_flow()

        app.notify.assert_called_once_with(
            "AI summary access was accepted locally, but the server denied it. "
            "Your account entitlement has not reached the summary API yet.",
            severity="error",
            markup=False,
        )
