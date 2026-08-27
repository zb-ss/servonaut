"""Regression tests for manual Memory Sync UI behavior."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Button, Static

from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen


class _AuthStub:
    is_authenticated = True
    _token = SimpleNamespace(plan="solo")

    @staticmethod
    def has_feature(feature: str) -> bool:
        return feature == "memory_sync"


class _SetupSyncStub:
    """Two-batch sync whose second batch can be held during navigation."""

    is_configured = True

    def __init__(self) -> None:
        self.pending = 0
        self.last_sync_at = None
        self.quota = None
        self.drain_calls = 0
        self.second_batch_started = asyncio.Event()
        self.release_second_batch = asyncio.Event()

    @property
    def status(self) -> SimpleNamespace:
        return SimpleNamespace(
            state="idle",
            last_sync_at=self.last_sync_at,
            last_error=None,
            pending_envelopes=self.pending,
            quota=self.quota,
            halted_reason=None,
        )

    @staticmethod
    def is_enrolled_locally() -> bool:
        return True

    @staticmethod
    def get_key_material() -> None:
        return None

    def backfill_from_local_store(self) -> int:
        self.pending = 2
        return 2

    async def drain_now(self) -> SimpleNamespace:
        self.drain_calls += 1
        if self.drain_calls == 1:
            self.pending = 1
            self.last_sync_at = datetime.now(tz=timezone.utc).isoformat()
            self.quota = SimpleNamespace(
                envelopes_used=1,
                envelopes_soft_cap=100,
            )
            return SimpleNamespace(accepted=["first"], rejected=[])
        if self.drain_calls == 2:
            self.second_batch_started.set()
            await self.release_second_batch.wait()
            self.pending = 0
            self.last_sync_at = datetime.now(tz=timezone.utc).isoformat()
            self.quota = SimpleNamespace(
                envelopes_used=2,
                envelopes_soft_cap=100,
            )
            return SimpleNamespace(accepted=["second"], rejected=[])
        return SimpleNamespace(accepted=[], rejected=[])

    @staticmethod
    async def pull_annotations(instance_id: str, name: str, provider: str) -> str:
        return "unchanged"

    @staticmethod
    async def pull_findings(instance_id: str, name: str, provider: str) -> str:
        return "unchanged"


class _ElsewhereScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Static("Elsewhere", id="elsewhere")


class _SetupApp(App):
    def __init__(self, sync_service: _SetupSyncStub) -> None:
        super().__init__()
        self.auth_service = _AuthStub()
        self.memory_sync_service = sync_service
        self.memory_service = MagicMock()
        self.memory_service.list_all.return_value = []
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = SimpleNamespace(
            memory=SimpleNamespace(
                sync_remember_device=False,
                sync_remember_expires_at="",
            )
        )
        self.notifications: list[str] = []

    def on_mount(self) -> None:
        self.push_screen(MemorySyncSetupScreen())

    def notify(self, message: str, **kwargs: object) -> None:
        self.notifications.append(message)


@pytest.mark.asyncio
async def test_sync_card_repaints_and_job_survives_navigation() -> None:
    sync = _SetupSyncStub()
    app = _SetupApp(sync)

    with patch(
        "servonaut.services.memory.passphrase_store.keyring_available",
        return_value=False,
    ):
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause()
            button = app.screen.query_one("#msync_btn_sync_now", Button)
            assert str(button.label) == "Sync all local memory"

            await pilot.click("#msync_btn_sync_now")
            await asyncio.wait_for(sync.second_batch_started.wait(), timeout=2)
            await pilot.pause()

            pending = (
                app.screen.query_one("#msync_pending_value", Static).render().plain
            )
            progress = app.screen.query_one("#msync_status", Static).render().plain
            assert pending == "1 envelope(s)"
            assert "1 uploaded" in progress

            app.switch_screen(_ElsewhereScreen())
            await pilot.pause()
            sync.release_second_batch.set()

            for _ in range(20):
                if not getattr(app, "_memory_manual_sync_in_progress", False):
                    break
                await pilot.pause(0.05)

            assert sync.pending == 0
            assert sync.drain_calls == 3
            assert not getattr(app, "_memory_manual_sync_in_progress", False)

            app.switch_screen(MemorySyncSetupScreen())
            await pilot.pause()
            refreshed_pending = (
                app.screen.query_one("#msync_pending_value", Static).render().plain
            )
            refreshed_last_sync = (
                app.screen.query_one("#msync_last_sync_value", Static).render().plain
            )
            assert refreshed_pending == "0 envelope(s)"
            assert refreshed_last_sync != "never"
