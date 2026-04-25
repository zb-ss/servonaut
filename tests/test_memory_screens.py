"""Tests for memory cloud-sync UI screens and widgets (Stream 4).

Covers:
- PassphraseEnrolModal: mount, strength readout, confirm button state
- MemoryDriftScreen: mount, tier-gate pushes UpsellModal when has_feature is False
- MemorySettingsScreen: render with mocked settings_service
- MemoryExportScreen: render, entitlement gate
- ShareInstanceModal: render with mocked team_service
- UpsellModal / BetaWaitlistModal / BackendMaintenanceModal: render for known keys
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button, Input, Select, Static


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_with_feature(features: dict[str, bool]) -> MagicMock:
    """Return a mock AuthService whose has_feature() uses *features* mapping."""
    auth = MagicMock()
    auth.has_feature = MagicMock(side_effect=lambda slug: features.get(slug, False))
    auth.list_teams = AsyncMock(return_value=[])
    auth.is_authenticated = True
    return auth


def _make_settings_service(*, digest: str = "weekly", mercure: bool = True) -> MagicMock:
    """Build a settings service mock that returns a real MemorySettings dataclass.

    Using the real dataclass instead of MagicMock catches field-name typos
    in the screen — a MagicMock would happily resolve any attribute access.
    """
    from servonaut.services.memory.interfaces import MemorySettings
    svc = MagicMock()
    settings = MemorySettings(
        digest_frequency=digest,
        mercure_push_enabled=mercure,
        anomaly_rules={},
        raw={},
        ai_consent_mode="off",
    )
    svc.get_settings = AsyncMock(return_value=settings)
    svc.patch_settings = AsyncMock(return_value=settings)
    return svc


def _make_drift_service(events: list | None = None) -> MagicMock:
    svc = MagicMock()
    events = events or []
    svc.list_drift = AsyncMock(return_value=events)
    svc.acknowledge_drift = AsyncMock(return_value=None)
    return svc


# ---------------------------------------------------------------------------
# PassphraseEnrolModal
# ---------------------------------------------------------------------------


class _EnrolApp(App):
    """Minimal host that pushes PassphraseEnrolModal."""

    def __init__(self, mode: str = "enrol") -> None:
        super().__init__()
        self._mode = mode
        self.dismissed_value = "__sentinel__"

    def on_mount(self) -> None:
        from servonaut.screens.memory_keys import PassphraseEnrolModal

        def _on_dismiss(result):
            self.dismissed_value = result

        self.push_screen(PassphraseEnrolModal(mode=self._mode), _on_dismiss)


class TestPassphraseEnrolModal:
    @pytest.mark.asyncio
    async def test_modal_mounts(self):
        app = _EnrolApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            container = app.screen.query("#enrol-container")
            assert len(container) == 1

    @pytest.mark.asyncio
    async def test_confirm_button_disabled_initially(self):
        app = _EnrolApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            btn = app.screen.query_one("#enrol-btn-confirm", Button)
            assert btn.disabled is True

    @pytest.mark.asyncio
    async def test_strength_readout_updates_on_input(self):
        app = _EnrolApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            input1 = app.screen.query_one("#enrol-pass1", Input)
            await pilot.click("#enrol-pass1")
            await pilot.press("a", "b", "c")
            await pilot.pause()
            strength = app.screen.query_one("#enrol-strength", Static)
            rendered = strength.content
            assert rendered != "Strength: —"

    @pytest.mark.asyncio
    async def test_escape_dismisses_with_none(self):
        app = _EnrolApp()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            assert app.dismissed_value is None

    @pytest.mark.asyncio
    async def test_unlock_mode_mounts(self):
        app = _EnrolApp(mode="unlock")
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            title = app.screen.query_one("#enrol-title", Static)
            assert "Unlock" in str(title.content)


# ---------------------------------------------------------------------------
# UpsellModal / BetaWaitlistModal / BackendMaintenanceModal
# ---------------------------------------------------------------------------


class _ModalHostApp(App):
    """Host that can push any ModalScreen."""

    def __init__(self, modal_cls, *args, **kwargs) -> None:
        super().__init__()
        self._modal_cls = modal_cls
        self._args = args
        self._kwargs = kwargs

    def on_mount(self) -> None:
        self.push_screen(self._modal_cls(*self._args, **self._kwargs))


class TestUpsellModal:
    @pytest.mark.asyncio
    async def test_renders_for_memory_sync(self):
        from servonaut.widgets.upsell_modal import UpsellModal

        app = _ModalHostApp(UpsellModal, "memory_sync")
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            container = app.screen.query("#upsell-container")
            assert len(container) == 1

    @pytest.mark.asyncio
    async def test_renders_for_memory_drift(self):
        from servonaut.widgets.upsell_modal import UpsellModal

        app = _ModalHostApp(UpsellModal, "memory_drift")
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            title = app.screen.query_one("#upsell-title", Static)
            assert "Drift" in str(title.content)

    @pytest.mark.asyncio
    async def test_close_button_dismisses(self):
        from servonaut.widgets.upsell_modal import UpsellModal

        app = _ModalHostApp(UpsellModal, "memory_ai_summary")
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.click("#upsell-btn-close")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_escape_dismisses(self):
        from servonaut.widgets.upsell_modal import UpsellModal

        app = _ModalHostApp(UpsellModal, "memory_compliance_export")
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()

    @pytest.mark.asyncio
    async def test_beta_waitlist_modal_mounts(self):
        from servonaut.widgets.upsell_modal import BetaWaitlistModal

        app = _ModalHostApp(BetaWaitlistModal)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            container = app.screen.query("#waitlist-container")
            assert len(container) == 1

    @pytest.mark.asyncio
    async def test_maintenance_modal_mounts(self):
        from servonaut.widgets.upsell_modal import BackendMaintenanceModal

        app = _ModalHostApp(BackendMaintenanceModal)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            container = app.screen.query("#maintenance-container")
            assert len(container) == 1


# ---------------------------------------------------------------------------
# MemoryDriftScreen — tier gate
# ---------------------------------------------------------------------------


class _DriftApp(App):
    """Host that mounts MemoryDriftScreen with configurable auth."""

    def __init__(self, has_drift_feature: bool = True) -> None:
        super().__init__()
        self.auth_service = _auth_with_feature({"memory_drift": has_drift_feature})
        self.drift_service = _make_drift_service()
        self.upsell_pushes: list = []

    def on_mount(self) -> None:
        from servonaut.screens.memory_drift import MemoryDriftScreen
        self.push_screen(MemoryDriftScreen())

    def push_screen(self, screen, callback=None):
        from servonaut.widgets.upsell_modal import UpsellModal
        if isinstance(screen, UpsellModal):
            self.upsell_pushes.append(screen)
        return super().push_screen(screen, callback)


class TestMemoryDriftScreen:
    @pytest.mark.asyncio
    async def test_mounts_with_entitlement(self):
        app = _DriftApp(has_drift_feature=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            container = app.screen.query("#drift-container")
            assert len(container) == 1

    @pytest.mark.asyncio
    async def test_tier_gate_pushes_upsell_when_no_feature(self):
        app = _DriftApp(has_drift_feature=False)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            # UpsellModal should have been pushed
            assert len(app.upsell_pushes) == 1


# ---------------------------------------------------------------------------
# MemorySettingsScreen
# ---------------------------------------------------------------------------


class _SettingsApp(App):
    """Host that mounts MemorySettingsScreen."""

    def __init__(self, has_sync_feature: bool = True) -> None:
        super().__init__()
        self.auth_service = _auth_with_feature({"memory_sync": has_sync_feature})
        self.memory_settings_service = _make_settings_service()
        self.upsell_pushes: list = []

    def on_mount(self) -> None:
        from servonaut.screens.memory_settings import MemorySettingsScreen
        self.push_screen(MemorySettingsScreen())

    def push_screen(self, screen, callback=None):
        from servonaut.widgets.upsell_modal import UpsellModal
        if isinstance(screen, UpsellModal):
            self.upsell_pushes.append(screen)
        return super().push_screen(screen, callback)


class TestMemorySettingsScreen:
    @pytest.mark.asyncio
    async def test_renders_with_mocked_settings_service(self):
        app = _SettingsApp(has_sync_feature=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await pilot.pause()  # allow load worker
            form = app.screen.query("#settings-form")
            assert len(form) == 1

    @pytest.mark.asyncio
    async def test_tier_gate_pushes_upsell_when_no_feature(self):
        app = _SettingsApp(has_sync_feature=False)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            assert len(app.upsell_pushes) == 1

    @pytest.mark.asyncio
    async def test_save_button_present(self):
        app = _SettingsApp(has_sync_feature=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            btn = app.screen.query("#btn-settings-save")
            assert len(btn) == 1


# ---------------------------------------------------------------------------
# MemoryExportScreen
# ---------------------------------------------------------------------------


class _ExportApp(App):
    """Host that mounts MemoryExportScreen."""

    def __init__(self, has_export_feature: bool = True) -> None:
        super().__init__()
        self.auth_service = _auth_with_feature(
            {"memory_compliance_export": has_export_feature}
        )
        self.export_service = MagicMock()
        self.export_service.export = AsyncMock(return_value="/tmp/test-export.tar.gz")
        self.export_service.verify_export = AsyncMock(return_value=True)
        self.upsell_pushes: list = []

    def on_mount(self) -> None:
        from servonaut.screens.memory_export import MemoryExportScreen
        self.push_screen(MemoryExportScreen())

    def push_screen(self, screen, callback=None):
        from servonaut.widgets.upsell_modal import UpsellModal
        if isinstance(screen, UpsellModal):
            self.upsell_pushes.append(screen)
        return super().push_screen(screen, callback)


class TestMemoryExportScreen:
    @pytest.mark.asyncio
    async def test_renders_with_entitlement(self):
        app = _ExportApp(has_export_feature=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            container = app.screen.query("#export-container")
            assert len(container) == 1

    @pytest.mark.asyncio
    async def test_tier_gate_pushes_upsell_when_no_feature(self):
        app = _ExportApp(has_export_feature=False)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            assert len(app.upsell_pushes) == 1

    @pytest.mark.asyncio
    async def test_start_export_button_present(self):
        app = _ExportApp(has_export_feature=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            btn = app.screen.query("#btn-export-start")
            assert len(btn) == 1


# ---------------------------------------------------------------------------
# ShareInstanceModal
# ---------------------------------------------------------------------------


class _ShareApp(App):
    """Host that mounts ShareInstanceModal."""

    def __init__(self, has_share_feature: bool = True) -> None:
        super().__init__()
        self.auth_service = _auth_with_feature(
            {"memory_team_share": has_share_feature}
        )
        self.team_memory_service = MagicMock()
        self.team_memory_service.list_team_member_keys = AsyncMock(return_value=[])
        self.team_memory_service.share_instance = AsyncMock(return_value=MagicMock())
        self.dismissed_value = "__sentinel__"
        self.upsell_pushes: list = []
        self._instance = {
            "id": "i-test123",
            "name": "test-server",
            "provider": "aws",
        }

    def on_mount(self) -> None:
        from servonaut.screens.memory_share import ShareInstanceModal

        def _on_dismiss(result):
            self.dismissed_value = result

        self.push_screen(ShareInstanceModal(self._instance), _on_dismiss)

    def push_screen(self, screen, callback=None):
        from servonaut.widgets.upsell_modal import UpsellModal
        if isinstance(screen, UpsellModal):
            self.upsell_pushes.append(screen)
        return super().push_screen(screen, callback)


class TestShareInstanceModal:
    @pytest.mark.asyncio
    async def test_renders_with_entitlement(self):
        app = _ShareApp(has_share_feature=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            container = app.screen.query("#share-container")
            assert len(container) == 1

    @pytest.mark.asyncio
    async def test_instance_name_in_title(self):
        app = _ShareApp(has_share_feature=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            title = app.screen.query_one("#share-title", Static)
            assert "test-server" in str(title.content)

    @pytest.mark.asyncio
    async def test_cancel_dismisses_with_none(self):
        app = _ShareApp(has_share_feature=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await pilot.click("#share-btn-cancel")
            await pilot.pause()
            assert app.dismissed_value is None

    @pytest.mark.asyncio
    async def test_escape_dismisses_with_none(self):
        app = _ShareApp(has_share_feature=True)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            assert app.dismissed_value is None
