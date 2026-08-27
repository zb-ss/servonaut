"""Tests for memory cloud-sync UI screens and widgets (Stream 4).

Covers:
- PassphraseEnrolModal: mount, strength readout, confirm button state
- MemoryDriftScreen: mount, tier-gate pushes UpsellModal when has_feature is False
- MemoryExportScreen: render, entitlement gate
- ShareInstanceModal: render with mocked team_service
- UpsellModal / BetaWaitlistModal / BackendMaintenanceModal: render for known keys
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button, Input, Select, Static, Switch

from servonaut.styles import CSS_FILES


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


def _make_settings_service(
    *,
    digest: str = "weekly",
    mercure: bool = True,
    auto_sync: bool = False,
) -> MagicMock:
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
        auto_sync_enabled=auto_sync,
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

    def __init__(
        self,
        mode: str = "enrol",
        *,
        remember_default: bool = False,
    ) -> None:
        super().__init__()
        self._mode = mode
        self._remember_default = remember_default
        self.dismissed_value = "__sentinel__"

    def on_mount(self) -> None:
        from servonaut.screens.memory_keys import PassphraseEnrolModal

        def _on_dismiss(result):
            self.dismissed_value = result

        modal = PassphraseEnrolModal(
            mode=self._mode,
            remember_default=self._remember_default,
        )
        self.push_screen(modal, _on_dismiss)


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

    @pytest.mark.asyncio
    async def test_remember_copy_explains_keychain_and_30_day_window(self):
        app = _EnrolApp(mode="unlock")
        async with app.run_test(size=(100, 24)) as pilot:
            await pilot.pause()
            label = app.screen.query_one("#enrol-remember-label", Static)
            rendered = str(label.render())
            assert "30 days" in rendered
            assert "OS keychain" in rendered

    @pytest.mark.asyncio
    async def test_remember_can_be_preselected_by_explicit_manage_action(self):
        app = _EnrolApp(mode="unlock", remember_default=True)
        async with app.run_test(size=(100, 24)) as pilot:
            await pilot.pause()
            remember = app.screen.query_one("#enrol-remember", Switch)
            assert remember.value is True


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
# SettingsScreen — Memory Sync section
# (Replaces the deleted MemorySettingsScreen tests after consolidation.)
# ---------------------------------------------------------------------------


def _make_sync_service(*, configured: bool) -> MagicMock:
    """Mock memory_sync_service exposing only what the settings gate inspects."""
    sync = MagicMock()
    sync.is_configured = configured
    return sync


class _SettingsApp(App):
    """Host that mounts the real SettingsScreen with mocked dependencies.

    Loads the production CSS bundle (styles/) so tests catch layout regressions
    (e.g. a Container collapsing to height=1 because no `height: auto`
    rule exists for it).
    """

    CSS_PATH = CSS_FILES

    def __init__(
        self,
        *,
        has_memory_sync_feature: bool,
        sync_configured: bool,
    ) -> None:
        super().__init__()
        from servonaut.config.schema import AppConfig
        # Real config object — settings.py touches a lot of attributes
        # during _load_settings and _populate_*.
        self._config = AppConfig()
        self.config_manager = MagicMock()
        self.config_manager.get = MagicMock(return_value=self._config)
        self.auth_service = _auth_with_feature(
            {"memory_sync": has_memory_sync_feature}
        )
        self.memory_settings_service = _make_settings_service()
        self.memory_sync_service = _make_sync_service(configured=sync_configured)
        # OVH and config_sync nav are unrelated; the screen only needs
        # them to exist as either a service or None.
        self.ovh_service = None
        self.config_sync_service = None

    def on_mount(self) -> None:
        from servonaut.screens.settings import SettingsScreen
        self.push_screen(SettingsScreen())


async def _open_memory_sync_panel(app, pilot) -> None:
    """Switch the settings shell to the Memory Sync panel.

    Post-refactor the settings screen is a master/detail shell that mounts
    each category as a panel (hidden unless active). The Memory Sync panel is
    not the default, so we activate it via the shell's switch before asserting.
    """
    app.screen._switch_to("memory_sync")
    await pilot.pause()
    await pilot.pause()


class TestSettingsScreenMemorySync:
    """Verify the Memory Sync panel's gating + load path.

    Gate: the form section is visible ONLY for authenticated users with the
    ``memory_sync`` entitlement. Non-entitled users get the discovery
    affordance via the sidebar, not via an upsell in the settings panel.
    """

    @pytest.mark.asyncio
    async def test_section_hidden_when_not_entitled(self):
        app = _SettingsApp(has_memory_sync_feature=False, sync_configured=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_memory_sync_panel(app, pilot)
            section = app.screen.query_one("#settings_msync_section")
            assert section.display is False

    @pytest.mark.asyncio
    async def test_section_visible_but_disabled_when_entitled_not_configured(self):
        app = _SettingsApp(has_memory_sync_feature=True, sync_configured=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_memory_sync_panel(app, pilot)
            section = app.screen.query_one("#settings_msync_section")
            assert section.display is True
            # Regression: without `height: auto` on the section container it
            # collapses to height=1 and renders all children on a single row —
            # display=True but invisible to the user. The section needs enough
            # rows for the note + status banner + 3 setting rows + button row.
            assert section.size.height >= 10, (
                f"Section visually collapsed: height={section.size.height}"
            )
            # Inputs + buttons must be disabled so the user cannot edit
            # values that have no backing keypair to encrypt against.
            for wid in (
                "#settings_msync_digest",
                "#settings_msync_mercure",
                "#settings_msync_ai_mode",
                "#btn_msync_save",
                "#btn_msync_reload",
            ):
                assert app.screen.query_one(wid).disabled is True
            status = app.screen.query_one("#settings_msync_status", Static)
            assert "Memory Sync is locked" in str(status.render())

    @pytest.mark.asyncio
    async def test_section_loads_settings_when_entitled_and_configured(self):
        app = _SettingsApp(has_memory_sync_feature=True, sync_configured=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_memory_sync_panel(app, pilot)
            await pilot.pause()  # let the load worker run
            await pilot.pause()
            section = app.screen.query_one("#settings_msync_section")
            assert section.display is True
            # Inputs come from the mocked settings_service (digest=weekly,
            # mercure=True, ai_consent_mode="off")
            digest = app.screen.query_one("#settings_msync_digest", Select)
            assert digest.value == "weekly"
            mercure = app.screen.query_one("#settings_msync_mercure", Switch)
            assert mercure.value is True
            assert app.memory_settings_service.get_settings.await_count == 1

    @pytest.mark.asyncio
    async def test_auto_sync_switch_loads_from_settings(self):
        """The auto-sync switch value is populated from MemorySettings.auto_sync_enabled."""
        app = _SettingsApp(has_memory_sync_feature=True, sync_configured=True)
        # Override the settings service to return auto_sync_enabled=True.
        app.memory_settings_service = _make_settings_service(auto_sync=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_memory_sync_panel(app, pilot)
            await pilot.pause()
            await pilot.pause()
            auto_sync_sw = app.screen.query_one("#settings_msync_auto_sync", Switch)
            assert auto_sync_sw.value is True

    @pytest.mark.asyncio
    async def test_auto_sync_switch_defaults_false_from_settings(self):
        """The auto-sync switch is False when settings returns auto_sync_enabled=False."""
        app = _SettingsApp(has_memory_sync_feature=True, sync_configured=True)
        app.memory_settings_service = _make_settings_service(auto_sync=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_memory_sync_panel(app, pilot)
            await pilot.pause()
            await pilot.pause()
            auto_sync_sw = app.screen.query_one("#settings_msync_auto_sync", Switch)
            assert auto_sync_sw.value is False

    @pytest.mark.asyncio
    async def test_auto_sync_delta_sent_on_save(self):
        """Toggling auto-sync and saving sends auto_sync_enabled in the PATCH delta."""
        from unittest.mock import call
        from servonaut.services.memory.interfaces import MemorySettings

        # Start with auto_sync=False so toggling to True produces a delta.
        app = _SettingsApp(has_memory_sync_feature=True, sync_configured=True)
        updated_settings = MemorySettings(
            digest_frequency="weekly",
            mercure_push_enabled=True,
            anomaly_rules={},
            raw={},
            ai_consent_mode="off",
            auto_sync_enabled=True,
        )
        svc = _make_settings_service(auto_sync=False)
        svc.patch_settings = AsyncMock(return_value=updated_settings)
        app.memory_settings_service = svc
        # Provide a no-op _refresh_memory_sync_loop so the panel's await doesn't crash.
        async def _noop_refresh():
            pass
        app._refresh_memory_sync_loop = _noop_refresh

        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _open_memory_sync_panel(app, pilot)
            await pilot.pause()
            await pilot.pause()
            # Toggle the switch on.
            auto_sync_sw = app.screen.query_one("#settings_msync_auto_sync", Switch)
            auto_sync_sw.value = True
            # Click Save.
            await pilot.click("#btn_msync_save")
            await pilot.pause()
            await pilot.pause()

        # patch_settings must have been called with the delta including auto_sync_enabled.
        patch_calls = svc.patch_settings.call_args_list
        assert len(patch_calls) >= 1
        last_call_kwargs = patch_calls[-1].kwargs if patch_calls[-1].kwargs else {}
        last_call_args = patch_calls[-1].args
        # patch_settings is called as svc.patch_settings(delta_dict)
        sent_delta = last_call_args[0] if last_call_args else last_call_kwargs.get("delta", {})
        assert "auto_sync_enabled" in sent_delta
        assert sent_delta["auto_sync_enabled"] is True

    @pytest.mark.asyncio
    async def test_auto_unlock_status_refreshes_after_manage_screen_back(self):
        """Returning from Manage refreshes the device-local unlock status."""
        from dataclasses import replace
        from types import SimpleNamespace

        from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

        with patch(
            "servonaut.services.memory.passphrase_store.keyring_available",
            return_value=True,
        ):
            app = _SettingsApp(
                has_memory_sync_feature=True,
                sync_configured=True,
            )
            app.memory_sync_service.status = SimpleNamespace(
                last_sync_at=None,
                quota=None,
                pending_envelopes=0,
            )
            app.memory_sync_service.get_key_material.return_value = None
            async with app.run_test(size=(140, 48)) as pilot:
                await pilot.pause()
                app.screen._switch_to("memory")
                await pilot.pause()
                panel = app.screen._panels["memory"]
                status = panel.query_one(
                    "#memory_device_auto_unlock_status", Static
                )
                assert status.render().plain == "Off"

                await pilot.click("#memory_manage_device_auto_unlock")
                await pilot.pause()
                assert isinstance(app.screen, MemorySyncSetupScreen)

                app._config.memory = replace(
                    app._config.memory,
                    sync_remember_device=True,
                )
                await pilot.press("escape")
                await pilot.pause()
                assert status.render().plain == "On (30-day re-prompt)"


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
        from servonaut.screens.memory_share import ShareInstanceScreen
        self.push_screen(ShareInstanceScreen(self._instance))

    def push_screen(self, screen, callback=None):
        from servonaut.widgets.upsell_modal import UpsellModal
        if isinstance(screen, UpsellModal):
            self.upsell_pushes.append(screen)
        return super().push_screen(screen, callback)


class TestShareInstanceScreen:
    @pytest.mark.asyncio
    async def test_renders_with_entitlement(self):
        app = _ShareApp(has_share_feature=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            container = app.screen.query("#share-container")
            assert len(container) == 1
            # Sidebar must be present — this is the whole point of the
            # ModalScreen → Screen conversion.
            assert len(app.screen.query("Sidebar")) == 1

    @pytest.mark.asyncio
    async def test_instance_name_in_title(self):
        app = _ShareApp(has_share_feature=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            title = app.screen.query_one("#share-title", Static)
            assert "test-server" in str(title.render())

    @pytest.mark.asyncio
    async def test_cancel_pops_screen(self):
        app = _ShareApp(has_share_feature=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            stack_depth_before = len(app.screen_stack)
            await pilot.click("#share-btn-cancel")
            await pilot.pause()
            assert len(app.screen_stack) == stack_depth_before - 1

    @pytest.mark.asyncio
    async def test_escape_pops_screen(self):
        app = _ShareApp(has_share_feature=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            stack_depth_before = len(app.screen_stack)
            await pilot.press("escape")
            await pilot.pause()
            assert len(app.screen_stack) == stack_depth_before - 1
