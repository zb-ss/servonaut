"""Tests for the Memory & Sync settings panel (screens/settings/panels/memory.py).

Exercises the auto-scan toggle and interval validation:
- ``collect()`` validation for auto_scan_interval_seconds (<60, >max, valid)
- ``persist()`` round-trips auto_scan_enabled and auto_scan_interval_seconds
  via dataclasses.replace to disk and verifies they are read back correctly.
- ``persist()`` preserves un-exposed fields (per_server_overrides, etc.) so
  unrelated memory config is not clobbered.

Uses the same ``_PanelHost`` / ``_temp_config_manager`` harness established in
``test_settings_panels_roundtrip.py`` so the panel exercises real Textual
widget mounting, real ConfigManager writes, and real disk round-trips.
"""

from __future__ import annotations

from typing import Optional, Type
from unittest.mock import MagicMock, patch

import pytest
from textual.app import App
from textual.widgets import Input, Static, Switch

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, MemoryConfig
from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.styles import CSS_FILES
from servonaut.screens.settings.panels.memory import MemoryPanel


# ---------------------------------------------------------------------------
# Harness (mirrors test_settings_panels_roundtrip.py)
# ---------------------------------------------------------------------------


def _temp_config_manager(tmp_path, config: AppConfig) -> ConfigManager:
    manager = ConfigManager()
    manager._config_path = tmp_path / "config.json"
    manager._config = config
    manager.save(config)
    return manager


def _reload(tmp_path) -> AppConfig:
    manager = ConfigManager()
    manager._config_path = tmp_path / "config.json"
    return manager.load()


class _PanelHost(App):
    CSS_PATH = CSS_FILES

    def __init__(
        self,
        panel_cls: Type[SettingsPanel],
        manager: ConfigManager,
        has_memory_sync: bool = False,
    ) -> None:
        super().__init__()
        self._panel_cls = panel_cls
        self.config_manager = manager
        self.auth_service = MagicMock()
        self.auth_service.is_authenticated = has_memory_sync
        self.auth_service.has_feature = MagicMock(
            side_effect=lambda feat: feat == "memory_sync" and has_memory_sync
        )
        self.aws_object_storage_service = None
        self.hetzner_object_storage_service = None
        self.ovh_object_storage_service = None
        self.panel: Optional[SettingsPanel] = None

    def on_mount(self) -> None:
        self.panel = self._panel_cls()
        self.mount(self.panel)


# ---------------------------------------------------------------------------
# collect() — interval validation
# ---------------------------------------------------------------------------


class TestMemoryPanelCollectValidation:
    @pytest.mark.asyncio
    async def test_rejects_auto_scan_interval_below_60(self, tmp_path) -> None:
        """collect() raises ValidationError when interval < 60."""
        manager = _temp_config_manager(tmp_path, AppConfig())
        app = _PanelHost(MemoryPanel, manager)
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            panel.query_one("#memory_auto_scan_interval", Input).value = "59"
            with pytest.raises(ValidationError) as exc:
                panel.collect()
            assert exc.value.field_id == "memory_auto_scan_interval"

    @pytest.mark.asyncio
    async def test_rejects_auto_scan_interval_zero(self, tmp_path) -> None:
        """collect() raises ValidationError for interval = 0."""
        manager = _temp_config_manager(tmp_path, AppConfig())
        app = _PanelHost(MemoryPanel, manager)
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            panel.query_one("#memory_auto_scan_interval", Input).value = "0"
            with pytest.raises(ValidationError) as exc:
                panel.collect()
            assert exc.value.field_id == "memory_auto_scan_interval"

    @pytest.mark.asyncio
    async def test_rejects_auto_scan_interval_above_max(self, tmp_path) -> None:
        """collect() raises ValidationError when interval > _MAX_SECONDS."""
        from servonaut.screens.settings.panels.memory import _MAX_SECONDS

        manager = _temp_config_manager(tmp_path, AppConfig())
        app = _PanelHost(MemoryPanel, manager)
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            panel.query_one("#memory_auto_scan_interval", Input).value = str(
                _MAX_SECONDS + 1
            )
            with pytest.raises(ValidationError) as exc:
                panel.collect()
            assert exc.value.field_id == "memory_auto_scan_interval"

    @pytest.mark.asyncio
    async def test_rejects_non_integer_auto_scan_interval(self, tmp_path) -> None:
        """collect() raises ValidationError for a non-integer interval."""
        manager = _temp_config_manager(tmp_path, AppConfig())
        app = _PanelHost(MemoryPanel, manager)
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            panel.query_one("#memory_auto_scan_interval", Input).value = "daily"
            with pytest.raises(ValidationError) as exc:
                panel.collect()
            assert exc.value.field_id == "memory_auto_scan_interval"

    @pytest.mark.asyncio
    async def test_accepts_valid_auto_scan_interval(self, tmp_path) -> None:
        """collect() succeeds for a valid interval (60 ≤ value ≤ _MAX_SECONDS)."""
        manager = _temp_config_manager(tmp_path, AppConfig())
        app = _PanelHost(MemoryPanel, manager)
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            panel.query_one("#memory_auto_scan_interval", Input).value = "3600"
            fields = panel.collect()
        assert fields["auto_scan_interval_seconds"] == 3600

    @pytest.mark.asyncio
    async def test_accepts_minimum_interval_60(self, tmp_path) -> None:
        """collect() accepts the minimum valid value of exactly 60."""
        manager = _temp_config_manager(tmp_path, AppConfig())
        app = _PanelHost(MemoryPanel, manager)
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            panel.query_one("#memory_auto_scan_interval", Input).value = "60"
            fields = panel.collect()
        assert fields["auto_scan_interval_seconds"] == 60


# ---------------------------------------------------------------------------
# persist() — round-trip via disk + preserve unexposed fields
# ---------------------------------------------------------------------------


class TestMemoryPanelPersistRoundTrip:
    @pytest.mark.asyncio
    async def test_auto_scan_enabled_persists(self, tmp_path) -> None:
        """Toggling auto-scan enabled writes the value through to disk."""
        manager = _temp_config_manager(tmp_path, AppConfig())
        app = _PanelHost(MemoryPanel, manager)
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            panel.query_one("#memory_auto_scan_enabled", Switch).value = True
            panel.query_one("#memory_auto_scan_interval", Input).value = "7200"
            panel.persist()
            await pilot.pause()

        mc = _reload(tmp_path).memory
        assert mc.auto_scan_enabled is True
        assert mc.auto_scan_interval_seconds == 7200

    @pytest.mark.asyncio
    async def test_persist_preserves_per_server_overrides(self, tmp_path) -> None:
        """persist() must NOT clobber per_server_overrides (unexposed field)."""
        seeded_mem = MemoryConfig(
            per_server_overrides={
                "i-abc123": {"memory_disabled": True},
            }
        )
        seeded = AppConfig(memory=seeded_mem)
        manager = _temp_config_manager(tmp_path, seeded)
        app = _PanelHost(MemoryPanel, manager)
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            # Enable auto-scan (a new field) and save.
            panel.query_one("#memory_auto_scan_enabled", Switch).value = True
            panel.query_one("#memory_auto_scan_interval", Input).value = "3600"
            panel.persist()
            await pilot.pause()

        fresh = _reload(tmp_path).memory
        # New field written correctly.
        assert fresh.auto_scan_enabled is True
        assert fresh.auto_scan_interval_seconds == 3600
        # Unexposed field preserved verbatim — the central correctness invariant.
        assert fresh.per_server_overrides == {
            "i-abc123": {"memory_disabled": True}
        }

    @pytest.mark.asyncio
    async def test_persist_preserves_disabled_modules_alongside_new_fields(
        self, tmp_path
    ) -> None:
        """disabled_modules (exposed) and per_server_overrides (not) both survive."""
        seeded_mem = MemoryConfig(
            disabled_modules=["containers"],
            per_server_overrides={"db-1": {"memory_disabled": False}},
        )
        seeded = AppConfig(memory=seeded_mem)
        manager = _temp_config_manager(tmp_path, seeded)
        app = _PanelHost(MemoryPanel, manager)
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            panel.query_one("#memory_auto_scan_enabled", Switch).value = True
            panel.query_one("#memory_auto_scan_interval", Input).value = "86400"
            panel.persist()
            await pilot.pause()

        fresh = _reload(tmp_path).memory
        assert fresh.auto_scan_enabled is True
        assert "containers" in fresh.disabled_modules
        assert fresh.per_server_overrides == {"db-1": {"memory_disabled": False}}


# ---------------------------------------------------------------------------
# Device auto-unlock — read-only status and setup navigation
# ---------------------------------------------------------------------------


def _auto_unlock_status(panel: SettingsPanel) -> str:
    """Return the rendered read-only auto-unlock status."""
    return panel.query_one("#memory_device_auto_unlock_status", Static).render().plain


class TestMemoryPanelDeviceAutoUnlock:
    @pytest.mark.asyncio
    async def test_shows_unavailable_without_a_trusted_os_keychain(
        self, tmp_path
    ) -> None:
        """The panel never implies auto-unlock works without a trusted backend."""
        manager = _temp_config_manager(tmp_path, AppConfig())
        with patch(
            "servonaut.services.memory.passphrase_store.keyring_available",
            return_value=False,
        ):
            app = _PanelHost(MemoryPanel, manager)
            async with app.run_test() as pilot:
                await pilot.pause()
                assert _auto_unlock_status(app.panel) == (
                    "Unavailable (no trusted OS keychain)"
                )

    @pytest.mark.asyncio
    async def test_shows_off_when_the_device_has_not_opted_in(self, tmp_path) -> None:
        """A usable keychain remains off until setup explicitly remembers it."""
        manager = _temp_config_manager(tmp_path, AppConfig())
        with patch(
            "servonaut.services.memory.passphrase_store.keyring_available",
            return_value=True,
        ):
            app = _PanelHost(MemoryPanel, manager)
            async with app.run_test() as pilot:
                await pilot.pause()
                assert _auto_unlock_status(app.panel) == "Off"

    @pytest.mark.asyncio
    async def test_shows_on_with_the_reprompt_window(self, tmp_path) -> None:
        """A remembered device identifies the bounded automatic-unlock period."""
        config = AppConfig(memory=MemoryConfig(sync_remember_device=True))
        manager = _temp_config_manager(tmp_path, config)
        with patch(
            "servonaut.services.memory.passphrase_store.keyring_available",
            return_value=True,
        ):
            app = _PanelHost(MemoryPanel, manager)
            async with app.run_test() as pilot:
                await pilot.pause()
                assert _auto_unlock_status(app.panel) == "On (30-day re-prompt)"

    @pytest.mark.asyncio
    async def test_manage_opens_setup_without_marking_form_dirty(
        self, tmp_path
    ) -> None:
        """Management delegates to Memory Sync setup and changes no form state."""
        from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

        manager = _temp_config_manager(tmp_path, AppConfig())
        with patch(
            "servonaut.services.memory.passphrase_store.keyring_available",
            return_value=True,
        ):
            app = _PanelHost(MemoryPanel, manager)
            app.push_screen = MagicMock()
            async with app.run_test(size=(140, 48)) as pilot:
                await pilot.pause()
                assert app.panel.is_dirty() is False

                await pilot.click("#memory_manage_device_auto_unlock")
                await pilot.pause()

                app.push_screen.assert_called_once()
                screen = app.push_screen.call_args.args[0]
                assert isinstance(screen, MemorySyncSetupScreen)
                assert app.panel.is_dirty() is False
                assert manager.get().memory.sync_remember_device is False
