"""Unit tests for MemoryConfig integration with AppConfig / ConfigManager."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from servonaut.config.schema import (
    AppConfig,
    MemoryConfig,
    DEFAULT_AUTO_SCAN_INTERVAL_SECONDS,
    DEFAULT_SNAPSHOT_STALE_SECONDS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def default_app_config() -> AppConfig:
    return AppConfig()


# ---------------------------------------------------------------------------
# MemoryConfig defaults
# ---------------------------------------------------------------------------

class TestMemoryConfigDefaults:
    def test_memory_field_exists_on_app_config(
        self, default_app_config: AppConfig
    ) -> None:
        assert hasattr(default_app_config, "memory")
        assert isinstance(default_app_config.memory, MemoryConfig)

    def test_enabled_defaults_true(self, default_app_config: AppConfig) -> None:
        assert default_app_config.memory.enabled is True

    def test_redaction_defaults_true(self, default_app_config: AppConfig) -> None:
        assert default_app_config.memory.redaction_enabled is True

    def test_disabled_modules_defaults_empty(
        self, default_app_config: AppConfig
    ) -> None:
        assert default_app_config.memory.disabled_modules == []

    def test_default_ttl_overrides_defaults_empty(
        self, default_app_config: AppConfig
    ) -> None:
        assert default_app_config.memory.default_ttl_overrides == {}

    def test_per_server_overrides_defaults_empty(
        self, default_app_config: AppConfig
    ) -> None:
        assert default_app_config.memory.per_server_overrides == {}

    # -- new auto-scan fields -----------------------------------

    def test_auto_scan_enabled_defaults_false(
        self, default_app_config: AppConfig
    ) -> None:
        assert default_app_config.memory.auto_scan_enabled is False

    def test_auto_scan_interval_seconds_defaults_to_constant(
        self, default_app_config: AppConfig
    ) -> None:
        assert (
            default_app_config.memory.auto_scan_interval_seconds
            == DEFAULT_AUTO_SCAN_INTERVAL_SECONDS
        )

    def test_auto_scan_interval_seconds_value(
        self, default_app_config: AppConfig
    ) -> None:
        # The module-level constant must match the documented 24-hour default.
        assert DEFAULT_AUTO_SCAN_INTERVAL_SECONDS == 86400
        assert default_app_config.memory.auto_scan_interval_seconds == 86400

    def test_auto_scan_stale_only_defaults_true(
        self, default_app_config: AppConfig
    ) -> None:
        assert default_app_config.memory.auto_scan_stale_only is True

    def test_memory_config_bare_construction_has_auto_scan_fields(self) -> None:
        """MemoryConfig(**{}) absorbs the auto-scan fields from defaults."""
        mc = MemoryConfig()
        assert mc.auto_scan_enabled is False
        assert mc.auto_scan_interval_seconds == DEFAULT_AUTO_SCAN_INTERVAL_SECONDS
        assert mc.auto_scan_stale_only is True

    def test_auto_sync_enabled_not_on_memory_config(self) -> None:
        """auto_sync_enabled has been moved server-side; it must NOT be a MemoryConfig field."""
        mc = MemoryConfig()
        assert not hasattr(mc, "auto_sync_enabled"), (
            "auto_sync_enabled must no longer live in MemoryConfig — "
            "it is now server-side in MemorySettings"
        )

    def test_app_config_dict_construction_absorbs_auto_scan_fields(self) -> None:
        """AppConfig(**dict) with a bare 'memory' key sets auto-scan fields at defaults."""
        cfg = AppConfig(**{"default_username": "ubuntu"})
        assert cfg.memory.auto_scan_enabled is False
        assert cfg.memory.auto_scan_stale_only is True


# ---------------------------------------------------------------------------
# Round-trip through ConfigManager save/load
# ---------------------------------------------------------------------------

class TestMemoryConfigRoundTrip:
    def test_config_survives_json_roundtrip(self, tmp_path: Path) -> None:
        """MemoryConfig must survive the ConfigManager's JSON load path."""
        from servonaut.config.manager import ConfigManager

        config_path = tmp_path / "config.json"

        # Build config with non-default memory settings.
        config = AppConfig()
        config.memory.enabled = False
        config.memory.disabled_modules = ["containers", "git"]
        config.memory.default_ttl_overrides = {"services": 1800}
        config.memory.per_server_overrides = {
            "i-critical": {"memory_disabled": True}
        }

        # Save via ConfigManager.
        manager = ConfigManager()
        manager._config_path = config_path
        manager.save(config)

        # Reload from disk.
        manager2 = ConfigManager()
        manager2._config_path = config_path
        mc = manager2.load().memory

        assert mc.enabled is False
        assert "containers" in mc.disabled_modules
        assert "git" in mc.disabled_modules
        assert mc.default_ttl_overrides == {"services": 1800}
        assert mc.per_server_overrides["i-critical"]["memory_disabled"] is True

    def test_auto_scan_fields_round_trip(self, tmp_path: Path) -> None:
        """auto_scan_enabled, auto_scan_interval_seconds, and auto_scan_stale_only
        all survive the JSON save/load cycle."""
        from servonaut.config.manager import ConfigManager

        config_path = tmp_path / "config.json"

        import dataclasses
        config = AppConfig()
        config.memory = dataclasses.replace(
            config.memory,
            auto_scan_enabled=True,
            auto_scan_interval_seconds=3600,
            auto_scan_stale_only=False,
        )

        manager = ConfigManager()
        manager._config_path = config_path
        manager.save(config)

        manager2 = ConfigManager()
        manager2._config_path = config_path
        mc = manager2.load().memory

        assert mc.auto_scan_enabled is True
        assert mc.auto_scan_interval_seconds == 3600
        assert mc.auto_scan_stale_only is False

    def test_existing_disk_config_without_new_fields_loads_cleanly(
        self, tmp_path: Path
    ) -> None:
        """A config.json that pre-dates the new fields loads with safe defaults."""
        from servonaut.config.manager import ConfigManager

        config_path = tmp_path / "config.json"
        # Write a minimal v5 config with no 'auto_*' keys inside memory.
        old_config = {
            "version": 5,
            "memory": {
                "enabled": True,
                "redaction_enabled": True,
            },
        }
        config_path.write_text(json.dumps(old_config))

        manager = ConfigManager()
        manager._config_path = config_path
        mc = manager.load().memory

        assert mc.auto_scan_enabled is False
        assert mc.auto_scan_interval_seconds == DEFAULT_AUTO_SCAN_INTERVAL_SECONDS
        assert mc.auto_scan_stale_only is True


# ---------------------------------------------------------------------------
# is_module_enabled
# ---------------------------------------------------------------------------

class TestIsModuleEnabled:
    def test_all_enabled_by_default(self) -> None:
        config = MemoryConfig()
        assert config.is_module_enabled("i-abc", "runtimes") is True
        assert config.is_module_enabled("i-abc", "os") is True

    def test_disabled_module_globally(self) -> None:
        config = MemoryConfig(disabled_modules=["containers"])
        assert config.is_module_enabled("i-abc", "containers") is False
        assert config.is_module_enabled("i-abc", "runtimes") is True

    def test_memory_disabled_per_server_disables_all_modules(self) -> None:
        config = MemoryConfig(
            per_server_overrides={"i-critical": {"memory_disabled": True}}
        )
        assert config.is_module_enabled("i-critical", "runtimes") is False
        assert config.is_module_enabled("i-critical", "os") is False
        # Other instances are unaffected.
        assert config.is_module_enabled("i-safe", "runtimes") is True

    def test_per_server_override_false_does_not_disable(self) -> None:
        config = MemoryConfig(
            per_server_overrides={"i-abc": {"memory_disabled": False}}
        )
        assert config.is_module_enabled("i-abc", "runtimes") is True


# ---------------------------------------------------------------------------
# is_module_disabled_for
# ---------------------------------------------------------------------------

class TestIsModuleDisabledFor:
    def test_not_disabled_by_default(self) -> None:
        config = MemoryConfig()
        assert config.is_module_disabled_for("i-abc") is False

    def test_disabled_when_flag_set(self) -> None:
        config = MemoryConfig(
            per_server_overrides={"i-prod": {"memory_disabled": True}}
        )
        assert config.is_module_disabled_for("i-prod") is True
        assert config.is_module_disabled_for("i-dev") is False

    def test_enabled_when_flag_explicitly_false(self) -> None:
        config = MemoryConfig(
            per_server_overrides={"i-prod": {"memory_disabled": False}}
        )
        assert config.is_module_disabled_for("i-prod") is False
