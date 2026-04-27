"""Unit tests for MemoryConfig integration with AppConfig / ConfigManager."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from servonaut.config.schema import AppConfig, MemoryConfig


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
