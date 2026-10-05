"""Native-vault migration preserves preferences and explicit file consent."""

import pytest

from servonaut.config.manager import ConfigManager
from servonaut.config.migration import migrate_to_latest
from servonaut.config.schema import CONFIG_VERSION, VaultConfig


def test_migration_preserves_old_configuration_and_safe_defaults(tmp_path):
    original = {"version": 6, "default_username": "operator", "instance_keys": {"web-1": "key"}}
    migrated = migrate_to_latest(original)
    assert original["version"] == 6
    assert migrated["version"] == CONFIG_VERSION
    assert migrated["default_username"] == "operator"
    assert migrated["vault"]["allow_file_key_store"] is False
    manager = ConfigManager(config_path=tmp_path / "config.json")
    loaded = manager._deserialize(migrated)
    assert isinstance(loaded.vault, VaultConfig)
    manager.save(loaded)
    assert manager.load().vault == loaded.vault


def test_existing_vault_preferences_survive_migration():
    data = {"version": 6, "vault": {"strict_verification": True, "auto_grant": False}}
    result = migrate_to_latest(data)
    assert result["vault"]["strict_verification"] is True
    assert result["vault"]["auto_grant"] is False
    assert migrate_to_latest(result) == result


@pytest.mark.parametrize("value", ["true", 1, None])
def test_file_key_store_requires_boolean_consent(value):
    with pytest.raises(ValueError, match="boolean"):
        VaultConfig(allow_file_key_store=value)


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), True])
def test_timeouts_are_positive_finite_numbers(value):
    with pytest.raises(ValueError):
        VaultConfig(request_timeout_seconds=value)
