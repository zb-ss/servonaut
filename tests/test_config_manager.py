"""Tests for configuration manager."""

import json

import pytest

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import (
    AppConfig,
    ConnectionProfile,
    ConnectionRule,
    CONFIG_VERSION,
)


class TestConfigManager:

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Config manager with temp path."""
        manager = ConfigManager()
        manager._config_path = tmp_path / 'config.json'
        return manager

    def test_load_default_when_no_file(self, config_manager):
        config = config_manager.load()
        assert isinstance(config, AppConfig)
        assert config.version == CONFIG_VERSION
        assert config.default_username == 'ec2-user'

    def test_save_and_load(self, config_manager):
        config = AppConfig(default_username='ubuntu', cache_ttl_seconds=600)
        config_manager.save(config)
        config_manager._config = None
        loaded = config_manager.load()
        assert loaded.default_username == 'ubuntu'
        assert loaded.cache_ttl_seconds == 600

    def test_get_caches_config(self, config_manager):
        config1 = config_manager.get()
        config2 = config_manager.get()
        assert config1 is config2

    def test_update(self, config_manager):
        config_manager.get()
        updated = config_manager.update(cache_ttl_seconds=1200, theme='light')
        assert updated.cache_ttl_seconds == 1200
        assert updated.theme == 'light'

    def test_update_ignores_unknown_fields(self, config_manager):
        config_manager.get()
        updated = config_manager.update(nonexistent_field='value')
        assert not hasattr(updated, 'nonexistent_field')

    def test_save_and_load_with_profiles(self, config_manager):
        config = AppConfig(
            connection_profiles=[
                ConnectionProfile(
                    name='bastion',
                    bastion_host='bastion.example.com',
                    bastion_user='ec2-user',
                    ssh_port=22,
                )
            ],
            connection_rules=[
                ConnectionRule(
                    name='prod',
                    match_conditions={'region': 'us-east-1'},
                    profile_name='bastion',
                )
            ],
        )
        config_manager.save(config)
        config_manager._config = None
        loaded = config_manager.load()
        assert len(loaded.connection_profiles) == 1
        assert loaded.connection_profiles[0].name == 'bastion'
        assert loaded.connection_profiles[0].bastion_host == 'bastion.example.com'
        assert len(loaded.connection_rules) == 1
        assert loaded.connection_rules[0].profile_name == 'bastion'

    def test_load_corrupted_json(self, config_manager):
        config_manager._config_path.write_text('not valid json{{{')
        config = config_manager.load()
        assert isinstance(config, AppConfig)
        assert config.version == CONFIG_VERSION

    def test_validate_negative_ttl(self, config_manager):
        config = AppConfig(cache_ttl_seconds=-1)
        warnings = config_manager._validate(config)
        assert any('negative' in w for w in warnings)

    def test_validate_invalid_ssh_port(self, config_manager):
        config = AppConfig(
            connection_profiles=[
                ConnectionProfile(name='bad', ssh_port=99999)
            ]
        )
        warnings = config_manager._validate(config)
        assert any('port' in w.lower() for w in warnings)

    def test_validate_missing_profile_reference(self, config_manager):
        config = AppConfig(
            connection_rules=[
                ConnectionRule(
                    name='rule',
                    match_conditions={},
                    profile_name='nonexistent',
                )
            ]
        )
        warnings = config_manager._validate(config)
        assert any('nonexistent' in w for w in warnings)

    def test_v1_migration(self, config_manager):
        v1_data = {
            'instance_keys': {'i-abc123': '/path/to/key.pem'},
            'default_key': '/path/to/default.pem',
        }
        config_manager._config_path.write_text(json.dumps(v1_data))
        config = config_manager.load()
        assert config.version == CONFIG_VERSION
        assert config.instance_keys == {'i-abc123': '/path/to/key.pem'}
        assert config.default_key == '/path/to/default.pem'
        assert config.default_username == 'ec2-user'

    def test_update_persists_to_disk(self, config_manager):
        config_manager.get()
        config_manager.update(default_username='admin')
        config_manager._config = None
        reloaded = config_manager.load()
        assert reloaded.default_username == 'admin'
