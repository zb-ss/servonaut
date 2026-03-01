"""Tests for configuration schema."""

from servonaut.config.schema import (
    AppConfig,
    ScanRule,
    ConnectionProfile,
    ConnectionRule,
    CONFIG_VERSION,
)


class TestAppConfig:

    def test_defaults(self):
        config = AppConfig()
        assert config.version == CONFIG_VERSION
        assert config.default_key == ""
        assert config.instance_keys == {}
        assert config.default_username == "ec2-user"
        assert config.cache_ttl_seconds == 3600
        assert config.terminal_emulator == "auto"
        assert config.theme == "dark"
        assert config.default_scan_paths == ["~/"]

    def test_custom_values(self):
        config = AppConfig(
            default_key='/path/to/key.pem',
            default_username='ubuntu',
            cache_ttl_seconds=600,
        )
        assert config.default_key == '/path/to/key.pem'
        assert config.default_username == 'ubuntu'
        assert config.cache_ttl_seconds == 600

    def test_mutable_defaults_independent(self):
        config1 = AppConfig()
        config2 = AppConfig()
        config1.instance_keys['i-123'] = '/key.pem'
        assert 'i-123' not in config2.instance_keys


class TestScanRule:

    def test_creation(self):
        rule = ScanRule(
            name='test-rule',
            match_conditions={'name_contains': 'web'},
            scan_paths=['/var/log/'],
            scan_commands=['pm2 list'],
        )
        assert rule.name == 'test-rule'
        assert rule.match_conditions == {'name_contains': 'web'}
        assert rule.scan_paths == ['/var/log/']
        assert rule.scan_commands == ['pm2 list']

    def test_defaults(self):
        rule = ScanRule(name='r', match_conditions={})
        assert rule.scan_paths == []
        assert rule.scan_commands == []


class TestConnectionProfile:

    def test_defaults(self):
        profile = ConnectionProfile(name='test')
        assert profile.bastion_host is None
        assert profile.bastion_user is None
        assert profile.bastion_key is None
        assert profile.proxy_command is None
        assert profile.ssh_port == 22

    def test_full_profile(self):
        profile = ConnectionProfile(
            name='bastion',
            bastion_host='bastion.example.com',
            bastion_user='ec2-user',
            bastion_key='~/.ssh/bastion.pem',
            ssh_port=2222,
        )
        assert profile.bastion_host == 'bastion.example.com'
        assert profile.ssh_port == 2222


class TestConnectionRule:

    def test_creation(self):
        rule = ConnectionRule(
            name='prod',
            match_conditions={'region': 'us-east-1'},
            profile_name='bastion-prod',
        )
        assert rule.profile_name == 'bastion-prod'
        assert rule.match_conditions == {'region': 'us-east-1'}
