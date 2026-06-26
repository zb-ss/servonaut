"""Tests for configuration schema."""

from servonaut.config.schema import (
    AppConfig,
    MCPConfig,
    ScanRule,
    ConnectionProfile,
    ConnectionRule,
    SSHConfig,
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


class TestSSHConfig:

    def test_defaults(self):
        cfg = SSHConfig()
        assert cfg.server_alive_interval == 30
        assert cfg.server_alive_count_max == 5
        assert cfg.tcp_keepalive is True
        assert cfg.connect_timeout == 15

    def test_custom_values(self):
        cfg = SSHConfig(
            server_alive_interval=60,
            server_alive_count_max=3,
            tcp_keepalive=False,
            connect_timeout=30,
        )
        assert cfg.server_alive_interval == 60
        assert cfg.server_alive_count_max == 3
        assert cfg.tcp_keepalive is False
        assert cfg.connect_timeout == 30


class TestMCPConfigTimeouts:

    def test_default_timeouts(self):
        cfg = MCPConfig()
        assert cfg.command_timeout_seconds == 60
        assert cfg.transfer_timeout_seconds == 300

    def test_custom_timeouts(self):
        cfg = MCPConfig(command_timeout_seconds=300, transfer_timeout_seconds=600)
        assert cfg.command_timeout_seconds == 300
        assert cfg.transfer_timeout_seconds == 600


class TestAppConfigAdditiveSshField:

    def test_app_config_has_ssh_field_with_defaults(self):
        """AppConfig() must expose .ssh with SSHConfig defaults (additive)."""
        config = AppConfig()
        assert hasattr(config, 'ssh')
        assert isinstance(config.ssh, SSHConfig)
        assert config.ssh.server_alive_interval == 30
        assert config.ssh.connect_timeout == 15

    def test_app_config_ssh_independent_across_instances(self):
        """Mutable default isolation — two AppConfig() share no state."""
        c1 = AppConfig()
        c2 = AppConfig()
        c1.ssh.server_alive_interval = 999
        assert c2.ssh.server_alive_interval == 30

    def test_app_config_loaded_without_ssh_key_uses_defaults(self):
        """Old configs that lack the 'ssh' key load cleanly via AppConfig()."""
        # Simulate what the manager does: AppConfig(**config_dict) where
        # config_dict has no 'ssh' key.
        config_dict = {'default_key': '/some/key', 'default_username': 'ubuntu'}
        config = AppConfig(**config_dict)
        assert isinstance(config.ssh, SSHConfig)
        assert config.ssh.server_alive_interval == 30

    def test_app_config_mcp_timeout_defaults(self):
        config = AppConfig()
        assert config.mcp.command_timeout_seconds == 60
        assert config.mcp.transfer_timeout_seconds == 300
