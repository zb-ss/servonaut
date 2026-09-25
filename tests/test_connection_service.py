"""Tests for connection service."""

import pytest
from unittest.mock import MagicMock

from servonaut.services.connection_service import ConnectionService
from servonaut.config.schema import (
    AppConfig,
    ConnectionProfile,
    ConnectionRule,
)


class TestConnectionService:

    @pytest.fixture
    def config_with_profiles(self):
        return AppConfig(
            connection_profiles=[
                ConnectionProfile(
                    name='bastion-prod',
                    bastion_host='bastion.example.com',
                    bastion_user='ec2-user',
                    bastion_key='~/.ssh/bastion.pem',
                    ssh_port=22,
                ),
                ConnectionProfile(
                    name='proxy-staging',
                    bastion_host='proxy.staging.com',
                    bastion_user='ubuntu',
                    ssh_port=2222,
                ),
                ConnectionProfile(
                    name='custom-proxy',
                    proxy_command='ssh -W %h:%p myproxy',
                ),
            ],
            connection_rules=[
                ConnectionRule(
                    name='prod-rule',
                    match_conditions={'name_contains': 'prod', 'region': 'us-east-1'},
                    profile_name='bastion-prod',
                ),
                ConnectionRule(
                    name='staging-rule',
                    match_conditions={'name_contains': 'staging'},
                    profile_name='proxy-staging',
                ),
            ],
        )

    @pytest.fixture
    def service(self, config_with_profiles):
        manager = MagicMock()
        manager.get.return_value = config_with_profiles
        return ConnectionService(manager)


class TestResolveProfile(TestConnectionService):

    def test_matches_first_rule(self, service):
        instance = {'id': 'i-123', 'name': 'web-prod', 'region': 'us-east-1'}
        profile = service.resolve_profile(instance)
        assert profile is not None
        assert profile.name == 'bastion-prod'


    def test_matches_second_rule(self, service):
        instance = {'id': 'i-456', 'name': 'api-staging', 'region': 'us-west-2'}
        profile = service.resolve_profile(instance)
        assert profile is not None
        assert profile.name == 'proxy-staging'

    def test_no_match_returns_none(self, service):
        instance = {'id': 'i-789', 'name': 'dev-server', 'region': 'eu-west-1'}
        profile = service.resolve_profile(instance)
        assert profile is None

    def test_first_match_wins(self, service):
        instance = {'id': 'i-999', 'name': 'prod-staging-crossover', 'region': 'us-east-1'}
        profile = service.resolve_profile(instance)
        assert profile.name == 'bastion-prod'


class TestGetProxyArgs(TestConnectionService):

    def test_with_bastion_key_uses_proxy_command(self, service):
        profile = ConnectionProfile(
            name='test',
            bastion_host='bastion.example.com',
            bastion_user='ec2-user',
            bastion_key='~/.ssh/bastion.pem',
        )
        args = service.get_proxy_args(profile)
        assert args[0] == '-o'
        assert 'ProxyCommand=' in args[1]
        assert 'bastion.example.com' in args[1]
        assert 'IdentitiesOnly=yes' in args[1]
        # Keepalive options must be present in the inner bastion ssh command
        assert 'ServerAliveInterval=30' in args[1]
        assert 'ServerAliveCountMax=5' in args[1]
        assert 'TCPKeepAlive=yes' in args[1]
        assert 'ConnectTimeout=15' in args[1]

    def test_without_bastion_key_uses_proxy_command(self, service, monkeypatch):
        # -J would not carry the host-key options to the bastion hop.
        monkeypatch.setattr(
            'servonaut.services.connection_service.get_os', lambda: 'linux',
        )
        profile = ConnectionProfile(
            name='test',
            bastion_host='bastion.example.com',
            bastion_user='ubuntu',
        )
        args = service.get_proxy_args(profile)
        assert args[0] == '-o'
        assert args[1].startswith('ProxyCommand=ssh ')
        assert '-o StrictHostKeyChecking=accept-new' in args[1]
        assert args[1].endswith(
            f"-W '[%h]:%p' -- {profile.bastion_user}@{profile.bastion_host}"
        )
        assert ' -i ' not in args[1]

    def test_explicit_proxy_command(self, service):
        profile = ConnectionProfile(
            name='test',
            proxy_command='ssh -W %h:%p myproxy',
        )
        args = service.get_proxy_args(profile)
        assert args == ['-o', 'ProxyCommand=ssh -W %h:%p myproxy']

    def test_no_bastion_returns_empty(self, service):
        profile = ConnectionProfile(name='test')
        assert service.get_proxy_args(profile) == []

    def test_none_profile_returns_empty(self, service):
        assert service.get_proxy_args(None) == []

    def test_custom_port_proxy_command(self, service, monkeypatch):
        monkeypatch.setattr(
            'servonaut.services.connection_service.get_os', lambda: 'linux',
        )
        profile = ConnectionProfile(
            name='test',
            bastion_host='bastion.example.com',
            bastion_user='ec2-user',
            ssh_port=2222,
        )
        args = service.get_proxy_args(profile)
        destination = f'{profile.bastion_user}@{profile.bastion_host}'
        assert f"-p 2222 -W '[%h]:%p' -- {destination}" in args[1]

    def test_bastion_key_with_custom_port(self, service):
        profile = ConnectionProfile(
            name='test',
            bastion_host='bastion.example.com',
            bastion_user='ec2-user',
            bastion_key='~/.ssh/key.pem',
            ssh_port=2222,
        )
        args = service.get_proxy_args(profile)
        proxy_cmd = args[1]
        assert '-p' in proxy_cmd
        assert '2222' in proxy_cmd
        # Keepalive options present even with custom port
        assert 'ServerAliveInterval=30' in proxy_cmd


class TestGetProxyJumpString(TestConnectionService):

    def test_basic(self, service):
        profile = ConnectionProfile(
            name='test',
            bastion_host='bastion.example.com',
            bastion_user='ec2-user',
        )
        assert service.get_proxy_jump_string(profile) == 'ec2-user@bastion.example.com'

    def test_with_custom_port(self, service):
        profile = ConnectionProfile(
            name='test',
            bastion_host='bastion.example.com',
            bastion_user='ec2-user',
            ssh_port=2222,
        )
        assert service.get_proxy_jump_string(profile) == 'ec2-user@bastion.example.com:2222'

    def test_no_bastion_host(self, service):
        profile = ConnectionProfile(name='test')
        assert service.get_proxy_jump_string(profile) is None

    def test_no_user(self, service):
        profile = ConnectionProfile(name='test', bastion_host='bastion.example.com')
        assert service.get_proxy_jump_string(profile) == 'bastion.example.com'


class TestGetTargetHost(TestConnectionService):

    def test_direct_prefers_public_ip(self, service):
        instance = {'public_ip': '9.9.9.9', 'private_ip': '10.0.1.1'}
        assert service.get_target_host(instance) == '9.9.9.9'

    def test_direct_falls_back_to_private(self, service):
        instance = {'public_ip': None, 'private_ip': '10.0.1.1'}
        assert service.get_target_host(instance) == '10.0.1.1'

    def test_bastion_prefers_private_ip(self, service):
        instance = {'public_ip': '9.9.9.9', 'private_ip': '10.0.1.1'}
        profile = ConnectionProfile(name='test', bastion_host='bastion.example.com')
        assert service.get_target_host(instance, profile) == '10.0.1.1'

    def test_bastion_falls_back_to_public(self, service):
        instance = {'public_ip': '9.9.9.9', 'private_ip': None}
        profile = ConnectionProfile(name='test', bastion_host='bastion.example.com')
        assert service.get_target_host(instance, profile) == '9.9.9.9'

    def test_no_ip_returns_empty(self, service):
        instance = {'public_ip': None, 'private_ip': None}
        assert service.get_target_host(instance) == ''


class TestGetTargetPort(TestConnectionService):

    def test_custom_server_returns_its_port(self, service):
        instance = {'id': 'custom-web-1', 'is_custom': True, 'port': 2222}
        assert service.get_target_port(instance) == 2222

    def test_custom_server_without_port_is_default(self, service):
        assert service.get_target_port({'id': 'custom-web-1', 'is_custom': True}) is None

    def test_aws_instance_is_default(self, service):
        assert service.get_target_port({'id': 'i-0abc', 'public_ip': '9.9.9.9'}) is None

    def test_port_ignored_without_custom_flag(self, service):
        # Only custom servers define a target port; other providers' dicts
        # never did, so a stray key must not start emitting -p.
        assert service.get_target_port({'id': 'i-0abc', 'port': 2222}) is None


@pytest.mark.parametrize("instance_key,ovh_key,global_key,fallback_key,expected", [
    ("/keys/instance", "/keys/ovh", "/keys/global", "/keys/discovered", "/keys/instance"),
    ("", "/keys/ovh", "/keys/global", "/keys/discovered", "/keys/ovh"),
    ("", "", "/keys/global", "/keys/discovered", "/keys/global"),
    ("", "", "", "/keys/discovered", "/keys/discovered"),
    ("", "", "", None, None),
])
def test_ovh_key_precedence(instance_key, ovh_key, global_key, fallback_key, expected) -> None:
    config = AppConfig(default_key=global_key)
    config.instance_keys["vps-web-1"] = instance_key
    config.ovh.default_ssh_key = ovh_key
    manager = MagicMock()
    manager.get.return_value = config
    options = ConnectionService(manager).resolve_ovh_connection(
        {"id": "vps-web-1", "public_ip": "192.0.2.1", "provider_type": "vps"}, fallback_key,
    )
    assert options["key_path"] == expected


@pytest.mark.parametrize("provider_type,expected", [("vps", "ubuntu"), ("dedicated", "debian"), ("cloud", "ubuntu")])
def test_ovh_user_defaults_do_not_inherit_aws_user(provider_type: str, expected: str) -> None:
    config = AppConfig(default_username="ec2-user")
    config.ovh.default_username = ""
    manager = MagicMock()
    manager.get.return_value = config
    service = ConnectionService(manager)
    row = {"provider_type": provider_type, "private_ip": "10.0.0.2"}
    assert service.resolve_ovh_connection(row)["username"] == expected
    config.ovh.default_username = "operator"
    options = service.resolve_ovh_connection(row)
    assert options["username"] == "operator"
    assert options["host"] == "10.0.0.2"
