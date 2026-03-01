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

    def test_without_bastion_key_uses_proxy_jump(self, service):
        profile = ConnectionProfile(
            name='test',
            bastion_host='bastion.example.com',
            bastion_user='ubuntu',
        )
        args = service.get_proxy_args(profile)
        assert args == ['-J', 'ubuntu@bastion.example.com']

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

    def test_custom_port_proxy_jump(self, service):
        profile = ConnectionProfile(
            name='test',
            bastion_host='bastion.example.com',
            bastion_user='ec2-user',
            ssh_port=2222,
        )
        args = service.get_proxy_args(profile)
        jump_str = args[1]
        assert ':2222' in jump_str

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
        instance = {'public_ip': '54.1.2.3', 'private_ip': '10.0.1.1'}
        assert service.get_target_host(instance) == '54.1.2.3'

    def test_direct_falls_back_to_private(self, service):
        instance = {'public_ip': None, 'private_ip': '10.0.1.1'}
        assert service.get_target_host(instance) == '10.0.1.1'

    def test_bastion_prefers_private_ip(self, service):
        instance = {'public_ip': '54.1.2.3', 'private_ip': '10.0.1.1'}
        profile = ConnectionProfile(name='test', bastion_host='bastion.example.com')
        assert service.get_target_host(instance, profile) == '10.0.1.1'

    def test_bastion_falls_back_to_public(self, service):
        instance = {'public_ip': '54.1.2.3', 'private_ip': None}
        profile = ConnectionProfile(name='test', bastion_host='bastion.example.com')
        assert service.get_target_host(instance, profile) == '54.1.2.3'

    def test_no_ip_returns_empty(self, service):
        instance = {'public_ip': None, 'private_ip': None}
        assert service.get_target_host(instance) == ''
