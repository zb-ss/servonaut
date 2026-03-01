"""Shared fixtures for Servonaut tests."""

import pytest

from servonaut.config.schema import (
    AppConfig,
    ConnectionProfile,
    ConnectionRule,
    CustomServer,
    ScanRule,
)


@pytest.fixture
def sample_instances():
    """Sample EC2 instance data for testing."""
    return [
        {
            'id': 'i-abc123',
            'name': 'web-server-prod',
            'type': 't3.medium',
            'state': 'running',
            'public_ip': '54.123.45.67',
            'private_ip': '10.0.1.100',
            'region': 'us-east-1',
            'key_name': 'prod-key',
        },
        {
            'id': 'i-def456',
            'name': 'api-server-staging',
            'type': 't3.small',
            'state': 'stopped',
            'public_ip': None,
            'private_ip': '10.0.2.200',
            'region': 'us-west-2',
            'key_name': 'staging-key',
        },
        {
            'id': 'i-ghi789',
            'name': 'bastion-host',
            'type': 't3.micro',
            'state': 'running',
            'public_ip': '34.56.78.90',
            'private_ip': '10.0.0.10',
            'region': 'us-east-1',
            'key_name': 'bastion-key',
        },
    ]


@pytest.fixture
def sample_custom_servers():
    """Sample custom server definitions for testing."""
    return [
        CustomServer(
            name='my-vps',
            host='203.0.113.10',
            username='ubuntu',
            ssh_key='~/.ssh/vps.pem',
            port=22,
            provider='DigitalOcean',
            group='web',
            tags={'env': 'prod'},
        ),
        CustomServer(
            name='hetzner-db',
            host='203.0.113.20',
            username='root',
            ssh_key='~/.ssh/hetzner.pem',
            port=2222,
            provider='Hetzner',
            group='database',
            tags={'env': 'prod', 'role': 'db'},
        ),
        CustomServer(
            name='local-dev',
            host='192.168.1.50',
            username='vagrant',
            ssh_key='',
            port=22,
            provider='',
            group='dev',
            tags={},
        ),
    ]


@pytest.fixture
def config_with_custom_servers(sample_custom_servers):
    """AppConfig with custom servers populated."""
    return AppConfig(custom_servers=sample_custom_servers)


@pytest.fixture
def default_config():
    """Default AppConfig instance."""
    return AppConfig()


@pytest.fixture
def config_with_profiles():
    """AppConfig with connection profiles and rules."""
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
