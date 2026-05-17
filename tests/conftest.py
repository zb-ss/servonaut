"""Shared fixtures for Servonaut tests."""
from __future__ import annotations

import os

import pytest

from servonaut.config.schema import (
    AppConfig,
    ConnectionProfile,
    ConnectionRule,
    CustomServer,
    ScanRule,
)


# ---------------------------------------------------------------------------
# Env-var-gated marker plumbing — staging / real-stack E2E (Step 7).
#
# Three markers, each tied to an env var that must be present for the test
# to run. Absent → auto-skip with a clear reason so CI logs explain WHY a
# test didn't execute (silent skips are worse than failures).
#
# Markers (per servonaut-dev's 2026-05-17 01:22 UTC suggestion):
#
#   requires_e2e_oauth   — joint contract test against staging endpoint
#                          (E2E #5). Stubs out bws + Hetzner; only needs
#                          the OAuth bearer to fetch the team's SecretsConfig.
#
#   requires_e2e_bws     — full-stack BWS round-trip (E2E #3). Real bws
#                          subprocess invoked against a real Bitwarden
#                          project. Pre-prod smoke.
#
#   requires_e2e_hetzner — full-stack SSH-into-Hetzner (E2E #3 continuation).
#                          Provisions / connects to a real Hetzner instance
#                          using a key retrieved via BWS. Pre-prod smoke.
#
# CI today: nothing tagged with these markers runs (env vars unset).
# CI tomorrow (post-staging-deploy): SERVONAUT_E2E_OAUTH_TOKEN drops into
# the CI secrets and the joint contract suite runs on every PR.
# Nightly cron: all three env vars set, full pyramid exercised.
#
# This block does TWO things:
#   1. Registers the marker NAMES so ``pytest --strict-markers`` doesn't
#      reject them.
#   2. Installs an autouse skipif via ``pytest_collection_modifyitems``
#      that auto-skips any test carrying a marker whose env var isn't set.
# ---------------------------------------------------------------------------

# Marker → required env var name. Adding a new gated marker = one line here
# plus the matching ``pytest.mark.X`` decorator on the test.
E2E_MARKER_ENV_VARS = {
    "requires_e2e_oauth": "SERVONAUT_E2E_OAUTH_TOKEN",
    "requires_e2e_bws": "SERVONAUT_E2E_BWS_TOKEN",
    "requires_e2e_hetzner": "SERVONAUT_E2E_HETZNER_TOKEN",
}


def pytest_configure(config: pytest.Config) -> None:
    """Register the env-var-gated markers so strict-markers mode is happy."""
    for marker, env_var in E2E_MARKER_ENV_VARS.items():
        config.addinivalue_line(
            "markers",
            f"{marker}: skipped unless ${env_var} is set; "
            "see tests/conftest.py for the marker catalogue.",
        )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item],
) -> None:
    """Auto-skip every test whose env-var-gated marker has no value.

    Implemented in collection rather than fixture-time so the skip
    message is rendered once per test at "collected but skipped" time,
    not at body-entry time — quieter logs.
    """
    for item in items:
        for marker_name, env_var in E2E_MARKER_ENV_VARS.items():
            if item.get_closest_marker(marker_name) is None:
                continue
            if os.environ.get(env_var):
                continue
            item.add_marker(
                pytest.mark.skip(
                    reason=(
                        f"{marker_name}: set ${env_var} to enable. "
                        "Off-by-default in CI; runs only when the test "
                        "harness has been seeded with credentials."
                    )
                )
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
