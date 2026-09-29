"""Which IP-ban configs act in which AWS account."""
from __future__ import annotations

import pytest

from servonaut.config.schema import IPBanConfig
from servonaut.services.accounts import UnknownAccountError
from servonaut.services.ip_ban_service import configs_for_server, configs_in_account
from tests._account_fixtures import build_registry

DEFAULT = IPBanConfig(name="waf-a", method="waf")
NAMED_DEFAULT = IPBanConfig(name="sg-a", method="security_group", account="AWS")
PROD = IPBanConfig(name="waf-prod", method="waf", account="prod")
GONE = IPBanConfig(name="waf-gone", method="waf", account="retired")
CONFIGS = [DEFAULT, NAMED_DEFAULT, PROD, GONE]


@pytest.fixture
def two_accounts(monkeypatch):
    return build_registry(monkeypatch, aws={"aws": [], "prod": []})[0]


def _names(configs):
    return [c.name for c in configs]


def test_configs_in_account(two_accounts):
    assert _names(configs_in_account(CONFIGS, two_accounts, "")) == ["waf-a", "sg-a"]
    assert _names(configs_in_account(CONFIGS, two_accounts, "aws")) == ["waf-a", "sg-a"]
    assert _names(configs_in_account(CONFIGS, two_accounts, "PROD")) == ["waf-prod"]
    # A config naming a removed account acts nowhere; an unknown label has none.
    assert configs_in_account(CONFIGS, two_accounts, "retired") == []


def test_without_a_registry_every_config_is_in_the_one_account():
    assert configs_in_account(CONFIGS, None, "prod") == CONFIGS


def test_configs_for_a_server_of_the_second_account(two_accounts):
    server = {"id": "i-2", "name": "shop", "account": "prod"}
    configs, account = configs_for_server(CONFIGS, two_accounts, server)
    assert (_names(configs), account) == (["waf-prod"], "prod")


@pytest.mark.parametrize("server", [
    None,
    {"id": "4", "name": "lb-1", "is_hetzner": True, "account": "hetzner"},
    {"id": "custom-x", "name": "x", "is_custom": True},
])
def test_a_server_whose_aws_account_cannot_be_told_is_refused(two_accounts, server):
    with pytest.raises(UnknownAccountError, match="AWS account"):
        configs_for_server(CONFIGS, two_accounts, server)


def test_one_account_keeps_every_config(monkeypatch):
    registry, _ = build_registry(monkeypatch)
    assert configs_for_server(CONFIGS, registry, None) == (CONFIGS, "")
    assert configs_for_server(CONFIGS, None, {"id": "i-1"}) == (CONFIGS, "")
