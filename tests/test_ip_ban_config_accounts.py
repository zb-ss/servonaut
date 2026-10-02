"""Which IP-ban configs act in which AWS account."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from servonaut.config.schema import AppConfig, IPBanConfig
from servonaut.services.accounts import UnknownAccountError
from servonaut.services.ip_ban_service import IPBanService
from tests._account_fixtures import build_registry

DEFAULT = IPBanConfig(name="waf-a", method="waf")
NAMED_DEFAULT = IPBanConfig(name="sg-a", method="security_group", account="AWS")
PROD = IPBanConfig(name="waf-prod", method="waf", account="prod")
GONE = IPBanConfig(name="waf-gone", method="waf", account="retired")
CONFIGS = [DEFAULT, NAMED_DEFAULT, PROD, GONE]


def _service(registry=None, config=None):
    config = config or (registry.config if registry else AppConfig())
    config.ip_ban_configs = list(CONFIGS)
    return IPBanService(SimpleNamespace(get=lambda: config), accounts=registry)


@pytest.fixture
def two_accounts(monkeypatch):
    return _service(build_registry(monkeypatch, aws={"aws": [], "prod": []})[0])


def _names(configs):
    return [c.name for c in configs]


def test_configs_for_account(two_accounts):
    assert _names(two_accounts.configs_for_account("")) == ["waf-a", "sg-a"]
    assert _names(two_accounts.configs_for_account("aws")) == ["waf-a", "sg-a"]
    assert _names(two_accounts.configs_for_account("PROD")) == ["waf-prod"]
    # A config naming a removed account acts nowhere; an unknown label has none.
    assert two_accounts.configs_for_account("retired") == []


def test_account_of(two_accounts):
    assert [two_accounts.account_of(c) for c in CONFIGS] == ["aws", "AWS", "prod", "retired"]


def test_without_a_registry_every_config_is_in_the_one_account():
    service = _service()
    assert service.configs_for_account("prod") == CONFIGS
    assert service.configs_for_server({"id": "i-1"}) == (CONFIGS, "")


def test_configs_for_a_server_of_the_second_account(two_accounts):
    server = {"id": "i-2", "name": "shop", "account": "prod"}
    configs, account = two_accounts.configs_for_server(server)
    assert (_names(configs), account) == (["waf-prod"], "prod")


@pytest.mark.parametrize("server", [
    None,
    {"id": "4", "name": "lb-1", "is_hetzner": True, "account": "hetzner"},
    {"id": "custom-x", "name": "x", "is_custom": True},
])
def test_a_server_whose_aws_account_cannot_be_told_is_refused(two_accounts, server):
    with pytest.raises(UnknownAccountError, match="AWS account"):
        two_accounts.configs_for_server(server)


def test_one_account_keeps_every_config(monkeypatch):
    registry, _ = build_registry(monkeypatch)
    assert _service(registry).configs_for_server(None) == (CONFIGS, "")
