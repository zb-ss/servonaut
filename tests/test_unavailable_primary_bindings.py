"""An unusable primary account with a usable extra one: audit and bindings."""

from __future__ import annotations

from types import SimpleNamespace

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig, OVHAccount
from servonaut.screens._provider_accounts import with_account
from servonaut.services.accounts import AccountRegistry


def _registry_without_ovh_primary() -> AccountRegistry:
    """OVH enabled, the provider block has no credentials, account 'ca' does."""
    config = AppConfig()
    config.ovh.enabled = True
    config.ovh.accounts = [
        OVHAccount(
            label="ca", endpoint="ovh-ca",
            application_key="k", application_secret="s", consumer_key="c",
        )
    ]
    return AccountRegistry(config)


def test_the_setup_is_an_unusable_primary_with_a_usable_extra():
    registry = _registry_without_ovh_primary()
    assert [r.label for r in registry.accounts("ovh")] == ["ca"]
    assert registry.is_multi("ovh")
    assert registry.default_service("ovh") is None


def test_audit_details_name_the_account_while_the_primary_is_unavailable():
    app = SimpleNamespace(accounts=_registry_without_ovh_primary())
    assert with_account(app, "ovh", "ca", {"ip": "10.0.0.1"}) == {
        "ip": "10.0.0.1", "account": "ca",
    }


def test_changes_in_the_extra_ovh_account_are_audited():
    app = SimpleNamespace(accounts=_registry_without_ovh_primary(), aws_service=None)
    ServonautApp._bind_provider_aliases(app)
    assert app.ovh_service is None
    assert app.ovh_audit is not None


def test_nothing_is_audited_without_a_usable_ovh_account():
    app = SimpleNamespace(accounts=AccountRegistry(AppConfig()), aws_service=None)
    ServonautApp._bind_provider_aliases(app)
    assert app.ovh_audit is None
