"""Rules shared by the provider Accounts sections and the setup wizards.

Label validation, label suggestions for detected AWS profiles, region lists,
the demo-mode text scrubber and the fleet refresh after an accounts change.
"""

from __future__ import annotations

import asyncio
from typing import List
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import (
    AppConfig,
    AWSAccount,
    AWSConfig,
    HetznerAccount,
    HetznerConfig,
    OVHAccount,
    OVHConfig,
)
from servonaut.screens.settings import accounts as rules
from servonaut.services.redaction_service import RedactionService


def _config() -> AppConfig:
    return AppConfig(
        aws=AWSConfig(accounts=[AWSAccount(label="prod", profile="prod-admin")]),
        hetzner=HetznerConfig(
            enabled=True, accounts=[HetznerAccount(label="Staging", api_token="$TOKEN_B")]
        ),
        ovh=OVHConfig(label="eu-main"),
    )


class TestLabelError:
    def test_a_free_valid_label_is_accepted(self) -> None:
        assert rules.label_error(_config(), "aws", "dev", index=1) is None

    @pytest.mark.parametrize("label", ["", "-dash", "has space", "a" * 33, "sl/ash"])
    def test_an_invalid_label_is_refused(self, label: str) -> None:
        problem = rules.label_error(_config(), "aws", label, index=1)
        assert problem is not None and problem.endswith(".")

    def test_custom_is_reserved(self) -> None:
        assert "reserved" in rules.label_error(_config(), "hetzner", "Custom", index=1)

    def test_labels_are_unique_across_providers_ignoring_case(self) -> None:
        problem = rules.label_error(_config(), "aws", "STAGING", index=1)
        assert problem == "The label 'STAGING' is already used by Hetzner · Staging."

    def test_a_primary_default_label_is_taken(self) -> None:
        # The Hetzner primary shows as "hetzner" while its label is empty.
        assert "Hetzner · hetzner" in rules.label_error(_config(), "aws", "hetzner", index=1)

    def test_an_account_keeps_its_own_label(self) -> None:
        assert rules.label_error(_config(), "aws", "prod", index=0) is None
        assert rules.label_error(_config(), "ovh", "EU-MAIN") is None

    def test_an_empty_primary_label_means_the_provider_name(self) -> None:
        assert rules.label_error(_config(), "aws", "") is None
        config = _config()
        config.hetzner.accounts.append(HetznerAccount(label="aws", api_token="x"))
        assert "Hetzner · aws" in rules.label_error(config, "aws", "")


class TestSuggestLabel:
    def test_a_valid_free_profile_name_is_kept(self) -> None:
        assert rules.suggest_label("dev", _config()) == "dev"

    def test_invalid_characters_are_replaced(self) -> None:
        assert rules.suggest_label("team a/admin", _config()) == "team-a-admin"

    def test_a_taken_name_gets_a_number(self) -> None:
        assert rules.suggest_label("PROD", _config()) == "PROD-2"

    def test_a_reserved_name_is_changed(self) -> None:
        suggestion = rules.suggest_label("custom", _config())
        assert suggestion != "custom" and rules.label_problem(suggestion) is None

    def test_a_long_name_is_cut_to_the_limit(self) -> None:
        suggestion = rules.suggest_label("x" * 50, _config())
        assert len(suggestion) == 32 and rules.label_problem(suggestion) is None


class TestParseRegions:
    def test_commas_and_spaces_separate_regions(self) -> None:
        assert rules.parse_regions("eu-west-1, us-east-1 us-gov-west-1") == [
            "eu-west-1", "us-east-1", "us-gov-west-1",
        ]

    def test_duplicates_are_dropped_and_case_is_folded(self) -> None:
        assert rules.parse_regions("EU-WEST-1,eu-west-1") == ["eu-west-1"]

    def test_empty_means_every_region(self) -> None:
        assert rules.parse_regions("  ") == []

    @pytest.mark.parametrize("text", ["eu-west", "europe", "eu_west_1", "1.1.1.1"])
    def test_a_non_region_is_refused(self, text: str) -> None:
        with pytest.raises(ValueError, match="not an AWS region name"):
            rules.parse_regions(text)


class TestShownText:
    def test_outside_demo_mode_text_is_unchanged(self) -> None:
        assert rules.shown_text(None, _config(), "prod failed") == "prod failed"

    def test_labels_and_profiles_are_replaced_in_demo_mode(self) -> None:
        # Names no stand-in can contain, so the checks cannot pass by luck.
        config = AppConfig(
            aws=AWSConfig(
                accounts=[AWSAccount(label="northwind", profile="northwind-admin")]
            ),
            hetzner=HetznerConfig(accounts=[HetznerAccount(label="Contoso", api_token="x")]),
        )
        redaction = RedactionService()
        text = rules.shown_text(
            redaction,
            config,
            "northwind: profile northwind-admin failed; "
            "account 'contoso' is not available",
        )
        assert "northwind" not in text.lower() and "contoso" not in text.lower()
        assert text.startswith(f"{redaction.redact_name('northwind')}: profile ")

    def test_provider_names_stay(self) -> None:
        text = rules.shown_text(RedactionService(), _config(), "AWS account 'aws' is fine")
        assert text == "AWS account 'aws' is fine"

    def test_a_label_inside_a_longer_word_is_left_alone(self) -> None:
        text = rules.shown_text(RedactionService(), _config(), "production")
        assert text == "production"


class _Inventory:
    def __init__(self, cached: List[dict], fresh: List[dict]) -> None:
        self.cached = cached
        self.fresh = fresh
        self.fetches = 0
        self.last_fetch_error = None
        self.refs = [object(), object()]

    def get_cached_instances(self) -> List[dict]:
        return list(self.cached)

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        assert force_refresh
        self.fetches += 1
        return list(self.fresh)


class _App:
    """Just enough of the app for the fleet helpers."""

    def __init__(self, inventory) -> None:
        self.instances: List[dict] = [
            {"id": "i-1", "name": "app-1", "account": "old"},
            {"id": "4200001", "name": "cache-1", "is_hetzner": True},
        ]
        self._instances_pristine = [dict(row) for row in self.instances]
        self.demo_mode = False
        self.redaction_service = None
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = _config()
        self.notify = MagicMock()
        self.workers: list = []
        self._inventory = inventory

    def provider_inventory(self, provider: str):
        return self._inventory if provider == "aws" else None

    def run_worker(self, coroutine, **kwargs):
        self.workers.append((coroutine, kwargs))


class TestRefreshProviderFleet:
    def test_cached_rows_replace_the_slice_at_once_then_a_refresh_starts(self) -> None:
        inventory = _Inventory(
            cached=[{"id": "i-1", "name": "app-1", "account": "new"}],
            fresh=[{"id": "i-1", "name": "app-1", "account": "new"}, {"id": "i-2", "name": "db-1"}],
        )
        app = _App(inventory)
        rules.refresh_provider_fleet(app, "aws")

        # Re-tagged at once; other providers' rows are untouched.
        assert [row.get("account") for row in app.instances if row["id"] == "i-1"] == ["new"]
        assert any(row["id"] == "4200001" for row in app.instances)
        (coroutine, kwargs), = app.workers
        assert kwargs["group"] == "aws_accounts_refresh" and kwargs["exit_on_error"] is False

        asyncio.run(coroutine)
        assert inventory.fetches == 1
        assert {row["id"] for row in app.instances} == {"i-1", "i-2", "4200001"}
        message = app.notify.call_args.args[0]
        assert message == "AWS: 2 server(s) from 2 accounts."

    def test_a_provider_without_accounts_leaves_the_fleet(self) -> None:
        app = _App(None)
        rules.refresh_provider_fleet(app, "hetzner")
        assert [row["id"] for row in app.instances] == ["i-1"]
        assert app.workers == []

    def test_an_incomplete_refresh_is_reported(self) -> None:
        inventory = _Inventory(cached=[], fresh=[])
        inventory.last_fetch_error = "prod: expired token"
        app = _App(inventory)
        rules.refresh_provider_fleet(app, "aws")
        asyncio.run(app.workers[0][0])
        kwargs = app.notify.call_args.kwargs
        assert app.notify.call_args.args[0] == "AWS refresh incomplete. prod: expired token"
        assert kwargs["severity"] == "warning" and kwargs["markup"] is False


def test_ovh_auth_kind_never_needs_the_values() -> None:
    assert rules.ovh_auth_kind(OVHAccount(client_id="c", client_secret="s")) == "OAuth2"
    assert rules.ovh_auth_kind(
        OVHAccount(application_key="a", application_secret="b", consumer_key="c")
    ) == "application key"
    assert rules.ovh_auth_kind(OVHAccount(application_key="a")) == "incomplete"
    assert rules.ovh_auth_kind(OVHAccount()) == "missing"
