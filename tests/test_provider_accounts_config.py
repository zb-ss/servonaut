"""Provider accounts in the config: shape, round trip, validation."""

from __future__ import annotations

import json

import pytest

from servonaut.config.accounts import (
    AWS,
    HETZNER,
    OVH,
    account_cache_path,
    account_problems,
    aws_accounts,
    describe_account_problems,
    hetzner_accounts,
    label_problem,
    ovh_accounts,
    primary_label,
)
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import (
    AppConfig,
    AWSAccount,
    HetznerAccount,
    ObjectStorageConfig,
    OVHAccount,
)


def _config(**provider_accounts) -> AppConfig:
    config = AppConfig()
    config.aws.accounts = provider_accounts.get("aws", [])
    config.hetzner.accounts = provider_accounts.get("hetzner", [])
    config.ovh.accounts = provider_accounts.get("ovh", [])
    return config


class TestShape:
    def test_a_config_without_extra_accounts_has_one_account_per_provider(self):
        config = AppConfig()
        assert [a.ref.label for a in aws_accounts(config.aws)] == ["aws"]
        assert [r.label for r, _ in hetzner_accounts(config.hetzner)] == ["hetzner"]
        assert [r.label for r, _ in ovh_accounts(config.ovh)] == ["ovh"]

    def test_the_primary_label_can_be_renamed(self):
        config = AppConfig()
        config.hetzner.label = "  prod "
        assert primary_label(HETZNER, config.hetzner) == "prod"

    def test_an_extra_hetzner_project_keeps_its_own_token_and_cache(self):
        config = AppConfig()
        config.hetzner.api_token = "$PRIMARY"
        config.hetzner.default_local_ssh_key = "~/.ssh/primary"
        config.hetzner.default_hetzner_ssh_key = "primary-key"
        config.hetzner.accounts = [
            HetznerAccount(label="staging", api_token="$STAGING", default_username="deploy")
        ]
        (primary_ref, primary), (ref, extra) = hetzner_accounts(config.hetzner)
        assert primary is config.hetzner and primary_ref.primary
        assert not ref.primary and ref.label == "staging"
        assert extra.api_token == "$STAGING"
        # Local SSH defaults are inherited; a Hetzner-side key name is not,
        # because it only exists in the project that registered it.
        assert extra.default_local_ssh_key == "~/.ssh/primary"
        assert extra.default_hetzner_ssh_key == ""
        assert extra.default_username == "deploy"
        assert extra.cache_path == "~/.servonaut/hetzner_cache.staging.json"
        assert extra.accounts == []

    def test_an_extra_ovh_account_uses_only_its_own_credentials(self):
        config = AppConfig()
        config.ovh.application_key = "primary-ak"
        config.ovh.cloud_project_ids = ["p1"]
        config.ovh.accounts = [
            OVHAccount(label="ca", endpoint="ovh-ca", client_id="cid", client_secret="$S")
        ]
        _, (ref, extra) = ovh_accounts(config.ovh)
        assert extra.endpoint == "ovh-ca"
        assert extra.application_key == ""
        assert (extra.client_id, extra.client_secret) == ("cid", "$S")
        assert extra.cloud_project_ids == []

    def test_cache_path_of_an_extra_account(self):
        assert account_cache_path("~/.servonaut/cache.json", "prod") == "~/.servonaut/cache.prod.json"


class TestRoundTrip:
    def test_accounts_survive_save_and_load(self, tmp_path):
        path = tmp_path / "config.json"
        manager = ConfigManager(config_path=path)
        config = manager.get()
        config.aws.accounts = [AWSAccount(label="prod", profile="prod", regions=["eu-west-1"])]
        config.hetzner.accounts = [
            HetznerAccount(
                label="staging",
                api_token="$T",
                object_storage=ObjectStorageConfig(access_key="$K", region="fsn1"),
            )
        ]
        config.ovh.accounts = [OVHAccount(label="ca", client_id="c", client_secret="$S")]
        manager.save(config)

        loaded = ConfigManager(config_path=path).get()
        assert loaded.aws.accounts == config.aws.accounts
        assert loaded.hetzner.accounts[0].object_storage.region == "fsn1"
        assert isinstance(loaded.hetzner.accounts[0].object_storage, ObjectStorageConfig)
        assert loaded.ovh.accounts[0].client_secret == "$S"

    def test_a_malformed_entry_is_dropped_and_the_rest_loads(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({
            "version": 6,
            "hetzner": {"accounts": ["junk", {"label": "ok", "api_token": "$T", "stale": 1}]},
        }))
        loaded = ConfigManager(config_path=path).get()
        assert [a.label for a in loaded.hetzner.accounts] == ["ok"]

    def test_local_key_paths_of_extra_accounts_are_saved_home_relative(self, tmp_path):
        from pathlib import Path

        path = tmp_path / "config.json"
        manager = ConfigManager(config_path=path)
        config = manager.get()
        key = str(Path.home() / ".ssh" / "staging")
        config.hetzner.accounts = [HetznerAccount(label="s", api_token="$T", default_local_ssh_key=key)]
        config.ovh.accounts = [OVHAccount(label="o", client_id="c", client_secret="s", default_ssh_key=key)]
        manager.save(config)
        raw = json.loads(path.read_text())
        assert raw["hetzner"]["accounts"][0]["default_local_ssh_key"] == "~/.ssh/staging"
        assert raw["ovh"]["accounts"][0]["default_ssh_key"] == "~/.ssh/staging"

    def test_repr_never_shows_account_secrets(self):
        text = repr(_config(
            hetzner=[HetznerAccount(label="s", api_token="hetzner-secret")],
            ovh=[OVHAccount(label="o", application_secret="ovh-secret", client_secret="cs")],
        ).hetzner) + repr(OVHAccount(label="o", application_secret="ovh-secret"))
        assert "hetzner-secret" not in text and "ovh-secret" not in text


class TestValidation:
    @pytest.mark.parametrize("label", ["prod", "Prod-2", "eu.west_1", "a" * 32])
    def test_valid_labels(self, label):
        assert label_problem(label) is None

    @pytest.mark.parametrize(
        "label", ["", "-prod", "pro d", "prod/eu", "a" * 33, "custom", "CUSTOM"],
    )
    def test_invalid_labels(self, label):
        assert label_problem(label) is not None

    def test_labels_are_unique_across_providers_case_insensitively(self):
        config = _config(
            aws=[AWSAccount(label="prod", profile="p")],
            hetzner=[HetznerAccount(label="PROD", api_token="$T")],
        )
        problems = account_problems(config)
        assert list(problems) == [(HETZNER, 0)]
        assert "already used by AWS · prod" in problems[(HETZNER, 0)]

    def test_an_extra_account_cannot_take_a_primary_label(self):
        config = _config(aws=[AWSAccount(label="hetzner", profile="p")])
        assert (AWS, 0) in account_problems(config)

    def test_extra_accounts_need_their_own_credentials(self):
        config = _config(
            aws=[AWSAccount(label="a")],
            hetzner=[HetznerAccount(label="h")],
            ovh=[OVHAccount(label="o", application_key="k")],
        )
        problems = account_problems(config)
        assert set(problems) == {(AWS, 0), (HETZNER, 0), (OVH, 0)}

    def test_problems_read_as_sentences(self):
        config = _config(hetzner=[HetznerAccount(label="h")])
        assert describe_account_problems(config) == [
            "Hetzner account 'h' is skipped: needs its own API token"
        ]
