"""Config sync never uploads extra-account secrets and never loses accounts."""

from __future__ import annotations

import json
from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock

from servonaut.config.schema import (
    AppConfig,
    AWSAccount,
    HetznerAccount,
    ObjectStorageConfig,
    OVHAccount,
)
from servonaut.services.config_sync_service import ConfigSyncService

SECRETS = ("hz-token-b", "hz-s3-ak", "hz-s3-sk", "ovh-ak-b", "ovh-as-b", "ovh-ck-b",
           "ovh-cid-b", "ovh-cs-b", "ovh-s3-ak", "ovh-s3-sk")


def _local_config() -> AppConfig:
    config = AppConfig()
    config.aws.accounts = [AWSAccount(label="prod", profile="prod")]
    config.hetzner.accounts = [
        HetznerAccount(
            label="staging",
            api_token="hz-token-b",
            object_storage=ObjectStorageConfig(access_key="hz-s3-ak", secret_key="hz-s3-sk"),
        )
    ]
    config.ovh.accounts = [
        OVHAccount(
            label="ca",
            application_key="ovh-ak-b",
            application_secret="ovh-as-b",
            consumer_key="ovh-ck-b",
            client_id="ovh-cid-b",
            client_secret="ovh-cs-b",
            object_storage=ObjectStorageConfig(access_key="ovh-s3-ak", secret_key="ovh-s3-sk"),
        )
    ]
    return config


def _service(local: AppConfig) -> tuple[ConfigSyncService, MagicMock]:
    manager = MagicMock()
    manager.get.return_value = local
    manager._deserialize.side_effect = lambda data: data
    api = MagicMock()
    api.post = AsyncMock()
    return ConfigSyncService(api, manager), manager


def test_no_extra_account_secret_is_uploaded():
    service, _ = _service(_local_config())
    stripped = service._strip_sensitive(asdict(_local_config()))
    text = json.dumps(stripped)
    for secret in SECRETS:
        assert secret not in text, secret
    # Everything that is not a secret still syncs.
    assert stripped["hetzner"]["accounts"][0]["label"] == "staging"
    assert stripped["aws"]["accounts"][0]["profile"] == "prod"
    assert stripped["ovh"]["accounts"][0]["endpoint"] == "ovh-eu"


def test_pull_keeps_local_secrets_of_accounts_matched_by_label():
    service, manager = _service(_local_config())
    remote = service._strip_sensitive(asdict(_local_config()))
    remote["hetzner"]["accounts"][0]["label"] = "STAGING"  # labels match case-insensitively
    remote["hetzner"]["accounts"][0]["default_username"] = "deploy"  # a synced change
    service.apply_remote_config(remote)

    saved = manager.save.call_args[0][0]
    staging = saved["hetzner"]["accounts"][0]
    assert staging["api_token"] == "hz-token-b"
    assert staging["object_storage"]["secret_key"] == "hz-s3-sk"
    assert staging["default_username"] == "deploy"
    ovh = saved["ovh"]["accounts"][0]
    assert (ovh["application_secret"], ovh["client_secret"]) == ("ovh-as-b", "ovh-cs-b")


def test_pull_never_overwrites_a_secret_the_remote_carries():
    service, manager = _service(_local_config())
    remote = asdict(_local_config())
    remote["hetzner"]["accounts"][0]["api_token"] = "$ROTATED"
    service.apply_remote_config(remote)
    assert manager.save.call_args[0][0]["hetzner"]["accounts"][0]["api_token"] == "$ROTATED"


def test_an_account_only_on_the_remote_arrives_without_secrets():
    service, manager = _service(_local_config())
    remote = service._strip_sensitive(asdict(_local_config()))
    remote["hetzner"]["accounts"].append({"label": "dev"})
    service.apply_remote_config(remote)
    accounts = manager.save.call_args[0][0]["hetzner"]["accounts"]
    assert [a["label"] for a in accounts] == ["staging", "dev"]
    assert "api_token" not in accounts[1]


def test_a_snapshot_from_before_accounts_existed_keeps_the_local_accounts():
    service, manager = _service(_local_config())
    remote = asdict(AppConfig())
    for provider in ("aws", "hetzner", "ovh"):
        remote[provider].pop("accounts")
    service.apply_remote_config(remote)

    saved = manager.save.call_args[0][0]
    assert saved["aws"]["accounts"][0]["label"] == "prod"
    assert saved["hetzner"]["accounts"][0]["api_token"] == "hz-token-b"
    assert saved["ovh"]["accounts"][0]["consumer_key"] == "ovh-ck-b"


def test_malformed_remote_accounts_do_not_break_the_pull():
    service, manager = _service(_local_config())
    remote = service._strip_sensitive(asdict(_local_config()))
    remote["hetzner"]["accounts"] = ["junk", {"no_label": True}, {"label": "staging"}]
    service.apply_remote_config(remote)
    accounts = manager.save.call_args[0][0]["hetzner"]["accounts"]
    assert accounts[2]["api_token"] == "hz-token-b"
