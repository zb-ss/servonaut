"""The CLI finds cached AWS instances through a real AWSService.

``servonaut ssh``, ``servonaut servers`` and ``servonaut memory`` resolve
instances from the on-disk caches of every provider account. These tests
drive the real ``AWSService`` + ``CacheService`` pair (no mocks on the cache
path) so a read of an attribute the service does not have fails the test
instead of being swallowed and reported as "instance not found".
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig
from servonaut.services.accounts.headless import CachedFleet
from servonaut.services.aws_service import AWSService
from servonaut.services.cache_service import CacheService

_AWS_INSTANCE = {
    "id": "i-0123456789abcdef0",
    "name": "web-1",
    "type": "t3.small",
    "state": "running",
    "public_ip": "9.9.9.9",
    "private_ip": "10.0.0.5",
    "region": "eu-west-1",
    "key_name": "web-key",
}
# The same row as the CLI lists it: tagged with the account it belongs to.
_LISTED = {**_AWS_INSTANCE, "account": "aws"}


@pytest.fixture
def aws_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Write a stale (past-TTL) AWS cache holding one instance."""
    cache_path = tmp_path / "cache.json"
    cache_path.write_text(json.dumps({
        "timestamp": datetime(2020, 1, 1).isoformat(),
        "instances": [_AWS_INSTANCE],
    }))
    monkeypatch.setattr(CacheService, "CACHE_PATH", cache_path)
    return cache_path


def _custom_service() -> MagicMock:
    svc = MagicMock()
    svc.list_as_instances.return_value = []
    return svc


def _aws_service() -> AWSService:
    return AWSService(CacheService(ttl_seconds=60))


class TestAWSServiceGetCachedInstances:
    def test_returns_stale_cache(self, aws_cache: Path) -> None:
        assert _aws_service().get_cached_instances() == [_AWS_INSTANCE]

    def test_missing_cache_is_empty_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(CacheService, "CACHE_PATH", tmp_path / "absent.json")
        assert _aws_service().get_cached_instances() == []

    def test_corrupt_cache_is_empty_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        bad = tmp_path / "cache.json"
        bad.write_text("{not json")
        monkeypatch.setattr(CacheService, "CACHE_PATH", bad)
        assert _aws_service().get_cached_instances() == []


class TestAWSServiceNeverListed:
    """What tells the CLI an AWS account was never listed on this machine."""

    def test_a_stale_or_empty_cache_counts_as_listed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, aws_cache: Path,
    ) -> None:
        assert _aws_service().has_cached_instances()
        aws_cache.write_text(json.dumps({"timestamp": datetime.now().isoformat(), "instances": []}))
        assert _aws_service().has_cached_instances()

    @pytest.mark.parametrize("content", [None, "{not json", "[]"])
    def test_a_missing_or_unreadable_cache_does_not(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content,
    ) -> None:
        cache_path = tmp_path / "cache.json"
        if content is not None:
            cache_path.write_text(content)
        monkeypatch.setattr(CacheService, "CACHE_PATH", cache_path)
        assert not _aws_service().has_cached_instances()


@pytest.fixture
def offline_aws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """No AWS environment, shared files under tmp_path, and no way to resolve.

    Resolving credentials (instance metadata, a credential_process, SSO)
    or opening any connection fails the test.
    """
    import socket

    import boto3

    for name in list(os.environ):
        if name.startswith("AWS_"):
            monkeypatch.delenv(name)
    files = SimpleNamespace(credentials=tmp_path / "credentials", config=tmp_path / "config")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(files.credentials))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(files.config))

    def forbidden(*args, **kwargs):
        raise AssertionError("the presence check must stay offline")

    monkeypatch.setattr(boto3.session.Session, "get_credentials", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    return files


class TestAWSCredentialsCheckedOffline:
    """Whether AWS is set up here is read from the environment and files only."""

    def test_nothing_set_up(self, offline_aws) -> None:
        assert not _aws_service().has_credentials()

    @pytest.mark.parametrize("variable", [
        "AWS_ACCESS_KEY_ID", "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
    ])
    def test_an_environment_variable(self, offline_aws, monkeypatch, variable) -> None:
        monkeypatch.setenv(variable, "x")
        assert _aws_service().has_credentials()

    def test_keys_in_the_shared_credentials_file(self, offline_aws) -> None:
        offline_aws.credentials.write_text("[other]\naws_access_key_id = AKIDEXAMPLE\n")
        assert not _aws_service().has_credentials()
        offline_aws.credentials.write_text("[default]\naws_access_key_id = AKIDEXAMPLE\n")
        assert _aws_service().has_credentials()

    @pytest.mark.parametrize("entry", [
        "sso_session = corp", "sso_start_url = https://sso.invalid/start",
        "role_arn = example-role", "login_session = s",
    ])
    def test_credential_keys_in_the_config_file(self, offline_aws, entry) -> None:
        offline_aws.config.write_text(f"[default]\nregion = eu-west-1\n{entry}\n")
        assert _aws_service().has_credentials()

    def test_a_region_alone_is_not_credentials(self, offline_aws) -> None:
        offline_aws.config.write_text("[default]\nregion = eu-west-1\n")
        assert not _aws_service().has_credentials()

    def test_a_credential_process_is_never_run(self, offline_aws, tmp_path) -> None:
        marker = tmp_path / "ran"
        offline_aws.config.write_text(
            f"[default]\ncredential_process = /bin/sh -c 'touch {marker}'\n"
        )
        assert _aws_service().has_credentials()
        assert not marker.exists()

    def test_a_file_botocore_cannot_parse_counts_as_set_up(self, offline_aws) -> None:
        # Listing then says what is wrong with it.
        offline_aws.config.write_text("[default\nregion = eu-west-1\n")
        assert _aws_service().has_credentials()

    def test_an_account_with_a_profile_is_set_up(self, offline_aws) -> None:
        from servonaut.config.accounts import AccountRef
        from servonaut.services.accounts.aws_account import AWSAccountContext

        account = AWSAccountContext(AccountRef("aws", "prod", False), "prod")
        assert AWSService(CacheService(ttl_seconds=60), account=account).has_credentials()


class TestCliFindsCachedAwsInstances:
    def test_servers_cli(self, aws_cache: Path) -> None:
        from servonaut.cli.servers import _find_instance, _load_all_instances

        instances = asyncio.run(
            _load_all_instances(AppConfig(cache_ttl_seconds=60), _custom_service(), "web-1"),
        )
        assert _find_instance("web-1", instances) == _LISTED

    def test_memory_cli_list(self, aws_cache: Path) -> None:
        from servonaut.cli.memory import _list_all_instances

        instances = _list_all_instances(CachedFleet(_custom_service(), aws=_aws_service()))
        assert _AWS_INSTANCE in instances

    def test_memory_cli_resolve(self, aws_cache: Path) -> None:
        from servonaut.cli.memory import _resolve_or_exit

        args = SimpleNamespace(instance="i-0123456789abcdef0")
        inst = _resolve_or_exit(args, CachedFleet(_custom_service(), aws=_aws_service()))
        assert inst == _AWS_INSTANCE

    def test_ssh_cli(self, aws_cache: Path) -> None:
        from servonaut.cli.ssh import _find_instance, _load_instances

        config = AppConfig(cache_ttl_seconds=60)
        instances = asyncio.run(_load_instances(_custom_service(), config, "web-1"))
        assert _find_instance(instances, "web-1") == [_LISTED]


class TestCacheReadBugsSurface:
    """A programming error on the AWS cache read must not be swallowed."""

    def test_cli_fleet_does_not_swallow_attribute_error(self) -> None:
        broken = MagicMock(spec=AWSService)
        broken.get_cached_instances.side_effect = AttributeError("boom")
        with pytest.raises(AttributeError):
            CachedFleet(_custom_service(), aws=broken).instances()

    def test_memory_cli_does_not_swallow_attribute_error(self) -> None:
        from servonaut.cli.memory import _list_all_instances

        broken = MagicMock(spec=AWSService)
        broken.get_cached_instances.side_effect = AttributeError("boom")
        with pytest.raises(AttributeError):
            _list_all_instances(CachedFleet(_custom_service(), aws=broken))


class TestSshCliSurvivesOddCacheFiles:
    """``servonaut ssh`` reads cache.json directly; odd shapes must not crash it.

    A cache that cannot be read counts as never written: the account is
    listed once (stubbed here) to find out which servers it has.
    """

    @pytest.mark.parametrize("payload", [
        [],
        {"timestamp": "2026-01-01T00:00:00", "instances": {"i-1": {}}},
        {"timestamp": "2026-01-01T00:00:00", "instances": [1, "x"]},
    ])
    def test_bad_shape_means_no_aws_instances(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload,
    ) -> None:
        from servonaut.cli.ssh import _load_instances

        cache_path = tmp_path / "cache.json"
        cache_path.write_text(json.dumps(payload))
        monkeypatch.setattr(CacheService, "CACHE_PATH", cache_path)

        config = AppConfig(cache_ttl_seconds=60)
        listing = AsyncMock(return_value=[])
        monkeypatch.setattr(AWSService, "has_credentials", lambda self: True)
        monkeypatch.setattr(AWSService, "fetch_instances", listing)
        assert asyncio.run(_load_instances(_custom_service(), config, "web-1")) == []
        listing.assert_awaited_once()

    def test_aware_timestamp_still_finds_instance(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from datetime import timezone

        from servonaut.cli.ssh import _find_instance, _load_instances

        cache_path = tmp_path / "cache.json"
        cache_path.write_text(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "instances": [_AWS_INSTANCE],
        }))
        monkeypatch.setattr(CacheService, "CACHE_PATH", cache_path)

        config = AppConfig(cache_ttl_seconds=60)
        instances = asyncio.run(_load_instances(_custom_service(), config, "web-1"))
        assert _find_instance(instances, "web-1") == [_LISTED]
