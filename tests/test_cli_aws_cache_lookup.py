"""The CLI finds cached AWS instances through a real AWSService.

``servonaut ssh``, ``servonaut servers`` and ``servonaut memory`` resolve
instances from the on-disk AWS cache. These tests drive the real
``AWSService`` + ``CacheService`` pair (no mocks on the cache path) so a
read of an attribute the service does not have fails the test instead of
being swallowed and reported as "instance not found".
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

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


class TestCliFindsCachedAwsInstances:
    def test_servers_cli(self, aws_cache: Path) -> None:
        from servonaut.cli.servers import _find_instance, _load_all_instances

        instances = _load_all_instances(_aws_service(), _custom_service())
        assert _find_instance("web-1", instances) == _AWS_INSTANCE

    def test_memory_cli_list(self, aws_cache: Path) -> None:
        from servonaut.cli.memory import _list_all_instances

        instances = _list_all_instances(_aws_service(), _custom_service(), None)
        assert _AWS_INSTANCE in instances

    def test_memory_cli_resolve(self, aws_cache: Path) -> None:
        from servonaut.cli.memory import _resolve_or_exit

        args = SimpleNamespace(instance="i-0123456789abcdef0")
        inst = _resolve_or_exit(args, _aws_service(), _custom_service(), None)
        assert inst == _AWS_INSTANCE

    def test_ssh_cli(self, aws_cache: Path) -> None:
        from servonaut.cli.ssh import _find_instance, _load_instances

        config = SimpleNamespace(cache_ttl_seconds=60)
        instances = _load_instances(_custom_service(), config)
        assert _find_instance(instances, "web-1") == [_AWS_INSTANCE]


class TestCacheReadBugsSurface:
    """A programming error on the AWS cache read must not be swallowed."""

    def test_servers_cli_does_not_swallow_attribute_error(self) -> None:
        from servonaut.cli.servers import _load_all_instances

        broken = MagicMock(spec=AWSService)
        broken.get_cached_instances.side_effect = AttributeError("boom")
        with pytest.raises(AttributeError):
            _load_all_instances(broken, _custom_service())

    def test_memory_cli_does_not_swallow_attribute_error(self) -> None:
        from servonaut.cli.memory import _list_all_instances

        broken = MagicMock(spec=AWSService)
        broken.get_cached_instances.side_effect = AttributeError("boom")
        with pytest.raises(AttributeError):
            _list_all_instances(broken, _custom_service(), None)
