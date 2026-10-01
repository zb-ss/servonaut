"""A caller that will not wait long bounds each provider's API requests."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.accounts import AccountRef
from servonaut.config.schema import HetznerConfig, OVHConfig
from servonaut.services.accounts.aws_account import AWSAccountContext
from servonaut.services.aws_service import AWSFetchError, AWSService
from servonaut.services.cache_service import CacheService
from servonaut.services.hetzner_service import HetznerService
from servonaut.services.ovh_service import OVHService


def _aws(tmp_path, regions=()):
    account = AWSAccountContext(AccountRef("aws", "aws", True), "", tuple(regions))
    return AWSService(CacheService(cache_path=tmp_path / "cache.json"), account=account)


def test_aws_requests_get_the_time_and_no_retry(tmp_path):
    service = _aws(tmp_path)
    service.limit_request_time(4)

    with patch("servonaut.services.aws_service.boto3.client") as client:
        service._client("ec2", "eu-west-1")

    config = client.call_args.kwargs["config"]
    assert (config.connect_timeout, config.read_timeout) == (4, 4)
    assert config.retries == {"total_max_attempts": 1}


def test_aws_clients_are_unchanged_without_a_limit(tmp_path):
    with patch("servonaut.services.aws_service.boto3.client") as client:
        _aws(tmp_path)._client("ec2", "eu-west-1")
    assert client.call_args.kwargs == {"region_name": "eu-west-1"}


def test_aws_lists_no_region_once_the_time_is_up(tmp_path, monkeypatch):
    service = _aws(tmp_path, regions=("eu-west-1", "us-east-1", "ap-south-1"))
    service.limit_request_time(5)
    listed = []

    def one_region(region):
        listed.append(region)
        # The first region takes all the time there was.
        service._listing_deadline = time.monotonic() - 1
        return [{"id": "i-1", "region": region}]

    monkeypatch.setattr(service, "_fetch_region", one_region)

    rows = service._fetch_all_regions()

    assert listed == ["eu-west-1"] and [r["id"] for r in rows] == ["i-1"]
    assert service._failed_regions == ["us-east-1", "ap-south-1"]


def test_aws_with_no_region_listed_in_time_is_a_failed_listing(tmp_path):
    service = _aws(tmp_path, regions=("eu-west-1",))
    service.limit_request_time(5)
    service._listing_deadline = time.monotonic() - 1

    with pytest.raises(AWSFetchError, match="not listed within the time allowed"):
        service._fetch_all_regions()


@pytest.mark.parametrize("limit, expected", [(None, None), (3, 3)])
def test_hetzner_requests_get_the_time(tmp_path, limit, expected):
    hcloud = pytest.importorskip("hcloud")
    service = HetznerService(HetznerConfig(
        enabled=True, api_token="token", cache_path=str(tmp_path / "hetzner_cache.json"),
    ))
    if limit is not None:
        service.limit_request_time(limit)

    with patch.object(hcloud, "Client", autospec=True) as client:
        service._get_client()

    assert client.call_args.kwargs.get("timeout") == expected


@pytest.mark.parametrize("limit, expected", [(None, None), (3, 3)])
def test_ovh_requests_get_the_time(tmp_path, limit, expected):
    ovh = pytest.importorskip("ovh")
    service = OVHService(
        OVHConfig(enabled=True, application_key="k", application_secret="s", consumer_key="c"),
        cache_path=tmp_path / "ovh_cache.json",
    )
    if limit is not None:
        service.limit_request_time(limit)

    with patch.object(ovh, "Client", return_value=MagicMock()) as client:
        service._get_client()

    assert client.call_args.kwargs.get("timeout") == expected


def test_hetzner_turns_hcloud_retries_off_under_a_limit(tmp_path):
    """Guard: hcloud keeps its retry count in a private attribute; fail if it moves."""
    pytest.importorskip("hcloud")
    config = HetznerConfig(enabled=True, api_token="token",
                           cache_path=str(tmp_path / "hetzner_cache.json"))
    unlimited = HetznerService(config)._get_client()
    limited_service = HetznerService(config)
    limited_service.limit_request_time(3)
    limited = limited_service._get_client()

    assert unlimited._client._retry_max_retries > 0
    assert limited._client._retry_max_retries == 0
