"""A caller that will not wait long bounds each provider's API requests."""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
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
    service.limit_listing_time(4, 2)

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
    service.limit_listing_time(5, 5)
    listed = []

    def one_region(region):
        listed.append(region)
        # The first region takes all the time there was.
        service._listing_deadline = time.monotonic() - 1
        return [{"id": "i-1", "region": region}]

    monkeypatch.setattr(service, "_fetch_region", one_region)

    rows = service._fetch_all_regions()

    assert listed == ["eu-west-1"] and [r["id"] for r in rows] == ["i-1"]
    assert service._failed_regions == service._late_regions == ["us-east-1", "ap-south-1"]


def test_aws_says_which_regions_failed_and_which_were_late(tmp_path, monkeypatch):
    service = _aws(tmp_path, regions=("eu-west-1", "us-east-1", "ap-south-1"))
    service.limit_listing_time(5, 5)

    def one_region(region):
        if region == "eu-west-1":
            return [{"id": "i-1", "region": region}]
        service._listing_deadline = time.monotonic() - 1
        raise RuntimeError("AccessDenied")

    monkeypatch.setattr(service, "_fetch_region", one_region)

    rows = asyncio.run(service.fetch_instances_cached(force_refresh=True))

    assert [r["id"] for r in rows] == ["i-1"]
    assert service.last_fetch_error == (
        "1 region(s) failed: us-east-1; 1 region(s) not listed in the time allowed"
    )
    assert service.cache_service.load_any() is None


def test_aws_with_no_region_listed_in_time_is_a_failed_listing(tmp_path):
    service = _aws(tmp_path, regions=("eu-west-1",))
    service.limit_listing_time(5, 5)
    service._listing_deadline = time.monotonic() - 1

    with pytest.raises(AWSFetchError, match="not listed in the time allowed"):
        service._fetch_all_regions()


@pytest.mark.parametrize("limit, expected", [(None, None), (3, 3)])
def test_hetzner_requests_get_the_time(tmp_path, limit, expected):
    hcloud = pytest.importorskip("hcloud")
    service = HetznerService(HetznerConfig(
        enabled=True, api_token="token", cache_path=str(tmp_path / "hetzner_cache.json"),
    ))
    if limit is not None:
        service.limit_listing_time(limit, limit)

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
        service.limit_listing_time(limit, limit)

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
    limited_service.limit_listing_time(3, 3)
    limited = limited_service._get_client()

    assert unlimited._client._retry_max_retries > 0
    assert limited._client._retry_max_retries == 0


# ---------------------------------------------------------------------------
# Region order: a time-limited listing reaches the likeliest regions first
# ---------------------------------------------------------------------------

AWS_ORDER = ["ap-south-1", "eu-west-1", "us-east-1", "eu-central-1"]


def _listed_order(service, monkeypatch):
    client = SimpleNamespace(describe_regions=lambda: {
        "Regions": [{"RegionName": name} for name in AWS_ORDER],
    })
    monkeypatch.setattr(service, "_client", lambda name, region=None: client)
    listed = []
    monkeypatch.setattr(service, "_fetch_region", lambda region: listed.append(region) or [])
    service._fetch_all_regions()
    return listed


def test_aws_lists_its_default_region_then_us_east_1_first(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-central-1")

    listed = _listed_order(_aws(tmp_path), monkeypatch)

    assert listed == ["eu-central-1", "us-east-1", "ap-south-1", "eu-west-1"]


def test_aws_takes_a_profiles_region_as_its_default(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.write_text("[profile prod]\nregion = eu-west-1\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    account = AWSAccountContext(AccountRef("aws", "prod", False), "prod")
    service = AWSService(CacheService(cache_path=tmp_path / "cache.prod.json"), account=account)

    listed = _listed_order(service, monkeypatch)

    assert listed == ["eu-west-1", "us-east-1", "ap-south-1", "eu-central-1"]


def test_aws_configured_regions_keep_their_order(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-central-1")
    service = _aws(tmp_path, regions=("ap-south-1", "eu-west-1"))
    listed = []
    monkeypatch.setattr(service, "_fetch_region", lambda region: listed.append(region) or [])

    service._fetch_all_regions()

    assert listed == ["ap-south-1", "eu-west-1"]
