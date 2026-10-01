"""A CLI lookup's listing of a never-listed account, against a slow API.

Real AWS, Hetzner and OVH services, whose SDK requests each take a while
and come one after the other in one blocking call (the AWS region loop,
hcloud's paging, OVH's per-server requests). Whatever the provider, the
whole ``asyncio.run`` of the lookup, as a command runs it, ends with the
budget, and what was listed in time comes back as a partial listing.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig, HetznerConfig, OVHConfig
from servonaut.services import ovh_service
from servonaut.services.accounts import AccountRegistry
from servonaut.services.accounts.headless import CachedFleet
from servonaut.services.accounts.listing_record import PARTIAL
from servonaut.services.aws_service import AWSService
from servonaut.services.cache_service import CacheService
from servonaut.services.hetzner_service import HetznerService
from servonaut.services.ovh_service import OVHService

BUDGET = 1.0
REQUEST = 0.3
# Enough requests that listing everything would take far longer than BUDGET.
REQUESTS = 10
MARGIN = 0.6


def _custom():
    service = MagicMock()
    service.list_as_instances.return_value = []
    return service


@pytest.fixture
def config(tmp_path, monkeypatch):
    """A config whose ambient AWS account has credentials and an empty cache."""
    for name in [name for name in os.environ if name.startswith("AWS_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    aws_cache = tmp_path / "cache.json"
    aws_cache.write_text(json.dumps({"timestamp": datetime.now().isoformat(), "instances": []}))
    monkeypatch.setattr(CacheService, "CACHE_PATH", aws_cache)
    return AppConfig(account_check_timeout_seconds=BUDGET)


def _lookup(config):
    """Run the lookup as a command does; return the rows, notes and seconds taken."""
    fleet = CachedFleet.from_registry(AccountRegistry(config), _custom())
    begin = time.monotonic()
    checked = asyncio.run(fleet.checked_rows("web-1"))
    return checked, time.monotonic() - begin


def _assert_partly_listed(checked, elapsed, account, record):
    assert elapsed < BUDGET + MARGIN, elapsed
    assert 1 <= len(checked.rows) < REQUESTS, len(checked.rows)
    assert len(checked.notes) == 1
    assert checked.notes[0].startswith(f"Note: {account} was only partly listed (")
    assert record.load().outcome == PARTIAL


def test_aws_regions_listed_in_time_come_back(config, tmp_path, monkeypatch):
    regions = [f"r-{n}" for n in range(REQUESTS)]
    config.aws.regions = regions
    (tmp_path / "cache.json").unlink()  # the AWS account was never listed

    def one_region(self, region):
        time.sleep(REQUEST)
        return [{"id": f"i-{region}", "name": "web-1", "region": region}]

    monkeypatch.setattr(AWSService, "_fetch_region", one_region)

    checked, elapsed = _lookup(config)

    _assert_partly_listed(checked, elapsed, "AWS account 'aws'",
                          AWSService(CacheService(ttl_seconds=60)).listing_record())
    assert "region(s) not listed in the time allowed" in checked.notes[0]
    assert not (tmp_path / "cache.json").exists()


def test_hetzner_pages_listed_in_time_come_back(config, tmp_path, monkeypatch):
    config.hetzner = HetznerConfig(enabled=True, api_token="token",
                                   cache_path=str(tmp_path / "hetzner_cache.json"))

    def page_of(page, per_page):
        time.sleep(REQUEST)
        more = page < REQUESTS
        return [f"server-{page}"], SimpleNamespace(
            pagination=SimpleNamespace(next_page=page + 1 if more else None),
        )

    client = SimpleNamespace(servers=SimpleNamespace(
        max_per_page=1, get_list=page_of,
        get_all=lambda: pytest.fail("a time-limited listing pages itself"),
    ))
    monkeypatch.setattr(HetznerService, "_get_client", lambda self: client)
    monkeypatch.setattr(HetznerService, "_server_to_dict",
                        lambda self, server: {"id": server, "name": "web-1", "is_hetzner": True})

    checked, elapsed = _lookup(config)

    service = HetznerService(config.hetzner)
    _assert_partly_listed(checked, elapsed, "Hetzner project 'hetzner'", service.listing_record())
    assert "the rest was not listed in the time allowed" in checked.notes[0]
    assert not service.has_cached_instances()


def test_ovh_servers_listed_in_time_come_back(config, tmp_path, monkeypatch):
    config.ovh = OVHConfig(enabled=True, application_key="k", application_secret="s",
                           consumer_key="c", include_dedicated=False, include_cloud=False)
    monkeypatch.setattr(ovh_service, "_OVH_CACHE_PATH", tmp_path / "ovh_cache.json")

    def get(path):
        if path == "/vps":
            return [f"vps-{n}" for n in range(REQUESTS)]
        if path.endswith("/ips"):
            return []
        time.sleep(REQUEST)
        return {"displayName": "web-1"}

    monkeypatch.setattr(OVHService, "_get_client", lambda self: SimpleNamespace(get=get))

    checked, elapsed = _lookup(config)

    service = OVHService(config.ovh)
    _assert_partly_listed(checked, elapsed, "OVH account 'ovh'", service.listing_record())
    assert "OVH VPS not fully listed in the time allowed" in checked.notes[0]
    assert not service.has_cached_instances()


# ---------------------------------------------------------------------------
# No answer vs an error response: how long each is left alone
# ---------------------------------------------------------------------------

RETRY = 7


def _outcome(config, record):
    """The remembered outcome after one lookup, and for how many seconds it counts."""
    config.account_retry_seconds = RETRY
    checked, _ = _lookup(config)
    remembered = record.load()
    return remembered.outcome, round(remembered.until - remembered.at), checked.notes[0]


def _aws_timeout():
    from botocore.exceptions import ConnectTimeoutError

    return ConnectTimeoutError(endpoint_url="http://ec2.invalid")


def _aws_auth_failure():
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": "AuthFailure", "Message": "not authorized"}},
                       "DescribeInstances")


def _aws_tls_failure():
    from botocore.exceptions import SSLError

    return SSLError(endpoint_url="https://ec2.invalid", error="certificate verify failed")


def _aws_proxy_failure():
    from botocore.exceptions import ProxyConnectionError

    return ProxyConnectionError(proxy_url="http://proxy.invalid:3128", error="refused")


@pytest.mark.parametrize("make_error, expected", [
    (_aws_timeout, "timeout"),
    (_aws_auth_failure, "failed"),
    # A TLS-intercepting or wrongly set proxy does not heal in seconds.
    (_aws_tls_failure, "failed"),
    (_aws_proxy_failure, "failed"),
])
def test_aws_no_answer_and_error_response(config, tmp_path, monkeypatch, make_error, expected):
    config.aws.regions = ["r-1", "r-2"]
    (tmp_path / "cache.json").unlink()

    def one_region(self, region):
        raise make_error()

    monkeypatch.setattr(AWSService, "_fetch_region", one_region)

    outcome, keep, note = _outcome(
        config, AWSService(CacheService(ttl_seconds=config.cache_ttl_seconds)).listing_record(),
    )

    ttl = config.cache_ttl_seconds
    assert (outcome, keep) == (expected, RETRY if expected == "timeout" else ttl)
    prefix = "no answer: " if expected == "timeout" else ""
    assert f"could not be listed ({prefix}all 2 AWS regions failed" in note


@pytest.mark.parametrize("make_error, expected", [
    (lambda: __import__("requests").exceptions.ReadTimeout("read timed out"), "timeout"),
    (lambda: __import__("hcloud").APIException("unauthorized", "unable to authenticate", None),
     "failed"),
    (lambda: __import__("requests").exceptions.SSLError("certificate verify failed"), "failed"),
    (lambda: __import__("requests").exceptions.ProxyError("proxy refused"), "failed"),
])
def test_hetzner_no_answer_and_error_response(config, tmp_path, monkeypatch, make_error,
                                              expected):
    config.hetzner = HetznerConfig(enabled=True, api_token="token", cache_ttl_seconds=120,
                                   cache_path=str(tmp_path / "hetzner_cache.json"))

    def refuse(page, per_page):
        raise make_error()

    client = SimpleNamespace(servers=SimpleNamespace(max_per_page=50, get_list=refuse))
    monkeypatch.setattr(HetznerService, "_get_client", lambda self: client)

    outcome, keep, _ = _outcome(config, HetznerService(config.hetzner).listing_record())

    assert (outcome, keep) == (expected, RETRY if expected == "timeout" else 120)


def _ovh_http_error():
    """python-ovh's wrapper of a requests error, raised while handling it."""
    import ovh.exceptions
    import requests

    try:
        raise requests.exceptions.ConnectTimeout("connect timed out")
    except requests.exceptions.ConnectTimeout as error:
        try:
            raise ovh.exceptions.HTTPError("Low HTTP request failed error", error)
        except ovh.exceptions.HTTPError as wrapped:
            return wrapped


@pytest.mark.parametrize("make_error, expected", [
    (_ovh_http_error, "timeout"),
    (lambda: __import__("ovh").exceptions.InvalidCredential("Invalid credential"), "failed"),
])
def test_ovh_no_answer_and_error_response(config, tmp_path, monkeypatch, make_error, expected):
    config.ovh = OVHConfig(enabled=True, application_key="k", application_secret="s",
                           consumer_key="c", include_dedicated=False, include_cloud=False)
    monkeypatch.setattr(ovh_service, "_OVH_CACHE_PATH", tmp_path / "ovh_cache.json")

    def get(path):
        raise make_error()

    monkeypatch.setattr(OVHService, "_get_client", lambda self: SimpleNamespace(get=get))

    outcome, keep, _ = _outcome(config, OVHService(config.ovh).listing_record())

    assert (outcome, keep) == (expected, RETRY if expected == "timeout" else 300)
