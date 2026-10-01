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
