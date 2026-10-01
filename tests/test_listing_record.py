"""The record of a failed or incomplete listing, kept next to an account's cache."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from servonaut.config.schema import HetznerConfig, OVHConfig
from servonaut.services.accounts.listing_record import FAILED, PARTIAL, ListingRecord
from servonaut.services.aws_service import AWSService
from servonaut.services.cache_service import CacheService
from servonaut.services.hetzner_service import HetznerService
from servonaut.services.ovh_service import OVHService

ROWS = [{"id": "i-2", "name": "web-1"}]


def test_it_sits_next_to_the_cache(tmp_path):
    record = ListingRecord.beside(tmp_path / "hetzner_cache.staging.json", 60)
    record.save(FAILED, "401 Unauthorized", [], now=1000.0)

    path = tmp_path / "hetzner_cache.staging.json.listing"
    assert path.exists() and stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_it_counts_for_the_ttl_only(tmp_path):
    record = ListingRecord.beside(tmp_path / "cache.json", 60)
    record.save(PARTIAL, "1 region(s) failed: eu-west-1", ROWS, now=1000.0)

    remembered = record.load(now=1059.0)
    assert (remembered.outcome, remembered.detail, remembered.rows) == (
        PARTIAL, "1 region(s) failed: eu-west-1", ROWS,
    )
    assert (remembered.at, remembered.until) == (1000.0, 1060.0)
    assert record.load(now=1060.0) is None
    # A record from the future (the clock went back) does not count either.
    assert record.load(now=999.0) is None


def test_a_failure_counts_for_the_time_the_caller_says(tmp_path):
    record = ListingRecord.beside(tmp_path / "cache.json", 3600)
    record.save(FAILED, "401 Unauthorized", [], now=1000.0, keep_seconds=30)

    assert record.load(now=1029.0).until == 1030.0
    assert record.load(now=1030.0) is None


@pytest.mark.parametrize("content", ["{not json", "[]", '{"outcome": "odd", "at": 1, "rows": []}',
                                     '{"outcome": "failed", "at": "x", "rows": []}'])
def test_an_unusable_record_is_ignored(tmp_path, content):
    (tmp_path / "cache.json.listing").write_text(content)
    assert ListingRecord.beside(tmp_path / "cache.json", 60).load(now=10.0) is None


def test_a_record_that_cannot_be_written_is_only_logged(tmp_path, caplog):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    record = ListingRecord.beside(blocker / "cache.json", 60)

    record.save(FAILED, "boom", [])

    assert record.load() is None
    assert "Could not remember the listing" in caplog.text


def _remembers_for(record: ListingRecord, ttl: float) -> bool:
    record.save(FAILED, "x", [], now=0.0)
    return record.load(now=ttl - 1) is not None and record.load(now=ttl) is None


def test_each_provider_keeps_it_beside_its_cache_for_its_ttl(tmp_path):
    aws = AWSService(CacheService(ttl_seconds=120, cache_path=tmp_path / "cache.prod.json"))
    hetzner = HetznerService(HetznerConfig(
        enabled=True, api_token="t", cache_path=str(tmp_path / "hetzner_cache.json"),
        cache_ttl_seconds=90,
    ))
    ovh = OVHService(OVHConfig(), cache_path=tmp_path / "ovh_cache.json")

    assert _remembers_for(aws.listing_record(), 120)
    assert _remembers_for(hetzner.listing_record(), 90)
    assert _remembers_for(ovh.listing_record(), 300)
    assert sorted(p.name for p in Path(tmp_path).iterdir()) == [
        "cache.prod.json.listing", "hetzner_cache.json.listing", "ovh_cache.json.listing",
    ]
