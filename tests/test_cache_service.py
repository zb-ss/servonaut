"""Tests for cache service."""

import json

import pytest
from datetime import datetime, timedelta, timezone

from servonaut.services.cache_service import CacheService


class TestCacheService:

    @pytest.fixture
    def cache_service(self, tmp_path):
        """Cache service with temp path."""
        service = CacheService(ttl_seconds=300)
        service.CACHE_PATH = tmp_path / 'cache.json'
        return service

    @pytest.fixture
    def sample_data(self):
        return [{'id': 'i-abc123', 'name': 'web-server'}]

    def test_save_and_load(self, cache_service, sample_data):
        cache_service.save(sample_data)
        loaded = cache_service.load()
        assert loaded == sample_data

    def test_load_returns_none_when_no_file(self, cache_service):
        assert cache_service.load() is None

    def test_load_returns_none_when_expired(self, cache_service, sample_data):
        cache_data = {
            'timestamp': (datetime.now() - timedelta(seconds=600)).isoformat(),
            'instances': sample_data,
        }
        with open(cache_service.CACHE_PATH, 'w') as f:
            json.dump(cache_data, f)
        assert cache_service.load() is None

    def test_load_any_ignores_ttl(self, cache_service, sample_data):
        cache_data = {
            'timestamp': (datetime.now() - timedelta(seconds=600)).isoformat(),
            'instances': sample_data,
        }
        with open(cache_service.CACHE_PATH, 'w') as f:
            json.dump(cache_data, f)
        assert cache_service.load() is None
        assert cache_service.load_any() == sample_data

    def test_is_fresh(self, cache_service, sample_data):
        cache_service.save(sample_data)
        assert cache_service.is_fresh() is True

    def test_is_fresh_when_expired(self, cache_service, sample_data):
        cache_data = {
            'timestamp': (datetime.now() - timedelta(seconds=600)).isoformat(),
            'instances': sample_data,
        }
        with open(cache_service.CACHE_PATH, 'w') as f:
            json.dump(cache_data, f)
        assert cache_service.is_fresh() is False

    def test_is_fresh_when_no_cache(self, cache_service):
        assert cache_service.is_fresh() is False

    def test_invalidate(self, cache_service, sample_data):
        cache_service.save(sample_data)
        assert cache_service.CACHE_PATH.exists()
        cache_service.invalidate()
        assert not cache_service.CACHE_PATH.exists()

    def test_invalidate_no_file(self, cache_service):
        cache_service.invalidate()

    def test_get_age(self, cache_service, sample_data):
        cache_service.save(sample_data)
        age = cache_service.get_age()
        assert age is not None
        assert age.total_seconds() < 5

    def test_get_age_no_cache(self, cache_service):
        assert cache_service.get_age() is None

    def test_load_corrupted_json(self, cache_service):
        cache_service.CACHE_PATH.write_text('not json{{{')
        assert cache_service.load() is None

    def test_load_missing_fields(self, cache_service):
        cache_service.CACHE_PATH.write_text('{"other": "data"}')
        assert cache_service.load() is None

    def test_is_valid(self, cache_service, sample_data):
        cache_service.save(sample_data)
        assert cache_service.is_valid() is True

    def test_is_valid_when_expired(self, cache_service, sample_data):
        cache_data = {
            'timestamp': (datetime.now() - timedelta(seconds=600)).isoformat(),
            'instances': sample_data,
        }
        with open(cache_service.CACHE_PATH, 'w') as f:
            json.dump(cache_data, f)
        assert cache_service.is_valid() is False


class TestCacheFileShapes:
    """cache.json is user-writable: an odd shape means "no cache", never a crash."""

    @pytest.fixture
    def cache_service(self, tmp_path):
        service = CacheService(ttl_seconds=300)
        service.CACHE_PATH = tmp_path / 'cache.json'
        return service

    @pytest.mark.parametrize("payload", [
        [],                                                      # top level not an object
        "just a string",
        {"timestamp": "2026-01-01T00:00:00", "instances": {"i-1": {}}},
        {"timestamp": "2026-01-01T00:00:00", "instances": [1, "x"]},
        {"timestamp": "2026-01-01T00:00:00", "instances": "i-1"},
    ])
    def test_bad_shapes_read_as_no_cache(self, cache_service, payload):
        cache_service.CACHE_PATH.write_text(json.dumps(payload))
        assert cache_service.load() is None
        assert cache_service.load_any() is None
        assert cache_service.is_valid() is False

    @pytest.mark.parametrize("timestamp", [12345, None, "not-a-date", ["2026"]])
    def test_bad_timestamp_has_no_age(self, cache_service, timestamp):
        cache_service.CACHE_PATH.write_text(json.dumps(
            {"timestamp": timestamp, "instances": [{"id": "i-1"}]},
        ))
        assert cache_service.get_age() is None
        assert cache_service.is_fresh() is False
        assert cache_service.load() is None
        # load_any ignores age, so the instances are still usable.
        assert cache_service.load_any() == [{"id": "i-1"}]

    @pytest.mark.parametrize("stamp", [
        lambda: datetime.now(timezone.utc),                                  # aware UTC
        lambda: datetime.now(timezone(timedelta(hours=-7))),                 # aware offset
        lambda: datetime.now(),                                              # naive local
    ])
    def test_aware_and_naive_timestamps_agree(self, cache_service, stamp):
        cache_service.CACHE_PATH.write_text(json.dumps(
            {"timestamp": stamp().isoformat(), "instances": [{"id": "i-1"}]},
        ))
        age = cache_service.get_age()
        assert age is not None and abs(age.total_seconds()) < 60
        assert cache_service.is_fresh() is True
        assert cache_service.load() == [{"id": "i-1"}]

    def test_old_aware_timestamp_is_stale(self, cache_service):
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        cache_service.CACHE_PATH.write_text(json.dumps(
            {"timestamp": old.isoformat(), "instances": [{"id": "i-1"}]},
        ))
        assert cache_service.is_fresh() is False
        assert cache_service.load() is None
        assert cache_service.load_any() == [{"id": "i-1"}]
