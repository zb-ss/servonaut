"""Tests for cache service."""

import json

import pytest
from datetime import datetime, timedelta

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
