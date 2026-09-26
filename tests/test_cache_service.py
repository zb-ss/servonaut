"""Tests for cache service."""

import json
import os
import time

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


class TestCacheTimestamps:
    """Cache age must survive time-zone and DST changes between write and read."""

    @pytest.fixture
    def cache_service(self, tmp_path):
        service = CacheService(ttl_seconds=300)
        service.CACHE_PATH = tmp_path / 'cache.json'
        return service

    @pytest.fixture
    def sample_data(self):
        return [{'id': 'i-abc123', 'name': 'web-server'}]

    @pytest.fixture
    def local_zone(self):
        """Switch the process's local time zone; restore it afterwards."""
        if not hasattr(time, 'tzset'):
            pytest.skip('time.tzset is POSIX-only')
        original = os.environ.get('TZ')

        def switch(zone: str) -> None:
            os.environ['TZ'] = zone
            time.tzset()

        yield switch
        if original is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = original
        time.tzset()

    def _write(self, cache_service, **fields):
        cache_service.CACHE_PATH.write_text(json.dumps(fields))

    def test_save_stores_an_aware_utc_timestamp(self, cache_service, sample_data):
        cache_service.save(sample_data)

        data = json.loads(cache_service.CACHE_PATH.read_text())
        written = datetime.fromisoformat(data['timestamp_utc'])
        assert written.utcoffset() == timedelta(0)
        assert abs(datetime.now(timezone.utc) - written) < timedelta(seconds=5)

    def test_older_releases_can_still_read_a_new_cache(self, cache_service, sample_data):
        """Older installs sharing ~/.servonaut subtract ``timestamp`` from a naive
        ``datetime.now()``; an aware value there would raise TypeError."""
        cache_service.save(sample_data)

        data = json.loads(cache_service.CACHE_PATH.read_text())
        legacy_age = datetime.now() - datetime.fromisoformat(data['timestamp'])
        assert timedelta(0) <= legacy_age < timedelta(seconds=5)

    def test_cache_written_in_another_time_zone(self, cache_service, sample_data, local_zone):
        local_zone('JST-9')
        cache_service.save(sample_data)
        local_zone('EST+5')

        age = cache_service.get_age()
        assert age is not None
        assert timedelta(0) <= age < timedelta(seconds=5)
        assert cache_service.is_fresh() is True
        assert cache_service.load() == sample_data

    def test_naive_timestamp_from_an_older_release_is_local_time(self, cache_service, sample_data):
        self._write(
            cache_service,
            timestamp=(datetime.now() - timedelta(seconds=60)).isoformat(),
            instances=sample_data,
        )

        age = cache_service.get_age()
        assert timedelta(seconds=55) < age < timedelta(seconds=65)
        assert cache_service.is_fresh() is True
        assert cache_service.load() == sample_data

    def test_future_timestamp_never_shows_a_negative_age(self, cache_service, sample_data):
        """A naive stamp an hour ahead used to render as "Cache: -3599s ago"."""
        from servonaut.widgets.status_bar import StatusBar

        self._write(
            cache_service,
            timestamp=(datetime.now() + timedelta(hours=1)).isoformat(),
            instances=sample_data,
        )

        age = cache_service.get_age()
        assert age == timedelta(0)
        assert StatusBar._format_age(None, age) == "0s ago"

    def test_future_timestamp_counts_as_stale(self, cache_service, sample_data):
        """An age that cannot be trusted must not keep the cache fresh past its TTL."""
        self._write(
            cache_service,
            timestamp=(datetime.now() + timedelta(hours=1)).isoformat(),
            instances=sample_data,
        )

        assert cache_service.is_fresh() is False
        assert cache_service.load() is None
        assert cache_service.load_any() == sample_data

    def test_aware_timestamp_in_any_offset(self, cache_service, sample_data):
        ten_seconds_ago = datetime.now(timezone.utc) - timedelta(seconds=10)
        plus_five = timezone(timedelta(hours=5))
        self._write(
            cache_service,
            timestamp=ten_seconds_ago.astimezone(plus_five).isoformat(),
            instances=sample_data,
        )

        age = cache_service.get_age()
        assert timedelta(seconds=5) < age < timedelta(seconds=15)
        assert cache_service.is_fresh() is True

    def test_utc_timestamp_wins_over_the_legacy_field(self, cache_service, sample_data):
        self._write(
            cache_service,
            timestamp=(datetime.now() + timedelta(hours=3)).isoformat(),
            timestamp_utc=(datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat(),
            instances=sample_data,
        )

        age = cache_service.get_age()
        assert timedelta(seconds=25) < age < timedelta(seconds=35)
        assert cache_service.is_fresh() is True

    @pytest.mark.parametrize("timestamp", ["not-a-date", 12345, None])
    def test_unusable_timestamp(self, cache_service, sample_data, timestamp):
        self._write(cache_service, timestamp=timestamp, instances=sample_data)

        assert cache_service.get_age() is None
        assert cache_service.is_fresh() is False
        assert cache_service.load() is None
        assert cache_service.load_any() == sample_data

    def test_non_object_cache_file(self, cache_service):
        cache_service.CACHE_PATH.write_text('[1, 2, 3]')

        assert cache_service.get_age() is None
        assert cache_service.load() is None
        assert cache_service.load_any() is None


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
