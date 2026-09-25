"""File-based cache service with TTL for EC2 instance data."""

from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

# ``timestamp_utc`` is the authoritative write time: an ISO 8601 string with a
# UTC offset, so the cache age is right after a time-zone or DST change.
# ``timestamp`` keeps the naive local-time form older releases write and read.
# They subtract it from a naive ``datetime.now()``, so an offset-aware value
# there would crash them when several installed versions share ~/.servonaut.
_UTC_TIMESTAMP_KEY = 'timestamp_utc'
_LEGACY_TIMESTAMP_KEY = 'timestamp'


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse a stored cache timestamp into an aware UTC datetime.

    A naive value comes from an older release, which wrote the machine's
    local time, so it is read as local time.

    Returns:
        The timestamp in UTC, or None when *value* is not a usable ISO string.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def timestamp_fields(written_at: Optional[datetime] = None) -> Dict[str, str]:
    """Return the timestamp keys a cache file stores for *written_at* (default: now)."""
    moment = (written_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return {
        _UTC_TIMESTAMP_KEY: moment.isoformat(),
        _LEGACY_TIMESTAMP_KEY: moment.astimezone().replace(tzinfo=None).isoformat(),
    }


def _written_at(cache_data: Dict[str, Any]) -> Optional[datetime]:
    """Return when *cache_data* was written, as an aware UTC datetime."""
    return (
        _parse_timestamp(cache_data.get(_UTC_TIMESTAMP_KEY))
        or _parse_timestamp(cache_data.get(_LEGACY_TIMESTAMP_KEY))
    )


class CacheService:
    """File-based cache with TTL for EC2 instance lists."""

    CACHE_PATH = Path.home() / '.servonaut' / 'cache.json'

    def __init__(self, ttl_seconds: int = 300):
        """Initialize cache service.

        Args:
            ttl_seconds: Time-to-live for cached data (default: 300 = 5 minutes).
        """
        self.ttl_seconds = ttl_seconds

    def load(self) -> Optional[List[dict]]:
        """Load instances from cache if valid.

        Returns:
            List of instance dictionaries, or None if cache invalid/expired.
        """
        cache_data = self._read()
        if cache_data is None:
            return None

        instances = cache_data.get('instances')
        age = self._raw_age(cache_data)
        if age is None or instances is None:
            logger.warning("Invalid cache file format (missing timestamp or instances)")
            return None

        if not self._within_ttl(age):
            logger.debug("Cache expired (age: %s, TTL: %ss)", age, self.ttl_seconds)
            return None

        logger.debug("Loaded %d instances from cache (age: %s)", len(instances), age)
        return instances

    def save(self, instances: List[dict]) -> None:
        """Save instances to cache.

        Args:
            instances: List of instance dictionaries to cache.
        """
        cache_data = {**timestamp_fields(), 'instances': instances}

        try:
            with open(self.CACHE_PATH, 'w') as f:
                json.dump(cache_data, f, indent=2)
            logger.debug(f"Cached {len(instances)} instances")
        except IOError as e:
            logger.error(f"Error writing cache file: {e}")

    def load_any(self) -> Optional[List[dict]]:
        """Load instances from cache regardless of TTL.

        Returns cached data even if expired. Returns None only if
        no cache file exists or the file is corrupt.

        Returns:
            List of instance dictionaries, or None if no cache available.
        """
        cache_data = self._read()
        if cache_data is None:
            return None

        instances = cache_data.get('instances')
        if instances is None:
            return None

        age = self._raw_age(cache_data)
        logger.debug("Loaded %d instances from cache (age: %s, stale: %s)",
                     len(instances), age, age is None or not self._within_ttl(age))
        return instances

    def is_fresh(self) -> bool:
        """Check if cache exists and is within TTL.

        A write time in the future (clock or time-zone change) means the age
        is unknown, so that cache counts as stale and gets refreshed.

        Returns:
            True if cache is valid and not expired.
        """
        cache_data = self._read()
        if cache_data is None:
            return False
        age = self._raw_age(cache_data)
        return age is not None and self._within_ttl(age)

    def is_valid(self) -> bool:
        """Check if cache exists and is not expired.

        Returns:
            True if cache is valid and fresh.
        """
        return self.load() is not None

    def get_age(self) -> Optional[timedelta]:
        """Get age of cached data.

        Never negative: a write time in the future reads as "just now"
        (``is_fresh`` still treats that cache as stale).

        Returns:
            timedelta representing cache age, or None if cache doesn't exist.
        """
        cache_data = self._read()
        if cache_data is None:
            return None
        age = self._raw_age(cache_data)
        if age is None:
            return None
        return max(age, timedelta(0))

    def _read(self) -> Optional[Dict[str, Any]]:
        """Return the parsed cache file, or None if missing or unreadable."""
        if not self.CACHE_PATH.exists():
            logger.debug("Cache file does not exist")
            return None
        try:
            with open(self.CACHE_PATH, 'r') as f:
                cache_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Error reading cache file: %s", e)
            return None
        if not isinstance(cache_data, dict):
            logger.error("Error reading cache file: expected a JSON object")
            return None
        return cache_data

    @staticmethod
    def _raw_age(cache_data: Dict[str, Any]) -> Optional[timedelta]:
        """Time since *cache_data* was written; negative if it is in the future."""
        written_at = _written_at(cache_data)
        if written_at is None:
            return None
        return datetime.now(timezone.utc) - written_at

    def _within_ttl(self, age: timedelta) -> bool:
        return timedelta(0) <= age < timedelta(seconds=self.ttl_seconds)

    def invalidate(self) -> None:
        """Delete cache file to force fresh fetch."""
        if self.CACHE_PATH.exists():
            try:
                self.CACHE_PATH.unlink()
                logger.debug("Cache invalidated")
            except OSError as e:
                logger.error(f"Error deleting cache file: {e}")
