"""File-based cache service with TTL for EC2 instance data."""

from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional
import logging

logger = logging.getLogger(__name__)


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
        cache_data = self._read_cache_file()
        if cache_data is None:
            return None

        instances = self._valid_instances(cache_data)
        age = self._age_of(cache_data)
        if instances is None or age is None:
            logger.warning("Invalid cache file format (missing timestamp or instances)")
            return None

        if age >= timedelta(seconds=self.ttl_seconds):
            logger.debug(f"Cache expired (age: {age}, TTL: {self.ttl_seconds}s)")
            return None

        logger.debug(f"Loaded {len(instances)} instances from cache (age: {age})")
        return instances

    def save(self, instances: List[dict]) -> None:
        """Save instances to cache.

        Args:
            instances: List of instance dictionaries to cache.
        """
        cache_data = {
            'timestamp': datetime.now().isoformat(),
            'instances': instances
        }

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
        cache_data = self._read_cache_file()
        if cache_data is None:
            return None

        instances = self._valid_instances(cache_data)
        if instances is None:
            return None

        age = self._age_of(cache_data)
        logger.debug("Loaded %d instances from cache (age: %s, stale: %s)",
                     len(instances), age, age and age >= timedelta(seconds=self.ttl_seconds))
        return instances

    def is_fresh(self) -> bool:
        """Check if cache exists and is within TTL.

        Returns:
            True if cache is valid and not expired.
        """
        age = self.get_age()
        if age is None:
            return False
        return age < timedelta(seconds=self.ttl_seconds)

    def is_valid(self) -> bool:
        """Check if cache exists and is not expired.

        Returns:
            True if cache is valid and fresh.
        """
        return self.load() is not None

    def get_age(self) -> Optional[timedelta]:
        """Get age of cached data.

        Returns:
            timedelta representing cache age, or None if cache doesn't exist.
        """
        cache_data = self._read_cache_file()
        if cache_data is None:
            return None
        return self._age_of(cache_data)

    # ------------------------------------------------------------------
    # Parsing helpers — the cache file is user-writable, so every shape
    # check degrades to "no usable cache" instead of raising.
    # ------------------------------------------------------------------

    def _read_cache_file(self) -> Optional[dict]:
        """Return the decoded cache object, or ``None`` if absent/unusable."""
        if not self.CACHE_PATH.exists():
            logger.debug("Cache file does not exist")
            return None
        try:
            with open(self.CACHE_PATH, 'r') as f:
                cache_data = json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            logger.error("Error reading cache file: %s", e)
            return None
        if not isinstance(cache_data, dict):
            logger.warning(
                "Ignoring cache file: expected a JSON object, got %s",
                type(cache_data).__name__,
            )
            return None
        return cache_data

    @staticmethod
    def _valid_instances(cache_data: dict) -> Optional[List[dict]]:
        """Return ``instances`` when it is a list of dicts, else ``None``."""
        instances = cache_data.get('instances')
        if instances is None:
            return None
        if not isinstance(instances, list) or not all(
            isinstance(item, dict) for item in instances
        ):
            logger.warning("Ignoring cache file: 'instances' is not a list of objects")
            return None
        return instances

    @staticmethod
    def _age_of(cache_data: dict) -> Optional[timedelta]:
        """Age of the cache, or ``None`` when the timestamp is unusable.

        :meth:`save` writes a naive local time; an aware timestamp (any
        offset) is accepted too. Both are compared as aware datetimes —
        a naive value is read as local time — so neither form can raise.
        """
        raw: Any = cache_data.get('timestamp')
        if not isinstance(raw, str):
            return None
        try:
            stamp = datetime.fromisoformat(raw)
            if stamp.tzinfo is None:
                stamp = stamp.astimezone()  # naive → local time, made aware
            return datetime.now(timezone.utc) - stamp
        except (ValueError, OverflowError, OSError):
            logger.warning("Ignoring unusable cache timestamp %r", raw)
            return None

    def invalidate(self) -> None:
        """Delete cache file to force fresh fetch."""
        if self.CACHE_PATH.exists():
            try:
                self.CACHE_PATH.unlink()
                logger.debug("Cache invalidated")
            except OSError as e:
                logger.error(f"Error deleting cache file: {e}")
