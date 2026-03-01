"""File-based cache service with TTL for EC2 instance data."""

from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional
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
        if not self.CACHE_PATH.exists():
            logger.debug("Cache file does not exist")
            return None

        try:
            with open(self.CACHE_PATH, 'r') as f:
                cache_data = json.load(f)

            timestamp_str = cache_data.get('timestamp')
            instances = cache_data.get('instances')

            if timestamp_str is None or instances is None:
                logger.warning("Invalid cache file format (missing timestamp or instances)")
                return None

            cache_timestamp = datetime.fromisoformat(timestamp_str)
            age = datetime.now() - cache_timestamp

            if age >= timedelta(seconds=self.ttl_seconds):
                logger.debug(f"Cache expired (age: {age}, TTL: {self.ttl_seconds}s)")
                return None

            logger.debug(f"Loaded {len(instances)} instances from cache (age: {age})")
            return instances

        except (json.JSONDecodeError, IOError, KeyError, ValueError) as e:
            logger.error(f"Error reading cache file: {e}")
            return None

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
        if not self.CACHE_PATH.exists():
            return None

        try:
            with open(self.CACHE_PATH, 'r') as f:
                cache_data = json.load(f)

            instances = cache_data.get('instances')
            if instances is None:
                return None

            age = self.get_age()
            logger.debug("Loaded %d instances from cache (age: %s, stale: %s)",
                         len(instances), age, age and age >= timedelta(seconds=self.ttl_seconds))
            return instances

        except (json.JSONDecodeError, IOError, KeyError, ValueError) as e:
            logger.error("Error reading cache file: %s", e)
            return None

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
        if not self.CACHE_PATH.exists():
            return None

        try:
            with open(self.CACHE_PATH, 'r') as f:
                cache_data = json.load(f)

            timestamp_str = cache_data.get('timestamp')
            if timestamp_str is None:
                return None

            cache_timestamp = datetime.fromisoformat(timestamp_str)
            return datetime.now() - cache_timestamp

        except (json.JSONDecodeError, IOError, KeyError, ValueError) as e:
            logger.error(f"Error reading cache timestamp: {e}")
            return None

    def invalidate(self) -> None:
        """Delete cache file to force fresh fetch."""
        if self.CACHE_PATH.exists():
            try:
                self.CACHE_PATH.unlink()
                logger.debug("Cache invalidated")
            except OSError as e:
                logger.error(f"Error deleting cache file: {e}")
