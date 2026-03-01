"""Status bar widget for Servonaut v2.0."""

from __future__ import annotations
from typing import Optional
from datetime import timedelta

from textual.widgets import Static


class StatusBar(Static):
    """Status bar showing instance counts, cache age, and filter status."""

    def __init__(self) -> None:
        """Initialize status bar."""
        super().__init__("")
        self._total_count = 0
        self._filtered_count = 0
        self._cache_age: Optional[timedelta] = None
        self._filter_active = False
        self._update_display()

    def update_instance_count(self, total: int, filtered: int) -> None:
        """Update instance counts.

        Args:
            total: Total number of instances.
            filtered: Number of filtered instances shown.
        """
        self._total_count = total
        self._filtered_count = filtered
        self._filter_active = (total != filtered)
        self._update_display()

    def update_cache_age(self, age: Optional[timedelta]) -> None:
        """Update cache age display.

        Args:
            age: Cache age as timedelta, or None if no cache.
        """
        self._cache_age = age
        self._update_display()

    def _update_display(self) -> None:
        """Update the status bar display text."""
        parts = []

        # Instance count
        if self._filter_active:
            parts.append(f"{self._filtered_count}/{self._total_count} instances")
        else:
            parts.append(f"{self._total_count} instances")

        # Cache age
        if self._cache_age is not None:
            age_str = self._format_age(self._cache_age)
            parts.append(f"Cache: {age_str}")

        # Filter status
        if self._filter_active:
            parts.append("[yellow]Filter: active[/yellow]")

        self.update(" | ".join(parts))

    def _format_age(self, age: timedelta) -> str:
        """Format cache age as human-readable string.

        Args:
            age: Cache age as timedelta.

        Returns:
            Formatted string like "2m 30s" or "1h 5m".
        """
        total_seconds = int(age.total_seconds())

        if total_seconds < 60:
            return f"{total_seconds}s ago"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes}m {seconds}s ago"
        else:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m ago"
