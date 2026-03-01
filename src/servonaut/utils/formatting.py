"""Formatting utilities for time, strings, and file sizes."""

from __future__ import annotations
from datetime import timedelta


def format_timedelta(td: timedelta) -> str:
    """Format a timedelta object into a human-readable string.

    Args:
        td: timedelta to format.

    Returns:
        Human-readable string like "2d 3h 15m" or "45s".

    Examples:
        >>> format_timedelta(timedelta(days=2, hours=3, minutes=15))
        '2d 3h 15m'
        >>> format_timedelta(timedelta(minutes=3, seconds=42))
        '3m 42s'
        >>> format_timedelta(timedelta(seconds=30))
        '30s'
    """
    parts = []

    if td.days > 0:
        parts.append(f"{td.days}d")

    seconds = td.seconds
    hours = seconds // 3600
    if hours > 0:
        parts.append(f"{hours}h")

    minutes = (seconds % 3600) // 60
    if minutes > 0:
        parts.append(f"{minutes}m")

    # Show seconds if total is less than a minute or only seconds exist
    if not parts or (hours == 0 and minutes == 0):
        parts.append(f"{seconds % 60}s")

    return " ".join(parts) if parts else "0s"


def truncate_string(s: str, max_length: int = 40) -> str:
    """Truncate a string to a maximum length with ellipsis.

    Args:
        s: String to truncate.
        max_length: Maximum length (default: 40).

    Returns:
        Truncated string with '...' if longer than max_length.

    Examples:
        >>> truncate_string("short")
        'short'
        >>> truncate_string("this is a very long string that will be truncated", 20)
        'this is a very lo...'
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + '...'


def format_file_size(size_bytes: int) -> str:
    """Format file size in bytes to human-readable format.

    Args:
        size_bytes: File size in bytes.

    Returns:
        Formatted string like "1.5 KB", "2.3 MB", "1.2 GB".

    Examples:
        >>> format_file_size(1024)
        '1.0 KB'
        >>> format_file_size(1536)
        '1.5 KB'
        >>> format_file_size(1048576)
        '1.0 MB'
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
