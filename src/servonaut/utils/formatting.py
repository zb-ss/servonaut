"""Formatting utilities for time, strings, and file sizes."""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Optional


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


def _format_token_count(n: int) -> str:
    """Compact token count rendering: 1500000 -> '1.5M', 12300 -> '12.3K'.

    Mirrors the convention used by the chat-panel quota footer in the plan
    (e.g. "[14.5M / +500K topup]"). Negatives are clamped to 0.
    """
    if n <= 0:
        return "0"
    if n >= 1_000_000:
        # Trim a trailing .0 for clean integer-millions like "15M".
        value = n / 1_000_000
        return f"{value:.1f}M".replace(".0M", "M")
    if n >= 1_000:
        value = n / 1_000
        return f"{value:.1f}K".replace(".0K", "K")
    return str(n)


def format_tokens_remaining(used: int, limit: int, topup: int) -> str:
    """Render the chat-panel "tokens remaining" footer string.

    Args:
        used: Tokens consumed in the current billing period.
        limit: Monthly bucket cap (0 indicates a free user — quota null).
        topup: Top-up balance, separate from the monthly bucket.

    Returns:
        - ``"—"`` for free users (limit == 0).
        - ``"14.5M"`` style when ``topup`` is zero or negative.
        - ``"14.5M / +500K topup"`` when ``topup`` is positive — the ``+``
          telegraphs that top-up is additive (per architect decision §7).

    Never raises; coerces non-int inputs via best-effort defaults.
    """
    try:
        used = int(used)
        limit = int(limit)
        topup = int(topup)
    except (TypeError, ValueError):
        return "—"

    if limit <= 0:
        return "—"

    remaining = max(0, limit - used)
    base = _format_token_count(remaining)
    if topup > 0:
        return f"{base} / +{_format_token_count(topup)} topup"
    return base


def format_resets_at(iso_str: str) -> str:
    """Convert an ISO-8601 timestamp into a human-relative string.

    Args:
        iso_str: ISO 8601 datetime, ideally with timezone (server emits
            ``"2026-05-01T00:00:00+00:00"``). Bare-Z form is also accepted.

    Returns:
        - ``""`` for empty/invalid/None input — defensive: never raises.
        - ``"reset overdue"`` when the date is in the past.
        - ``"today"`` when it falls in the current calendar day (UTC).
        - ``"tomorrow"`` when exactly one day off.
        - ``"in 4 days"`` for ≥2 days but <30.
        - ``"in 2h"`` for sub-day windows.
    """
    if not iso_str or not isinstance(iso_str, str):
        return ""

    parsed = _parse_iso(iso_str)
    if parsed is None:
        return ""

    # Normalise both sides to UTC so naive vs aware mixing doesn't blow up.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    delta = parsed - now
    total_seconds = delta.total_seconds()

    if total_seconds < 0:
        return "reset overdue"

    # Sub-day windows render as "in Nh" (or "today" if same calendar day UTC).
    if total_seconds < 24 * 3600:
        # If it's still the same calendar day in UTC, prefer "today".
        if parsed.date() == now.date():
            return "today"
        # Crosses midnight but is <24h away — render as hours.
        hours = max(1, int(total_seconds // 3600))
        return f"in {hours}h"

    # Day-resolution comparison uses calendar dates so "tomorrow" matches the
    # user's mental model regardless of clock skew within the day.
    days = (parsed.date() - now.date()).days
    if days <= 0:
        # Defensive — shouldn't happen given the >24h branch above, but if
        # tz arithmetic places parsed.date() on or before now.date() while
        # total_seconds >= 24h (rare DST edge case) fall back to hours.
        hours = max(1, int(total_seconds // 3600))
        return f"in {hours}h"
    if days == 1:
        return "tomorrow"
    return f"in {days} days"


def format_soft_cap_badge(
    soft_capped: bool,
    hard_capped: bool,
    model: Optional[str] = None,
) -> Optional[str]:
    """Pick the right cap badge string for the chat panel.

    Hard cap takes precedence — if a user is hard-capped the soft-cap state is
    irrelevant to the user-facing badge.

    Args:
        soft_capped: True iff server force-downgraded to a faster model.
        hard_capped: True iff token quota is fully exhausted.
        model: Optional model name from the latest ``usage`` event. When
            present and only ``soft_capped`` is true the badge reads
            ``"downgraded to <model>"``; absent → generic
            ``"downgraded to faster model"`` (D3 — never hardcode "Flash").

    Returns:
        ``"out of tokens"`` when ``hard_capped`` is true (regardless of soft).
        ``"downgraded to <model>"`` or ``"downgraded to faster model"`` when
        only ``soft_capped`` is true.
        ``None`` otherwise — caller hides the badge widget.
    """
    if hard_capped:
        return "out of tokens"
    if soft_capped:
        if model:
            return f"downgraded to {model}"
        return "downgraded to faster model"
    return None


def _parse_iso(iso_str: str) -> Optional[datetime]:
    """Parse ISO 8601, tolerant of trailing 'Z'. Returns None on failure."""
    s = iso_str.strip()
    if not s:
        return None
    # Python's fromisoformat doesn't accept the bare 'Z' suffix until 3.11+
    # for all forms; normalise to '+00:00' to widen compat.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return None


def _format_age(seconds: float) -> str:
    """Compact human-readable age — '5m', '2h', '3d'. Floors to the unit."""
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)}m"
    hours = minutes / 60
    if hours < 24:
        return f"{int(hours)}h"
    days = hours / 24
    return f"{int(days)}d"


def format_ssh_verify_state(
    status: Optional[str],
    verified_at: Optional[str],
    *,
    now_utc: Optional[datetime] = None,
) -> str:
    """Render the SSH verify state as a Rich-markup string for the TUI.

    Locked contract with servonaut.dev (2026-05-24): the server NULLs
    ``ssh_verified_at`` whenever ``ssh_verify_status`` is anything other
    than ``"verified"``. This helper enforces the same invariant
    client-side — even if a buggy server response includes a timestamp
    alongside a non-verified status, we IGNORE it so the UI never shows
    a stale "last verified 3h ago" next to a red "auth failed" badge.

    Args:
        status: One of ``"verified"``, ``"not_found"``, ``"auth_failed"``
            from :mod:`servonaut.services.bw_ssh_config_service`. Anything
            else (None, unknown enum, non-string) renders as "no data".
        verified_at: ISO-8601 timestamp from the server. Only consulted
            when ``status == "verified"``.
        now_utc: Override for testing; defaults to current UTC time.

    Returns:
        Rich-markup string suitable for ``DataTable.add_row`` /
        ``Static.update``. Never raises.
    """
    if not isinstance(status, str) or not status:
        return "[dim]—[/dim]"
    s = status.strip().lower()
    if s == "verified":
        if not verified_at or not isinstance(verified_at, str):
            # Server contract says this shouldn't happen, but degrade
            # gracefully if it does — show verified without an age.
            return "[green]✓ verified[/green]"
        parsed = _parse_iso(verified_at)
        if parsed is None:
            return "[green]✓ verified[/green]"
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        now = now_utc or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        age_seconds = max(0.0, (now - parsed).total_seconds())
        return f"[green]✓ verified[/green] ({_format_age(age_seconds)} ago)"
    if s == "not_found":
        return "[red]✗ not found[/red]"
    if s == "auth_failed":
        return "[red]✗ auth failed[/red]"
    # Defensive: unknown status enum value — degrade to "no data" rather
    # than render literal text the user can't interpret.
    return "[dim]—[/dim]"
