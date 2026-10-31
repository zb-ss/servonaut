"""How long a rate-limited (429) API reply asks the caller to wait."""
from __future__ import annotations

import math
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional


def retry_after_seconds(exc: Exception) -> Optional[float]:
    """The wait a 429's ``Retry-After`` asks for (seconds or an HTTP date); None when absent."""
    headers = getattr(exc, "response_headers", None) or {}
    value = str(headers.get("retry-after") or "").strip()
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        pass
    else:
        # "inf", "nan" or an overflowing number name no wait that can be honoured.
        return max(0.0, seconds) if math.isfinite(seconds) else None
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def is_rate_limited(exc: Exception) -> bool:
    """Whether *exc* is the API's 429 refusal."""
    from servonaut.services.api_client import APIError

    return isinstance(exc, APIError) and exc.status == 429


def wait_text(seconds: Optional[float]) -> str:
    """``try again in …`` for a wait in seconds; ``try again later`` when unknown."""
    if seconds is None:
        return "try again later"
    if seconds < 60:
        return f"try again in {max(1, round(seconds))} s"
    return f"try again in {max(1, round(seconds / 60))} min"
