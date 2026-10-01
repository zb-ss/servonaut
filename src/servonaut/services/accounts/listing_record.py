"""What listing an account without a cache found, kept for the cache's TTL.

A CLI name lookup lists an account that was never listed on this machine
(see ``CachedFleet.checked_rows``). A complete listing writes the account's
cache. One that failed, or found servers but was not complete enough to be
saved as the cache, writes nothing there, so without a record every command
would list the account again. The record sits next to the cache
(``<cache file>.listing``) and holds the outcome, why, until when it counts,
and the servers an incomplete listing found. An incomplete listing counts for
as long as a cache would; the caller says how long a failure counts.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from servonaut.utils.atomic_file import write_json_atomic

logger = logging.getLogger(__name__)

# An error response (credentials, permissions, a credential helper).
FAILED = "failed"
# Listed in part; what was listed counts as checked.
PARTIAL = "partial"
# No answer: the time ran out, a request timed out or could not connect.
TIMEOUT = "timeout"
_OUTCOMES = (FAILED, PARTIAL, TIMEOUT)


@dataclass(frozen=True)
class Listing:
    """One remembered listing of an account."""

    outcome: str
    # Why it failed or was incomplete, in the provider's words.
    detail: str
    # Epoch seconds of the listing, and until when it counts.
    at: float
    until: float
    # The servers an incomplete listing found (none for a failed one).
    rows: List[dict] = field(default_factory=list)


class ListingRecord:
    """The remembered listing of one account, stored next to its cache."""

    def __init__(self, path: Optional[Path], ttl_seconds: float) -> None:
        """*path* None keeps the record in memory (tests, fakes)."""
        self._path = Path(path) if path is not None else None
        self._ttl_seconds = max(float(ttl_seconds), 0.0)
        self._memory: Optional[Dict[str, Any]] = None

    @classmethod
    def beside(cls, cache_path: Path, ttl_seconds: float) -> "ListingRecord":
        """The record of the account whose cache is *cache_path*."""
        cache_path = Path(cache_path).expanduser()
        return cls(cache_path.with_name(cache_path.name + ".listing"), ttl_seconds)

    def load(self, now: Optional[float] = None) -> Optional[Listing]:
        """The remembered listing, or None when there is none that still counts."""
        data = self._read()
        if not isinstance(data, dict) or data.get("outcome") not in _OUTCOMES:
            return None
        at, until = data.get("at"), data.get("until")
        rows = data.get("rows")
        if not all(isinstance(t, (int, float)) for t in (at, until)) or not isinstance(rows, list):
            return None
        now = time.time() if now is None else now
        # A listing from the future (a clock change) does not count either.
        if not at <= now < until:
            return None
        return Listing(
            outcome=data["outcome"], detail=str(data.get("detail") or ""),
            at=at, until=until, rows=[row for row in rows if isinstance(row, dict)],
        )

    def save(
        self, outcome: str, detail: str, rows: List[dict], now: Optional[float] = None,
        *, keep_seconds: Optional[float] = None,
    ) -> None:
        """Remember a listing for *keep_seconds* (default: the cache's TTL).

        A record that cannot be written is only logged.
        """
        at = time.time() if now is None else now
        keep = self._ttl_seconds if keep_seconds is None else max(float(keep_seconds), 0.0)
        data = {
            "outcome": outcome,
            "detail": detail,
            "at": at,
            "until": at + keep,
            "rows": rows,
        }
        if self._path is None:
            self._memory = data
            return
        try:
            write_json_atomic(self._path, data)
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("Could not remember the listing in %s: %s", self._path, exc)

    def _read(self) -> Optional[Dict[str, Any]]:
        if self._path is None:
            return self._memory
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            logger.debug("Ignoring the unreadable listing record %s: %s", self._path, exc)
            return None
