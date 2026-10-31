"""The team-copy merge for processes that have no running app.

The CLI and the standalone MCP server (and the relay's tool executor) list a
team's copy of a server folded into the user's own, so they run the same
pass the app runs (:func:`~servonaut.services.memory.team_merge.merge_team_copies`).
They never unlock Memory Sync, so they never read from or upload to the
service: a stand-in reports Memory Sync as locked when this computer has the
local keypair cache, and as not set up otherwise. The service part of a copy is
then marked as owed (``remote_pending``) and a later pass in the app completes
it.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, FrozenSet, Mapping, Optional, Sequence, Set, Tuple

from servonaut.services.memory.team_merge import TeamMergeReport, merge_team_copies
from servonaut.services.shared_servers import is_shared_row, own_twin

logger = logging.getLogger(__name__)


class _LockedSync:
    """Stands in for a Memory Sync that is set up here but not unlocked."""

    is_configured = False

    def is_enrolled_locally(self) -> bool:
        return True


def headless_sync_state() -> Optional[_LockedSync]:
    """What to pass as the sync service: a locked stand-in, or ``None`` (not set up)."""
    from servonaut.services.memory.sync_service import local_keypair_cache_exists  # noqa: PLC0415

    return _LockedSync() if local_keypair_cache_exists() else None


def pass_key(rows: Sequence[Mapping[str, Any]]) -> FrozenSet[Tuple[str, str]]:
    """The ``(share id, own twin id)`` pairs of the shared rows; empty without any."""
    pairs = set()
    for row in rows:
        if is_shared_row(row) and row.get("id"):
            twin = own_twin(row, rows)
            pairs.add((str(row["id"]), str(twin.get("id") or "") if twin is not None else ""))
    return frozenset(pairs)


class HeadlessTeamMerge:
    """Runs the merge pass once per distinct set of shared rows in this process.

    A pass that finds another pass running on this computer (``skipped``) is
    tried again by the next caller; any other outcome, a failure included, is
    final for its key. A failure is logged by type only.
    """

    def __init__(self, memory_service: Any) -> None:
        self._memory_service = memory_service
        self._done: Set[FrozenSet[Tuple[str, str]]] = set()
        self._lock: Optional[asyncio.Lock] = None

    async def run(self, rows: Sequence[Mapping[str, Any]]) -> Optional[TeamMergeReport]:
        """The pass's report, or ``None`` when there was nothing to do or it already ran."""
        key = pass_key(rows)
        if not key:
            return None
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if key in self._done:
                return None
            try:
                report = await merge_team_copies(self._memory_service, headless_sync_state(), rows)
            except Exception as exc:  # noqa: BLE001 - a failed pass leaves every copy where it was
                logger.warning("Merging team copies of server memory failed (%s)", type(exc).__name__)
                self._done.add(key)
                return None
            if not report.skipped:
                self._done.add(key)
            return report
