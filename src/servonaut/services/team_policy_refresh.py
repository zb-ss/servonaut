"""Keeping a process's team agent rules fresh.

Every surface where agents act on team shared servers (the TUI, the MCP
server, ``servonaut connect``) owns one :class:`TeamPolicyRefresher` over the
process's :class:`~servonaut.services.team_policy.TeamPolicyStore`:

- :meth:`~TeamPolicyRefresher.load` applies the rules saved on this device,
  before any fetch answers;
- :meth:`~TeamPolicyRefresher.refresh` fetches every team's rules; a surface
  calls it wherever it lists the teams' shared servers, with the same teams.
  Each refresh schedules the next one for when the rules are due
  (``TeamPolicyStore.seconds_until_refresh``), so they stay fresh while the
  process runs;
- :meth:`~TeamPolicyRefresher.ensure_loaded` fetches them before an agent
  acts on a team whose rules are not in force because they were never
  fetched, the last fetch failed or they expired.

A headless surface wraps its lifetime in :func:`kept_fresh`, which fetches
the rules at start and stops the schedule when it ends.

Fetching never raises: a team without rules in force stays at the readonly
level, and refusals say why.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any, AsyncIterator, Callable, Iterable, List, Mapping, Optional

from servonaut.services.team_policy import (
    EXPIRED,
    NOT_LOADED,
    UNREACHABLE,
    TeamPolicyStatus,
    TeamPolicyStore,
)

logger = logging.getLogger(__name__)

# What another fetch can cure. Rules the team service sent and this device
# refused wait for the next listing of the teams instead.
_FETCH_AGAIN = frozenset({NOT_LOADED.code, UNREACHABLE.code, EXPIRED.code})


class TeamPolicyRefresher:
    """Fetches the teams' agent rules into a store, and keeps them fresh."""

    def __init__(self, store: TeamPolicyStore, team_service: Callable[[], Any]) -> None:
        """*team_service* returns the signed-in user's team service, None when signed out."""
        self._store = store
        self._team_service = team_service
        # The next scheduled refresh (an event-loop timer, not a worker:
        # nothing waits on it), and the refresh it started.
        self._timer: Optional[asyncio.TimerHandle] = None
        self._scheduled: Optional[asyncio.Future] = None

    @property
    def store(self) -> TeamPolicyStore:
        return self._store

    def load(self) -> None:
        """Apply the rules saved on this device (see ``TeamPolicyStore.load``)."""
        self._store.load()

    async def refresh(
        self, teams: Optional[Iterable[Mapping[str, Any]]] = None,
    ) -> List[TeamPolicyStatus]:
        """Fetch the rules of *teams* (team-list rows; None: every team of the user).

        Returns what applies to each team now; nothing when signed out or
        the team list could not be read. Signed in, the next refresh is
        scheduled for when the rules are due.
        """
        service = self._team_service()
        if service is None:
            self._cancel_timer()
            return []
        try:
            statuses = await self._store.refresh(service, teams)
        except Exception as exc:  # noqa: BLE001 — offline, signed out on the server, no team plan
            logger.info("Team agent rules not refreshed (%s)", type(exc).__name__)
            statuses = []
        self._schedule()
        return statuses

    async def ensure_loaded(self, slug: Any) -> None:
        """Fetch the rules again when team *slug*'s are not in force for want of a fetch.

        That is: never fetched, the last fetch failed, or they expired.
        Rules the team service sent and this device refused are left alone.
        """
        status = self._store.status(slug) if isinstance(slug, str) else None
        if status is not None and (status.problem is None or status.problem.code not in _FETCH_AGAIN):
            return
        await self.refresh()

    def close(self) -> None:
        """Stop the scheduled refresh (and one it already started)."""
        self._cancel_timer()
        if self._scheduled is not None and not self._scheduled.done():
            self._scheduled.cancel()
        self._scheduled = None

    def _schedule(self) -> None:
        """Refresh again when the rules are next due; not at all with none in force."""
        self._cancel_timer()
        delay = self._store.seconds_until_refresh()
        if delay is not None:
            self._timer = asyncio.get_running_loop().call_later(delay, self._refresh_when_due)

    def _refresh_when_due(self) -> None:
        self._timer = None
        self._scheduled = asyncio.ensure_future(self.refresh())

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None


@contextlib.asynccontextmanager
async def kept_fresh(refresher: Optional[TeamPolicyRefresher]) -> AsyncIterator[None]:
    """Fetch the teams' rules at start and keep them fresh while the block runs."""
    if refresher is None:
        yield
        return
    first = asyncio.create_task(refresher.refresh())
    try:
        yield
    finally:
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        refresher.close()
