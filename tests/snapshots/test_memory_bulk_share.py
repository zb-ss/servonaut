"""Screenshot tests: sharing several servers' memory with a team at once.

Fleet Memory with two servers marked, the bulk Share form those marks open,
and the form's per-server summary after a batch. The team and its members are
stand-ins with neutral names; nothing reaches the Servonaut service. Captured
at both terminal sizes (see ``test_screens.py``).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, List

import pytest
from textual.widgets import DataTable

from servonaut.services.memory import bulk_share as bulk
from servonaut.services.memory.team_service import TeamMemberKey, TeamMemoryService

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))

_TEAM = {"slug": "team-a", "name": "Team A"}

# Fixed members: a snapshot must not depend on a generated key.
_MEMBERS: List[TeamMemberKey] = [
    TeamMemberKey(2, "0123456789abcdef" * 4, "AAAA", "member", "alice"),
    TeamMemberKey(3, "a1b2c3d4e5f60718" * 4, "AAAA", "admin", "bob"),
]

_TARGETS = [
    bulk.ShareTarget("i-00000000000000001", "app-1"),
    bulk.ShareTarget("i-00000000000000002", "db-1"),
    bulk.ShareTarget("i-00000000000000003", "bastion-1", probed=False),
    bulk.ShareTarget("vps-1.example.net", "vps-1"),
]


class _TeamMemory:
    """Stands in for the team memory service.

    It lists the member keys the form shows, and shares the first server of a
    batch at once while the second one never finishes, so a capture can show
    a batch in flight.
    """

    _ROLE_ORDER = TeamMemoryService._ROLE_ORDER

    def __init__(self) -> None:
        self._shared = 0

    async def list_team_member_keys(self, _slug: str) -> List[TeamMemberKey]:
        return list(_MEMBERS)

    def eligible_members(self, members: List[TeamMemberKey], role: str) -> List[TeamMemberKey]:
        return TeamMemoryService.eligible_members(self, members, role)  # type: ignore[arg-type]

    def is_unlocked(self) -> bool:
        return True

    def check_member_keys(self, *_args: Any) -> None:
        return None

    async def own_live_grants(self, _slug: str, *, fresh: bool = False) -> dict:
        return {}

    async def share_instance(self, **_kwargs: Any) -> Any:
        self._shared += 1
        if self._shared > 1:
            await asyncio.Event().wait()  # held until the capture is over
        return SimpleNamespace(pending_recipients=[])


class _Entitled:
    """The app's auth service, with team memory sharing in the plan and one team."""

    def __init__(self, auth: Any) -> None:
        self._auth = auth

    def has_feature(self, feature: str) -> bool:
        return feature == "memory_team_share" or self._auth.has_feature(feature)

    async def list_teams(self) -> List[dict]:
        return [dict(_TEAM)]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._auth, name)


async def _fleet_memory_with_marks(pilot: Any) -> None:
    from servonaut.screens.fleet_memory import FleetMemoryScreen

    app = pilot.app
    app.push_screen(FleetMemoryScreen())
    screen = await _harness.wait_for_screen(pilot, "FleetMemoryScreen")
    table = screen.query_one("#fleet-memory-table", DataTable)
    await _harness.wait_until(pilot, lambda: table.row_count >= 3, "the fleet memory rows")
    await _harness.wait_until(
        pilot, lambda: not any(w.group == "memory_fleet" for w in app.workers), "the rows to settle",
    )
    table.focus()
    table.move_cursor(row=0)
    await pilot.pause()
    await pilot.press("space")  # marks app-1, moves to the next row
    await pilot.press("down")
    await pilot.press("space")  # marks the third row
    await pilot.pause()


async def _open_form(pilot: Any) -> Any:
    from servonaut.screens.memory_bulk_share import BulkShareScreen

    app = pilot.app
    app.auth_service = _Entitled(app.auth_service)
    app.team_memory_service = _TeamMemory()
    app.push_screen(BulkShareScreen(_TARGETS))
    screen = await _harness.wait_for_screen(pilot, "BulkShareScreen")
    readers = screen.query_one("#bulk-readers")
    await _harness.wait_until(pilot, lambda: "alice" in str(readers.render()), "the readers")
    await pilot.pause()
    return screen


async def _bulk_form(pilot: Any) -> None:
    await _open_form(pilot)


async def _bulk_sending(pilot: Any) -> None:
    from textual.widgets import Button

    screen = await _open_form(pilot)
    screen.query_one("#bulk-btn-confirm", Button).press()
    progress = screen.query_one("#bulk-progress")
    await _harness.wait_until(pilot, lambda: "1 / 4" in str(progress.render()), "the first server")
    await pilot.pause()


async def _bulk_summary(pilot: Any) -> None:
    screen = await _open_form(pilot)
    report = bulk.BulkShareReport(
        outcomes=(
            bulk.ShareOutcome(_TARGETS[0], bulk.SHARED),
            bulk.ShareOutcome(_TARGETS[1], bulk.ALREADY_SHARED),
            bulk.ShareOutcome(_TARGETS[2], bulk.SKIPPED, bulk.NEVER_PROBED),
            bulk.ShareOutcome(_TARGETS[3], bulk.SKIPPED, bulk.ID_NOT_ACCEPTED),
        ),
        pending=({"user_id": 4, "name": "carol"},),
    )
    screen._finish("team-a", report)
    await pilot.pause()


def _capture(screen_snapshot: Any, size: str, scenario: Scenario) -> None:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], run_before)


@sizes
def test_fleet_memory_with_marks(screen_snapshot, size: str) -> None:
    """Two servers marked: a tick on their rows, the count in the status line."""
    _capture(screen_snapshot, size, _fleet_memory_with_marks)


@sizes
def test_bulk_share_form(screen_snapshot, size: str) -> None:
    """The bulk form: the servers, team, lowest role, readers, update option, modules."""
    _capture(screen_snapshot, size, _bulk_form)


@sizes
def test_bulk_share_sending(screen_snapshot, size: str) -> None:
    """A batch in flight: the progress line, and Stop in place of Share."""
    _capture(screen_snapshot, size, _bulk_sending)


@sizes
def test_bulk_share_summary(screen_snapshot, size: str) -> None:
    """After a batch: one line per server, grouped, with each skip's reason."""
    _capture(screen_snapshot, size, _bulk_summary)
