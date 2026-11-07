"""Screenshot tests: a server whose memory the user already shares.

The team shares app-1 already. One member set up Memory Sync after that and
cannot read it yet, so the form names them and offers "Share with them too".
Fleet Memory names the team in its "Shared with" column and counts the
shared servers in its status line.
The team and its members are stand-ins with neutral names; nothing reaches
the Servonaut service. Captured at both terminal sizes (see
``test_screens.py``).
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Any, List

import pytest

from servonaut.services.memory.shared_view import SharedMemoryReader
from servonaut.services.memory.team_service import (
    Grant,
    SharedInstance,
    TeamMemberKey,
    TeamMemoryService,
)
from servonaut.services.memory.team_wraps import GrantCoverage

from . import _harness

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))

_TEAM = {"slug": "team-a", "name": "Team A"}
_INSTANCE = {"id": "i-00000000000000001", "name": "app-1"}

# Fixed members: a snapshot must not depend on a generated key.
_MEMBERS: List[TeamMemberKey] = [
    TeamMemberKey(2, "0123456789abcdef" * 4, "AAAA", "member", "alice"),
    TeamMemberKey(3, "a1b2c3d4e5f60718" * 4, "AAAA", "admin", "bob"),
]

_GRANT = SimpleNamespace(
    id="g-1", instance_id=_INSTANCE["id"], required_role="viewer",
    modules=["os", "services", "logs"], pending_recipients=[],
)


class _TeamMemory:
    """The team memory service: a live share of app-1 that bob cannot read yet."""

    _ROLE_ORDER = TeamMemoryService._ROLE_ORDER

    async def list_team_member_keys(self, _slug: str) -> List[TeamMemberKey]:
        return list(_MEMBERS)

    def eligible_members(self, members: List[TeamMemberKey], role: str) -> List[TeamMemberKey]:
        return TeamMemoryService.eligible_members(self, members, role)  # type: ignore[arg-type]

    async def find_live_grant(self, _slug: str, _instance_id: str) -> Any:
        return _GRANT

    async def grant_coverage(self, _slug: str, _grant_id: str) -> GrantCoverage:
        return GrantCoverage(envelopes=(), pending=())

    def waiting_key_changes(self, *_args: Any) -> list:
        return []

    def addable_members(self, *_args: Any) -> List[str]:
        return ["bob"]

    def caller_user_id(self) -> int:
        return 1

    async def list_shared_instances(self, _slug: str) -> List[SharedInstance]:
        grant = Grant(
            id="g-1", instance_id=_INSTANCE["id"], required_role="viewer",
            modules=["os", "services", "logs"], status="active", granted_by_user_id=1,
            created_at=datetime.fromisoformat("2026-10-01T10:00:00+00:00"), revoked_at=None,
        )
        return [SharedInstance(grant=grant, instance={"instance_id": _INSTANCE["id"]},
                               readable_modules=["os"])]


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


async def _shared_form(pilot: Any) -> None:
    from servonaut.screens.memory_share import ShareInstanceScreen

    app = pilot.app
    app.auth_service = _Entitled(app.auth_service)
    app.team_memory_service = _TeamMemory()
    app.push_screen(ShareInstanceScreen(dict(_INSTANCE)))
    screen = await _harness.wait_for_screen(pilot, "ShareInstanceScreen")
    existing = screen.query_one("#share-existing-text")
    await _harness.wait_until(
        pilot, lambda: "Cannot read it yet" in str(existing.render()), "the existing share",
    )
    await _harness.wait_until(
        pilot, lambda: not any(w.group == "memory_share_form" for w in app.workers), "the form",
    )
    await pilot.pause()


async def _fleet_memory_shared(pilot: Any) -> None:
    from textual.widgets import DataTable

    from servonaut.screens.fleet_memory import FleetMemoryScreen

    app = pilot.app
    app.auth_service = _Entitled(app.auth_service)
    app.team_memory_service = _TeamMemory()

    async def teams() -> List[dict]:
        return [dict(_TEAM)]

    app.shared_memory_reader = SharedMemoryReader(app.team_memory_service, lambda: 0.0,
                                                  teams_provider=teams)
    app.push_screen(FleetMemoryScreen())
    screen = await _harness.wait_for_screen(pilot, "FleetMemoryScreen")
    table = screen.query_one("#fleet-memory-table", DataTable)
    await _harness.wait_until(
        pilot, lambda: any(row.get("shared_with") for row in screen._rows), "the shared row",
    )
    await _harness.wait_until(
        pilot, lambda: not any(w.group in ("memory_fleet", "memory_shared_listing")
                               for w in app.workers), "the rows to settle",
    )
    table.focus()
    await pilot.pause()


def _capture(screen_snapshot: Any, size: str, scenario: Any = _shared_form) -> None:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], run_before)


@sizes
def test_share_form_of_a_shared_server(screen_snapshot, size: str) -> None:
    """The live share's settings, who cannot read it yet, and its actions."""
    _capture(screen_snapshot, size)


@sizes
def test_fleet_memory_shared_with(screen_snapshot, size: str) -> None:
    """The team a server is shared with, in its column and counted in the status line."""
    _capture(screen_snapshot, size, _fleet_memory_shared)
