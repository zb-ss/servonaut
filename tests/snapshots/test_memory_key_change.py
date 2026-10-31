"""Screenshot tests: confirming a team member's changed memory key.

The screen is pushed with fixed neutral data, as the Share form does when a
share meets a changed key, and as the review button of an existing share does.
Captured at both terminal sizes (see ``test_screens.py``).
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, List

import pytest
from textual.widgets import Checkbox

from servonaut.services.memory.team_wraps import KeyChange

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))

# Fixed fingerprints: a snapshot must not depend on a generated key.
_CHANGES: List[KeyChange] = [
    KeyChange("team-a", 2, "alice", "0123456789abcdef" * 4, "fedcba9876543210" * 4,
              "2026-02-27T14:05:00Z"),
    KeyChange("team-a", 3, "bob", "a1b2c3d4e5f60718" * 4, None, None),
]


def _screen(mode: str, *, ticked: int = 0) -> Scenario:
    async def scenario(pilot: Any) -> None:
        from servonaut.screens.memory_key_change import MemberKeyChangeScreen

        pilot.app.push_screen(MemberKeyChangeScreen(_CHANGES, mode=mode))  # type: ignore[arg-type]
        screen = await _harness.wait_for_screen(pilot, "MemberKeyChangeScreen")
        for box in list(screen.query(Checkbox))[:ticked]:
            box.value = True

    return scenario


def _capture(screen_snapshot: Any, size: str, scenario: Scenario) -> None:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], run_before)


@sizes
def test_share_needs_every_key_confirmed(screen_snapshot, size: str) -> None:
    """Nothing ticked: Trust and share is disabled, Cancel has focus."""
    _capture(screen_snapshot, size, _screen("share"))


@sizes
def test_catch_up_with_one_key_ticked(screen_snapshot, size: str) -> None:
    """One of two ticked: Trust checked keys is enabled."""
    _capture(screen_snapshot, size, _screen("catch_up", ticked=1))
