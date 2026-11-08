"""Real screens, real stylesheet: hostile team and server names in memory sharing.

Fleet Memory and Server Memory name the teams a server is shared with. Each
screen is drawn once with a name holding terminal control sequences and once
with the same name without them; the bytes written to the terminal must be
identical.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, List

import pytest

from servonaut.services.memory.shared_view import SharedListing

from . import _harness
from . import test_memory_share as share
from .test_terminal_safe_screens import (
    BENIGN,
    HOSTILE,
    _assert_same_and_safe,
    _frame,
    _named,
    filter_installed,  # noqa: F401 - autouse fixture
    sizes,
)


@sizes
def test_fleet_memory_shared_server_and_team_names(
    monkeypatch: pytest.MonkeyPatch, size: str
) -> None:
    def frame(name: str) -> str:
        _named(monkeypatch, name)
        monkeypatch.setitem(share._TEAM, "name", name)
        return _frame(size, share._fleet_memory_shared)

    hostile = frame(HOSTILE)
    assert "web]52" in hostile
    _assert_same_and_safe(hostile, frame(BENIGN))


@sizes
def test_server_memory_shared_with_line(size: str) -> None:
    from servonaut.screens.memory import MemoryScreen

    def scenario(name: str) -> Callable[[Any], Awaitable[None]]:
        async def run(pilot: Any) -> None:
            listings: List[SharedListing] = [SharedListing(
                team_slug="team-a", team_name=name, module_count=1,
                last_probe_at="", required_role="viewer",
            )]
            pilot.app.push_screen(MemoryScreen(dict(_harness.AWS_ROWS[0])))
            screen = await _harness.wait_for_screen(pilot, "MemoryScreen")
            screen._show_own_shares(listings)
            await pilot.pause()

        return run

    hostile = _frame(size, scenario(HOSTILE))
    assert "web]52" in hostile
    _assert_same_and_safe(hostile, _frame(size, scenario(BENIGN)))
