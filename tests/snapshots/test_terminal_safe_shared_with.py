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
    _STILL_UNSAFE,
    _TEXTUAL_OWN,
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


def test_fleet_memory_team_cell_is_drawn_as_plain_text(monkeypatch: pytest.MonkeyPatch) -> None:
    # A short server name keeps the "Shared with" column on screen, so the team
    # cell is really drawn (a long hostile server name pushes it out of view).
    # Only the wide size shows that column; the narrow one has no room for it.
    size = "160x50"
    monkeypatch.setitem(share._TEAM, "name", HOSTILE)
    frame = _frame(size, share._fleet_memory_shared)
    assert "Shared with" in frame
    assert not _STILL_UNSAFE.search(_TEXTUAL_OWN.sub("", frame))
    assert "\x1b]52" not in frame
    # The cell is plain text: the control bytes are written out, not drawn, and
    # no link is attached to it.
    assert "web\\x1b]52" in frame
    assert "http://1.2.3.4/" not in frame
