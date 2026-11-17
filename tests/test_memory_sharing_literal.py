"""Team names and service error text in the memory sharing screens are drawn as typed.

The tests run with the parser backstop uninstalled, so they show the screens are safe on their
own (same convention as ``tests/test_outside_text_literal.py``).
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut.screens.fleet_memory import _SHARED_WIDTH
from servonaut.utils.text_fit import cut
from rich.text import Text
from textual.app import App

from servonaut.app import ServonautApp
from tests import test_memory_shared_with as shared
from tests._literal_probe import (  # noqa: F401 - no_backstop is a fixture
    PAYLOADS, assert_literal, clickable_cells, no_backstop, screen_text,
)
from tests._async_bounds import wait_until
from tests.test_fleet_memory_shared import _table, _Team

KINDS = list(PAYLOADS)

# A name that ends in backslashes used to swallow or double them, or to show
# the closing tag; a filler character is drawn wider than it is measured.
TRAILING = ["team\\", "team\\\\", "team\\\\\\"]


def _shared_cell_text(app):
    table = _table(app)
    return table.get_row_at(0)[shared.SHARED_WITH] if table.row_count else None


async def _shared_cell_drawn(app) -> None:
    """Wait until the table itself holds the team cell and no refresh is running.

    The rows gain their teams in one step and the table is rebuilt by another
    (a slow fleet refresh rebuilds the rows without them until the team lookup
    runs again), so the rows alone do not say the table shows the cell.
    """
    await wait_until(lambda: (
        str(_shared_cell_text(app) or "") != ""
        and not any(w.group in ("memory_fleet", "memory_shared_listing") for w in app.workers)
    ))


@pytest.mark.asyncio
@pytest.mark.parametrize("name", TRAILING + list(PAYLOADS.values()))
@pytest.mark.parametrize("teams", [1, 2])
async def test_fleet_memory_shared_with_draws_the_team_name_as_typed(
    no_backstop, monkeypatch, tmp_path, name, teams  # noqa: F811
) -> None:
    monkeypatch.setattr(shared, "TEAMS", [
        {"slug": "team-a", "name": name}, {"slug": "team-b", "name": "Team B"},
    ])
    listings = {"team-a": [shared._grant("i-own-1", shared.ME)]}
    if teams == 2:
        listings["team-b"] = [shared._grant("i-own-1", shared.ME)]
    app = shared._app(tmp_path, _Team(listings))
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await _shared_cell_drawn(app)
        cell = _table(app).get_row_at(0)[shared.SHARED_WITH]
        assert isinstance(cell, Text), "a team name is never a markup string"
        # With two teams the first by name is shown, then the count.
        # The cell is cut with an ellipsis to its column width, never silently.
        shown = {name, "Team B"} if teams == 2 else {name}
        suffix = " +1" if teams == 2 else ""
        expected = {cut(f"{label}{suffix}", _SHARED_WIDTH) for label in shown}
        assert cell.plain in expected
        assert clickable_cells(app) == []


@pytest.mark.asyncio
async def test_fleet_memory_shared_with_shows_a_filler_character_visibly(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(shared, "TEAMS", [{"slug": "team-a", "name": "TeamㅤA"}])
    app = shared._app(tmp_path, _Team({"team-a": [shared._grant("i-own-1", shared.ME)]}))
    async with app.run_test(headless=True, size=(160, 50)) as pilot:
        await _shared_cell_drawn(app)
        assert str(_table(app).get_row_at(0)[shared.SHARED_WITH]) == "Team\\u3164A"


class _SetupHost(App):
    """The attributes the Memory Sync screen reads, with the real stylesheet."""

    CSS_PATH = ServonautApp.CSS_PATH
    demo_mode = False
    redaction_service = None

    def __init__(self) -> None:
        super().__init__()
        self.instances = []
        self.config_manager = SimpleNamespace(get=MagicMock())
        self.memory_sync_service = None
        self.auth_service = None

    def action_ran(self) -> None:
        raise AssertionError("an action named by outside text must not run")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", KINDS)
async def test_memory_sync_setup_error_status_draws_service_text_as_typed(
    no_backstop, kind  # noqa: F811
) -> None:
    from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

    payload = PAYLOADS[kind]
    app = _SetupHost()
    async with app.run_test(size=(160, 50)) as pilot:
        await app.push_screen(MemorySyncSetupScreen())
        await pilot.pause(0.2)
        app.screen._show_setup_error(OSError(payload))
        await pilot.pause()
        assert_literal(app, payload, shown=["Setup failed"])
        for x, y in clickable_cells(app):
            await pilot.click(offset=(x, y))
