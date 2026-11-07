"""The owner sees which teams a server's memory is shared with.

Fleet Memory's "Shared with" column and the Memory screen's line both come
from the teams' share lists the app already reads; only shares the user made
count. A team's copy shared by someone else is not "shared with" anyone.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Static

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.shared_view import SharedMemoryReader, shared_with_text
from servonaut.services.memory.store import MemoryStore
from servonaut.services.memory.team_service import Grant, SharedInstance
from servonaut.widgets.safe_header import SafeHeader
from tests.test_fleet_memory_shared import _cells, _real_screen_app, _table, _Team, _wait_for  # noqa: F401

pytestmark = pytest.mark.asyncio

ME, TEAMMATE = 1, 2
OWN_ROW = {"id": "i-own-1", "name": "web-1", "provider": "aws"}
TEAMS = [{"slug": "team-a", "name": "Team A"}, {"slug": "team-b", "name": "Team B"}]
SHARED_WITH = 5  # the column after "Memory"


def _grant(instance_id: str, by: int, role: str = "member") -> SharedInstance:
    grant = Grant(
        id=f"g-{instance_id}-{by}", instance_id=instance_id, required_role=role, modules=["os"],
        status="active", granted_by_user_id=by,
        created_at=datetime.fromisoformat("2026-10-01T10:00:00+00:00"), revoked_at=None,
    )
    return SharedInstance(grant=grant, instance={"instance_id": instance_id}, readable_modules=["os"])


def _app(tmp_path, team: _Team, *, screen: str = "fleet", demo: bool = False, caller=ME):
    from servonaut.screens.fleet_memory import FleetMemoryScreen
    from servonaut.screens.memory import MemoryScreen

    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    reader = SharedMemoryReader(team, lambda: 0.0, teams_provider=AsyncMock(return_value=TEAMS))
    auth = MagicMock()
    auth.has_feature = lambda feature: feature == "memory_team_share"

    class Host(App):
        CSS = ""
        memory_service = MemoryService(store=store, config=MemoryConfig(), probers=[])
        shared_memory_reader = reader
        team_memory_service = SimpleNamespace(caller_user_id=lambda: caller)
        auth_service = auth
        demo_mode = False
        instances = [dict(OWN_ROW)]
        fleet_service = None

        def compose(self) -> ComposeResult:
            yield SafeHeader()
            yield Footer()

        def on_mount(self) -> None:
            if demo:
                self.demo_mode = True
                self.redaction_service = MagicMock()
                self.redaction_service.redact_name = lambda n: "stand-in-team"
                self.redaction_service.redact_instance_id = lambda n: n
                self.redaction_service.redact_provider = lambda n: n
                self.redaction_service.real_instance_id = lambda n: n
                self.redaction_service.scrub_stream = lambda t: t
            self.push_screen(FleetMemoryScreen() if screen == "fleet" else MemoryScreen(dict(OWN_ROW)))

    return Host()


class _Blank(Screen):
    """Stands in for a share form opened over Fleet Memory."""

    def compose(self) -> ComposeResult:
        yield Static("form")


def _shared_with(app) -> str:
    return str(_table(app).get_row_at(0)[SHARED_WITH])


async def test_fleet_memory_names_the_team_an_own_server_is_shared_with(tmp_path):
    app = _app(tmp_path, _Team({"team-a": [_grant("i-own-1", ME)]}))
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and "Team A" in _shared_with(app))
        assert _shared_with(app) == "[blue]Team A[/blue]"
        assert str(_table(app).columns[_table(app).ordered_columns[SHARED_WITH].key].label) == "Shared with"


async def test_the_status_line_counts_the_servers_shared_with_a_team(tmp_path):
    app = _app(tmp_path, _Team({"team-a": [_grant("i-own-1", ME)]}))
    async with app.run_test(headless=True) as pilot:
        status = app.screen.query_one("#fleet-memory-status", Static)
        await _wait_for(pilot, lambda: "1 shared with a team" in str(status.render()))
        # Before the status counts: a narrow terminal cuts the end of the line.
        text = str(status.render())
        assert text.index("1 shared with a team") < text.index("fresh")


async def test_more_than_one_team_is_counted(tmp_path):
    team = _Team({"team-a": [_grant("i-own-1", ME)], "team-b": [_grant("i-own-1", ME)]})
    app = _app(tmp_path, team)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and "+1" in _shared_with(app))
        assert _shared_with(app) == "[blue]Team A +1[/blue]"


async def test_a_share_someone_else_made_is_not_shared_with(tmp_path):
    app = _app(tmp_path, _Team({"team-a": [_grant("i-own-1", TEAMMATE)]}))
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count
                        and app.screen._rows[0].get("grant_candidates"))
        assert _shared_with(app) == "[dim]—[/dim]"


async def test_an_unshared_server_shows_a_dash(tmp_path):
    team = _Team({})
    app = _app(tmp_path, team)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and team.calls)
        await pilot.pause(0.1)
        assert _shared_with(app) == "[dim]—[/dim]"


async def test_demo_mode_shows_a_stand_in_team_name(tmp_path):
    app = _app(tmp_path, _Team({"team-a": [_grant("i-own-1", ME)]}), demo=True)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and "stand-in" in _shared_with(app))
        assert "Team A" not in _shared_with(app)


async def test_coming_back_from_a_share_form_reads_the_lists_again(tmp_path):
    team = _Team({})
    app = _app(tmp_path, team)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and team.calls)
        team.listings = {"team-a": [_grant("i-own-1", ME)]}
        fleet = app.screen
        # S on the row opens the single Share form; it is stood in for here.
        import servonaut.screens.memory_share as memory_share
        original = memory_share.ShareInstanceScreen
        memory_share.ShareInstanceScreen = lambda _instance: _Blank()
        try:
            _table(app).move_cursor(row=0)
            fleet.action_share_selected()
            await _wait_for(pilot, lambda: isinstance(app.screen, _Blank))
        finally:
            memory_share.ShareInstanceScreen = original
        app.pop_screen()
        await _wait_for(pilot, lambda: app.screen is fleet and "Team A" in _shared_with(app))


async def test_coming_back_from_another_screen_does_not_read_them_again(tmp_path):
    team = _Team({})
    app = _app(tmp_path, team)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: _table(app).row_count and team.calls)
        before = len(team.calls)
        fleet = app.screen
        app.push_screen(_Blank())
        await pilot.pause(0.05)
        app.pop_screen()
        await pilot.pause(0.3)
        assert app.screen is fleet and len(team.calls) == before


# --- the Memory screen -------------------------------------------------------

def _share_line(app) -> Any:
    return app.screen.query_one("#memory-share-state", Static)


async def test_the_memory_screen_says_whom_an_own_server_is_shared_with(tmp_path):
    team = _Team({"team-a": [_grant("i-own-1", ME, role="viewer")],
                  "team-b": [_grant("i-own-1", ME, role="admin")]})
    app = _app(tmp_path, team, screen="memory")
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: not _share_line(app).has_class("hidden"))
        text = str(_share_line(app).render())
        assert text.startswith("Shared with Team A (viewer and above); Team B (admin and above).")
        assert "Fleet Memory and press S" in text


async def test_the_memory_screen_says_nothing_when_it_is_not_shared(tmp_path):
    team = _Team({"team-a": [_grant("i-own-1", TEAMMATE)]})
    app = _app(tmp_path, team, screen="memory")
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: team.calls)
        await pilot.pause(0.1)
        assert _share_line(app).has_class("hidden")


async def test_the_memory_screen_names_a_stand_in_in_demo_mode(tmp_path):
    app = _app(tmp_path, _Team({"team-a": [_grant("i-own-1", ME)]}), screen="memory", demo=True)
    async with app.run_test(headless=True) as pilot:
        await _wait_for(pilot, lambda: not _share_line(app).has_class("hidden"))
        assert "Team A" not in str(_share_line(app).render())
        assert "stand-in-team" in str(_share_line(app).render())


async def test_without_team_sharing_in_the_plan_no_list_is_read(tmp_path):
    team = _Team({"team-a": [_grant("i-own-1", ME)]})
    app = _app(tmp_path, team, screen="memory")
    app.auth_service.has_feature = lambda feature: False
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.3)
        assert team.calls == []
        assert _share_line(app).has_class("hidden")


def test_the_text_names_each_team_with_its_lowest_role():
    listings: List[Any] = [
        SimpleNamespace(team_name="Team A", team_slug="team-a", required_role="viewer"),
        SimpleNamespace(team_name="", team_slug="team-b", required_role=""),
    ]
    assert shared_with_text(listings, str.upper) == "Shared with TEAM A (viewer and above); TEAM-B."
    assert shared_with_text([], str) == ""
