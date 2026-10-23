"""Screenshot tests: what agents may do on a team's servers (Teams screen).

A signed-in member opens a team; the card at the end of the team shows the
team's verified agent rules, or the readonly fallback and why. The team
service is a stand-in, and the rules are signed with the test suite's
throwaway key at the frozen time. Captured at both terminal sizes (see
``test_screens.py``).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Awaitable, Callable, Optional
from unittest.mock import AsyncMock

import pytest
from textual.widgets import Button, DataTable, Static

from tests._team_policy_fixtures import (
    agent_rules_with,
    envelope,
    response,
    team_id_for,
    trust_test_key,
)

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))

_TEAM = {
    "id": team_id_for("ops-team"), "slug": "ops-team", "name": "Ops Team",
    "role": "member", "member_count": 2,
}
_SERVERS = [
    {"id": "srv-1", "name": "web-1", "hostname": "web-1.example.com", "region": "eu-west-1"},
    {"id": "srv-2", "name": "db-1", "hostname": "db-1.example.com", "region": "eu-west-1"},
]
_RULES = agent_rules_with(
    role_levels={"member": "readonly"},
    servers={"srv-1": {"role_levels": {"member": "standard", "admin": "dangerous"}}},
    command_allowlist=["uptime", "df", "systemctl"],
    command_blocklist=[r"\bcurl\b"],
)


def _team_service(agent_rules: Optional[dict], *, signed: bool) -> SimpleNamespace:
    signed_rules = envelope(
        team_id_for("ops-team"), agent_rules, version=7, issued_at=_harness.FROZEN_NOW,
    ) if signed else None
    return SimpleNamespace(
        list_teams=AsyncMock(return_value=[_TEAM]),
        get_team=AsyncMock(return_value={
            "name": "Ops Team", "slug": "ops-team", "role": "member", "max_seats": 5,
            "members": [
                {"invitation_email": "lead@example.com", "role": "admin", "is_accepted": True},
                {"invitation_email": "dev@example.com", "role": "member", "is_accepted": True},
            ],
        }),
        list_shared_servers=AsyncMock(return_value=list(_SERVERS)),
        list_team_configs=AsyncMock(return_value=[]),
        get_team_policy_with_date=AsyncMock(return_value=(response(signed_rules), None)),
    )


class _SignedIn:
    """The app's auth service, signed in for the Teams screen; the rest as it is."""

    is_authenticated = True
    user_id = None
    user_email = None

    def __init__(self, auth: Any) -> None:
        self._auth = auth

    def __getattr__(self, name: str) -> Any:
        return getattr(self._auth, name)


def _agent_rules_card(agent_rules: Optional[dict] = None, *, signed: bool = True) -> Scenario:
    async def scenario(pilot: Any) -> None:
        from servonaut.screens.team_management import TeamManagementScreen
        from servonaut.services.team_policy import team_policy_store
        from servonaut.services.team_policy_refresh import TeamPolicyRefresher

        app = pilot.app
        trust_test_key()
        service = _team_service(agent_rules, signed=signed)
        app.team_service = service
        app.auth_service = _SignedIn(app.auth_service)
        app.team_policy = TeamPolicyRefresher(team_policy_store(), lambda: service)
        app.push_screen(TeamManagementScreen())
        screen = await _harness.wait_for_screen(pilot, "TeamManagementScreen")
        table = screen.query_one("#teams_table", DataTable)
        await _harness.wait_until(pilot, lambda: table.row_count == 1, "the team list")
        screen.query_one("#btn_view_team", Button).press()
        body = screen.query_one("#agent_rules_body", Static)
        await _harness.wait_until(
            pilot, lambda: "fetched" in str(body.render()) or "refreshed" in str(body.render()),
            "the agent rules card",
        )
        await _harness.wait_until(
            pilot, lambda: not any(w.name == "load_team_detail" for w in app.workers),
            "the team to finish loading",
        )
        screen.query_one("#team_management_container").scroll_to_widget(
            screen.query_one("#agent_rules_section"), animate=False, top=True,
        )
        await pilot.pause()

    return scenario


def _capture(screen_snapshot: Any, size: str, scenario: Scenario) -> None:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], run_before)


@sizes
def test_agent_rules_in_force(screen_snapshot, size: str) -> None:
    """Levels per role, a per-server level, the team's command lists, version and times."""
    _capture(screen_snapshot, size, _agent_rules_card(_RULES))


@sizes
def test_agent_rules_fallback(screen_snapshot, size: str) -> None:
    """No signed rules: agents run at the readonly level, and the card says why."""
    _capture(screen_snapshot, size, _agent_rules_card(signed=False))
