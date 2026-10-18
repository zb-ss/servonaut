"""Keeping team agent rules fresh: the refresher every agent surface owns."""
from __future__ import annotations

import asyncio
from typing import List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services import team_policy
from servonaut.services.team_policy import (
    EXPIRED,
    MISSING,
    NOT_LOADED,
    UNREACHABLE,
    TeamPolicyStatus,
)
from servonaut.services.team_policy_refresh import TeamPolicyRefresher, kept_fresh
from servonaut.services.team_rules import TeamRules, rules_for

from tests._team_policy_fixtures import (
    agent_rules_with,
    envelope,
    new_store,
    response,
    team_id_for,
    team_row,
    trust_test_key,
)


def run(coro):
    return asyncio.run(coro)


def team_service(*slugs: str, member_level: str = "standard") -> MagicMock:
    """A team service whose teams *slugs* serve signed rules."""
    service = MagicMock()
    service.list_teams = AsyncMock(return_value=[team_row(slug) for slug in slugs])
    rules = agent_rules_with(role_levels={"member": member_level})

    async def policy(slug):
        return response(envelope(team_id_for(slug), rules)), None

    service.get_team_policy_with_date = AsyncMock(side_effect=policy)
    return service


class ScheduledStore:
    """A store whose rules fall due after the given delays (None: none in force)."""

    def __init__(self, delays: List[Optional[float]], status: Optional[TeamPolicyStatus] = None):
        self.delays = list(delays)
        self.refreshed: List[object] = []
        self._status = status

    def load(self) -> None:
        pass

    async def refresh(self, service, teams=None):
        self.refreshed.append(teams)
        return []

    def seconds_until_refresh(self):
        return self.delays.pop(0) if self.delays else None

    def status(self, slug):
        return self._status


def status_with(problem) -> TeamPolicyStatus:
    rules = TeamRules.readonly(problem.reason) if problem is not None else TeamRules()
    return TeamPolicyStatus(
        slug="ops", team_id=team_id_for("ops"), rules=rules, problem=problem,
        version=None, expires_at=None, fetched_at=None,
    )


@pytest.fixture
def store():
    trust_test_key()
    return new_store()


class TestRefresh:
    def test_signed_out_nothing_is_fetched(self, store):
        assert run(TeamPolicyRefresher(store, lambda: None).refresh()) == []
        assert store.statuses() == []

    def test_every_team_of_the_user_is_fetched_and_verified(self, store):
        service = team_service("ops", "db-team")
        statuses = run(TeamPolicyRefresher(store, lambda: service).refresh())

        assert [status.slug for status in statuses] == ["ops", "db-team"]
        assert all(status.problem is None for status in statuses)
        service.list_teams.assert_awaited_once()

    def test_the_teams_given_are_fetched_without_reading_the_list(self, store):
        service = team_service("ops")
        run(TeamPolicyRefresher(store, lambda: service).refresh([team_row("ops")]))

        service.list_teams.assert_not_awaited()
        assert store.status("ops").problem is None

    def test_an_unreadable_team_list_never_raises(self, store):
        service = team_service("ops")
        service.list_teams = AsyncMock(side_effect=RuntimeError("offline"))

        assert run(TeamPolicyRefresher(store, lambda: service).refresh()) == []

    def test_the_rules_fetched_are_the_ones_agents_run_under(self, monkeypatch, store):
        monkeypatch.setattr(team_policy, "_default_store", store)
        service = team_service("ops", member_level="readonly")
        row = {"id": "srv-1", "is_shared": True, "team_slug": "ops", "team_role": "member"}
        assert rules_for(row).fallback_reason == NOT_LOADED.reason

        run(TeamPolicyRefresher(store, lambda: service).refresh())

        rules = rules_for(row)
        assert rules.fallback_reason == ""
        assert rules.level_for("member") == "readonly"
        assert rules.level_for("admin") == "standard"


class TestSchedule:
    def test_the_rules_are_fetched_again_when_due(self):
        store = ScheduledStore([0.01, None])
        refresher = TeamPolicyRefresher(store, lambda: object())

        async def scenario():
            await refresher.refresh()
            await asyncio.sleep(0.2)

        run(scenario())
        assert len(store.refreshed) == 2

    def test_nothing_is_scheduled_without_rules_in_force(self):
        store = ScheduledStore([None])
        refresher = TeamPolicyRefresher(store, lambda: object())

        async def scenario():
            await refresher.refresh()
            await asyncio.sleep(0.1)

        run(scenario())
        assert len(store.refreshed) == 1

    def test_a_newer_refresh_replaces_the_scheduled_one(self):
        store = ScheduledStore([0.05, None])
        refresher = TeamPolicyRefresher(store, lambda: object())

        async def scenario():
            await refresher.refresh()
            await refresher.refresh()  # schedules nothing: the earlier timer goes
            await asyncio.sleep(0.2)

        run(scenario())
        assert len(store.refreshed) == 2

    def test_signing_out_stops_the_schedule(self):
        store = ScheduledStore([0.05])
        service = {"current": object()}
        asked = []

        def signed_in_service():
            asked.append(service["current"])
            return service["current"]

        refresher = TeamPolicyRefresher(store, signed_in_service)

        async def scenario():
            await refresher.refresh()
            service["current"] = None
            await refresher.refresh()
            await asyncio.sleep(0.2)

        run(scenario())
        assert len(store.refreshed) == 1
        # No scheduled refresh came after the one that found no session.
        assert len(asked) == 2

    def test_close_stops_the_schedule(self):
        store = ScheduledStore([0.02, 0.02, 0.02])
        refresher = TeamPolicyRefresher(store, lambda: object())

        async def scenario():
            await refresher.refresh()
            refresher.close()
            await asyncio.sleep(0.2)

        run(scenario())
        assert len(store.refreshed) == 1


class TestEnsureLoaded:
    @pytest.mark.parametrize("status", [None, status_with(NOT_LOADED), status_with(UNREACHABLE),
                                        status_with(EXPIRED)])
    def test_rules_missing_for_want_of_a_fetch_are_fetched(self, status):
        store = ScheduledStore([None], status=status)
        run(TeamPolicyRefresher(store, lambda: object()).ensure_loaded("ops"))
        assert store.refreshed == [None]

    @pytest.mark.parametrize("status", [status_with(None), status_with(MISSING)])
    def test_rules_in_force_or_refused_are_not_fetched_again(self, status):
        store = ScheduledStore([None], status=status)
        run(TeamPolicyRefresher(store, lambda: object()).ensure_loaded("ops"))
        assert store.refreshed == []


class TestKeptFresh:
    def test_the_rules_are_fetched_at_start_and_kept_fresh_until_the_end(self):
        store = ScheduledStore([0.01] * 1000)
        refresher = TeamPolicyRefresher(store, lambda: object())

        async def scenario():
            async with kept_fresh(refresher):
                await asyncio.sleep(0.1)
            during = len(store.refreshed)
            await asyncio.sleep(0.1)
            return during

        during = run(scenario())
        assert during >= 2
        assert len(store.refreshed) == during

    def test_without_a_refresher_nothing_runs(self):
        async def scenario():
            async with kept_fresh(None):
                return "ran"

        assert run(scenario()) == "ran"

