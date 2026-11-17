"""Screenshots of the fleet list's quick filters and loading states.

Real app, real stylesheet, seeded fleet (see ``_harness``). The loading
states hold providers back with gates, so the capture lands while some have
answered and others have not.
"""

from __future__ import annotations

import copy
from typing import Any, Awaitable, Callable

import pytest

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


async def settle(pilot: Any, predicate: Callable[[], Any], what: str) -> None:
    await _harness.wait_until(pilot, predicate, what)
    await pilot.pause()


def _run(scenario: Scenario) -> Callable[[Any], Awaitable[None]]:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    return run_before


def _capture(screen_snapshot: Any, size: str, scenario: Scenario) -> None:
    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], _run(scenario))


def _table(pilot: Any) -> Any:
    return pilot.app.screen.query_one("InstanceTable")


async def _running_only(pilot: Any) -> None:
    pilot.app.screen.query_one("#chip_state_running").press()
    await settle(pilot, lambda: _table(pilot).row_count == 4, "the running servers")


async def _stopped_hetzner_nothing(pilot: Any) -> None:
    screen = pilot.app.screen
    screen.query_one("#chip_state_stopped").press()
    screen.query_one("#chip_provider_hetzner").press()
    await settle(pilot, lambda: _table(pilot).row_count == 0, "an empty result")


async def _search_and_provider(pilot: Any) -> None:
    pilot.app.screen.query_one("#chip_provider_ovh").press()
    await pilot.press("slash", *"mail")
    await settle(pilot, lambda: _table(pilot).row_count == 1, "the searched OVH server")


async def _first_run(pilot: Any) -> None:
    await _harness.empty_fleet(pilot)
    gates = _harness.gate_providers(pilot.app, cached=False)
    pilot.app.screen.action_refresh()
    gates["hetzner"].release()
    await settle(pilot, lambda: _table(pilot).row_count == 1, "the first provider's rows")


async def _refresh_with_cache(pilot: Any) -> None:
    gates = _harness.gate_providers(pilot.app)
    await _harness.select_fleet_row(pilot, "mail-1")
    pilot.app.screen.action_refresh()
    changed = copy.deepcopy(_harness.AWS_ROWS)
    changed[1]["state"] = "running"
    changed.append({**changed[0], "id": "i-00000000000000009", "name": "worker-3"})
    gates["aws"].release(changed)
    gates["hetzner"].release()
    await settle(pilot, lambda: _table(pilot).row_count == len(_harness.FLEET_NAMES) + 1, "the new row")


async def _refresh_with_failure(pilot: Any) -> None:
    gates = _harness.gate_providers(pilot.app)
    pilot.app.screen.action_refresh()
    gates["aws"].release()
    gates["hetzner"].release()
    gates["ovh"].release(error="OVH API: request timed out")
    await settle(pilot, lambda: not pilot.app.screen._load.active, "the refresh to end")


@sizes
def test_fleet_running_only(screen_snapshot, size: str) -> None:
    """The Running chip: four servers, the inspector on the first."""
    _capture(screen_snapshot, size, _running_only)


@sizes
def test_fleet_filters_match_nothing(screen_snapshot, size: str) -> None:
    """Stopped plus Hetzner matches nothing: an empty table and a clear summary."""
    _capture(screen_snapshot, size, _stopped_hetzner_nothing)


@sizes
def test_fleet_search_with_a_provider_chip(screen_snapshot, size: str) -> None:
    """The search and a provider chip narrow the list together."""
    _capture(screen_snapshot, size, _search_and_provider)


@sizes
def test_fleet_first_run_loading(screen_snapshot, size: str) -> None:
    """Nothing cached: one provider's rows are in, the others are still answering."""
    _capture(screen_snapshot, size, _first_run)


@sizes
def test_fleet_refresh_with_cache(screen_snapshot, size: str) -> None:
    """A refresh over a cached list: the cursor stays, changed rows are marked."""
    _capture(screen_snapshot, size, _refresh_with_cache)


@sizes
def test_fleet_refresh_with_a_failing_provider(screen_snapshot, size: str) -> None:
    """A provider that failed keeps its cached rows and says they are stale."""
    _capture(screen_snapshot, size, _refresh_with_failure)
