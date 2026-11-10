"""Screenshots of the fleet list while providers answer.

The spinner is frozen on its first frame (animation is off in the harness), so
a capture never lands between two turns. Providers are gates the scenario opens.
"""

from __future__ import annotations

import copy
from typing import Any, Awaitable, Callable

import pytest

from servonaut.screens._fleet_load import Phase
from servonaut.services.load_progress import LoadProgress

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


def _capture(screen_snapshot: Any, size: str, scenario: Scenario) -> None:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], run_before)


def _table(pilot: Any) -> Any:
    return pilot.app.screen.query_one("InstanceTable")


async def _wait(pilot: Any, predicate: Callable[[], Any], what: str) -> None:
    await _harness.wait_until(pilot, predicate, what)
    await pilot.pause()


async def _first_run_mid_load(pilot: Any) -> None:
    """Hetzner answered, AWS is reading its first account, OVH has not started."""
    screen = pilot.app.screen
    await _harness.empty_fleet(pilot)
    gates = _harness.gate_providers(pilot.app, cached=False)
    screen.action_refresh()
    await _wait(pilot, lambda: screen._load.active, "the load to start")
    gates["hetzner"].release()
    await _wait(pilot, lambda: table_rows(pilot) == 1, "Hetzner's row")
    gates["aws"].load_progress = LoadProgress(1, 2, "us-east-1")
    screen._tick_load()
    screen._load.providers["ovh"].phase = Phase.WAITING
    screen._render_load()
    await pilot.pause()


def table_rows(pilot: Any) -> int:
    return _table(pilot).row_count


async def _refresh_mid_load(pilot: Any) -> None:
    """A cached list on screen; AWS and Hetzner answered, OVH is still loading."""
    screen = pilot.app.screen
    gates = _harness.gate_providers(pilot.app)
    await _harness.select_fleet_row(pilot, "mail-1")
    screen.action_refresh()
    changed = copy.deepcopy(_harness.AWS_ROWS)
    changed[1]["state"] = "running"
    changed.append({**changed[0], "id": "i-00000000000000009", "name": "worker-3"})
    gates["aws"].release(changed)
    gates["hetzner"].release()
    await _wait(pilot, lambda: table_rows(pilot) == len(_harness.FLEET_NAMES) + 1, "the new row")
    await _wait(pilot, lambda: screen._load.providers["hetzner"].phase is Phase.DONE, "Hetzner")
    assert screen._load.active  # OVH has not answered


@sizes
def test_fleet_first_run_mid_load(screen_snapshot, size: str) -> None:
    """First run: one provider listed, one reading an account, one waiting; placeholder rows below."""
    _capture(screen_snapshot, size, _first_run_mid_load)


@sizes
def test_fleet_refresh_mid_load(screen_snapshot, size: str) -> None:
    """A refresh over a cached list: the pill names who answered, the cursor stays, rows are marked."""
    _capture(screen_snapshot, size, _refresh_mid_load)
