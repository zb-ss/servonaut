"""Screenshots of the server actions screen at the sizes its layout changes.

Real app, real stylesheet, seeded state (see ``_harness``). Besides the two
standard terminal sizes, 130 and 142 columns show the layout between "narrow"
(compact buttons) and "wide" (bordered buttons, Logs and Ban IP in the footer).
"""

from __future__ import annotations

from typing import Any, Tuple

import pytest

from . import _harness
from .test_screens import _server_actions_of

SIZES = {"160x50": (160, 50), "142x40": (142, 40), "130x40": (130, 40), "100x30": (100, 30)}
STANDARD = ["160x50", "100x30"]


def _capture(screen_snapshot: Any, size: str, name: str, *, demo: bool = False) -> None:
    scenario = _server_actions_of(name)

    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(demo=demo), SIZES[size], run_before)


@pytest.mark.parametrize("size", list(SIZES))
def test_server_actions_cards(screen_snapshot, size: str) -> None:
    """An AWS server: header, toolbar, two card columns, Findings and monitoring."""
    _capture(screen_snapshot, size, _harness.FOCUS_SERVER["name"])


@pytest.mark.parametrize("size", STANDARD)
def test_server_actions_cards_demo_mode(screen_snapshot, size: str) -> None:
    """Demo mode redacts the header context line and every card."""
    _capture(screen_snapshot, size, _harness.FOCUS_SERVER["name"], demo=True)


@pytest.mark.parametrize("size", STANDARD)
def test_server_actions_cards_custom_server(screen_snapshot, size: str) -> None:
    """A custom server has no state and no memory yet."""
    _capture(screen_snapshot, size, _harness.CUSTOM_SERVERS[0].name)


@pytest.mark.parametrize("size", STANDARD)
def test_server_actions_cards_ovh(screen_snapshot, size: str) -> None:
    """An OVH VPS adds its own maintenance card."""
    _capture(screen_snapshot, size, _harness.OVH_ROWS[0]["name"])
