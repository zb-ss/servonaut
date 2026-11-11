"""Layout defects found when every screen was looked at, as geometry checks.

Each test runs the same scenario as the screenshot of that screen, with the
real stylesheets, and asserts what a user would see: nothing clipped, nothing
scrolled out of view.
"""

from __future__ import annotations

from typing import Any

import pytest
from textual.widgets import Tree

from . import _geometry, test_screens

sizes = pytest.mark.parametrize("size", ["160x50", "100x30"])


@sizes
def test_help_topics_show_whole_labels_without_sideways_scroll(size: str) -> None:
    def check(pilot: Any) -> None:
        tree = pilot.app.screen.query_one("#help_topics Tree", Tree)
        assert tree.max_scroll_x == 0, "the topic list scrolls sideways"
    _geometry.run(test_screens._help, size, check, name="help")


def _strip_problems(pilot: Any) -> list:
    """Values the one-line details strip cuts, and a scrollbar it should not need."""
    from servonaut.widgets.fleet_values import FleetValueLine, ValueRow

    strip = pilot.app.screen.query_one(FleetValueLine)
    problems = []
    if strip.max_scroll_y:
        problems.append("the strip scrolls")
    for row in strip.query(ValueRow):
        if row.display and len(row.value) > row.value_widget.content_size.width:
            problems.append(f"{row.field} is cut")
    return problems


def _select(name: str):
    from . import _harness

    async def scenario(pilot: Any) -> None:
        await _harness.select_fleet_row(pilot, name)

    return scenario


@pytest.mark.parametrize("name", ["app-1", "web-1", "mail-1", "cache-1"])
def test_fleet_details_strip_shows_every_value_whole_at_100x30(name: str) -> None:
    def check(pilot: Any) -> None:
        assert _strip_problems(pilot) == []

    _geometry.run(_select(name), "100x30", check, name=f"fleet-strip-{name}")


async def _secrets_hub_unscrolled(pilot: Any) -> None:
    from tests.test_secrets_screen import _mock_auth, _mock_guard

    from . import _harness
    from .test_screens import _navigate

    pilot.app.auth_service = _mock_auth(plan="solo")
    pilot.app.entitlement_guard = _mock_guard(allow_secrets=True)
    screen = await _navigate(pilot, "nav_secrets", "SecretsScreen")
    await _harness.wait_until(
        pilot, lambda: bool(screen.query("ActionButton")), "the secrets actions",
    )


def test_secrets_hub_fits_its_cards_without_scrolling_at_100x30() -> None:
    def check(pilot: Any) -> None:
        body = pilot.app.screen.query_one("#secrets_body")
        cards = list(body.query(".secrets_card"))
        assert cards
        assert body.max_scroll_y == 0, "the cards need scrolling"
        for card in cards:
            assert body.region.contains_region(card.region), "a card is cut"

    _geometry.run(_secrets_hub_unscrolled, "100x30", check, name="secrets-hub")
