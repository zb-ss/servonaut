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
