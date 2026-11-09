"""Shared checks for screens that show text chosen outside the app.

A screen is literal when a name such as ``a[@click=app.ran]b[/]`` is drawn as
typed, nothing on screen carries a click action or a link, and a name that is
not valid markup (``key-1[/]``) does not stop the screen from drawing.

The tests that use these helpers run with the parser backstop uninstalled, so
they show the screen is safe on its own and not only because of the net.
"""
from __future__ import annotations

import html
import re
from typing import Iterable, List, Tuple

import pytest

from servonaut.utils import markup_backstop

CLICK = "x[@click=app.ran]y[/]"
CRASH = "key-1[/]"
# Each of these defeats one of the escape helpers: Rich's escape leaves a tag
# with a leading space, and a bracket-only escape is undone by a backslash.
SPACED_CLICK = "[ @click=app.ran]x[/]"
BACKSLASH_CLICK = "\\[@click=app.ran]x\\[/]"
BACKSLASH_CRASH = "a\\[/]b\\"
PAYLOADS = {
    "click": CLICK,
    "crash": CRASH,
    "spaced_click": SPACED_CLICK,
    "backslash_click": BACKSLASH_CLICK,
    "backslash_crash": BACKSLASH_CRASH,
}


@pytest.fixture
def no_backstop():
    """Run a test against the upstream parsers (the screens' own safety)."""
    markup_backstop.uninstall()
    yield
    markup_backstop.install()


# The scroll bars' own drag and track actions are drawn by Textual itself.
_SCROLL_BAR_ACTIONS = {"grab", "scroll_up", "scroll_down"}


def _is_action(key: str, value: object) -> bool:
    if not key.startswith("@"):
        return False
    return not (key == "@mouse.down" and value in _SCROLL_BAR_ACTIONS)


def clickable_cells(app) -> List[Tuple[int, int]]:
    """Cells of the active screen whose style carries an action or a link."""
    width, height = app.size
    cells = []
    for y in range(height):
        for x in range(width):
            try:
                style = app.screen.get_style_at(x, y)
            except Exception:  # noqa: BLE001 - an undrawn cell
                continue
            if style is None:
                continue
            if style.link or any(_is_action(key, value) for key, value in (style.meta or {}).items()):
                cells.append((x, y))
    return cells


def screen_text(app) -> str:
    """The text drawn on screen, as plain text."""
    svg = app.export_screenshot()
    text = html.unescape(re.sub(r"<[^>]+>", "", svg))
    return text.replace("\xa0", " ")


def assert_literal(app, payload: str, *, shown: Iterable[str] = ()) -> None:
    """The payload is on screen as typed and nothing is clickable."""
    assert clickable_cells(app) == []
    text = screen_text(app)
    assert payload in text, f"{payload!r} was not drawn as typed"
    for extra in shown:
        assert extra in text
