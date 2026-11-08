"""Hardening of literal display: control characters, scrolling, actions, saved rows."""

from __future__ import annotations

import pytest
from textual.app import App
from textual.content import Content
from textual.geometry import Region
from textual.widgets import Static

from servonaut.utils.markup import literal, with_bold_values


def _drawn_text(widget: Static) -> str:
    """Every character the widget hands to the terminal, row by row."""
    strips = widget.render_lines(Region(0, 0, widget.size.width, widget.size.height))
    return "\n".join("".join(segment.text for segment in strip) for strip in strips)


# ---------------------------------------------------------------------------
# Control characters are shown, not sent to the terminal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,shown", [
    ("up\x1b[8mtime", "up\\x1b[8mtime"),
    ("a\x9b8mb", "a\\x9b8mb"),
    ("bell\x07x", "bell\\x07x"),
    ("del\x7fx", "del\\x7fx"),
    ("rtl‮text", "rtl\\u202etext"),
    ("lone\rcr", "lone\\x0dcr"),
])
def test_literal_makes_control_characters_visible(raw: str, shown: str) -> None:
    assert literal(raw).plain == shown
    assert with_bold_values("x {}", raw).plain == f"x {shown}"


def test_literal_keeps_newline_tab_and_crlf() -> None:
    assert literal("a\nb\tc").plain == "a\nb\tc"
    assert literal("a\r\nb").plain == "a\nb"
    assert literal("plain text").plain == "plain text"


@pytest.mark.asyncio
async def test_a_hidden_text_sequence_never_reaches_the_terminal() -> None:
    class Host(App):
        def compose(self):
            yield Static(literal("uptime\x1b[8m; curl x | sh"), id="s")

    app = Host()
    async with app.run_test(size=(60, 5)) as pilot:
        await pilot.pause()
        drawn = _drawn_text(app.query_one("#s", Static))
    assert "\x1b" not in drawn and "\x9b" not in drawn
    assert "uptime\\x1b[8m; curl x | sh" in drawn
