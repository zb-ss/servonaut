"""Placeholder rows under the servers already listed while providers answer."""

from __future__ import annotations

import textwrap
from typing import List, Sequence

from textual.content import Content
from textual.widget import Widget

from servonaut.utils.markup import literal

# What the user can do while the list fills; the last line of the widget.
FOOTNOTE = "Rows appear as each provider answers. Esc cancels the slow provider, not the others."
# For an area too narrow for one line of the footnote.
SHORT_FOOTNOTE = "Esc cancels the slow providers only."

# Widths of the cells of one placeholder row (index, name, state, provider,
# region); the pattern repeats with a different length each row so the
# block reads as rows of unknown text, not as a grid.
_CELLS = (3, 16, 8, 9, 12)
_LENGTHS = (1.0, 0.7, 0.85, 0.55)
_GAP = 2
# A few rows say "more is coming"; a wall of them only adds noise.
_MAX_ROWS = 6
_BAR = "▬"


def _row(width: int, number: int) -> Content:
    """One placeholder row: a bar per column, the last one shortened."""
    pieces: List[Content | str] = []
    used = 0
    for position, cell in enumerate(_CELLS):
        size = cell if position < len(_CELLS) - 1 else int(cell * _LENGTHS[number % len(_LENGTHS)])
        gap = _GAP if used else 0
        size = min(size, width - used - gap)
        if size <= 0:
            break
        pieces += [" " * gap, literal(_BAR * size, "$text-muted")]
        used += gap + size
    return Content.assemble(*pieces)


def skeleton_lines(width: int, height: int, footnote: str = FOOTNOTE) -> Sequence[Content]:
    """The placeholder rows and the footnote that fit a *width* by *height* area.

    The footnote is kept whole or left out, and its short form replaces it
    where the long one would take a second line; rows (a few at most) fill what remains.
    """
    if footnote == FOOTNOTE and len(footnote) > width:
        footnote = SHORT_FOOTNOTE
    wrapped = textwrap.wrap(footnote, max(width, 1))
    note = [literal(line, "$text-muted") for line in wrapped]
    if len(note) >= height:
        note = []
    rows = [_row(width, number) for number in range(min(max(height - len(note), 0), _MAX_ROWS))]
    return rows + note


class FleetSkeleton(Widget):
    """Rows of placeholder bars, then the footnote, drawn without selecting anything.

    These are not servers: the widget cannot take focus, has no cursor and
    sits outside the fleet table, so no count, search, filter or key ever
    sees them.
    """

    can_focus = False

    def render(self) -> Content:
        lines = skeleton_lines(self.size.width, self.size.height)
        return Content("\n").join(lines)
