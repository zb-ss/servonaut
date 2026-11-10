"""Table cells that follow the theme.

``DataTable`` measures string and Rich ``Text`` cells, but sizes a Textual
``Content`` cell as empty, so a column of them collapses to its header. Cells
are therefore Rich ``Text``; this builds one from outside text (shown
verbatim) in a theme colour resolved at the time the row is added.
"""

from __future__ import annotations

from typing import Any, Callable

from rich.text import Text
from textual.color import Color, ColorParseError
from textual.widgets import DataTable

from servonaut.utils.markup import inert_text

_MODIFIERS = frozenset({"bold", "dim", "italic", "underline"})


def themed_cell(app: Any, value: str, style: str = "") -> Text:
    """*value* verbatim, styled by *style*: modifiers and one ``$theme-token``.

    A token the theme does not give as a plain colour (terminal-colour themes)
    leaves the modifiers only.
    """
    parts = []
    for word in style.split():
        if word in _MODIFIERS:
            parts.append(word)
        elif word.startswith("$"):
            colour = _colour(app, word[1:])
            if colour:
                parts.append(colour)
    return Text(inert_text(value), style=" ".join(parts))


def _colour(app: Any, token: str) -> str:
    """The Rich colour for a theme token, or "" when the theme gives none.

    The terminal-colour themes give names such as ``ansi_red``, which Rich
    spells ``red`` (``ansi_bright_red`` -> ``bright_red``); passing the
    Textual spelling would make Rich drop the whole style.
    """
    try:
        value = app.get_css_variables()[token]
        if not isinstance(value, str):
            return ""
        colour = Color.parse(value).hex
    except (KeyError, ColorParseError, AttributeError):
        return ""
    return colour.removeprefix("ansi_")


def rebuild_keeping_cursor(table: DataTable, rebuild: Callable[[], None]) -> None:
    """Run *rebuild* (which refills *table*) and put the cursor back on its row.

    Used when cells carry theme colours: they are fixed when a row is added, so
    a table rebuilds its rows when the app theme changes.
    """
    row = table.cursor_row
    rebuild()
    if table.row_count:
        table.move_cursor(row=min(row, table.row_count - 1), animate=False)
