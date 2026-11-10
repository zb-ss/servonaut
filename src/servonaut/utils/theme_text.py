"""Text coloured from the active theme.

Rich renderables (table cells, ``RichLog`` lines) cannot resolve a theme token
such as ``$text-error`` themselves, and ``DataTable`` sizes a Textual
``Content`` cell as empty, so a column of them collapses to its header. Cells
and log lines are therefore Rich ``Text`` whose colour is read from the theme
when they are built; a table rebuilds its rows when the theme changes.
"""
from __future__ import annotations

from typing import Any, Callable

from rich.text import Text
from textual.color import Color, ColorParseError
from textual.screen import Screen
from textual.widgets import DataTable

from servonaut.utils.markup import inert_text

_MODIFIERS = frozenset({"bold", "dim", "italic", "underline"})


def theme_style(app: Any, style: str) -> str:
    """A Rich style for *style*: modifiers and one ``$theme-token``.

    ``"bold $text-error"`` becomes ``"bold #d17e92"`` under a colour theme. A token
    the theme does not give as a colour leaves the modifiers only.
    """
    parts = []
    for word in style.split():
        if word in _MODIFIERS:
            parts.append(word)
        elif word.startswith("$"):
            colour = _colour(app, word[1:])
            if colour:
                parts.append(colour)
    return " ".join(parts)


def themed_text(app: Any, text: str, style: str = "") -> Text:
    """*text* verbatim (never read as markup), styled by *style* (see ``theme_style``)."""
    return Text(inert_text(text), style=theme_style(app, style))


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
    except (KeyError, TypeError, ColorParseError, AttributeError):
        return ""
    return colour.removeprefix("ansi_")


def rebuild_keeping_cursor(table: DataTable, rebuild: Callable[[], None]) -> None:
    """Run *rebuild* (which refills *table*) and put the cursor back on its row."""
    row = table.cursor_row
    rebuild()
    if table.row_count:
        table.move_cursor(row=min(row, table.row_count - 1), animate=False)


def follow_theme(screen: Screen, table_id: str, rebuild: Callable[[], None]) -> None:
    """Rebuild *table_id* of *screen* with *rebuild* whenever the app theme changes.

    Cells carry theme colours fixed when a row is added, so a table that stays
    mounted across a theme switch has to draw its rows again.
    """
    def restyle(_theme: Any = None) -> None:
        table = screen.query_one(table_id, DataTable)
        screen.call_after_refresh(rebuild_keeping_cursor, table, rebuild)

    screen.app.theme_changed_signal.subscribe(screen, restyle)
