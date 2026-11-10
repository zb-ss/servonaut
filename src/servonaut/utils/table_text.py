"""Table cells that follow the theme.

``DataTable`` measures string and Rich ``Text`` cells, but sizes a Textual
``Content`` cell as empty, so a column of them collapses to its header. Cells
are therefore Rich ``Text``; this builds one from outside text (shown
verbatim) in a theme colour resolved at the time the row is added.
"""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.color import Color, ColorParseError

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
    try:
        value = app.get_css_variables()[token]
        return Color.parse(value).hex if isinstance(value, str) else ""
    except (KeyError, ColorParseError, AttributeError):
        return ""
