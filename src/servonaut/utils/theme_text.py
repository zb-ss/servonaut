"""Rich text coloured from the active theme.

Widgets that render Rich renderables (``RichLog``) cannot resolve a theme
token such as ``$text-error`` in a style, so the token is read from the app's
theme when the line is written. A theme whose colours are not plain values (the
terminal-colour themes) leaves the text in the default colour, keeping only
its weight.
"""
from __future__ import annotations

from rich.text import Text
from textual.app import App
from textual.color import Color, ColorParseError

from servonaut.utils.markup import inert_text


def theme_style(app: App, token: str, *, bold: bool = False) -> str:
    """A Rich style in the theme colour named by *token* (e.g. ``text-error``)."""
    styles = ["bold"] if bold else []
    try:
        styles.append(Color.parse(app.get_css_variables()[token]).hex)
    except (KeyError, ColorParseError):
        pass
    return " ".join(styles)


def themed_text(app: App, text: str, token: str, *, bold: bool = False) -> Text:
    """*text*, shown literally, in the theme colour named by *token*."""
    return Text(inert_text(text), style=theme_style(app, token, bold=bold))
