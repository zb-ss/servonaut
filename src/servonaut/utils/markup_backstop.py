"""A backstop under every markup parse in the app.

Text that comes from outside the app (server, team and provider names, remote
output, API responses) must never be parsed as markup; see
``servonaut.utils.markup`` for the helpers that keep it literal. This module is
the net under any call site that still hands such text to a parser.

Textual and Rich each read markup through one function:
``textual.markup.to_content`` (every widget that shows a ``str``, toasts,
border titles) and ``rich.markup.render`` (data tables, trees, Rich tables).
``install`` wraps both so that markup parsed from a plain string

* never raises: an unbalanced or malformed tag shows the string literally
  instead of ending the app while a screen draws, and
* never carries a click action or other style metadata, and never a hyperlink:
  the app's own markup uses colours and text styles only. A link the app means
  to draw is built as ``Content`` or ``Text`` with an explicit style, which
  never passes through these parsers.

The wrappers look at the parser's result rather than at the input, so every
spelling of a tag (extra spaces, quoting, theme variables in front, escapes) is
covered the same way.
"""
from __future__ import annotations

import contextlib
import dataclasses
from typing import Any, Callable, Iterator

import rich.console
import rich.markup
import textual.markup
from rich.errors import MarkupError as RichMarkupError
from rich.style import Style as RichStyle
from rich.text import Span as RichSpan, Text
from textual.content import Content, Span
from textual.style import Style as TextualStyle

# The upstream parsers while the backstop is installed (empty otherwise). The
# wrappers call these directly, so another wrapper placed on top of them (the
# test harness watches the parsers) cannot make them call themselves.
_upstream: dict[str, Callable[..., Any]] = {}


# ---------------------------------------------------------------------------
# Cleaning a parsed style
# ---------------------------------------------------------------------------

def _rich_style_words(style: str) -> str:
    """A Rich style string without ``link <url>`` pairs and ``@meta`` words."""
    kept: list[str] = []
    words = iter(style.split())
    for word in words:
        if word == "link":
            next(words, None)
        elif not word.startswith("@"):
            kept.append(word)
    return " ".join(kept)


def _clean_rich_style(style: Any) -> Any:
    """*style* without meta or a link; the same object when it has neither."""
    if isinstance(style, RichStyle):
        return style.clear_meta_and_links() if (style._meta or style._link) else style
    if isinstance(style, str) and ("link" in style or "@" in style):
        return _rich_style_words(style)
    return style


def _clean_textual_style(style: Any) -> Any:
    """*style* without meta or a link; the same object when it has neither.

    Textual reads every ``key=value`` word in a style as metadata (``@click``
    and ``link`` among them). The app's own styles never contain ``=``, so a
    span that does is drawn unstyled.
    """
    if isinstance(style, str):
        return "" if "=" in style else style
    if isinstance(style, TextualStyle) and (style._meta is not None or style.link):
        return dataclasses.replace(style, link=None, _meta=None)
    return style


# ---------------------------------------------------------------------------
# The wrapped parsers
# ---------------------------------------------------------------------------

def _inert_rich_markup(markup: str, args: tuple, kwargs: dict) -> Text:
    style = args[0] if args else kwargs.get("style", "")
    return Text(markup, style=style)


def safe_rich_render(markup: str, *args: Any, **kwargs: Any) -> Text:
    """``rich.markup.render`` that never raises and never yields meta or links."""
    try:
        text = _upstream["rich"](markup, *args, **kwargs)
    except RichMarkupError:
        return _inert_rich_markup(markup, args, kwargs)
    spans = text._spans
    for index, span in enumerate(spans):
        cleaned = _clean_rich_style(span.style)
        if cleaned is not span.style:
            spans[index] = RichSpan(span.start, span.end, cleaned)
    return text


def _inert_textual_markup(markup: str, args: tuple, kwargs: dict) -> Content:
    style = args[0] if args else kwargs.get("style", "")
    return Content.styled(markup, style) if style else Content(markup)


def safe_to_content(markup: str, *args: Any, **kwargs: Any) -> Content:
    """``textual.markup.to_content`` that never raises and never yields meta or links."""
    try:
        content = _upstream["textual"](markup, *args, **kwargs)
    except textual.markup.MarkupError:
        return _inert_textual_markup(markup, args, kwargs)
    spans = content.spans
    cleaned = [
        span if (new := _clean_textual_style(span.style)) is span.style
        else Span(span.start, span.end, new)
        for span in spans
    ]
    if any(after is not before for after, before in zip(cleaned, spans)):
        return Content(content.plain, cleaned, content.cell_length)
    return content


# ---------------------------------------------------------------------------
# Installing
# ---------------------------------------------------------------------------

def original_textual_parser() -> Callable[..., Content]:
    """Textual's own markup parser, whether or not the backstop is installed."""
    return _upstream.get("textual") or textual.markup.to_content


def original_rich_parser() -> Callable[..., Text]:
    """Rich's own markup parser, whether or not the backstop is installed."""
    return _upstream.get("rich") or rich.markup.render


def installed() -> bool:
    return bool(_upstream)


def install() -> None:
    """Put the safe parsers in place. Safe to call repeatedly."""
    if installed():
        return
    _upstream["textual"] = textual.markup.to_content
    _upstream["rich"] = rich.markup.render
    # ``inspect.unwrap`` finds the upstream parser from the wrapper.
    safe_to_content.__wrapped__ = _upstream["textual"]  # type: ignore[attr-defined]
    safe_rich_render.__wrapped__ = _upstream["rich"]  # type: ignore[attr-defined]
    textual.markup.to_content = safe_to_content
    rich.markup.render = safe_rich_render
    # ``Console.render_str`` reads its own module-level binding.
    rich.console.render_markup = safe_rich_render


def uninstall() -> None:
    """Restore the upstream parsers (for tests that need the raw behaviour)."""
    if not installed():
        return
    textual.markup.to_content = _upstream["textual"]
    rich.markup.render = _upstream["rich"]
    rich.console.render_markup = _upstream["rich"]
    del safe_to_content.__wrapped__  # type: ignore[attr-defined]
    del safe_rich_render.__wrapped__  # type: ignore[attr-defined]
    _upstream.clear()


@contextlib.contextmanager
def suspended() -> Iterator[None]:
    """Run a block with the upstream parsers, then put the backstop back."""
    was_installed = installed()
    uninstall()
    try:
        yield
    finally:
        if was_installed:
            install()
