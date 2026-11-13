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
import inspect
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

# Off while the backstop is suspended. The wrappers then pass straight through,
# which also works when a harness checker sits above them and the bindings
# cannot be put back.
_enabled = True


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
    if not _enabled:
        return _upstream["rich"](markup, *args, **kwargs)
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
    if not _enabled:
        return _upstream["textual"](markup, *args, **kwargs)
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
    return inspect.unwrap(textual.markup.to_content)


def original_rich_parser() -> Callable[..., Text]:
    """Rich's own markup parser, whether or not the backstop is installed."""
    return inspect.unwrap(rich.markup.render)


def _in_chain(function: Callable[..., Any], target: Callable[..., Any]) -> bool:
    """Whether *target* is *function* or sits beneath it (wrappers set ``__wrapped__``)."""
    seen = set()
    while function is not None and id(function) not in seen:
        if function is target:
            return True
        seen.add(id(function))
        function = getattr(function, "__wrapped__", None)
    return False


def installed() -> bool:
    """Whether the safe parsers are live right now: the live parsers are, or wrap, them.

    Read from the bindings themselves, so a test harness that replaced a
    parser (and restored it) cannot leave this answering from stale state.
    A harness checker placed on top of the safe parsers still counts.
    """
    return (
        _enabled
        and _in_chain(textual.markup.to_content, safe_to_content)
        and _in_chain(rich.markup.render, safe_rich_render)
        and rich.console.render_markup is safe_rich_render
    )


def install() -> None:
    """Make the safe parsers live. Safe to call repeatedly.

    A parser that already is, or wraps, the safe one is left as it is. Any
    other (the upstream parser, or a harness checker around it) is wrapped, and
    the wrapper calls it, so installing never hides a layer beneath it.
    """
    global _enabled
    _enabled = True
    if not _in_chain(textual.markup.to_content, safe_to_content):
        _upstream["textual"] = textual.markup.to_content
        safe_to_content.__wrapped__ = _upstream["textual"]  # type: ignore[attr-defined]
        textual.markup.to_content = safe_to_content
    if not _in_chain(rich.markup.render, safe_rich_render):
        _upstream["rich"] = rich.markup.render
        safe_rich_render.__wrapped__ = _upstream["rich"]  # type: ignore[attr-defined]
        rich.markup.render = safe_rich_render
    # ``Console.render_str`` reads its own module-level binding.
    rich.console.render_markup = safe_rich_render


def uninstall() -> None:
    """Make the parsers behave as upstream (for tests that need the raw behaviour).

    The safe parsers are taken out of the bindings when they are on top; under
    a harness checker they stay in place and pass straight through.
    """
    global _enabled
    _enabled = False
    if textual.markup.to_content is safe_to_content:
        textual.markup.to_content = _upstream["textual"]
    if rich.markup.render is safe_rich_render:
        rich.markup.render = _upstream["rich"]
    if rich.console.render_markup is safe_rich_render:
        rich.console.render_markup = rich.markup.render


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
