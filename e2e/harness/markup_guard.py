"""Catch fixed colour names, and malformed tags, in text that the app's markup draws.

Textual reads ``[cyan]``, ``[yellow]`` and the like in its markup (labels,
statics, buttons, toasts) as fixed web colours: ``#00FFFF`` and ``#FFFF00``
whatever the theme, which cannot be read on a light background. Text there
takes theme colours instead (``[$text-accent]``, ``[$text-warning]``).
Rich markup (table cells, tree labels, logs) keeps the names: Textual draws
them through the theme's ANSI palette, and Rich does not know theme
variables, so a ``$`` colour there is dropped without a word.

:func:`watch` wraps both parsers (whichever are live) and records text that
breaks either rule, or that the upstream parser cannot read at all;
:func:`named_colour_tags` and :func:`theme_variable_tags` are the checks.

This module must not import ``servonaut`` (see the package docstring).
"""

from __future__ import annotations

import contextlib
import inspect
import re
import traceback
from dataclasses import dataclass, field
from typing import Iterator

# The colour names the codebase used; any of them, with or without
# ``bright_``, as a foreground or after ``on``.
_COLOUR_NAMES = frozenset(
    {"black", "red", "green", "yellow", "blue", "magenta", "cyan", "white", "grey", "gray"}
)
_TAG = re.compile(r"(?<!\\)\[([^\[\]/][^\[\]]*)\]")
_VARIABLE = re.compile(r"(?:^|\s)\$[a-z]")


def named_colour_tags(markup: str) -> list[str]:
    """Opening tags in *markup* that name a fixed colour."""
    found = []
    for match in _TAG.finditer(markup):
        tokens = match.group(1).lower().split()
        if any(token.removeprefix("bright_") in _COLOUR_NAMES for token in tokens):
            found.append(match.group(0))
    return found


def theme_variable_tags(markup: str) -> list[str]:
    """Opening tags in *markup* that use a theme variable such as ``$accent``."""
    return [
        match.group(0) for match in _TAG.finditer(markup) if _VARIABLE.search(match.group(1))
    ]


@dataclass
class Finding:
    """Markup that names a fixed colour in Textual, or a theme colour in Rich."""

    tags: list[str]
    markup: str
    where: str
    parser: str = "Textual"


@dataclass
class Watcher:
    findings: list[Finding] = field(default_factory=list)

    def report(self) -> str:
        return "\n".join(
            f"{finding.where}: {' '.join(finding.tags)} in {finding.parser} markup "
            f"{finding.markup[:120]!r}"
            for finding in self.findings
        )


def _caller() -> str:
    """The innermost Servonaut frame on the stack, if the text is parsed there.

    Widgets usually parse their text when they are drawn, after the code
    that set it has returned; the text itself then says where it came from.
    """
    for frame in reversed(traceback.extract_stack()):
        path = frame.filename.replace("\\", "/")
        if "/src/servonaut/" in path or "/site-packages/servonaut/" in path:
            return f"servonaut/{path.rsplit('/servonaut/', 1)[-1]}:{frame.lineno}"
    return "<drawn later>"


@contextlib.contextmanager
def watch() -> Iterator[Watcher]:
    """Record markup that a theme cannot colour: see the module docstring.

    The checkers wrap whatever parsers are live, so the app's own safe parsers
    (when installed) keep working under them and journeys run as shipped. A
    malformed tag would no longer raise there, so each checker also parses
    with the unwrapped upstream parser first and records the error it raises.
    """
    import rich.markup as rich_markup
    import textual.markup as textual_markup

    saved = textual_markup.to_content, rich_markup.render
    textual_live, rich_live = saved
    textual_upstream = inspect.unwrap(textual_live)
    rich_upstream = inspect.unwrap(rich_live)
    watcher = Watcher()

    def record(tags, markup, parser):
        watcher.findings.append(Finding(tags, markup, _caller(), parser))

    def textual_checked(markup, *args, **kwargs):
        if isinstance(markup, str):
            tags = named_colour_tags(markup)
            if tags:
                record(tags, markup, "Textual")
            try:
                textual_upstream(markup, *args, **kwargs)
            except Exception as error:  # noqa: BLE001 - any parse failure is a finding
                if type(error).__name__ == "MarkupError":
                    record([f"[malformed markup: {error}]"], markup, "Textual")
        return textual_live(markup, *args, **kwargs)

    def rich_checked(markup, *args, **kwargs):
        if isinstance(markup, str):
            tags = theme_variable_tags(markup)
            if tags:
                record(tags, markup, "Rich")
            try:
                rich_upstream(markup, *args, **kwargs)
            except Exception as error:  # noqa: BLE001 - any parse failure is a finding
                if type(error).__name__ == "MarkupError":
                    record([f"[malformed markup: {error}]"], markup, "Rich")
        return rich_live(markup, *args, **kwargs)

    textual_checked.__wrapped__ = textual_live
    rich_checked.__wrapped__ = rich_live
    textual_markup.to_content, rich_markup.render = textual_checked, rich_checked
    try:
        yield watcher
    finally:
        textual_markup.to_content, rich_markup.render = saved
