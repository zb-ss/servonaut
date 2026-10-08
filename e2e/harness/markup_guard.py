"""Catch fixed colour names in text that Textual's own markup draws.

Textual reads ``[cyan]``, ``[yellow]`` and the like in its markup (labels,
statics, buttons, toasts) as fixed web colours: ``#00FFFF`` and ``#FFFF00``
whatever the theme, which cannot be read on a light background. Text there
takes theme colours instead (``[$text-accent]``, ``[$text-warning]``).
Rich markup (table cells, tree labels, logs) keeps the names: Textual draws
them through the theme's ANSI palette, and Rich does not know theme
variables, so a ``$`` colour there is dropped without a word.

:func:`watch` wraps both parsers and records text that breaks either rule;
:func:`named_colour_tags` and :func:`theme_variable_tags` are the checks.

This module must not import ``servonaut`` (see the package docstring).
"""

from __future__ import annotations

import contextlib
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
    """Record markup that a theme cannot colour: see the module docstring."""
    import rich.markup as rich_markup
    import textual.markup as textual_markup

    textual_parse, rich_parse = textual_markup.to_content, rich_markup.render
    watcher = Watcher()

    def textual_checked(markup, *args, **kwargs):
        if isinstance(markup, str):
            tags = named_colour_tags(markup)
            if tags:
                watcher.findings.append(Finding(tags, markup, _caller()))
        return textual_parse(markup, *args, **kwargs)

    def rich_checked(markup, *args, **kwargs):
        if isinstance(markup, str):
            tags = theme_variable_tags(markup)
            if tags:
                watcher.findings.append(Finding(tags, markup, _caller(), "Rich"))
        return rich_parse(markup, *args, **kwargs)

    textual_markup.to_content, rich_markup.render = textual_checked, rich_checked
    try:
        yield watcher
    finally:
        textual_markup.to_content, rich_markup.render = textual_parse, rich_parse
