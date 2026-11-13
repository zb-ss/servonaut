"""Keep terminal control characters in displayed text away from the terminal.

Server, tag and team names, remote command output and similar text come from
outside the app. Textual hands every widget's text to the terminal in one
place, ``Strip.render``, and writes it as it is, so an escape sequence inside
a name (set the clipboard, retitle the window, add a hidden link, move the
cursor over what is shown) reaches a terminal that honours it. Escaping markup
does not help, because the characters are plain text.

``install`` wraps ``Strip.render`` so control characters are removed from
every segment, and from the target of a hyperlink, before the strip is turned
into terminal bytes. Removing them (instead of showing a placeholder) keeps
the measured width: they take no cells, so the layout does not move. Content
that wants a visible placeholder uses ``servonaut.utils.markup.literal``.

Styles are rendered by Textual from colours and attributes, not from segment
text, so its own sequences are untouched.
"""
from __future__ import annotations

import re
import sys
from typing import Any, Callable, List, TextIO

from rich.console import Console
from rich.segment import Segment
from textual.strip import Strip

from servonaut.utils.markup import inert_text

# C0 controls (ESC, BEL, tab and newline too: a drawn row has neither), DEL,
# C1 controls (0x9b is a one-byte CSI), and the bidirectional controls that
# reorder what is shown.
_UNSAFE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]"
)

_ORIGINAL_ATTR = "_servonaut_original_render"


def has_controls(text: str) -> bool:
    """Whether *text* holds a character a terminal would act on."""
    return _UNSAFE.search(text) is not None


def first_control_index(text: str) -> int:
    """Position of the first terminal-acting character in *text*, or -1."""
    match = _UNSAFE.search(text)
    return match.start() if match else -1


def strip_controls(text: str) -> str:
    """*text* without terminal-acting characters."""
    return _UNSAFE.sub("", text)


def _clean_segment(segment: Segment) -> Segment:
    text, style, control = segment
    text = _UNSAFE.sub("", text)
    if style is not None and style._link and _UNSAFE.search(style._link):
        style = style.update_link(None)
    return Segment(text, style, control)


def _needs_cleaning(segments: List[Segment]) -> bool:
    search = _UNSAFE.search
    for text, style, _ in segments:
        if search(text) or (style is not None and style._link and search(style._link)):
            return True
    return False


def _wrap(original: Callable[[Strip, Console], str]) -> Callable[[Strip, Console], str]:
    def render(self: Strip, console: Console) -> str:
        if self._render_cache is None and _needs_cleaning(self._segments):
            cleaned = Strip(
                [_clean_segment(segment) for segment in self._segments],
                self._cell_length,
            )
            self._render_cache = original(cleaned, console)
            return self._render_cache
        return original(self, console)

    setattr(render, _ORIGINAL_ATTR, original)
    render.__doc__ = original.__doc__
    return render


def install() -> None:
    """Make ``Strip.render`` drop terminal controls. Safe to call repeatedly."""
    if hasattr(Strip.render, _ORIGINAL_ATTR):
        return
    Strip.render = _wrap(Strip.render)  # type: ignore[method-assign]


def uninstall() -> None:
    """Restore Textual's own ``Strip.render`` (for tests)."""
    original: Any = getattr(Strip.render, _ORIGINAL_ATTR, None)
    if original is not None:
        Strip.render = original  # type: ignore[method-assign]


class _InertStream:
    """A text stream that writes terminal-acting characters out visibly.

    Everything else (``fileno``, ``isatty``, ``buffer``, ...) is the wrapped
    stream's own, so prompts and encoding handling keep working.
    """

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        self._stream.write(inert_text(text))
        return len(text)

    def writelines(self, lines: Any) -> None:
        for line in lines:
            self.write(line)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def protect_cli_output() -> None:
    """Show control characters in everything the CLI prints as text.

    The CLI prints names and output that come from servers and the service.
    Wrapping the two text streams once covers every ``print`` without
    touching each call site. The caller restores the streams when done.
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        if not isinstance(stream, _InertStream):
            setattr(sys, name, _InertStream(stream))


__all__ = ["install", "uninstall", "strip_controls", "has_controls", "first_control_index", "protect_cli_output"]
