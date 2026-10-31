"""Escaping text from outside the app for Textual/Rich markup."""
from __future__ import annotations

from typing import Callable, Union

from textual.content import Content


def escape_markup(text: str) -> str:
    """*text* with every ``[`` literal.

    Names and fingerprints from the service must never be read as markup.
    Rich's ``escape`` leaves an unterminated ``[link=...`` alone, and Textual
    then refuses to render it (``MarkupError``), so every bracket is escaped.
    """
    return text.replace("[", "\\[")


def literal(text: str, style: str = "") -> Content:
    """*text* as styled content that is never parsed as markup.

    Backslash escapes cannot make arbitrary text safe next to a closing tag (a
    name ending in a backslash escapes the tag after it), so text from outside
    the app that sits beside styles is built as content, not as markup.
    """
    return Content.styled(text, style) if style else Content(text)


def scrub(value: Union[str, Content], scrubber: Callable[[str], str]) -> Union[str, Content]:
    """*value* run through *scrubber* (the demo-mode redaction of free text).

    Content is scrubbed through its plain text and loses its styling only when
    something was actually redacted.
    """
    if isinstance(value, str):
        return scrubber(value)
    cleaned = scrubber(value.plain)
    return value if cleaned == value.plain else Content(cleaned)
