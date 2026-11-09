"""Escaping text from outside the app for Textual/Rich markup."""
from __future__ import annotations

import re
import urllib.parse
from typing import Callable, Union

from rich.text import Text
from textual.content import Content
from textual.style import Style as TextualStyle


def escape_markup(text: str) -> str:
    """*text* with every ``[`` literal.

    Names and fingerprints from the service must never be read as markup.
    Rich's ``escape`` leaves an unterminated ``[link=...`` alone, and Textual
    then refuses to render it (``MarkupError``), so every bracket is escaped.
    """
    return text.replace("[", "\\[")


# Characters a terminal acts on instead of drawing (C0 and C1 controls, DEL)
# and bidirectional controls that reorder what is shown. Also invisible
# characters that Rich measures as zero cells wide but terminals draw one or
# two cells wide (fillers, line and paragraph separators), which would push
# the end of a line off screen. Newline and tab stay.
_UNSAFE_CHARS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069\u061c\u115f\u1160\u2028\u2029\u3164\uffa0]")


def _visible_placeholder(match: "re.Match[str]") -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def inert_text(text: str) -> str:
    """*text* with every terminal-acting character written out visibly.

    An escape sequence in a name or a command must show up as ``\\x1b[8m``
    rather than reach the terminal (where it could hide the text after it).
    """
    return _UNSAFE_CHARS.sub(_visible_placeholder, text.replace("\r\n", "\n"))


def literal(text: str, style: str = "") -> Content:
    """*text* as styled content that is never parsed as markup.

    Backslash escapes cannot make arbitrary text safe next to a closing tag (a
    name ending in a backslash escapes the tag after it), so text from outside
    the app that sits beside styles is built as content, not as markup.
    Control characters are shown as visible placeholders (see ``inert_text``).
    """
    text = inert_text(text)
    return Content.styled(text, style) if style else Content(text)


# Whitespace and control characters never belong in an address that is opened.
_URL_UNSAFE = re.compile("[\x00-\x20\x7f-\x9f]")
WEB_SCHEMES = frozenset({"http", "https"})


def is_web_url(url: object) -> bool:
    """Whether *url* is an absolute ``http``/``https`` address with a host."""
    if not isinstance(url, str) or not url or _URL_UNSAFE.search(url):
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return parsed.scheme.lower() in WEB_SCHEMES and bool(parsed.netloc)


def web_link(url: str, style: str = "") -> Content:
    """*url* as text that opens the address when clicked (only for web addresses).

    The link is a style on the content, never markup, so the address cannot
    carry anything but the link itself. Anything that is not an ``http`` or
    ``https`` address is drawn as plain text.
    """
    content = literal(url, style)
    if not is_web_url(url):
        return content
    return content.stylize(TextualStyle(link=url))


def cell(value: object, style: str = "") -> Text:
    """*value* as a table cell that is drawn exactly as typed.

    Data tables read a plain string as markup. A name chosen outside the app
    must not be, so cells that show one are built as ``Text``.
    """
    return Text(inert_text(str(value)), style=style)


def scrub(value: Union[str, Content], scrubber: Callable[[str], str]) -> Union[str, Content]:
    """*value* run through *scrubber* (the demo-mode redaction of free text).

    Content is scrubbed through its plain text and loses its styling only when
    something was actually redacted.
    """
    if isinstance(value, str):
        return scrubber(value)
    cleaned = scrubber(value.plain)
    return value if cleaned == value.plain else Content(cleaned)


def with_bold_values(template: str, *values: object) -> Content:
    """*template* with each ``{}`` replaced by a value shown literally in bold.

    The template is fixed text written in the app; the values may come from
    outside it, so none of them is ever read as markup.
    """
    parts = template.split("{}")
    if len(parts) != len(values) + 1:
        raise ValueError("template and values do not match")
    pieces: list = [parts[0]]
    for value, tail in zip(values, parts[1:]):
        pieces.append(literal(str(value), "bold"))
        pieces.append(tail)
    return Content.assemble(*pieces)
