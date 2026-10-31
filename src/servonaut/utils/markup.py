"""Escaping text from outside the app for Textual/Rich markup."""
from __future__ import annotations


def escape_markup(text: str) -> str:
    """*text* with every ``[`` literal.

    Names and fingerprints from the service must never be read as markup.
    Rich's ``escape`` leaves an unterminated ``[link=...`` alone, and Textual
    then refuses to render it (``MarkupError``), so every bracket is escaped.
    """
    return text.replace("[", "\\[")
