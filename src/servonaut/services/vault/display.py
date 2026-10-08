"""Showing text another user or the service chose, safely, in a terminal."""
from __future__ import annotations

# Bidirectional-text controls that can make a shown name read differently.
_BIDI_CONTROLS = frozenset("‎‏‪‫‬‭‮⁦⁧⁨⁩")


def terminal_safe(value: object) -> str:
    """*value* as inert text: no control characters, escape sequences or bidi controls."""
    return "".join(
        char for char in str(value)
        if not (ord(char) < 32 or 127 <= ord(char) <= 159 or char in _BIDI_CONTROLS)
    )
