"""Showing text another user or the service chose, safely, in a terminal."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# Bidirectional-text controls that can make a shown name read differently.
_BIDI_CONTROLS = frozenset("‎‏‪‫‬‭‮⁦⁧⁨⁩")


def terminal_safe(value: object) -> str:
    """*value* as inert text: no control characters, escape sequences or bidi controls."""
    return "".join(
        char for char in str(value)
        if not (ord(char) < 32 or 127 <= ord(char) <= 159 or char in _BIDI_CONTROLS)
    )


def flatten_rows(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Dotted ``key: value`` rows of nested mappings and lists, nested data included."""
    if isinstance(value, Mapping):
        rows: list[tuple[str, Any]] = []
        for key, item in value.items():
            rows.extend(flatten_rows(item, f"{prefix}{key}."))
        return rows if rows or not prefix else [(prefix[:-1], "{}")]
    if isinstance(value, list):
        if not value:
            return [(prefix[:-1], "[]")] if prefix else []
        rows = []
        for index, item in enumerate(value, start=1):
            rows.extend(flatten_rows(item, f"{prefix}{index}."))
        return rows
    return [(prefix[:-1], value)]
