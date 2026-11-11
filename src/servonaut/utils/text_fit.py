"""Fitting text into a fixed number of cells without hiding that it was cut."""

from __future__ import annotations


def cut(text: str, width: int) -> str:
    """*text* within *width* cells, ended with an ellipsis when it is cut."""
    if len(text) <= width:
        return text
    return text[: max(width - 1, 0)] + "…"
