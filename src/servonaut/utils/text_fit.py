"""Fitting text into a number of terminal cells without hiding that it was cut."""

from __future__ import annotations

from rich.cells import cell_len


def cut(text: str, width: int) -> str:
    """*text* within *width* terminal cells, ended with an ellipsis when it is cut.

    Wide characters (CJK, emoji) take two cells. A width of zero or less
    leaves nothing, not even the ellipsis.
    """
    if width <= 0:
        return ""
    if cell_len(text) <= width:
        return text
    kept, used = [], 0
    for char in text:
        step = cell_len(char)
        if used + step > width - 1:
            break
        kept.append(char)
        used += step
    return "".join(kept) + "…"
