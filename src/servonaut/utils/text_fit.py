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


def cut_middle(text: str, width: int) -> str:
    """*text* within *width* cells, cut in the middle so both ends stay readable.

    Long opaque identifiers differ at their end more often than at their
    start, so the ellipsis goes between a kept head and a kept tail.
    """
    if width <= 0:
        return ""
    if cell_len(text) <= width:
        return text
    if width < 3:
        return cut(text, width)
    tail_width = (width - 1) // 2
    head_width = width - 1 - tail_width
    head = ""
    for char in text:
        if cell_len(head) + cell_len(char) > head_width:
            break
        head += char
    tail = ""
    for char in reversed(text):
        if cell_len(tail) + cell_len(char) > tail_width:
            break
        tail = char + tail
    return f"{head}…{tail}"
