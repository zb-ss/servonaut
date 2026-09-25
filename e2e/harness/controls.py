"""Drive Textual form controls the way a user does.

Kept apart from ``pilot.py`` so journeys can grow their own helpers without
touching the core driver.
"""

from __future__ import annotations

from typing import Any, Callable

from textual.widgets import Select
from textual.widgets._select import SelectCurrent, SelectOverlay


def option_labels(select: Select) -> list[str]:
    """The prompts a user sees when the menu opens, in order."""
    labels = []
    for prompt, _value in select._options:
        labels.append(getattr(prompt, "plain", str(prompt)))
    return labels


async def choose(t: Any, selector: str, matches: "str | Callable[[str], bool]") -> Any:
    """Open the Select *selector* on the active screen and pick an option.

    *matches* is the start of the option's label, or a predicate over the
    label. Clicks the control, moves the highlight with the arrow keys and
    confirms with Enter, then waits for the value to land. Returns the value.
    """
    select = t.on_screen(selector, Select)
    predicate = matches if callable(matches) else (lambda label: label.startswith(matches))
    labels = option_labels(select)
    targets = [index for index, label in enumerate(labels) if predicate(label)]
    if not targets:
        raise AssertionError(f"no option in {selector} matches {matches!r}: {labels}")
    target = targets[0]
    expected = select._options[target][1]

    # The visible part of a closed Select is its current-value label.
    await t.click(select.query_one(SelectCurrent).query_one("#label"))
    overlay = select.query_one(SelectOverlay)
    await t.wait_until(lambda: select.expanded and overlay.has_focus, desc=f"{selector} menu")
    for _ in range(len(labels) + 1):
        if overlay.highlighted == target:
            break
        current = overlay.highlighted if overlay.highlighted is not None else -1
        await t.press("down" if current < target else "up")
    if overlay.highlighted != target:
        raise AssertionError(f"could not highlight option {target} in {selector}")
    await t.press("enter")
    await t.wait_until(
        lambda: not select.expanded and select.value == expected,
        desc=f"{selector} set to {labels[target]!r}",
    )
    return expected


async def clear(t: Any, selector: str) -> None:
    """Pick the blank entry (the prompt) of a Select that allows one."""
    await choose(t, selector, lambda label: label == "")


async def click_row(t: Any, table: Any, index: int) -> None:
    """Click row *index* of a DataTable on the active screen.

    A click on a row moves the cursor there and selects it, like Enter.
    """
    table.scroll_to(y=0, animate=False, immediate=True)
    await t.pilot.pause()
    header = table.header_height if table.show_header else 0
    offset = (table.gutter.left + 1, table.gutter.top + header + index)
    if not await t.pilot.click(table, offset=offset):
        raise AssertionError(f"click on row {index} of {table!r} landed on another widget")
    await t.wait_until(lambda: table.cursor_row == index, desc=f"cursor on row {index}")
