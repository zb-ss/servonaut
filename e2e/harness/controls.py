"""Drive and read Textual form controls the way a user does.

Kept apart from ``pilot.py`` so journeys can grow their own helpers without
touching the core driver. Textual has no public API for a Select's option
list or for the parts of its drop-down; :func:`_select_parts` is the one
place this module reaches into Textual internals, so a Textual upgrade that
moves them breaks here, loudly, and nowhere else.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Union

from rich.text import Text
from textual.widget import Widget
from textual.widgets import DataTable, Select


@dataclass(frozen=True)
class _SelectParts:
    labels: list[str]  # what the open menu shows, in order ("" is the blank entry)
    values: list[Any]
    current: Widget  # the visible label of the closed control
    menu: Any  # the drop-down option list (an OptionList)


def _select_parts(select: Select) -> _SelectParts:
    """The option list and drop-down of *select* (private Textual API, v8)."""
    from textual.widgets._select import SelectCurrent, SelectOverlay

    options = select._options
    return _SelectParts(
        labels=[getattr(prompt, "plain", str(prompt)) for prompt, _ in options],
        values=[value for _, value in options],
        current=select.query_one(SelectCurrent).query_one("#label"),
        menu=select.query_one(SelectOverlay),
    )


def option_labels(select: Select) -> list[str]:
    """The prompts a user sees when the menu opens, in order."""
    return _select_parts(select).labels


async def choose(t: Any, selector: str, matches: "str | Callable[[str], bool]") -> Any:
    """Open the Select *selector* on the active screen and pick an option.

    *matches* is the start of the option's label, or a predicate over the
    label. Clicks the control, moves the highlight with the arrow keys and
    confirms with Enter, then waits for the value to land. Returns the value.
    """
    select = t.on_screen(selector, Select)
    parts = _select_parts(select)
    predicate = matches if callable(matches) else (lambda label: label.startswith(matches))
    targets = [index for index, label in enumerate(parts.labels) if predicate(label)]
    if not targets:
        raise AssertionError(f"no option in {selector} matches {matches!r}: {parts.labels}")
    target = targets[0]
    expected = parts.values[target]

    await t.click(parts.current)
    menu = parts.menu
    await t.wait_until(lambda: select.expanded and menu.has_focus, desc=f"{selector} menu")
    for _ in range(len(parts.labels) + 1):
        if menu.highlighted == target:
            break
        current = menu.highlighted if menu.highlighted is not None else -1
        await t.press("down" if current < target else "up")
    if menu.highlighted != target:
        raise AssertionError(f"could not highlight option {target} in {selector}")
    await t.press("enter")
    await t.wait_until(
        lambda: not select.expanded and select.value == expected,
        desc=f"{selector} set to {parts.labels[target]!r}",
    )
    return expected


async def clear(t: Any, selector: str) -> None:
    """Pick the blank entry (the prompt) of a Select that allows one."""
    await choose(t, selector, lambda label: label == "")


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------


def _cell_text(cell: Any) -> str:
    """A cell as shown: DataTable renders a str cell as Rich markup."""
    if isinstance(cell, Text):
        return cell.plain
    if isinstance(cell, str):
        return Text.from_markup(cell).plain
    return str(cell)


def table_text(t: Any, selector: Union[str, DataTable]) -> list[tuple[str, ...]]:
    """Every row of a DataTable on the active screen, as the user reads it."""
    table = t.on_screen(selector, DataTable) if isinstance(selector, str) else selector
    return [tuple(_cell_text(cell) for cell in table.get_row(key)) for key in table.rows]


async def click_row(t: Any, table: DataTable, index: int) -> None:
    """Click row *index* of *table*, scrolling it into view first.

    The first click on a row highlights it; a click on the highlighted row
    selects it (see :func:`select_row`).
    """
    if not 0 <= index < table.row_count:
        raise AssertionError(f"{table!r} has no row {index} ({table.row_count} rows)")
    top = sum(row.height for row in table.ordered_rows[:index])
    table.scroll_to(y=top, animate=False, immediate=True)
    await t.pilot.pause()
    header = table.header_height if table.show_header else 0
    y = table.gutter.top + header + top - int(table.scroll_offset.y)
    visible = table.scrollable_content_region.height - header
    if not 0 <= y - table.gutter.top - header < visible:
        raise AssertionError(f"row {index} of {table!r} did not scroll into view")
    if not await t.pilot.click(table, offset=(table.gutter.left + 1, y)):
        raise AssertionError(f"click on row {index} of {table!r} landed on another widget")
    await t.wait_until(lambda: table.cursor_row == index, desc=f"cursor on row {index}")


async def select_row(t: Any, table: DataTable, index: int) -> None:
    """Open row *index* with the mouse: highlight it, then click it again."""
    if table.cursor_row != index:
        await click_row(t, table, index)
    await click_row(t, table, index)
