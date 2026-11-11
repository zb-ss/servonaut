"""Column widths for the OVH inventory, sized from its rows.

A fixed-width table column crops silently, which turns ``141.123.123.123``
into a different, complete-looking address. Here the widths come from the
values, the public address is never cut (an IPv6 address ends with an
ellipsis), and when the room runs out the Kind column goes first, then
Region, and only then Name and Type are shortened, with an ellipsis.
"""

from __future__ import annotations

from typing import Dict, Sequence

from rich.cells import cell_len

from servonaut.utils.text_fit import cut  # noqa: F401  (re-exported for the screen)

COLUMNS = ("#", "Name", "Type", "Kind", "State", "Public IP", "Region")
# Cells a DataTable adds around every column.
CELL_PADDING = 2
# A whole IPv4 address.
IP_WIDTH = 15
_NAME_CAP = 28
_TYPE_CAP = 20
_MIN_TEXT = 10
# What goes when the room runs out, first to last.
_DROP_ORDER = ("Kind", "Region")


def plan_columns(rows: Sequence[Sequence[str]], available: int) -> Dict[str, int]:
    """The width of each column that is shown, in column order.

    Args:
        rows: One ``(#, name, type, kind, state, address, region)`` of plain
            text per row.
        available: Cells the table has; 0 or less means no limit.
    """
    widths = {
        label: max([cell_len(label)] + [cell_len(row[index]) for row in rows])
        for index, label in enumerate(COLUMNS)
    }
    widths["Name"] = min(widths["Name"], _NAME_CAP)
    widths["Type"] = min(widths["Type"], _TYPE_CAP)
    widths["Public IP"] = min(widths["Public IP"], IP_WIDTH)
    shown = list(COLUMNS)

    def total() -> int:
        return sum(widths[label] for label in shown) + CELL_PADDING * len(shown)

    if available > 0:
        for label in _DROP_ORDER:
            if total() > available:
                shown.remove(label)
        for label in ("Name", "Type"):
            overflow = total() - available
            if overflow > 0:
                widths[label] = max(_MIN_TEXT, widths[label] - overflow)
    return {label: widths[label] for label in shown}
