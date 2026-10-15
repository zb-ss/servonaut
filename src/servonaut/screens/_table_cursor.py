"""Keep a DataTable's selected row when a screen redraws all of its rows.

``DataTable.clear()`` moves the cursor back to the first row. A screen that
redraws its rows after a refresh or an action would otherwise leave the next
key press (Delete, Power off…) acting on a different row than the one the
user picked.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from textual.coordinate import Coordinate
from textual.widgets import DataTable
from textual.widgets.data_table import CellDoesNotExist, RowDoesNotExist


@contextmanager
def keep_selected_row(table: DataTable) -> Iterator[None]:
    """Put the cursor back on the same row (by key) once the block has refilled *table*.

    When that row is gone (a deleted server), the cursor stays at the same
    position, clamped to the last row.
    """
    position = table.cursor_row if table.row_count else 0
    key: Optional[str] = None
    if table.row_count:
        try:
            key = table.coordinate_to_cell_key(Coordinate(position, 0)).row_key.value
        except CellDoesNotExist:
            key = None
    yield
    if not table.row_count:
        return
    row = min(position, table.row_count - 1)
    if key is not None:
        try:
            row = table.get_row_index(key)
        except RowDoesNotExist:
            pass
    if row != table.cursor_row:
        table.move_cursor(row=row)
