"""A table that tells its owner when its own width changes."""

from __future__ import annotations

from typing import Callable, Optional

from textual.events import Resize
from textual.widgets import DataTable


class PlannedTable(DataTable):
    """A ``DataTable`` whose owner plans its columns from the table's own room.

    The owner is called once the table has its final width, whatever made it
    change (a terminal resize, the navigation or the chat opening). Calls are
    skipped while the width is unchanged and never overlap: one rebuild is
    pending at a time.
    """

    _plan_handler: Optional[Callable[[], None]] = None
    _planned_width = -1
    _plan_pending = False

    def set_plan_handler(self, handler: Callable[[], None]) -> None:
        """Call *handler* whenever the table's width changes."""
        self._plan_handler = handler

    def on_resize(self, event: Resize) -> None:
        width = event.size.width
        if width == self._planned_width:
            return
        self._planned_width = width
        if self._plan_handler is not None and not self._plan_pending:
            self._plan_pending = True
            self.call_after_refresh(self._plan)

    def _plan(self) -> None:
        self._plan_pending = False
        if self._plan_handler is not None:
            self._plan_handler()


def plannable_width(table: DataTable) -> int:
    """The cells columns may use: the table's own width less its scrollbar.

    The scrollbar's cells are taken off whether or not it is showing, so the
    plan does not change when a scrollbar appears or goes (it would then plan
    differently for the same room). Zero until the table has been laid out.
    """
    width = table.region.width
    if not isinstance(width, int) or width <= 0:
        return 0
    return max(width - table.styles.scrollbar_size_vertical, 1)
