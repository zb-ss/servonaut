"""A dialog action row that leaves button behavior with its caller."""

from __future__ import annotations

from textual.containers import Horizontal
from textual.widgets import Button


class DialogActions(Horizontal):
    """Lay out existing buttons without changing their state or handling events."""

    DEFAULT_CSS = """
    DialogActions {
        width: 100%;
        height: 3;
        align: right middle;
    }
    """

    def __init__(
        self,
        *buttons: Button,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(*buttons, id=id, classes=classes)
