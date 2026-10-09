"""A masked input with a Show/Hide toggle, so people can check what they typed or pasted."""

from __future__ import annotations

from typing import Any, Optional

from textual import on
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Button, Input

# Two cells wide in every terminal and in Textual's own measure; the single
# eye (U+1F441) is not, and a width mismatch corrupts the whole row.
_SHOW_LABEL = "👀 Show"
_HIDE_LABEL = "👀 Hide"
_SHOW_TOOLTIP = "Show what you typed (Ctrl+R)"
_HIDE_TOOLTIP = "Hide it again (Ctrl+R)"


class SecretInput(Horizontal):
    """An ``Input(password=True)`` with a button that reveals or masks its value.

    The inner :class:`Input` keeps the ``id`` given here, so code that reads
    the field (``query_one("#x", Input)``) works unchanged; the container is
    ``<id>_field`` and the button ``<id>_reveal``. ``classes`` go on the
    container. The button is clicked, not tabbed to: Ctrl+R toggles while the
    field has focus, so a form keeps one tab stop per field. Demo mode never
    reveals, and masks a revealed value again when it is switched on.
    """

    DEFAULT_CSS = """
    SecretInput {
        height: auto;
        width: 1fr;
    }
    SecretInput > Input {
        width: 1fr !important;
        margin: 0 !important;
    }
    SecretInput > .secret-reveal {
        width: auto;
        min-width: 10;
        margin: 0 0 0 1;
    }
    """

    BINDINGS = [Binding("ctrl+r", "toggle_reveal", "Show/hide", show=False)]

    def __init__(
        self,
        value: Optional[str] = None,
        placeholder: str = "",
        *,
        id: Optional[str] = None,
        classes: Optional[str] = None,
        disabled: bool = False,
        **input_kwargs: Any,
    ) -> None:
        super().__init__(id=f"{id}_field" if id else None, classes=classes, disabled=disabled)
        self._input = Input(value, placeholder, password=True, id=id, **input_kwargs)
        self._button = Button(
            _SHOW_LABEL, id=f"{id}_reveal" if id else None, classes="secret-reveal", tooltip=_SHOW_TOOLTIP,
        )
        self._button.can_focus = False

    def compose(self):
        yield self._input
        yield self._button

    @property
    def input(self) -> Input:
        return self._input

    @property
    def value(self) -> str:
        return self._input.value

    @value.setter
    def value(self, value: str) -> None:
        self._input.value = value

    @property
    def revealed(self) -> bool:
        return not self._input.password

    def focus(self, scroll_visible: bool = True) -> "SecretInput":
        self._input.focus(scroll_visible)
        return self

    def reveal(self, shown: bool) -> None:
        """Show or mask the value; demo mode keeps it masked."""
        if shown and getattr(self.app, "demo_mode", False):
            self.app.notify("Secrets stay hidden in demo mode.", severity="warning", markup=False)
            shown = False
        self._input.password = not shown
        self._button.label = _HIDE_LABEL if shown else _SHOW_LABEL
        self._button.tooltip = _HIDE_TOOLTIP if shown else _SHOW_TOOLTIP

    def action_toggle_reveal(self) -> None:
        self.reveal(not self.revealed)

    @on(Button.Pressed, ".secret-reveal")
    def _reveal_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_toggle_reveal()

    def refresh_after_demo_toggle(self) -> None:
        """Mask a revealed value when demo mode is switched on."""
        if self.revealed and getattr(self.app, "demo_mode", False):
            self.reveal(False)
