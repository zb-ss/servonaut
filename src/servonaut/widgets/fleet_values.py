"""The selected server's full values, each one a click or a key away from the clipboard."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, VerticalScroll
from textual.events import Click, MouseDown, MouseUp
from textual.widget import Widget
from textual.widgets import Static

from servonaut.utils.markup import literal
from servonaut.utils.platform_utils import CopyOutcome, copy_text
from servonaut.widgets.instance_table import InstanceTable

# How long a copied value shows its confirmation in place of itself (seconds).
COPIED_SECONDS = 1.5

# Every value a row can carry, the ones people copy most first, with the label
# the list shows and the shorter one the one-line form shows. A server without
# a value for a field simply has no row for it.
VALUE_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("name", "Name", "Name"),
    ("public_ip", "Public IP", "IP"),
    ("private_ip", "Private IP", "Priv"),
    ("region", "Region", "Region"),
    ("type", "Type", "Type"),
    ("id", "ID", "ID"),
    ("key_name", "Key", "Key"),
    ("state", "State", "State"),
    ("provider", "Provider", "Prov"),
    ("login_user", "Team login", "Login"),
    ("username", "Username", "User"),
    ("port", "Port", "Port"),
    ("group", "Group", "Group"),
    ("account", "Account", "Acct"),
    ("account_id", "Account ID", "Acct ID"),
)
_ACCOUNT_FIELDS = frozenset({"account", "account_id"})


def instance_values(instance: Optional[dict]) -> dict[str, str]:
    """The labelled values to show for ``instance``, keyed by field."""
    if not instance:
        return {}
    qualified = bool(instance.get("account_qualified") and instance.get("account"))
    values: dict[str, str] = {}
    for key, _label, _short in VALUE_FIELDS:
        if key in _ACCOUNT_FIELDS and not qualified:
            continue
        value = instance.get(key)
        if value not in (None, ""):
            values[key] = str(value)
    return values


_CONFIRMATIONS = {
    CopyOutcome.COPIED: "✓ copied",
    CopyOutcome.SENT_TO_TERMINAL: "sent to terminal",
}


class ValueRow(Horizontal):
    """One labelled value; a click, or enter while it has the focus, copies it."""

    BINDINGS = [Binding("enter", "copy", "Copy value", show=False)]

    def __init__(self, field: str, label: str, compact: bool) -> None:
        super().__init__(
            id=f"fleet_value_{'line' if compact else 'list'}_{field}",
            classes="value-row -compact" if compact else "value-row",
        )
        self.field = field
        self.label = label
        self.value = ""
        self.copied = False
        self._label_widget = Static(label, markup=False, classes="value-label")
        self._value_widget = Static("", markup=False, classes="value-text")
        self._copied_timer = None
        self._returns_to: Optional[Widget] = None
        self.tooltip = "Click to copy this value, or press Y and pick it with the keys"

    def compose(self) -> ComposeResult:
        yield self._label_widget
        yield self._value_widget

    @property
    def value_widget(self) -> Static:
        return self._value_widget

    @property
    def shown_text(self) -> str:
        """What the value cell currently paints (the value, or its confirmation)."""
        return self._value_widget.visual.plain

    def allow_focus(self) -> bool:
        # Only "Y" (or a click) walks the values: they stay out of the Tab chain.
        parent = self.parent
        return isinstance(parent, _ValueWalker) and parent.walking

    def set_value(self, value: str) -> None:
        self.value = value
        self._clear_copied()
        self._paint()

    def _paint(self) -> None:
        self._value_widget.update(literal(self.value))

    def on_hide(self) -> None:
        # A value that leaves the screen (chat toggled, window narrowed) must
        # not keep the keyboard: it is handed back to the table.
        if self.has_focus and isinstance(self.parent, _ValueWalker):
            self.parent.leave()

    def on_mouse_down(self, event: MouseDown) -> None:
        if event.button != 1 or not isinstance(self.parent, _ValueWalker):
            return
        # Taking the focus for the gesture keeps another editor's old
        # selection (the chat composer's) from being copied when the click is
        # released; the focus then goes back to where it was.
        focused = self.screen.focused
        self._returns_to = None if isinstance(focused, ValueRow) else focused
        self.parent.walking = True
        self.focus()

    def on_mouse_up(self, event: MouseUp) -> None:
        if event.button != 1:
            return
        # Queued behind the app's selection hook, which reads the focus.
        self.app.call_later(self._give_focus_back)

    def _give_focus_back(self) -> None:
        target, self._returns_to = self._returns_to, None
        parent = self.parent
        if target is None or not isinstance(parent, _ValueWalker) or not self.has_focus:
            return
        parent.walking = False
        if target.is_attached and target.focusable:
            target.focus()
        else:
            parent.leave()

    def on_click(self, event: Click) -> None:
        # A drag that selects part of the value already copies just that part.
        if event.button != 1 or self.screen.get_selected_text():
            return
        event.stop()
        self.action_copy()

    def action_copy(self) -> None:
        if not self.value:
            return
        outcome = copy_text(self.app, self.value)
        if outcome is CopyOutcome.UNAVAILABLE:
            self.app.notify("Clipboard not available", severity="warning")
            return
        self._show_copied(_CONFIRMATIONS[outcome])

    def _show_copied(self, confirmation: str) -> None:
        self._clear_copied()
        self.copied = True
        self.add_class("-copied")
        self._value_widget.update(literal(confirmation, "$text-success"))
        self._copied_timer = self.set_timer(COPIED_SECONDS, self._end_copied)

    def _end_copied(self) -> None:
        self._copied_timer = None
        self._clear_copied()
        self._paint()

    def _clear_copied(self) -> None:
        if self._copied_timer is not None:
            self._copied_timer.stop()
            self._copied_timer = None
        self.copied = False
        self.remove_class("-copied")


class _ValueWalker:
    """Filling the rows and walking them with the keyboard, for both layouts."""

    compact = False
    walking = False
    can_focus = False

    def compose(self) -> ComposeResult:
        for key, label, short in VALUE_FIELDS:
            row = ValueRow(key, short if self.compact else label, compact=self.compact)
            row.display = False
            yield row

    def set_instance(self, instance: Optional[dict]) -> None:
        values = instance_values(instance)
        for row in self.query(ValueRow):
            value = values.get(row.field)
            row.display = value is not None
            if value is not None and value != row.value:
                row.set_value(value)
        if self.walking and not self._visible_rows():
            self.leave()

    def _visible_rows(self) -> list[ValueRow]:
        return [row for row in self.query(ValueRow) if row.display]

    def begin_walk(self) -> bool:
        """Move the focus onto the first value; ``False`` when there is none."""
        rows = self._visible_rows()
        if not rows:
            return False
        self.walking = True
        if self.screen.focused not in rows:
            rows[0].focus()
        return True

    def action_step(self, offset: int) -> None:
        rows = self._visible_rows()
        focused = self.screen.focused
        if focused not in rows:
            return
        target = rows[max(0, min(len(rows) - 1, rows.index(focused) + offset))]
        target.focus()
        target.scroll_visible()

    def action_leave(self) -> None:
        self.leave()

    def leave(self) -> None:
        """End the walk and hand the focus back to the fleet table."""
        self.walking = False
        self.screen.query_one(InstanceTable).focus()

    def on_descendant_blur(self) -> None:
        # Moving between rows blurs one and focuses the next; only a focus
        # that ends up outside the rows ends the walk.
        self.call_after_refresh(self._end_walk_if_outside)

    def _end_walk_if_outside(self) -> None:
        if self.screen.focused not in self._visible_rows():
            self.walking = False


class FleetValues(_ValueWalker, VerticalScroll):
    """The values as a labelled list, in the fleet inspector (up and down)."""

    BINDINGS = [
        Binding("up", "step(-1)", "Previous value", show=False),
        Binding("down", "step(1)", "Next value", show=False),
        Binding("escape", "leave", "Back to the table", show=False),
    ]


class FleetValueLine(_ValueWalker, Grid):
    """The values as a short block under the table (left and right)."""

    compact = True

    BINDINGS = [
        Binding("left", "step(-1)", "Previous value", show=False),
        Binding("right", "step(1)", "Next value", show=False),
        Binding("escape", "leave", "Back to the table", show=False),
    ]
