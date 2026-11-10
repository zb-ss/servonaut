"""The selected server's full values, each one a click or a key away from the clipboard."""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Grid, VerticalScroll
from textual.content import Content
from textual.events import Click
from textual.widgets import Static

from servonaut.utils.markup import literal

# How long a copied value shows its confirmation in place of itself (seconds).
COPIED_SECONDS = 1.5

# Every value a row can carry, the ones people copy most first. A server without a value for
# a field simply has no row for it.
VALUE_FIELDS: tuple[tuple[str, str], ...] = (
    ("name", "Name"),
    ("public_ip", "Public IP"),
    ("private_ip", "Private IP"),
    ("region", "Region"),
    ("type", "Type"),
    ("id", "ID"),
    ("key_name", "Key"),
    ("state", "State"),
    ("provider", "Provider"),
    ("login_user", "Team login"),
    ("username", "Username"),
    ("port", "Port"),
    ("group", "Group"),
    ("account", "Account"),
    ("account_id", "Account ID"),
)
_ACCOUNT_FIELDS = frozenset({"account", "account_id"})


def instance_values(instance: Optional[dict]) -> dict[str, str]:
    """The labelled values to show for ``instance``, keyed by field."""
    if not instance:
        return {}
    qualified = bool(instance.get("account_qualified") and instance.get("account"))
    values: dict[str, str] = {}
    for key, _label in VALUE_FIELDS:
        if key in _ACCOUNT_FIELDS and not qualified:
            continue
        value = instance.get(key)
        if value not in (None, ""):
            values[key] = str(value)
    return values


class ValueRow(Static):
    """One labelled value; a click, or enter while it has the focus, copies it."""

    BINDINGS = [Binding("enter", "copy", "Copy value", show=False)]

    def __init__(self, field: str, label: str, compact: bool) -> None:
        super().__init__(
            "", id=f"fleet_value_{'line' if compact else 'list'}_{field}",
            classes="value-row", markup=False,
        )
        self.field = field
        self.label = label
        self.value = ""
        self.copied = False
        self._compact = compact
        self._copied_timer = None
        self.tooltip = f"Click to copy the {label.lower()}"

    def allow_focus(self) -> bool:
        # Only "Y" walks the values: they stay out of the Tab chain.
        return getattr(self.parent, "walking", False)

    def set_value(self, value: str) -> None:
        self.value = value
        self._clear_copied()
        self._paint()

    def _paint(self) -> None:
        if self.copied:
            confirmation = literal("✓ copied", "$text-success")
            if self._compact:
                self.update(confirmation)
            else:
                self.update(Content.assemble(literal(self.label, "dim"), "  ", confirmation, "\n", literal(self.value)))
        elif self._compact:
            self.update(literal(self.value))
        else:
            self.update(Content.assemble(literal(self.label, "dim"), "\n", literal(self.value)))

    def on_click(self, event: Click) -> None:
        # A drag that selects part of the value already copies just that part.
        if self.screen.get_selected_text():
            return
        event.stop()
        self.action_copy()

    def action_copy(self) -> None:
        from servonaut.utils.platform_utils import copy_to_clipboard

        if not self.value:
            return
        if not copy_to_clipboard(self.value):
            self.app.copy_to_clipboard(self.value)
        self._show_copied()

    def _show_copied(self) -> None:
        self._clear_copied()
        self.copied = True
        self.add_class("-copied")
        self._paint()
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

    def compose(self) -> ComposeResult:
        for key, label in VALUE_FIELDS:
            row = ValueRow(key, label, compact=self.compact)
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
        from servonaut.widgets.instance_table import InstanceTable

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
