"""One button style for every screen's actions.

An action reads as plain sentence-case words with a quiet key hint on the
right (``Browse files  1``). The label is built here, in one place, so every
screen that adopts the widget looks the same.

A screen adopts the widgets by putting :class:`ActionButton` s in an
:class:`ActionRow` and setting ``compact`` on the buttons whenever its layout
is narrow; the row then keeps every button fully visible.
"""

from __future__ import annotations

from typing import Literal

from textual.containers import Horizontal
from textual.content import Content, ContentText
from textual.events import Resize
from textual.widget import Widget
from textual.widgets import Button

ActionRole = Literal["default", "primary", "warning", "error"]

_KEY_GAP = "  "
_COMPACT_KEY_GAP = "   "
# Cells a button adds around its label: padding and line pad, plus the border
# when it is not compact; every button also keeps a one-cell margin.
_COMPACT_CHROME = 4
_FULL_CHROME = 6
_MARGIN = 1
# Cells between two columns of a wrapped row (grid-gutter of ActionRow.-wrap).
_WRAP_GUTTER = 1
# A wrapped row keeps its key hints while it needs no more lines than this.
_MAX_HINTED_LINES = 2


def action_label(text: str, key: str | None = None, gap: str = _KEY_GAP) -> Content:
    """The label shown on an action: *text*, then *key* as a muted hint.

    Both parts are literal: neither is parsed as markup, so a label built from
    server- or user-supplied text cannot restyle or break the button.
    """
    if not key:
        return Content(text)
    return Content.assemble(text, gap, (key, "$text-muted"))


class ActionButton(Button):
    """A themed button with a key hint, a role and a compact (one-row) form."""

    def __init__(
        self,
        text: str,
        key: str | None = None,
        *,
        role: ActionRole = "default",
        compact: bool = False,
        short: str | None = None,
        id: str | None = None,
        classes: str | None = None,
        tooltip: ContentText | None = None,
        disabled: bool = False,
    ) -> None:
        self._text = text
        self._key = key
        self._short = short
        self._hint = True
        self._use_short = False
        super().__init__(
            self._label(compact, True),
            variant=role,
            id=id,
            classes=classes,
            tooltip=tooltip,
            disabled=disabled,
            compact=compact,
        )

    @property
    def words(self) -> str:
        """The full words of the action, without its key hint."""
        return self._text

    def _label(self, compact: bool, hint: bool, use_short: bool | None = None) -> Content:
        shorter = self._use_short if use_short is None else use_short
        words = self._short if (compact or shorter) and self._short else self._text
        gap = _COMPACT_KEY_GAP if compact else _KEY_GAP
        return action_label(words, self._key if hint else None, gap)

    def _refresh_label(self) -> None:
        self.label = self._label(self.compact, self._hint)
        # An auto width is measured from the label; measure it again.
        self.refresh(layout=True)
        if self.parent is not None:
            self.parent.refresh(layout=True)

    def on_mount(self) -> None:
        """Tell the row this button joined, so it fits with it counted."""
        row = self.parent
        if isinstance(row, ActionRow):
            row.request_fit()

    def watch_compact(self, compact: bool) -> None:
        """Use the short words when only one row is available."""
        self._refresh_label()

    def set_text(self, text: str, key: str | None = None, short: str | None = None) -> None:
        """Replace the words and, when given, the key hint and the short words."""
        self._text = text
        self._short = short if short is not None else self._short
        self._key = key if key is not None else self._key
        self._refresh_label()

    def set_fit(self, *, short: bool, hint: bool) -> None:
        """Choose the short words and the key hint (the ways a row saves space)."""
        if (short, hint) == (self._use_short, self._hint):
            return
        self._use_short, self._hint = short, hint
        self._refresh_label()

    def set_role(self, role: ActionRole) -> None:
        """Change how prominent the action looks."""
        self.variant = role

    def natural_width(self, *, short: bool, hint: bool) -> int:
        """Cells this button needs, margin included, for the given words and hint."""
        chrome = _COMPACT_CHROME if self.compact else _FULL_CHROME
        return self._label(self.compact, hint, short).cell_length + chrome + _MARGIN


class ActionRow(Horizontal):
    """A row of actions that never clips one.

    When the buttons do not fit it saves space in this order: shorter words,
    then no key hints, then it wraps onto further lines (class ``-wrap``).
    A row with ``keep_hints`` never drops the hints: it wraps instead, so every
    row of a screen shows the same hint state.
    """

    def __init__(self, *children: Widget, keep_hints: bool = False, **kwargs) -> None:
        super().__init__(*children, **kwargs)
        self._keep_hints = keep_hints
        self._fit_requested = False

    def on_resize(self, event: Resize) -> None:
        self.fit()

    def on_mount(self) -> None:
        self.request_fit()

    def request_fit(self) -> None:
        """Fit once the pending layout is done; many requests make one fit.

        The first Resize of a freshly mounted row can arrive before its
        buttons are mounted, so the row also fits when the row or one of its
        buttons mounts, not only when its size changes.
        """
        if self._fit_requested:
            return
        self._fit_requested = True
        self.call_after_refresh(self._fit_requested_now)

    def _fit_requested_now(self) -> None:
        self._fit_requested = False
        if self.is_attached:
            self.fit()

    def available_width(self) -> int:
        """Cells the buttons may use: the row's own width, or the parent's for an auto-width row.

        An auto-width row is as wide as its buttons, so its own width only
        echoes the layout it already has (a wrapped auto-width grid measures
        nothing). What it may grow to is what its parent leaves it.
        """
        parent = self.parent
        if self.styles.width is not None and self.styles.width.is_auto and isinstance(parent, Widget):
            return max(0, parent.content_size.width - self.styles.margin.width - self.gutter.width)
        return self.content_size.width

    def fit(self) -> None:
        """Choose words, hints and wrapping for the width the row may use.

        Order: one row with full words, one row with short words, then wrapped
        rows that keep the hints (up to two lines), then one row
        without hints, then wrapped rows without them.
        """
        width = self.available_width()
        # A button that is not shown takes no room, so it must not force a wrap.
        buttons = [button for button in self.query(ActionButton) if button.display]
        if width <= 0 or not buttons:
            return
        for short in (False, True):
            if sum(b.natural_width(short=short, hint=True) for b in buttons) <= width:
                self._apply(buttons, short=short, hint=True, wrap=False)
                return
        columns = self._column_count(buttons, hint=True, width=width)
        if -(-len(buttons) // columns) <= _MAX_HINTED_LINES or len(buttons) == 1:
            self._apply(buttons, short=True, hint=True, wrap=True)
        elif not self._keep_hints and sum(b.natural_width(short=True, hint=False) for b in buttons) <= width:
            self._apply(buttons, short=True, hint=False, wrap=False)
        else:
            self._apply(buttons, short=True, hint=self._keep_hints, wrap=True)

    @staticmethod
    def _column_count(buttons: list[ActionButton], *, hint: bool, width: int) -> int:
        """Equal columns for a wrapped row, each wide enough for the widest button."""
        widest = max(b.natural_width(short=True, hint=hint) for b in buttons)
        columns = (width + _WRAP_GUTTER) // (widest + _WRAP_GUTTER)
        return max(1, min(len(buttons), columns))

    def wrapped_columns(self, buttons: list[ActionButton], *, hint: bool) -> int:
        """Columns a wrapped row would have at the width it may use now."""
        return self._column_count(buttons, hint=hint, width=self.available_width())

    def _apply(
        self, buttons: list[ActionButton], *, short: bool, hint: bool, wrap: bool,
    ) -> None:
        width = self.available_width()
        for button in buttons:
            button.set_fit(short=short, hint=hint)
        self.set_class(wrap, "-wrap")
        # An id rule that fixes the layout (a toolbar kept horizontal) would
        # out-rank the class rule, leaving a "wrapped" row on one line.
        self.styles.layout = "grid" if wrap else None
        # Columns follow the labels as they are now shown, so none is squeezed.
        self.styles.grid_size_columns = (
            self._column_count(buttons, hint=hint, width=width) if wrap else None
        )
        # Widths are measured from the labels, which changed during a layout
        # pass: ask for another pass once this one is done.
        self.call_after_refresh(self._remeasure)

    def _remeasure(self) -> None:
        for button in self.query(ActionButton):
            button.refresh(layout=True)
        self.refresh(layout=True)
