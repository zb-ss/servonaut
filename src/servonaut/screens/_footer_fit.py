"""Keep a screen's footer to the shortcuts that fit on one line.

Textual's Footer is a single row. When a screen binds more shortcuts than
the terminal is wide, the row is cut wherever the width runs out, often in
the middle of a label. :func:`fit_footer` takes a screen's active bindings
and marks as hidden (``show=False``) the screen's own shortcuts that do not
fit, least useful first, so the footer ends on a whole label. Hidden
shortcuts stay bound and keep working; only their footer entry goes. The
app-wide keys (quit, help, chat) are never hidden: help lists everything.

A screen opts in by overriding ``active_bindings`` and refreshing its
bindings when it is resized::

    @property
    def active_bindings(self):
        return fit_footer(super().active_bindings, self, FOOTER_PRIORITY)

    def on_resize(self) -> None:
        self.refresh_bindings()
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Sequence

from rich.cells import cell_len
from textual.binding import ActiveBinding, Binding

# Cells a footer entry adds around its key and description: one space
# either side of the key and one after the description (Textual's Footer).
_ENTRY_PADDING = 3
# The command palette entry is docked right with a one-cell border before
# it and one cell of padding after it.
_PALETTE_EXTRA = 2


def entry_width(key_display: str, description: str) -> int:
    """Cells one footer entry takes."""
    return cell_len(key_display) + cell_len(description) + _ENTRY_PADDING


def fit_footer(
    bindings: Dict[str, ActiveBinding],
    screen: Any,
    priority: Sequence[str],
) -> Dict[str, ActiveBinding]:
    """*bindings* with the screen's footer entries cut to what fits.

    Args:
        bindings: The screen's active bindings, as Textual computes them.
        screen: The screen; its own bindings are the ones that may be hidden,
            and its width is the footer's.
        priority: The screen's actions, most useful first. Actions not
            listed come after, in binding order.

    Returns:
        The same mapping, in the same order, with every binding of an
        action that does not fit replaced by a copy with ``show=False``.
    """
    app = screen.app
    width = screen.size.width
    if width <= 0:
        return bindings

    shown = _footer_entries(bindings)
    budget = width
    palette_key = getattr(app, "COMMAND_PALETTE_BINDING", None)
    palette = bindings.get(palette_key) if palette_key else None
    if palette is not None and getattr(app, "ENABLE_COMMAND_PALETTE", False):
        budget -= _entry_cells(app, palette.binding) + _PALETTE_EXTRA

    own: List[ActiveBinding] = []
    for entry in shown:
        if entry.node is screen:
            own.append(entry)
        else:
            budget -= _entry_cells(app, entry.binding)

    order = {action: index for index, action in enumerate(priority)}
    ranked = sorted(own, key=lambda entry: order.get(entry.binding.action, len(order)))
    hidden_actions = set()
    for entry in ranked:
        cells = _entry_cells(app, entry.binding)
        if cells <= budget:
            budget -= cells
        else:
            hidden_actions.add(entry.binding.action)

    if not hidden_actions:
        return bindings
    return {
        key: (
            active._replace(binding=dataclasses.replace(active.binding, show=False))
            if active.node is screen and active.binding.action in hidden_actions
            else active
        )
        for key, active in bindings.items()
    }


def _footer_entries(bindings: Dict[str, ActiveBinding]) -> List[ActiveBinding]:
    """The entries the footer draws: the first shown binding of each action."""
    seen = set()
    entries = []
    for active in bindings.values():
        action = active.binding.action
        if not active.binding.show or action in seen:
            continue
        seen.add(action)
        entries.append(active)
    return entries


def _entry_cells(app: Any, binding: Binding) -> int:
    return entry_width(app.get_key_display(binding), binding.description)
