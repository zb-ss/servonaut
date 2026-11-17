"""One-row action buttons for narrow workspaces.

A workspace that is narrow has no height to spare either, so its bordered
three-row buttons become one-row borderless ones, and each row of actions
chooses its words, hints and wrapping again for the new button sizes.
"""

from __future__ import annotations

from textual.screen import Screen

from servonaut.widgets.action_button import ActionButton, ActionRow


def sync_compact_buttons(screen: Screen) -> None:
    """Make every action button compact while *screen* is laid out narrow."""
    compact = screen.has_class("-narrow") or screen.has_class("-content-narrow")
    for button in screen.query(ActionButton):
        button.compact = compact
    for row in screen.query(ActionRow):
        row.fit()
