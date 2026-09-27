"""Shared binding guard for screens with Input/TextArea widgets.

Prevents single-letter key bindings from stealing keystrokes when the
user is typing in an Input or TextArea widget.  Textual resolves screen-level
bindings *before* delivering the key to the focused widget, so without this
guard pressing 'y' in an Input would trigger ``action_copy_output`` instead
of inserting the character.

Usage — add to any Screen that mixes single-letter bindings with text widgets:

    from servonaut.screens._binding_guard import check_action_passthrough

    class MyScreen(Screen):
        BINDINGS = [
            Binding("y", "copy_output", "Copy", show=True),
            ...
        ]

        def check_action(self, action: str, parameters: tuple) -> bool | None:
            return check_action_passthrough(self, action)
"""

from __future__ import annotations

from textual.binding import Binding
from textual.widgets import Input, TextArea


def check_action_passthrough(screen, action: str) -> bool | None:
    """Return None for single-printable-key bindings when Input/TextArea is focused.

    Textual's ``check_action`` has three return values:

    - ``True``  → binding enabled; action fires; footer shows the key bright.
    - ``None``  → binding disabled-but-visible; action does NOT fire (key event
                  falls through to the focused widget); footer shows the key
                  greyed-out so the user can still discover it.
    - ``False`` → binding hidden entirely; gone from the footer too.

    We return ``None`` (not ``False``) so the footer can keep advertising
    every shortcut even while the user is typing in a search box. Textual
    itself leaves printable-key bindings out of the footer while an Input
    has focus, so an Input that should keep them listed also has to report
    that it does not consume those keys (see ``FleetSearchInput`` on the
    fleet screen). Two UX journeys preserved:

    1. **Act-on-a-row**: the fleet table has focus when the screen opens;
       the shortcuts are bright and fire normally.
    2. **Find-a-server-fast**: ``/`` focuses the search box; typing
       letters filters the table while the footer shows the shortcuts
       greyed out, as a hint of what works once focus is back on a row.

    Non-printable keys (escape, f5, enter, ctrl+*, arrows) are always
    allowed regardless of focus.
    """
    focused = screen.focused
    if not isinstance(focused, (Input, TextArea)):
        return True

    for binding in screen.BINDINGS:
        if isinstance(binding, Binding):
            key, bind_action = binding.key, binding.action
        else:
            # Handle tuple-style bindings: (key, action, description)
            key, bind_action = binding[0], binding[1]

        if bind_action == action and len(key) == 1 and key.isprintable():
            return None  # disabled-but-visible — footer still advertises it

    return True
