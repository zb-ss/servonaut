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
    """Return False for single-printable-key bindings when Input/TextArea is focused.

    When ``check_action`` returns False, Textual skips the binding and the
    key event falls through to the focused widget so it can handle it
    normally (i.e. insert the character).

    Non-printable key bindings (escape, f5, enter, ctrl+*, arrows) are
    always allowed regardless of focus.
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
            return False

    return True
