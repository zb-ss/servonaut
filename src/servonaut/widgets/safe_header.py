"""Application header that survives being removed while it mounts.

Textual's ``Header`` refreshes its title from a coroutine that it queues on
the app and on the screen when it mounts (and again whenever a title
changes). If the header's screen is closed before the app runs that queued
coroutine, the header's title child is already gone and the coroutine raises
``NoMatches``. Nothing catches that inside Textual, so the whole TUI exits.
A screen can be closed that early when a prompt is dismissed by a cancelled
or expired request while it is still opening, or when screens are switched
in quick succession.

``SafeHeader`` keeps the stock header's layout and styling but refreshes its
title synchronously, so no refresh is left pending when the header goes
away, and it skips the refresh once the title child has been removed.
"""

from __future__ import annotations

from textual.css.query import NoMatches
from textual.dom import NoScreen
from textual.events import Mount
from textual.widgets import Header, Static

# CSS type name of the title child that ``Header.compose`` creates. The class
# itself is private to Textual, so it is looked up by name.
_TITLE_SELECTOR = "HeaderTitle"


class SafeHeader(Header):
    """``Header`` whose title refresh cannot outlive the header."""

    def _on_mount(self, event: Mount) -> None:
        # Replace Header's own mount handler, which registers the deferred
        # refresh described in the module docstring; keep Widget's handler.
        event.prevent_default()
        super(Header, self)._on_mount(event)
        for owner in (self.app, self.screen):
            self.watch(owner, "title", self._refresh_title)
            self.watch(owner, "sub_title", self._refresh_title)

    def _refresh_title(self) -> None:
        """Show the current title unless the header is being taken apart."""
        try:
            title = self.query_one(_TITLE_SELECTOR, Static)
        except NoMatches:
            return
        try:
            title.update(self.format_title())
        except NoScreen:
            return


__all__ = ["SafeHeader"]
