"""One button style for every screen's actions.

An action reads as plain sentence-case words with a quiet key hint on the
right (``Browse files  1``). The label is built here, in one place, so every
screen that adopts the widget looks the same.
"""

from __future__ import annotations

from typing import Literal

from textual.content import Content, ContentText
from textual.widgets import Button

ActionRole = Literal["default", "primary", "warning", "error"]

_ROLE_VARIANTS = {
    "default": "default",
    "primary": "primary",
    "warning": "warning",
    "error": "error",
}
_KEY_GAP = "  "


def action_label(text: str, key: str | None = None) -> Content:
    """The label shown on an action: *text*, then *key* as a muted hint.

    Both parts are literal: neither is parsed as markup, so a label built from
    server- or user-supplied text cannot restyle or break the button.
    """
    if not key:
        return Content(text)
    return Content.assemble(text, _KEY_GAP, (key, "$text-muted"))


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
        super().__init__(
            action_label(short if compact and short else text, key),
            variant=_ROLE_VARIANTS[role],
            id=id,
            classes=classes,
            tooltip=tooltip,
            disabled=disabled,
            compact=compact,
        )

    def _words(self) -> str:
        return self._short if self.compact and self._short else self._text

    def watch_compact(self, compact: bool) -> None:
        """Use the short words when only one row is available."""
        if hasattr(self, "_text"):
            self.label = action_label(self._words(), self._key)

    def set_text(self, text: str, key: str | None = None) -> None:
        """Replace the words and, when given, the key hint."""
        self._text = text
        self._key = key if key is not None else self._key
        self.label = action_label(self._words(), self._key)

    def set_role(self, role: ActionRole) -> None:
        """Change how prominent the action looks."""
        self.variant = _ROLE_VARIANTS[role]
