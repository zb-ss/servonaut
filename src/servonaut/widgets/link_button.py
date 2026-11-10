"""A text-only button that reads as a link."""

from __future__ import annotations

from typing import Any

from textual.content import Content
from textual.widgets import Button

from servonaut.widgets.action_button import _KEY_GAP, action_label, hint_style


def action_label_underlined(words: str, key: str, style: str) -> Content:
    """*words* underlined, then *key* as the usual quiet hint, in *style*."""
    hint = action_label("", key).plain
    return Content.assemble((words, "underline"), (hint, style))


class LinkButton(Button):
    """A button drawn as underlined words, with no frame or fill.

    The underline is part of the label's own text, not of the widget style, so
    it covers the label's cells and never the padding or alignment fill around
    them. The remaining styling lives in ``styles/components/link_button.tcss``
    and is keyed on the ``link-button`` class.

    With a ``key`` the label reads like an action's: the words underlined,
    then a gap, then the key as a quiet hint that is not underlined.
    """

    def __init__(
        self, label: str | None = None, *args: Any, key: str | None = None,
        classes: str | None = None, **kwargs: Any,
    ) -> None:
        self._key = key
        # Textual drops DEFAULT_CLASSES when a caller passes classes, so the
        # link class is added here to stay on every instance.
        super().__init__(
            action_label(label, key) if label is not None and key else label,
            *args, classes=f"link-button {classes or ''}".strip(), **kwargs,
        )

    def render(self) -> Content:
        plain = self.label.plain
        suffix = f"{_KEY_GAP}{self._key}" if self._key else ""
        if suffix and plain.endswith(suffix):
            return action_label_underlined(plain[: -len(suffix)], self._key, hint_style(self))
        return Content.styled(plain, "underline")
