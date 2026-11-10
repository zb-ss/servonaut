"""A text-only button that reads as a link."""

from __future__ import annotations

from typing import Any

from textual.content import Content
from textual.widgets import Button


class LinkButton(Button):
    """A button drawn as underlined words, with no frame or fill.

    The underline is part of the label's own text, not of the widget style, so
    it covers the label's cells and never the padding or alignment fill around
    them. The remaining styling lives in ``styles/components/link_button.tcss``
    and is keyed on the ``link-button`` class.
    """

    def __init__(self, *args: Any, classes: str | None = None, **kwargs: Any) -> None:
        # Textual drops DEFAULT_CLASSES when a caller passes classes, so the
        # link class is added here to stay on every instance.
        super().__init__(*args, classes=f"link-button {classes or ''}".strip(), **kwargs)

    def render(self) -> Content:
        return Content.styled(self.label.plain, "underline")
