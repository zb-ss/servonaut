"""A text-only button that reads as a link."""

from __future__ import annotations

from textual.content import Content
from textual.widgets import Button


class LinkButton(Button):
    """A button drawn as underlined words, with no frame or fill.

    The underline is part of the label's own text, not of the widget style, so
    it covers the label's cells and never the padding or alignment fill around
    them. The remaining styling lives in ``styles/components/link_button.tcss``
    and is keyed on the ``link-button`` class.
    """

    DEFAULT_CLASSES = "link-button"

    def render(self) -> Content:
        return Content.styled(self.label.plain, "underline")
