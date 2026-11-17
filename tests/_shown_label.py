"""A button's label as a user sees it painted."""

from __future__ import annotations


def shown_label(button) -> str:
    """The label's text as drawn: the words and the key cap, enabled or disabled."""
    return str(button.label.plain if hasattr(button.label, "plain") else button.label)
