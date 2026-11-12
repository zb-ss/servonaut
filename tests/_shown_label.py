"""A button's label as a user sees it painted."""

from __future__ import annotations


def shown_label(button) -> str:
    """The label's text as drawn: a disabled button's key has no cap edges (they are spaces)."""
    text = str(button.label.plain if hasattr(button.label, "plain") else button.label)
    if getattr(button, "disabled", False):
        return text.replace("▐", " ").replace("▌", " ")
    return text
