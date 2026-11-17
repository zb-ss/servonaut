"""Compact native rows for settings with a label and one existing control."""

from __future__ import annotations

from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Static


def setting_row(label: str, field: Widget) -> Horizontal:
    """Keep each control's identity while sharing label and row presentation."""
    return Horizontal(
        Static(label, classes="label", markup=False),
        field,
        classes="setting_row settings-scalar-row",
    )
