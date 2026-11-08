"""Composable dialog presentation; callers own interaction and result values."""

from servonaut.widgets.dialogs.actions import DialogActions
from servonaut.widgets.dialogs.frame import (
    DIALOG_MINIMAL,
    DIALOG_ROOMY,
    DIALOG_TIGHT,
    DIALOG_VERTICAL_BREAKPOINTS,
    DialogBody,
    DialogContent,
    DialogFrame,
    DialogNotificationSpace,
)

__all__ = [
    "DIALOG_MINIMAL",
    "DIALOG_ROOMY",
    "DIALOG_TIGHT",
    "DIALOG_VERTICAL_BREAKPOINTS",
    "DialogActions",
    "DialogBody",
    "DialogContent",
    "DialogFrame",
    "DialogNotificationSpace",
]
