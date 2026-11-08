"""Shared dialog regions, without validation, dismissal, or service access."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widget import Widget

from servonaut.widgets.dialogs.actions import DialogActions


# Class names a ModalScreen gets from ``DIALOG_VERTICAL_BREAKPOINTS``; dialogs.tcss
# styles them. "Roomy" carries no rules: it exists so that from 40 rows up the
# screen drops the "tight" class instead of keeping it.
DIALOG_MINIMAL = "-dialog-minimal"
DIALOG_TIGHT = "-dialog-tight"
DIALOG_ROOMY = "-dialog-roomy"

DIALOG_VERTICAL_BREAKPOINTS = [(0, DIALOG_MINIMAL), (24, DIALOG_TIGHT), (40, DIALOG_ROOMY)]


class DialogNotificationSpace(Widget):
    """Reserve a stable native dock while notifications appear and expire."""


class DialogBody(VerticalScroll):
    """Offer a keyboard scroll target only when content needs scrolling."""

    def allow_focus(self) -> bool:
        return super().allow_focus() and self.allow_vertical_scroll


class DialogContent(Vertical):
    """Non-scrolling body for children that own their scrolling and focus."""


class DialogFrame(Vertical):
    """Keep heading, optional status and actions outside a bounded body.

    The supplied widgets retain their IDs, values, focus behavior and events.
    Use DialogBody for scrollable copy, DialogContent for an editor, or pass
    a native scroll widget such as OptionList directly as the body.
    Add ``dialog-screen`` to the owning ModalScreen for centered positioning.

    A dialog with a lot of content opts in to compact chrome on short terminals
    by setting ``VERTICAL_BREAKPOINTS = DIALOG_VERTICAL_BREAKPOINTS`` on its
    screen: below 24 rows the frame also drops its padding, and below 40 rows
    the heading margin and the reserved notification lane go, with toasts
    shown over the top of the dialog.
    """

    # The same stylesheet supports minimal hosts and the application bundle.
    # Every selector names a dialog type or class; none restyles other screens.
    DEFAULT_CSS = (
        Path(__file__).parents[2] / "styles" / "components" / "dialogs.tcss"
    ).read_text(encoding="utf-8")
    SCOPED_CSS = False

    def __init__(
        self,
        *,
        heading: Widget,
        body: Widget,
        actions: DialogActions,
        status: Widget | None = None,
        size: Literal["compact", "standard", "large", "fill"] = "standard",
        severity: Literal["neutral", "warning", "danger"] = "neutral",
        id: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=f"dialog-{size} dialog-{severity}")
        heading.add_class("dialog-heading")
        body.add_class("dialog-body")
        if status is not None:
            status.add_class("dialog-status")
        self._heading = heading
        self._body = body
        self._actions = actions
        self._status = status

    def compose(self) -> ComposeResult:
        yield self._heading
        yield self._body
        with Vertical(classes="dialog-footer"):
            if self._status is not None:
                yield self._status
            yield self._actions

    def on_mount(self) -> None:
        self.watch(self._body, "virtual_size", self._queue_overflow_hint)
        self.watch(self._body, "show_vertical_scrollbar", self._queue_overflow_hint)
        self._queue_overflow_hint()

    def on_resize(self) -> None:
        self._queue_overflow_hint()

    def _queue_overflow_hint(self) -> None:
        if self.is_attached:
            self.call_after_refresh(self._sync_overflow_hint)

    def _sync_overflow_hint(self) -> None:
        if not self.is_attached:
            return
        hint = (
            "Scroll for all details"
            if self._body.allow_vertical_scroll and self._body.max_scroll_y > 0
            else ""
        )
        if self.border_subtitle != hint:
            self.border_subtitle = hint
