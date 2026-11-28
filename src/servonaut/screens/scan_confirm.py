"""Confirmation dialog before running keyword scan SSH commands across the fleet."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from servonaut.widgets.dialogs import (
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)
from servonaut.widgets.safe_header import SafeHeader


class GlobalScanConfirmModal(ModalScreen[bool]):
    """Confirm running SSH directory/command scans across all running servers."""

    DEFAULT_CLASSES = "dialog-screen"
    AUTO_FOCUS = "#scan_confirm_cancel"
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    DEFAULT_CSS = """
    GlobalScanConfirmModal #scan_confirm_modal {
        width: 68;
        max-width: 92%;
        height: auto;
        border: round $warning;
        background: transparent;
        padding: 1 2;
    }
    GlobalScanConfirmModal #scan_confirm_title {
        text-style: bold;
        color: $text-warning;
    }
    GlobalScanConfirmModal #scan_confirm_text {
        margin-top: 1;
        height: auto;
    }
    GlobalScanConfirmModal #scan_confirm_cancel,
    GlobalScanConfirmModal #scan_confirm_run {
        width: auto;
        min-width: 12;
    }
    """

    def __init__(self, target_count: int) -> None:
        super().__init__()
        self._target_count = max(0, int(target_count))

    def compose(self) -> ComposeResult:
        noun = "server" if self._target_count == 1 else "servers"
        yield SafeHeader()
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("[bold]Scan all running servers[/bold]", id="scan_confirm_title"),
            body=DialogBody(
                Static(
                    f"This will connect over SSH to {self._target_count} {noun} and run "
                    "your default directory listings plus any matching keyword scan commands.",
                    id="scan_confirm_text",
                )
            ),
            actions=DialogActions(
                Button("Cancel", id="scan_confirm_cancel"),
                Button("Run scan", variant="primary", id="scan_confirm_run"),
            ),
            size="compact",
            severity="warning",
            id="scan_confirm_modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "scan_confirm_run")

    def action_cancel(self) -> None:
        self.dismiss(False)
