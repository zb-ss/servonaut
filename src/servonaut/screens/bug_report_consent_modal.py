"""Bug report consent modal for Servonaut.

Surfaces the privacy choices before any diagnostic data is collected.
The user selects which categories to include and where to send the
report.  A preview of the exact payload is shown on the next screen
(BugReportScreen) before anything leaves the machine.

This brief blocking choice returns to the report when dismissed.
BugReportScreen carries the report preview and submission controls.
"""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, RadioButton, RadioSet, Static

from servonaut.services.bug_report_service import BugReportConsent
from servonaut.widgets.dialogs import (
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)


class BugReportConsentModal(ModalScreen[Optional[BugReportConsent]]):
    """Capture user consent for bug-report data collection.

    Returns via ``dismiss``:
      - ``BugReportConsent`` — user pressed Continue; caller collects
        diagnostics according to the chosen options and proceeds to the
        preview/submit flow.
      - ``None`` — user pressed Cancel or Escape; caller aborts the
        bug-report flow without collecting anything.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    DEFAULT_CLASSES = "dialog-screen"
    AUTO_FOCUS = "#chk-include-logs"

    DEFAULT_CSS = """
    BugReportConsentModal #checkboxes {
        height: auto;
        margin-bottom: 1;
    }

    BugReportConsentModal Checkbox {
        width: 100%;
        height: auto;
        margin-bottom: 0;
    }

    BugReportConsentModal #channel-label {
        height: auto;
        text-style: bold;
        margin-top: 1;
        margin-bottom: 0;
    }

    BugReportConsentModal #channel-selector {
        height: auto;
        margin-bottom: 1;
    }

    """

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(
                "[bold $text-accent]Report a bug[/bold $text-accent]",
                id="consent-title",
            ),
            body=DialogBody(
                Static(
                    "Choose what to include in your report. You'll see exactly what will be "
                    "sent before anything leaves your machine.",
                    id="consent-copy",
                    classes="dialog-description dialog-muted",
                ),
                Vertical(
                    Checkbox(
                        "Last 200 lines of ~/.servonaut/logs/servonaut.log (secrets are scrubbed)",
                        value=True,
                        compact=True,
                        id="chk-include-logs",
                    ),
                    Checkbox(
                        "Configuration snapshot (api keys & secrets are removed)",
                        value=True,
                        compact=True,
                        id="chk-include-config",
                    ),
                    Checkbox(
                        "Anonymous instance counts by provider (no names, no ids)",
                        value=True,
                        compact=True,
                        id="chk-include-telemetry",
                    ),
                    id="checkboxes",
                ),
                Static("Send report via:", id="channel-label"),
                RadioSet(
                    RadioButton(
                        "Open prefilled GitHub issue (opens in browser)",
                        value=True,
                        compact=True,
                        id="radio-github",
                    ),
                    RadioButton(
                        "Submit via Servonaut backend (you can be anonymous)",
                        compact=True,
                        id="radio-backend",
                    ),
                    compact=True,
                    id="channel-selector",
                ),
            ),
            actions=DialogActions(
                Button("Continue", id="continue", variant="primary"),
                Button("Cancel", id="cancel", variant="default"),
                id="footer-buttons",
            ),
            id="consent-container",
            size="large",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "continue":
            self._do_continue()
        elif event.button.id == "cancel":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _do_continue(self) -> None:
        """Assemble a BugReportConsent from current widget state and dismiss."""
        include_logs = self.query_one("#chk-include-logs", Checkbox).value
        include_config = self.query_one("#chk-include-config", Checkbox).value
        include_telemetry = self.query_one("#chk-include-telemetry", Checkbox).value

        radio_set = self.query_one("#channel-selector", RadioSet)
        # RadioSet.pressed_index gives the 0-based index of the selected button.
        channel: str
        if radio_set.pressed_index == 1:
            channel = "backend"
        else:
            channel = "github"

        consent = BugReportConsent(
            include_logs=include_logs,
            include_config=include_config,
            include_anonymous_telemetry=include_telemetry,
            channel=channel,  # type: ignore[arg-type]
        )
        self.dismiss(consent)
