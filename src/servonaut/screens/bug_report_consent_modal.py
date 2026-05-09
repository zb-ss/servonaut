"""Bug report consent modal for Servonaut.

Surfaces the privacy choices before any diagnostic data is collected.
The user selects which categories to include and where to send the
report.  A preview of the exact payload is shown on the next screen
(BugReportScreen) before anything leaves the machine.

Per CLAUDE.md ModalScreen rule: brief blocking choice — dismiss to
return.  BugReportScreen is the multi-step content-heavy counterpart
that carries the Sidebar.
"""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, RadioButton, RadioSet, Static

from servonaut.services.bug_report_service import BugReportConsent


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

    DEFAULT_CSS = """
    BugReportConsentModal {
        align: center middle;
    }

    BugReportConsentModal #consent-container {
        width: 88;
        height: auto;
        max-height: 44;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    BugReportConsentModal #consent-title {
        height: auto;
        text-style: bold;
        color: $accent;
        text-align: center;
        margin-bottom: 1;
    }

    BugReportConsentModal #consent-copy {
        height: auto;
        color: $text-muted;
        margin-bottom: 1;
    }

    BugReportConsentModal #checkboxes {
        height: auto;
        margin-bottom: 1;
    }

    BugReportConsentModal Checkbox {
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

    BugReportConsentModal #footer-buttons {
        height: auto;
        align-horizontal: center;
        margin-top: 1;
    }

    BugReportConsentModal Button {
        margin: 0 1;
        min-width: 14;
    }

    BugReportConsentModal #continue {
        background: $primary;
        color: $text;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="consent-container"):
            yield Static("Report a bug", id="consent-title")
            yield Static(
                "Choose what to include in your report. You'll see exactly what will be "
                "sent before anything leaves your machine.",
                id="consent-copy",
            )
            with Vertical(id="checkboxes"):
                yield Checkbox(
                    "Last 200 lines of ~/.servonaut/logs/servonaut.log (secrets are scrubbed)",
                    value=True,
                    id="chk-include-logs",
                )
                yield Checkbox(
                    "Configuration snapshot (api keys & secrets are removed)",
                    value=True,
                    id="chk-include-config",
                )
                yield Checkbox(
                    "Anonymous instance counts by provider (no names, no ids)",
                    value=True,
                    id="chk-include-telemetry",
                )
            yield Static("Send report via:", id="channel-label")
            with RadioSet(id="channel-selector"):
                yield RadioButton(
                    "Open prefilled GitHub issue (opens in browser)",
                    value=True,
                    id="radio-github",
                )
                yield RadioButton(
                    "Submit via Servonaut backend (you can be anonymous)",
                    id="radio-backend",
                )
            with Horizontal(id="footer-buttons"):
                yield Button("Continue", id="continue", variant="primary")
                yield Button("Cancel", id="cancel", variant="default")

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
