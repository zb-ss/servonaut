"""Bug report screen — collect diagnostics, preview, and submit.

A regular Screen (not modal) so the persistent Sidebar stays visible
during the multi-step flow: consent -> collect -> preview -> submit.

Flow:
  1. on_mount pushes BugReportConsentModal.
  2. Consent returned -> worker collects diagnostics via BugReportService.
  3. Preview rendered into the Static widget; Submit button enabled.
  4. User edits title/description, optionally refreshes preview.
  5. Submit worker calls service.submit(); on success shows receipt.
"""

from __future__ import annotations

import logging
import webbrowser
from typing import Optional

from rich.markup import escape as _esc
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static, TextArea

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens.bug_report_consent_modal import BugReportConsentModal
from servonaut.services.bug_report_service import (
    BugReportConsent,
    BugReportPayload,
    BugReportReceipt,
    BugReportSubmissionError,
)
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class BugReportScreen(Screen):
    """Multi-step screen for filing a bug report.

    Compose layout (beside the Sidebar):
      - Title header
      - Short-summary Input
      - Multi-line description TextArea
      - Diagnostics status row
      - Action buttons: Edit consent / Refresh preview / Submit
      - Scrollable preview area populated after consent + collect
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    DEFAULT_CSS = """
    BugReportScreen #main-layout {
        height: 1fr;
    }

    BugReportScreen #bug-report-content {
        padding: 1 2;
        height: 1fr;
    }

    BugReportScreen #bug-title-header {
        height: auto;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    BugReportScreen .field-label {
        height: auto;
        text-style: bold;
        color: $accent;
        margin-top: 1;
    }

    BugReportScreen .field-help {
        height: auto;
        color: $text-muted;
        margin-bottom: 1;
    }

    BugReportScreen #title {
        margin-bottom: 1;
    }

    BugReportScreen #description {
        height: 8;
        margin-bottom: 1;
    }

    BugReportScreen #submission-error {
        height: auto;
        color: $error;
        background: $error 10%;
        padding: 1;
        margin-bottom: 1;
        display: none;
    }

    BugReportScreen #submission-error.visible {
        display: block;
    }

    BugReportScreen #diagnostics-status {
        height: auto;
        color: $text-muted;
        margin-bottom: 1;
    }

    BugReportScreen #btn-row {
        height: auto;
        margin-bottom: 1;
    }

    BugReportScreen #btn-row Button {
        margin-right: 1;
    }

    BugReportScreen #redact-warning {
        height: auto;
        color: $warning;
        margin-bottom: 1;
        display: none;
    }

    BugReportScreen #redact-warning.visible {
        display: block;
    }

    BugReportScreen #preview-scroll {
        height: 1fr;
        border: round $primary 50%;
    }

    BugReportScreen #preview {
        height: auto;
        padding: 1;
    }

    BugReportScreen #receipt-row {
        height: auto;
        margin-top: 1;
        display: none;
    }

    BugReportScreen #receipt-row.visible {
        display: block;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._consent: Optional[BugReportConsent] = None
        self._payload: Optional[BugReportPayload] = None
        self._receipt: Optional[BugReportReceipt] = None

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Container(id="bug-report-content"):
                yield Static("[bold cyan]Report a bug[/bold cyan]", id="bug-title-header")
                yield Label("Title", classes="field-label")
                yield Static(
                    "One sentence describing the problem (5-200 chars).",
                    classes="field-help",
                )
                yield Input(
                    placeholder="e.g. Crash when scanning EC2 instances in eu-west-3",
                    id="title",
                )
                yield Label("Description", classes="field-label")
                yield Static(
                    "Steps to reproduce, what you expected, what actually happened. "
                    "The command you ran helps. Logs and stack traces are auto-attached "
                    "in the preview below — don't paste them here.",
                    classes="field-help",
                )
                yield TextArea(
                    "",
                    id="description",
                )
                yield Static(
                    "Diagnostics: not collected yet",
                    id="diagnostics-status",
                )
                with Horizontal(id="btn-row"):
                    yield Button("Edit consent", id="edit-consent", variant="default")
                    yield Button("Refresh preview", id="refresh-preview", variant="default")
                    yield Button(
                        "Submit",
                        id="submit",
                        variant="primary",
                        disabled=True,
                    )
                yield Static("", id="submission-error")
                yield Static("", id="redact-warning")
                yield Static("", id="receipt-row")
                with VerticalScroll(id="preview-scroll"):
                    yield Static("", id="preview", markup=False)
        yield Footer()

    # ------------------------------------------------------------------
    # Mount — immediately push consent modal
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self.app.push_screen(
            BugReportConsentModal(),
            callback=self._on_consent_returned,
        )

    # ------------------------------------------------------------------
    # Consent callback
    # ------------------------------------------------------------------

    def _on_consent_returned(self, consent: Optional[BugReportConsent]) -> None:
        if consent is None:
            self.app.notify("Bug report cancelled", markup=False)
            self.app.pop_screen()
            return
        self._consent = consent
        self._start_collect()

    # ------------------------------------------------------------------
    # Diagnostics collection
    # ------------------------------------------------------------------

    def _start_collect(self) -> None:
        status = self.query_one("#diagnostics-status", Static)
        status.update("Diagnostics: collecting...")
        self.run_worker(
            self._do_collect(),
            group="bug_report",
            name="collect_diagnostics",
        )

    async def _do_collect(self) -> None:
        service = getattr(self.app, "bug_report_service", None)
        status = self.query_one("#diagnostics-status", Static)
        if service is None:
            status.update("[red]Bug report service not available.[/red]")
            return
        try:
            instances = getattr(self.app, "instances", [])
            payload = service.collect_diagnostics(
                consent=self._consent,
                instances=instances,
            )
            self._payload = payload

            # Warn about redacted categories
            redact_warning = self.query_one("#redact-warning", Static)
            if payload.redacted_categories_found:
                cats = ", ".join(payload.redacted_categories_found)
                redact_warning.update(
                    f"WARNING: Detected and redacted: {cats} — "
                    "review preview to confirm before submitting."
                )
                redact_warning.add_class("visible")
            else:
                redact_warning.remove_class("visible")

            status.update("Diagnostics: collected — review the preview below.")
            self._refresh_preview()
            submit_btn = self.query_one("#submit", Button)
            submit_btn.disabled = False
        except Exception as exc:
            logger.error("Failed to collect diagnostics: %s", exc)
            status.update(f"[red]Collection failed: {_esc(str(exc))}[/red]")

    # ------------------------------------------------------------------
    # Preview rendering
    # ------------------------------------------------------------------

    def _refresh_preview(self) -> None:
        """Re-render preview from current title/description without re-collecting."""
        service = getattr(self.app, "bug_report_service", None)
        if service is None or self._payload is None:
            return
        title = self.query_one("#title", Input).value
        description = self.query_one("#description", TextArea).text
        try:
            markdown = service.render_preview(
                payload=self._payload,
                title=title,
                description=description,
            )
            preview = self.query_one("#preview", Static)
            preview.update(markdown)
        except Exception as exc:
            logger.error("Failed to render preview: %s", exc)
            self.app.notify(
                f"Preview render failed: {exc}",
                severity="warning",
                markup=False,
            )

    # ------------------------------------------------------------------
    # Submit
    # ------------------------------------------------------------------

    async def _do_submit(self) -> None:
        service = getattr(self.app, "bug_report_service", None)
        if service is None:
            self.app.notify("Bug report service not available.", severity="error", markup=False)
            return

        title = self.query_one("#title", Input).value.strip()
        if not title:
            self.app.notify("Title is required", severity="warning", markup=False)
            return

        description = self.query_one("#description", TextArea).text

        status = self.query_one("#diagnostics-status", Static)
        status.update("Submitting...")
        self._clear_submission_error()

        # Disable submit to prevent double-clicks
        submit_btn = self.query_one("#submit", Button)
        submit_btn.disabled = True

        try:
            receipt = await service.submit(
                payload=self._payload,
                consent=self._consent,
                title=title,
                description=description,
            )
            self._receipt = receipt
            self._show_receipt(receipt)
        except BugReportSubmissionError as exc:
            logger.error("Bug report submission error: %s", exc)
            status.update("Diagnostics: collected — submission failed, try again.")
            submit_btn.disabled = False
            self._show_submission_error(str(exc))
        except Exception as exc:
            logger.error("Unexpected submission error: %s", exc)
            status.update("Diagnostics: collected — submission failed, try again.")
            submit_btn.disabled = False
            self._show_submission_error(f"Submission failed: {exc}")

    def _show_submission_error(self, message: str) -> None:
        """Pin the error message inline AND surface a toast.

        The toast fades; the inline panel stays so the user can read /
        copy the reason after they look back at the screen.
        """
        try:
            err = self.query_one("#submission-error", Static)
            err.update(_esc(message))
            err.add_class("visible")
        except Exception:  # pragma: no cover — defensive query
            pass
        self.app.notify(message, severity="error", markup=False, timeout=10)

    def _clear_submission_error(self) -> None:
        try:
            err = self.query_one("#submission-error", Static)
            err.remove_class("visible")
            err.update("")
        except Exception:
            pass

    def _show_receipt(self, receipt: BugReportReceipt) -> None:
        """Swap buttons area to success state and open URL if applicable."""
        status = self.query_one("#diagnostics-status", Static)
        status.update("[green]Bug report submitted.[/green]")

        btn_row = self.query_one("#btn-row", Horizontal)
        btn_row.remove()

        receipt_row = self.query_one("#receipt-row", Static)
        receipt_row.add_class("visible")

        if receipt.channel == "github":
            receipt_row.update(
                f"Opened GitHub issue draft in your browser — "
                f"review and click Submit.\n"
                f"URL: {receipt.url}"
            )
            webbrowser.open(receipt.url)
            self.app.notify(
                "Opened GitHub issue draft in your browser — review and click Submit.",
                markup=False,
            )
        else:
            receipt_row.update(
                f"Submitted as report {receipt.report_id} — {receipt.url}"
            )
            self.app.notify(
                f"Submitted as report {receipt.report_id} — {receipt.url}",
                markup=False,
            )

        # Mount a Back button below the receipt row
        self.query_one("#bug-report-content", Container).mount(
            Button("Back", id="back", variant="default")
        )

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "edit-consent":
            self.app.push_screen(
                BugReportConsentModal(),
                callback=self._on_re_consent,
            )
        elif event.button.id == "refresh-preview":
            self._refresh_preview()
        elif event.button.id == "submit":
            self.run_worker(
                self._do_submit(),
                group="bug_report",
                name="submit_bug_report",
            )
        elif event.button.id == "back":
            self.app.pop_screen()

    def _on_re_consent(self, consent: Optional[BugReportConsent]) -> None:
        """Handle consent returned from the re-open modal."""
        if consent is None:
            # User cancelled re-consent; keep existing consent.
            return
        self._consent = consent
        self._payload = None
        # Disable submit until new diagnostics are collected.
        try:
            submit_btn = self.query_one("#submit", Button)
            submit_btn.disabled = True
        except Exception:
            pass
        self._start_collect()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()
