"""Long pinned report messages retain native access to retry and Back."""

from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.reactive import reactive
from textual.widgets import Button, Input, Static

from servonaut.screens.bug_report import BugReportScreen
from servonaut.screens.bug_report_consent_modal import BugReportConsentModal
from servonaut.services.bug_report_service import (
    BugReportReceipt,
    BugReportService,
    BugReportSubmissionError,
)
from tests._async_bounds import wait_until
from tests._native_actions import click_action
from tests.test_basic_dialogs import BasicDialogHost
from tests.test_consent_dialogs import fake_payload


class _ReportHost(BasicDialogHost):
    """Keep the real navigation rail and its reactive discovery surface."""

    vault_available = reactive(False)
    relay_state = reactive(None)


@pytest.mark.asyncio
async def test_long_failure_and_receipt_keep_retry_and_back_reachable():
    error = "\n".join(f"Diagnostic detail {index}: report service unavailable" for index in range(30))
    receipt = BugReportReceipt(
        channel="backend",
        url="https://example.invalid/" + "report-reference/" * 100,
        submitted_at_iso="2026-01-01T00:00:00Z",
        report_id="example-report",
    )
    service = MagicMock(spec=BugReportService)
    payload = replace(
        fake_payload(),
        redacted_categories_found=["example-category-" + "detail/" * 25],
    )
    service.collect_diagnostics.return_value = payload
    service.render_preview.return_value = "Example diagnostic preview"
    service.submit = AsyncMock(side_effect=[BugReportSubmissionError(error), receipt])
    app = _ReportHost()
    app.bug_report_service = service
    report = BugReportScreen()

    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(report)
        await wait_until(lambda: isinstance(app.screen, BugReportConsentModal))
        await pilot.pause()
        assert await pilot.click("#radio-backend")
        await click_action(pilot, "#continue")
        await wait_until(lambda: app.screen is report and report._payload is not None)
        report.query_one("#title", Input).value = "Example report title"

        await click_action(pilot, "#submit")
        await wait_until(lambda: report.query_one("#submission-error").has_class("visible"))
        # The pinned failure must remain useful after its temporary toast goes.
        app.clear_notifications()
        await pilot.pause()
        assert error in str(report.query_one("#submission-error", Static).render())
        for selector in ("#edit-consent", "#refresh-preview", "#submit"):
            button = report.query_one(selector, Button)
            assert isinstance(button, Button)
            rendered_label = " ".join(
                button.render_line(row).text.strip()
                for row in range(button.size.height)
            )
            assert str(button.label) in " ".join(rendered_label.split())

        await click_action(pilot, "#submit")
        await wait_until(lambda: bool(report.query("#back")))
        app.clear_notifications()
        await pilot.pause()
        assert receipt.url in str(report.query_one("#receipt-row", Static).render())
        # Success ends editing and collection, including relocated review actions.
        for selector in ("#btn-row", "#edit-consent", "#refresh-preview", "#submit"):
            assert not report.query(selector), selector
        assert service.collect_diagnostics.call_count == 1
        await click_action(pilot, "#back")
        await wait_until(lambda: report not in app.screen_stack)
        assert service.submit.await_count == 2
