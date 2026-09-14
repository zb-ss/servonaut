"""Billing data must stay private throughout a demo, including pagination."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from rich.text import Text

from servonaut.screens.ovh_billing import (
    OVHBillingScreen,
    _format_current_usage,
    _format_spend_history,
)


@pytest.mark.parametrize("redact", [False, True])
def test_billing_totals_and_history_are_hidden_only_in_demo(redact: bool) -> None:
    usage = {
        "current_spend": {"total": {"value": 123.45, "currencyCode": "GBP"}},
        "forecast": {"total": {"value": 234.56, "currencyCode": "GBP"}},
    }
    history = [{"month": "2026-01", "total": 345.67, "currency": "GBP"}]
    current_text = _format_current_usage(usage, redact=redact)
    history_text = _format_spend_history(history, redact=redact)
    assert ("123.45" not in current_text) is redact
    assert ("234.56" not in current_text) is redact
    assert ("345.67" not in history_text) is redact
    assert ("#" not in history_text) is redact
    assert usage["current_spend"]["total"]["value"] == 123.45


@pytest.mark.parametrize("is_demo", [False, True])
def test_invoice_pagination_preserves_raw_data_but_shows_safe_ids(is_demo: bool) -> None:
    screen = OVHBillingScreen()
    screen._invoice_page = 1
    screen._all_invoices = [
        {"billId": f"private-bill-{i}", "priceWithTax": {"value": 123.45}}
        for i in range(16)
    ]
    widgets = {name: MagicMock() for name in (
        "#invoices_table", "#invoices_page_info", "#btn_prev_page", "#btn_next_page",
    )}
    with (
        patch.object(OVHBillingScreen, "app", new_callable=PropertyMock,
                     return_value=SimpleNamespace(demo_mode=is_demo)),
        patch.object(screen, "query_one", side_effect=lambda key, *args: widgets[key]),
    ):
        screen._render_invoice_page()
    row = widgets["#invoices_table"].add_row.call_args.args
    assert row[1] == ("invoice-016" if is_demo else "private-bill-15")
    assert row[2] == ("Hidden" if is_demo else "123.45")
    assert screen._all_invoices[15]["billId"] == "private-bill-15"
    assert widgets["#btn_next_page"].disabled is True
    assert widgets["#btn_prev_page"].disabled is False


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("method, service_method", [
    ("_load_current_usage", "get_current_usage"),
    ("_load_spend_history", "get_monthly_spend_history"),
    ("_load_invoices", "get_invoices"),
    ("_load_services", "get_service_list"),
])
def test_provider_errors_do_not_disclose_unknown_billing_details(
    is_demo: bool, method: str, service_method: str,
) -> None:
    error = RuntimeError("private-bill-123 [broken] 123.45")
    service = SimpleNamespace(**{service_method: AsyncMock(side_effect=error)})
    app = SimpleNamespace(demo_mode=is_demo, ovh_billing_service=service)
    screen = OVHBillingScreen()
    widget = MagicMock()
    with (
        patch.object(OVHBillingScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=widget),
        patch.object(screen, "notify") as notify,
    ):
        asyncio.run(getattr(screen, method)())
    message = (notify.call_args or widget.update.call_args).args[0]
    plain = Text.from_markup(message).plain
    assert ("private-bill-123" not in plain) is is_demo
    assert ("123.45" not in plain) is is_demo


def test_credential_error_is_safe_without_a_redaction_service() -> None:
    screen = OVHBillingScreen()
    widget = MagicMock()
    with (
        patch.object(OVHBillingScreen, "app", new_callable=PropertyMock,
                     return_value=SimpleNamespace(demo_mode=True, redaction_service=None)),
        patch.object(screen, "query_one", return_value=widget),
    ):
        screen._show_credential_error("unknown-account [broken]")
    assert "unknown-account" not in str(widget.update.call_args_list)


def test_demo_toggle_clears_visible_data_before_reloading() -> None:
    screen = OVHBillingScreen()
    widget = MagicMock()
    queued = []
    with (
        patch.object(screen, "query_one", return_value=widget),
        patch.object(screen, "_render_invoice_page") as render,
        patch.object(screen, "run_worker", side_effect=lambda coro, **kwargs: queued.append(coro)),
    ):
        screen.refresh_after_demo_toggle()
    render.assert_called_once_with()
    assert widget.update.call_count == 2
    widget.clear.assert_called_once_with()
    assert len(queued) == 1
    queued[0].close()
