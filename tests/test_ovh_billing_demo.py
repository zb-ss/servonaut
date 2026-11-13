"""Billing data must stay private throughout a demo, including pagination."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from textual.content import Content

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
    assert row[1].plain == ("invoice-016" if is_demo else "private-bill-15")
    assert row[2].plain == ("Hidden" if is_demo else "123.45")
    assert screen._all_invoices[15]["billId"] == "private-bill-15"
    assert widgets["#btn_next_page"].disabled is True
    assert widgets["#btn_prev_page"].disabled is False


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("method, service_method", [
    ("_load_current_usage", "get_current_usage"),
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
    plain = message.plain if isinstance(message, Content) else Content.from_markup(message).plain
    # The summary cards never repeat provider text; notifications do outside demo.
    hides = is_demo or method in ("_load_current_usage", "_load_invoices")
    assert ("private-bill-123" not in plain) is hides
    assert ("123.45" not in plain) is hides


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


def _card_screen(service):
    app = SimpleNamespace(demo_mode=False, ovh_billing_service=service)
    screen = OVHBillingScreen()
    widgets = {"#current_usage": MagicMock(), "#spend_history": MagicMock()}
    return screen, app, widgets


def _run(screen, app, widgets, method):
    with (
        patch.object(OVHBillingScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", side_effect=lambda sel, *_: widgets[sel]),
    ):
        asyncio.run(getattr(screen, method)())


@pytest.mark.parametrize("current", [
    {"price": {"value": 12.5, "currencyCode": "EUR"}},
    [{"price": {"value": 10.0, "currencyCode": "EUR"}}, {"price": {"value": 2.5, "currencyCode": "EUR"}}],
])
def test_current_month_card_shows_figure_for_list_and_dict(current) -> None:
    service = SimpleNamespace(get_current_usage=AsyncMock(return_value={
        "current_spend": current, "forecast": [],
    }))
    screen, app, widgets = _card_screen(service)
    _run(screen, app, widgets, "_load_current_usage")
    assert "12.50 EUR" in widgets["#current_usage"].update.call_args.args[0]


def test_failed_forecast_does_not_hide_current_figure() -> None:
    usage = {"current_spend": {"price": {"value": 5, "currencyCode": "EUR"}},
             "forecast": {}, "forecast_failed": True}
    text = _format_current_usage(usage)
    assert "5.00 EUR" in text
    assert "unavailable" in text


def _invoice_widgets():
    return {"#current_usage": MagicMock(), "#spend_history": MagicMock(),
            "#invoices_page_info": MagicMock(), "#invoices_table": MagicMock()}


def test_history_and_invoices_end_when_the_bill_call_fails() -> None:
    service = SimpleNamespace(get_invoices=AsyncMock(side_effect=RuntimeError("[bold]x[/] secret")))
    screen, app, _ = _card_screen(service)
    widgets = _invoice_widgets()
    _run(screen, app, widgets, "_load_invoices")
    for selector in ("#spend_history", "#invoices_page_info"):
        shown = widgets[selector].update.call_args.args[0]
        assert "Loading" not in shown.plain
        assert "secret" not in shown.plain
        assert "Could not load" in shown.plain


def test_invoice_loading_state_is_shown_then_replaced() -> None:
    service = SimpleNamespace(get_invoices=AsyncMock(return_value=[]))
    screen, app, _ = _card_screen(service)
    widgets = _invoice_widgets()
    with patch.object(screen, "_render_invoice_page"):
        _run(screen, app, widgets, "_load_invoices")
    assert widgets["#invoices_page_info"].update.call_args_list[0].args[0] == "[dim]Loading...[/dim]"


def test_invoices_end_on_timeout(monkeypatch) -> None:
    import servonaut.screens.ovh_billing as module

    async def never():
        await asyncio.sleep(60)

    monkeypatch.setattr(module, "_CARD_TIMEOUT_SECONDS", 0.05)
    screen, app, _ = _card_screen(SimpleNamespace(get_invoices=never))
    widgets = _invoice_widgets()
    _run(screen, app, widgets, "_load_invoices")
    assert "Could not load" in widgets["#spend_history"].update.call_args.args[0].plain
    assert "Could not load" in widgets["#invoices_page_info"].update.call_args.args[0].plain


def test_one_invoice_fetch_feeds_table_and_history() -> None:
    invoices = [{"billId": "B1", "date": "2026-03-02", "priceWithTax": {"value": 4.0, "currencyCode": "EUR"}}]
    service = SimpleNamespace(get_invoices=AsyncMock(return_value=invoices))
    screen, app, _ = _card_screen(service)
    widgets = _invoice_widgets()
    with patch.object(screen, "_render_invoice_page") as render:
        _run(screen, app, widgets, "_load_invoices")
    render.assert_called_once_with()
    assert "2026-03" in widgets["#spend_history"].update.call_args.args[0]
    service.get_invoices.assert_awaited_once()


def test_empty_invoices_show_an_empty_history_line() -> None:
    service = SimpleNamespace(get_invoices=AsyncMock(return_value=[]))
    screen, app, _ = _card_screen(service)
    widgets = _invoice_widgets()
    with patch.object(screen, "_render_invoice_page"):
        _run(screen, app, widgets, "_load_invoices")
    assert "No history" in widgets["#spend_history"].update.call_args.args[0]


def test_loaders_do_not_need_python_311_timeout_api(monkeypatch) -> None:
    """Python 3.10 has no asyncio.timeout; the loaders must not use it."""
    monkeypatch.delattr(asyncio, "timeout", raising=False)
    usage = {"current_spend": [{"price": {"value": 1, "currencyCode": "EUR"}}], "forecast": []}
    service = SimpleNamespace(
        get_current_usage=AsyncMock(return_value=usage),
        get_invoices=AsyncMock(return_value=[]),
    )
    screen, app, widgets = _card_screen(service)
    _run(screen, app, widgets, "_load_current_usage")
    assert "1.00 EUR" in widgets["#current_usage"].update.call_args.args[0]
    widgets = _invoice_widgets()
    with patch.object(screen, "_render_invoice_page"):
        _run(screen, app, widgets, "_load_invoices")
    assert "Could not load" not in str(widgets["#spend_history"].update.call_args.args[0])


def test_empty_usage_list_reads_as_zero_not_na() -> None:
    text = _format_current_usage({"current_spend": [], "forecast": []})
    assert "0.00" in text
    assert "n/a" not in text


def test_service_states_use_theme_tokens_not_named_colours() -> None:
    service = SimpleNamespace(get_service_list=AsyncMock(return_value=[
        {"name": "web-1", "type": "VPS", "status": "ok", "expiration": "2026-01-01", "auto_renew": True},
        {"name": "web-2", "type": "VPS", "status": "[x]odd", "expiration": "", "auto_renew": False},
    ]))
    table = MagicMock()
    screen = OVHBillingScreen()
    app = SimpleNamespace(demo_mode=False, ovh_billing_service=service)
    with (
        patch.object(OVHBillingScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", return_value=table),
    ):
        asyncio.run(screen._load_services())
    cells = [c for call in table.add_row.call_args_list for c in call.args]
    assert all(not isinstance(c, str) or "[" not in c for c in cells[1:] if c)
    assert any(isinstance(c, Content) and c.plain == "ok" for c in cells)
