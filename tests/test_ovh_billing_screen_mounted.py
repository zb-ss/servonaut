"""The billing screen, mounted, reaches a final state on every card."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from rich.text import Text

from servonaut.screens.ovh_billing import OVHBillingScreen
from servonaut.styles import CSS_FILES
from tests.test_cloud_screens_multi_account import (  # noqa: F401  (fixtures)
    Host, _wait_for, accounts, config,
)


def _price(value: float) -> dict:
    return {"serviceId": 1, "elements": [], "price": {"value": value, "currencyCode": "EUR"}}


def _bills() -> list[dict]:
    return [
        {"billId": "B2", "date": "2026-02-01", "priceWithTax": {"value": 7.0, "currencyCode": "EUR"}},
        {"billId": "B1", "date": "2026-01-01", "priceWithTax": {"value": 5.0, "currencyCode": "EUR"}},
    ]


async def _open(app) -> None:
    await app.push_screen(OVHBillingScreen())


def _text(app, selector: str) -> str:
    return str(app.screen.query_one(selector).render())


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_cards_show_the_real_list_shapes(size, accounts, config) -> None:
    app = Host(accounts, config)
    billing = accounts.bundles['ovh'].billing
    billing.get_current_usage = AsyncMock(return_value={
        "current_spend": [_price(10.0), _price(2.5)], "forecast": [_price(20.0)],
    })
    billing.get_invoices = AsyncMock(return_value=_bills())
    async with app.run_test(size=size) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: "12.50 EUR" in _text(app, "#current_usage"), "card")
        await _wait_for(pilot, lambda: "2026-02" in _text(app, "#spend_history"), "card")
        assert "20.00 EUR" in _text(app, "#current_usage")
        assert app.screen.query_one("#invoices_table").row_count == 2
        assert "Loading" not in _text(app, "#invoices_page_info")


@pytest.mark.asyncio
async def test_failed_bill_list_ends_history_and_invoices_with_a_short_error(accounts, config) -> None:
    app = Host(accounts, config)
    billing = accounts.bundles['ovh'].billing
    billing.get_current_usage = AsyncMock(return_value={
        "current_spend": [_price(3.0)], "forecast": [],
    })
    billing.get_invoices = AsyncMock(side_effect=RuntimeError("403 secret detail"))
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: "Could not load the monthly history" in _text(app, "#spend_history"), "card")
        await _wait_for(pilot, lambda: "Could not load the invoices" in _text(app, "#invoices_page_info"), "card")
        assert "secret" not in _text(app, "#spend_history")
        assert "3.00 EUR" in _text(app, "#current_usage")


class _StyledHost(Host):
    """The host with the real stylesheet, so the tables really paint."""

    CSS_PATH = CSS_FILES


def _painted(app) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["billId", "date", "status"])
async def test_invoice_cells_with_an_unmatched_closing_tag_paint_as_text(field, accounts, config) -> None:
    app = _StyledHost(accounts, config)
    billing = accounts.bundles["ovh"].billing
    bill = {"billId": "B1", "date": "2026-01-01", "status": "paid",
            "priceWithTax": {"value": 7.0, "currencyCode": "EUR"}}
    hostile = {"billId": "AB[/x]12", "date": "20[/x]6-01-01", "status": "pa[/x]id"}[field]
    bill[field] = hostile
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [_price(1.0)], "forecast": []})
    billing.get_invoices = AsyncMock(return_value=[bill])
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: app.screen.query_one("#invoices_table").row_count == 1, "table")
        for _ in range(5):
            await pilot.pause()
        assert app._exception is None and isinstance(app.screen, OVHBillingScreen)
        assert hostile[:10] in _painted(app)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["name", "type", "status", "expiration"])
async def test_service_cells_with_an_unmatched_closing_tag_paint_as_text(field, accounts, config) -> None:
    app = _StyledHost(accounts, config)
    billing = accounts.bundles["ovh"].billing
    service = {"name": "web-1.example.net", "type": "domain", "status": "ok",
               "expiration": "2027-01-01", "auto_renew": True}
    hostile = {"name": "web[/x]-1", "type": "dom[/x]ain", "status": "o[/x]k",
               "expiration": "20[/x]7-01"}[field]
    service[field] = hostile
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [_price(1.0)], "forecast": []})
    billing.get_invoices = AsyncMock(return_value=_bills())
    billing.get_service_list = AsyncMock(return_value=[service])
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: app.screen.query_one("#services_table").row_count == 1, "table")
        for _ in range(5):
            await pilot.pause()
        assert app._exception is None and isinstance(app.screen, OVHBillingScreen)
        # The table sits below the fold at this size: check the cell itself.
        cells = app.screen.query_one("#services_table").get_row_at(0)
        assert all(isinstance(c, Text) for c in cells[:4]), cells
        assert hostile in [c.plain for c in cells]


@pytest.mark.asyncio
async def test_selecting_an_invoice_names_it_as_typed(accounts, config) -> None:
    app = _StyledHost(accounts, config)
    billing = accounts.bundles["ovh"].billing
    bill = {"billId": "AB[bold]12", "date": "2026-01-01",
            "priceWithTax": {"value": 7.0, "currencyCode": "EUR"}}
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [_price(1.0)], "forecast": []})
    billing.get_invoices = AsyncMock(return_value=[bill])
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: app.screen.query_one("#invoices_table").row_count == 1, "table")
        table = app.screen.query_one("#invoices_table")
        seen = []
        app.notify = lambda message, **kwargs: seen.append((message, kwargs))
        app.screen.on_data_table_row_selected(
            SimpleNamespace(data_table=table, row_key=table.coordinate_to_cell_key((0, 0)).row_key),
        )
        assert seen and seen[0][0] == "Invoice selected: AB[bold]12"
        assert seen[0][1].get("markup") is False


@pytest.mark.asyncio
@pytest.mark.parametrize("currency", ["EU[/x]", "EUR\\", "[bold]E", None, 7])
async def test_a_currency_code_that_is_not_a_code_never_reaches_the_cards(currency, accounts, config) -> None:
    app = _StyledHost(accounts, config)
    billing = accounts.bundles["ovh"].billing
    price = {"serviceId": 1, "elements": [], "price": {"value": 4.0, "currencyCode": currency}}
    bill = {"billId": "B1", "date": "2026-01-01", "priceWithTax": {"value": 7.0, "currencyCode": currency}}
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [price], "forecast": [price]})
    billing.get_invoices = AsyncMock(return_value=[bill])
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: "2026-01" in _text(app, "#spend_history"), "history")
        for _ in range(5):
            await pilot.pause()
        assert app._exception is None and isinstance(app.screen, OVHBillingScreen)
        for card in ("#current_usage", "#spend_history"):
            text = _text(app, card)
            assert "4.00" in text or "7.00" in text
            assert "[/x]" not in text and "[bold]" not in text and "\\" not in text


def _bill(value, month: str = "2026-03", billId: str = "B3") -> dict:
    return {"billId": billId, "date": f"{month}-01",
            "priceWithTax": {"value": value, "currencyCode": "EUR"}}


@pytest.mark.asyncio
@pytest.mark.parametrize("extra", [
    [{"billId": "B3", "date": "2026-03-01", "priceWithTax": {"value": "abc", "currencyCode": "EUR"}}],
    [{"billId": "B3", "date": "2026-03-01", "priceWithTax": "12 EUR"}],
    [_bill(float("nan"))],
    [_bill("nan")],
    [_bill(float("inf"))],
    [_bill("inf")],
    [_bill(float("-inf"))],
    [_bill(1e308, billId="B3"), _bill(1e308, billId="B4")],
], ids=["text", "text-with-unit", "nan", "nan-text", "inf", "inf-text", "-inf", "sum-overflow"])
async def test_a_bill_with_an_unreadable_amount_does_not_stop_the_screen(extra, accounts, config) -> None:
    app = _StyledHost(accounts, config)
    billing = accounts.bundles["ovh"].billing
    bills = _bills() + extra
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [_price(1.0)], "forecast": []})
    billing.get_invoices = AsyncMock(return_value=bills)
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: "2026-02" in _text(app, "#spend_history"), "history")
        for _ in range(5):
            await pilot.pause()
        assert app._exception is None and isinstance(app.screen, OVHBillingScreen)
        history = _text(app, "#spend_history")
        assert "7.00 EUR" in history and "2026-01" in history
        assert "could not be read and" in history
        # The bill list still shows every bill.
        assert app.screen.query_one("#invoices_table").row_count == len(bills)


@pytest.mark.asyncio
async def test_unreadable_bills_are_named_on_the_history_card(accounts, config) -> None:
    app = _StyledHost(accounts, config)
    billing = accounts.bundles["ovh"].billing
    bills = [_bill(5.0, "2026-01", "G1"), _bill("abc", "2026-01", "X1")]
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [_price(1.0)], "forecast": []})
    billing.get_invoices = AsyncMock(return_value=bills)
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: "2026-01" in _text(app, "#spend_history"), "history")
        history = _text(app, "#spend_history")
        assert "5.00 EUR" in history
        assert history.rstrip().endswith("1 bill could not be read and is not counted.")
        assert app.screen.query_one("#invoices_table").row_count == 2


@pytest.mark.asyncio
async def test_with_no_readable_bill_the_card_says_so_instead_of_no_history(accounts, config) -> None:
    app = _StyledHost(accounts, config)
    billing = accounts.bundles["ovh"].billing
    bills = [_bill("abc", "2026-01", "X1"), _bill(float("nan"), "2026-02", "X2")]
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [_price(1.0)], "forecast": []})
    billing.get_invoices = AsyncMock(return_value=bills)
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: "could not be read" in _text(app, "#spend_history"), "history")
        history = _text(app, "#spend_history")
        assert "2 bills could not be read and are not counted." in history
        assert "No history available" not in history
        assert app.screen.query_one("#invoices_table").row_count == 2


def test_a_negative_or_overflowing_total_keeps_the_bar_inside_its_width() -> None:
    from servonaut.screens.ovh_billing import _format_spend_history

    text = _format_spend_history([
        {"month": "2026-01", "total": -50.0, "currency": "EUR"},
        {"month": "2026-02", "total": 7.0, "currency": "EUR"},
        {"month": "2026-03", "total": float("inf"), "currency": "EUR"},
    ])
    assert all(len(line.split("[")[-1].rstrip("]")) <= 20 for line in text.splitlines()[2:])


@pytest.mark.asyncio
async def test_a_failure_while_filling_the_invoice_table_ends_every_loading_state(
    accounts, config, monkeypatch,
) -> None:
    def boom(self) -> None:
        raise RuntimeError("row builder failed")

    monkeypatch.setattr(OVHBillingScreen, "_render_invoice_page", boom)
    app = _StyledHost(accounts, config)
    billing = accounts.bundles["ovh"].billing
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [_price(1.0)], "forecast": []})
    billing.get_invoices = AsyncMock(return_value=_bills())
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: "Could not load the invoices" in _text(app, "#invoices_page_info"), "page line")
        assert "Could not load the monthly history" in _text(app, "#spend_history")
        assert "Loading" not in _text(app, "#invoices_page_info")
        assert app.screen.query_one("#btn_prev_page").disabled is True
        assert app.screen.query_one("#btn_next_page").disabled is True
        assert app._exception is None and isinstance(app.screen, OVHBillingScreen)
