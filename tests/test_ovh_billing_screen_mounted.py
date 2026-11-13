"""The billing screen, mounted, reaches a final state on every card."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from servonaut.screens.ovh_billing import OVHBillingScreen
from servonaut.styles import CSS_FILES
from tests.test_cloud_screens_multi_account import (  # noqa: F401  (fixtures)
    Host, _wait_for, accounts, config,
)

# Navigation hides itself on narrow terminals; the 100x30 case keeps its
# layout expectations by holding the user's choice to show it.
pytestmark = pytest.mark.usefixtures("navigation_open")


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


def _bad_bill(**price) -> list[dict]:
    return [{"billId": "B1", "date": "2026-01-01", "priceWithTax": price}]


MALFORMED_BILLS = {
    "text value": _bad_bill(value="abc", currencyCode="EUR"),
    "null currency": _bad_bill(value=5.0, currencyCode=None),
    "missing value": _bad_bill(currencyCode="EUR"),
    "list for a dict": [{"billId": "B1", "date": "2026-01-01", "priceWithTax": [5.0, "EUR"]}],
    "bill that is not a mapping": ["B1"],
    "date that is not text": [{"billId": "B1", "date": 20260101, "priceWithTax": {"value": 1, "currencyCode": "EUR"}}],
}
MALFORMED_USAGE = {
    "text value": {"current_spend": [{"price": {"value": "abc", "currencyCode": "EUR"}}], "forecast": []},
    "null currency": {"current_spend": [{"price": {"value": 1.0, "currencyCode": None}}], "forecast": []},
    "list for a dict": {"current_spend": [{"price": [1.0]}], "forecast": []},
    "payload that is not a mapping": {"current_spend": "n/a", "forecast": 3},
}


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", list(MALFORMED_BILLS))
async def test_a_bill_the_parser_cannot_read_ends_on_the_card_and_the_app_keeps_running(
    shape, accounts, config,
) -> None:
    app = Host(accounts, config)
    billing = accounts.bundles["ovh"].billing
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [_price(1.0)], "forecast": []})
    billing.get_invoices = AsyncMock(return_value=MALFORMED_BILLS[shape])
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(
            pilot, lambda: "Loading" not in _text(app, "#invoices_page_info")
            and "Loading" not in _text(app, "#spend_history"), "card",
        )
        assert isinstance(app.screen, OVHBillingScreen) and app._exception is None
        history = _text(app, "#spend_history")
        assert "Traceback" not in history
        if "Could not read" in history:
            assert "Could not read the bill data" in _text(app, "#invoices_page_info")


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", ["text value", "list for a dict", "bill that is not a mapping"])
async def test_the_listed_unreadable_bills_say_so_on_the_cards(shape, accounts, config) -> None:
    app = Host(accounts, config)
    billing = accounts.bundles["ovh"].billing
    billing.get_current_usage = AsyncMock(return_value={"current_spend": [_price(1.0)], "forecast": []})
    billing.get_invoices = AsyncMock(return_value=MALFORMED_BILLS[shape])
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(
            pilot, lambda: "Could not read the bill data" in _text(app, "#invoices_page_info"), "card",
        )
        assert "Could not read the bill data" in _text(app, "#spend_history")
        assert app.screen.query_one("#invoices_table").row_count == 0
        assert isinstance(app.screen, OVHBillingScreen) and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", list(MALFORMED_USAGE))
async def test_unreadable_usage_ends_on_the_card_and_the_app_keeps_running(shape, accounts, config) -> None:
    app = Host(accounts, config)
    billing = accounts.bundles["ovh"].billing
    billing.get_current_usage = AsyncMock(return_value=MALFORMED_USAGE[shape])
    billing.get_invoices = AsyncMock(return_value=_bills())
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(pilot, lambda: "Loading" not in _text(app, "#current_usage"), "card")
        assert isinstance(app.screen, OVHBillingScreen) and app._exception is None


class _StyledHost(Host):
    """The host with the real stylesheet, so the table really paints."""

    CSS_PATH = CSS_FILES


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
        strips = app.screen._compositor.render_strips()
        painted = "\n".join(strip.text for strip in strips)
        assert hostile[:10] in painted, painted


# The usage payload itself can be a list or a string, not only a mapping.
@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [[{"price": {"value": 1}}], "unavailable"], ids=["list", "string"])
async def test_a_usage_payload_that_is_not_a_mapping_ends_on_the_card(payload, accounts, config) -> None:
    app = Host(accounts, config)
    billing = accounts.bundles["ovh"].billing
    billing.get_current_usage = AsyncMock(return_value=payload)
    billing.get_invoices = AsyncMock(return_value=_bills())
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app)
        await _wait_for(
            pilot, lambda: "Could not read the bill data for the current month" in _text(app, "#current_usage"),
            "card",
        )
        assert isinstance(app.screen, OVHBillingScreen) and app._exception is None
