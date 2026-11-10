"""The billing screen, mounted, reaches a final state on every card."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from servonaut.screens.ovh_billing import OVHBillingScreen
from tests._async_bounds import wait_until
from tests.test_workspace_ovh_resources import _ResourceApp

pytestmark = pytest.mark.usefixtures("navigation_open")


def _price(value: float) -> dict:
    return {"serviceId": 1, "elements": [], "price": {"value": value, "currencyCode": "EUR"}}


def _bills() -> list[dict]:
    return [
        {"billId": "B2", "date": "2026-02-01", "priceWithTax": {"value": 7.0, "currencyCode": "EUR"}},
        {"billId": "B1", "date": "2026-01-01", "priceWithTax": {"value": 5.0, "currencyCode": "EUR"}},
    ]


def _text(app, selector: str) -> str:
    return str(app.screen.query_one(selector).render())


async def _open(app, pilot) -> None:
    await app.push_screen(OVHBillingScreen())
    await wait_until(lambda: isinstance(app.screen, OVHBillingScreen))


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_cards_show_the_real_list_shapes(size) -> None:
    app = _ResourceApp()
    billing = next(iter(app.bundles.values())).billing
    billing.get_current_usage = AsyncMock(return_value={
        "current_spend": [_price(10.0), _price(2.5)], "forecast": [_price(20.0)],
    })
    billing.get_invoices = AsyncMock(return_value=_bills())
    async with app.run_test(size=size) as pilot:
        await _open(app, pilot)
        await wait_until(lambda: "12.50 EUR" in _text(app, "#current_usage"))
        await wait_until(lambda: "2026-02" in _text(app, "#spend_history"))
        assert "20.00 EUR" in _text(app, "#current_usage")
        assert app.screen.query_one("#invoices_table").row_count == 2
        assert "Loading" not in _text(app, "#invoices_page_info")


@pytest.mark.asyncio
async def test_failed_bill_list_ends_history_and_invoices_with_a_short_error() -> None:
    app = _ResourceApp()
    billing = next(iter(app.bundles.values())).billing
    billing.get_current_usage = AsyncMock(return_value={
        "current_spend": [_price(3.0)], "forecast": [],
    })
    billing.get_invoices = AsyncMock(side_effect=RuntimeError("403 secret detail"))
    async with app.run_test(size=(160, 50)) as pilot:
        await _open(app, pilot)
        await wait_until(lambda: "Could not load the monthly history" in _text(app, "#spend_history"))
        await wait_until(lambda: "Could not load the invoices" in _text(app, "#invoices_page_info"))
        assert "secret" not in _text(app, "#spend_history")
        assert "3.00 EUR" in _text(app, "#current_usage")
