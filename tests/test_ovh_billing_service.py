"""Tests for OVHBillingService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_billing_service import OVHBillingService
from servonaut.services.ovh_service import OVHService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_ovh_client():
    return MagicMock()


@pytest.fixture
def ovh_service(mock_ovh_client):
    """OVHService with a pre-injected mock client."""
    cfg = OVHConfig(
        enabled=True,
        endpoint="ovh-eu",
        application_key="APP_KEY",
        application_secret="APP_SECRET",
        consumer_key="CONSUMER_KEY",
    )
    svc = OVHService(cfg)
    svc._client = mock_ovh_client
    return svc


@pytest.fixture
def billing_service(ovh_service):
    return OVHBillingService(ovh_service)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_stores_ovh_service_reference(self, ovh_service):
        billing = OVHBillingService(ovh_service)
        assert billing._ovh_service is ovh_service


# ---------------------------------------------------------------------------
# get_current_usage
# ---------------------------------------------------------------------------

class TestGetCurrentUsage:

    def test_returns_usage_and_forecast(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = lambda path: {
            "/me/consumption/usage/current": {"total": {"currencyCode": "EUR", "value": 42.50}},
            "/me/consumption/usage/forecast": {"total": {"currencyCode": "EUR", "value": 85.00}},
        }[path]

        result = asyncio.run(billing_service.get_current_usage())

        assert result["provider"] == "ovh"
        assert result["current_spend"]["total"]["value"] == 42.50
        assert result["forecast"]["total"]["value"] == 85.00

    def test_usage_api_error_returns_empty_dict(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(billing_service.get_current_usage())

        assert result["provider"] == "ovh"
        assert result["current_spend"] == {}
        assert result["forecast"] == {}

    def test_only_forecast_fails_returns_partial_result(self, billing_service, mock_ovh_client):
        call_count = [0]

        def side_effect(path):
            call_count[0] += 1
            if path == "/me/consumption/usage/current":
                return {"total": {"value": 10.0}}
            raise Exception("forecast unavailable")

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_current_usage())

        assert result["provider"] == "ovh"
        assert result["current_spend"]["total"]["value"] == 10.0
        assert result["forecast"] == {}

    def test_only_current_fails_returns_partial_result(self, billing_service, mock_ovh_client):
        def side_effect(path):
            if path == "/me/consumption/usage/current":
                raise Exception("current unavailable")
            return {"total": {"value": 50.0}}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_current_usage())

        assert result["provider"] == "ovh"
        assert result["current_spend"] == {}
        assert result["forecast"]["total"]["value"] == 50.0

    def test_response_structure(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        result = asyncio.run(billing_service.get_current_usage())

        assert "provider" in result
        assert "current_spend" in result
        assert "forecast" in result


# ---------------------------------------------------------------------------
# get_cloud_usage
# ---------------------------------------------------------------------------

class TestGetCloudUsage:

    def test_returns_structured_usage(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "hourlyUsage": {
                "instance": [{"reference": "b2-7", "quantity": 3, "totalPrice": 0.09}],
                "storage": [{"type": "pca", "quantity": 100}],
            },
            "monthlyUsage": {
                "instance": [{"reference": "b2-15", "quantity": 1, "totalPrice": 15.00}],
            },
        }

        result = asyncio.run(billing_service.get_cloud_usage("proj-123"))

        assert result["provider"] == "ovh-cloud"
        assert result["project_id"] == "proj-123"
        assert len(result["hourly_instances"]) == 1
        assert result["hourly_instances"][0]["reference"] == "b2-7"
        assert len(result["monthly_instances"]) == 1
        assert result["monthly_instances"][0]["reference"] == "b2-15"
        assert len(result["storage"]) == 1

    def test_api_error_returns_empty_usage(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("project not found")

        result = asyncio.run(billing_service.get_cloud_usage("proj-bad"))

        assert result["provider"] == "ovh-cloud"
        assert result["project_id"] == "proj-bad"
        assert result["hourly_instances"] == []
        assert result["monthly_instances"] == []
        assert result["storage"] == []

    def test_missing_hourly_section_returns_empty_lists(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {"monthlyUsage": {"instance": [{"ref": "b2-7"}]}}

        result = asyncio.run(billing_service.get_cloud_usage("proj-123"))

        assert result["hourly_instances"] == []
        assert len(result["monthly_instances"]) == 1

    def test_missing_monthly_section_returns_empty_lists(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "hourlyUsage": {"instance": [{"ref": "b2-7"}], "storage": []},
        }

        result = asyncio.run(billing_service.get_cloud_usage("proj-123"))

        assert result["monthly_instances"] == []
        assert len(result["hourly_instances"]) == 1

    def test_project_id_forwarded_correctly(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(billing_service.get_cloud_usage("my-special-project"))

        mock_ovh_client.get.assert_called_once_with(
            "/cloud/project/my-special-project/usage/current"
        )

    def test_response_structure_keys_always_present(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        result = asyncio.run(billing_service.get_cloud_usage("proj-x"))

        for key in ("provider", "project_id", "hourly_instances", "monthly_instances", "storage"):
            assert key in result


# ---------------------------------------------------------------------------
# get_invoices
# ---------------------------------------------------------------------------

class TestGetInvoices:

    def test_returns_invoice_details(self, billing_service, mock_ovh_client):
        bill_ids = ["BILL-001", "BILL-002", "BILL-003"]
        bill_details = {
            "BILL-001": {"billId": "BILL-001", "amount": {"value": 100.0}},
            "BILL-002": {"billId": "BILL-002", "amount": {"value": 75.5}},
            "BILL-003": {"billId": "BILL-003", "amount": {"value": 42.0}},
        }

        def side_effect(path):
            if path == "/me/bill":
                return bill_ids
            for bill_id, detail in bill_details.items():
                if path == f"/me/bill/{bill_id}":
                    return detail
            return {}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_invoices())

        assert len(result) == 3
        ids_returned = [inv["billId"] for inv in result]
        assert "BILL-001" in ids_returned

    def test_respects_limit_parameter(self, billing_service, mock_ovh_client):
        bill_ids = [f"BILL-{i:03d}" for i in range(20)]

        def side_effect(path):
            if path == "/me/bill":
                return bill_ids
            return {"billId": path.split("/")[-1]}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_invoices(limit=5))

        assert len(result) == 5

    def test_empty_bill_list_returns_empty(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(billing_service.get_invoices())

        assert result == []

    def test_api_error_listing_bills_returns_empty(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(billing_service.get_invoices())

        assert result == []

    def test_individual_bill_fetch_error_skipped(self, billing_service, mock_ovh_client):
        def side_effect(path):
            if path == "/me/bill":
                return ["BILL-OK", "BILL-FAIL"]
            if path == "/me/bill/BILL-OK":
                return {"billId": "BILL-OK"}
            if path == "/me/bill/BILL-FAIL":
                raise Exception("bill fetch failed")
            return {}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_invoices())

        assert len(result) == 1
        assert result[0]["billId"] == "BILL-OK"

    def test_default_limit_is_10(self, billing_service, mock_ovh_client):
        bill_ids = [f"BILL-{i:03d}" for i in range(50)]

        def side_effect(path):
            if path == "/me/bill":
                return bill_ids
            return {"billId": path.split("/")[-1]}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_invoices())

        assert len(result) == 10

    def test_limit_larger_than_available_invoices(self, billing_service, mock_ovh_client):
        bill_ids = ["BILL-001", "BILL-002"]

        def side_effect(path):
            if path == "/me/bill":
                return bill_ids
            return {"billId": path.split("/")[-1]}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_invoices(limit=100))

        assert len(result) == 2


# ---------------------------------------------------------------------------
# get_service_list
# ---------------------------------------------------------------------------

class TestGetServiceList:

    def test_returns_service_details_for_each_id(self, billing_service, mock_ovh_client):
        def side_effect(path):
            if path == "/service":
                return ["svc-1", "svc-2"]
            if path == "/service/svc-1":
                return {"serviceId": "svc-1", "type": "VPS"}
            if path == "/service/svc-2":
                return {"serviceId": "svc-2", "type": "Dedicated"}
            return {}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_service_list())

        assert len(result) == 2
        assert result[0]["serviceId"] == "svc-1"
        assert result[1]["type"] == "Dedicated"

    def test_empty_service_list_returns_empty(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(billing_service.get_service_list())

        assert result == []

    def test_api_error_listing_services_returns_empty(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(billing_service.get_service_list())

        assert result == []

    def test_individual_service_fetch_error_skipped(self, billing_service, mock_ovh_client):
        def side_effect(path):
            if path == "/service":
                return ["svc-ok", "svc-fail"]
            if path == "/service/svc-ok":
                return {"serviceId": "svc-ok"}
            raise Exception("not found")

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_service_list())

        assert len(result) == 1
        assert result[0]["serviceId"] == "svc-ok"


# ---------------------------------------------------------------------------
# get_service_details
# ---------------------------------------------------------------------------

class TestGetServiceDetails:

    def test_returns_service_data(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {"serviceId": "svc-123", "type": "VPS"}

        result = asyncio.run(billing_service.get_service_details("svc-123"))

        mock_ovh_client.get.assert_called_once_with("/service/svc-123")
        assert result["serviceId"] == "svc-123"

    def test_api_error_returns_empty_dict(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("not found")

        result = asyncio.run(billing_service.get_service_details("svc-bad"))

        assert result == {}

    def test_empty_service_id_raises_value_error(self, billing_service, mock_ovh_client):
        with pytest.raises(ValueError):
            asyncio.run(billing_service.get_service_details(""))


# ---------------------------------------------------------------------------
# get_invoice_details
# ---------------------------------------------------------------------------

class TestGetInvoiceDetails:

    def test_merges_bill_and_line_items(self, billing_service, mock_ovh_client):
        def side_effect(path):
            if path == "/me/bill/BILL-001":
                return {"billId": "BILL-001", "amount": {"value": 99.0}}
            if path == "/me/bill/BILL-001/details":
                return ["DETAIL-A", "DETAIL-B"]
            if path == "/me/bill/BILL-001/details/DETAIL-A":
                return {"detailId": "DETAIL-A", "description": "VPS Monthly"}
            if path == "/me/bill/BILL-001/details/DETAIL-B":
                return {"detailId": "DETAIL-B", "description": "Bandwidth"}
            return {}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_invoice_details("BILL-001"))

        assert result["billId"] == "BILL-001"
        assert "line_items" in result
        assert len(result["line_items"]) == 2
        assert result["line_items"][0]["detailId"] == "DETAIL-A"

    def test_bill_fetch_error_returns_empty_dict(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("not found")

        result = asyncio.run(billing_service.get_invoice_details("BILL-MISSING"))

        assert result == {}

    def test_details_list_error_returns_bill_with_empty_line_items(
        self, billing_service, mock_ovh_client
    ):
        call_count = [0]

        def side_effect(path):
            call_count[0] += 1
            if path == "/me/bill/BILL-001":
                return {"billId": "BILL-001"}
            raise Exception("details unavailable")

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_invoice_details("BILL-001"))

        assert result["billId"] == "BILL-001"
        assert result["line_items"] == []

    def test_individual_line_item_error_skipped(self, billing_service, mock_ovh_client):
        def side_effect(path):
            if path == "/me/bill/BILL-001":
                return {"billId": "BILL-001"}
            if path == "/me/bill/BILL-001/details":
                return ["DETAIL-OK", "DETAIL-FAIL"]
            if path == "/me/bill/BILL-001/details/DETAIL-OK":
                return {"detailId": "DETAIL-OK"}
            raise Exception("detail fetch failed")

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_invoice_details("BILL-001"))

        assert len(result["line_items"]) == 1
        assert result["line_items"][0]["detailId"] == "DETAIL-OK"

    def test_empty_bill_id_raises_value_error(self, billing_service, mock_ovh_client):
        with pytest.raises(ValueError):
            asyncio.run(billing_service.get_invoice_details(""))


# ---------------------------------------------------------------------------
# get_invoice_pdf_url
# ---------------------------------------------------------------------------

class TestGetInvoicePdfUrl:

    def test_returns_url_string_directly(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = "https://example.com/invoice.pdf"

        result = asyncio.run(billing_service.get_invoice_pdf_url("BILL-001"))

        mock_ovh_client.get.assert_called_once_with("/me/bill/BILL-001/download")
        assert result == "https://example.com/invoice.pdf"

    def test_returns_url_from_dict_response(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {"url": "https://example.com/invoice.pdf"}

        result = asyncio.run(billing_service.get_invoice_pdf_url("BILL-001"))

        assert result == "https://example.com/invoice.pdf"

    def test_api_error_returns_empty_string(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(billing_service.get_invoice_pdf_url("BILL-001"))

        assert result == ""

    def test_empty_bill_id_raises_value_error(self, billing_service, mock_ovh_client):
        with pytest.raises(ValueError):
            asyncio.run(billing_service.get_invoice_pdf_url(""))

    def test_unexpected_response_type_returns_empty_string(
        self, billing_service, mock_ovh_client
    ):
        mock_ovh_client.get.return_value = 42  # unexpected type

        result = asyncio.run(billing_service.get_invoice_pdf_url("BILL-001"))

        assert result == ""


# ---------------------------------------------------------------------------
# get_monthly_spend_history
# ---------------------------------------------------------------------------

class TestGetMonthlySpendHistory:

    def _make_invoice(self, date: str, value: float, currency: str = "EUR") -> dict:
        return {
            "billId": f"BILL-{date}",
            "date": date,
            "priceWithTax": {"value": value, "currencyCode": currency},
            "status": "PAID",
        }

    def test_aggregates_invoices_by_month(self, billing_service, mock_ovh_client):
        invoices = [
            self._make_invoice("2026-03-15", 30.0),
            self._make_invoice("2026-03-28", 12.5),
            self._make_invoice("2026-02-10", 45.0),
        ]

        def side_effect(path):
            if path == "/me/bill":
                return [inv["billId"] for inv in invoices]
            for inv in invoices:
                if path == f"/me/bill/{inv['billId']}":
                    return inv
            return {}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_monthly_spend_history(months=6))

        months_map = {r["month"]: r for r in result}
        assert "2026-03" in months_map
        assert abs(months_map["2026-03"]["total"] - 42.5) < 0.01
        assert "2026-02" in months_map
        assert abs(months_map["2026-02"]["total"] - 45.0) < 0.01

    def test_returns_at_most_requested_months(self, billing_service, mock_ovh_client):
        invoices = [
            self._make_invoice(f"2026-0{m}-01", float(m * 10))
            for m in range(1, 7)
        ]

        def side_effect(path):
            if path == "/me/bill":
                return [inv["billId"] for inv in invoices]
            for inv in invoices:
                if path == f"/me/bill/{inv['billId']}":
                    return inv
            return {}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_monthly_spend_history(months=3))

        assert len(result) <= 3

    def test_empty_invoices_returns_empty_list(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(billing_service.get_monthly_spend_history())

        assert result == []

    def test_invalid_date_invoices_skipped(self, billing_service, mock_ovh_client):
        invoices = [
            {"billId": "BILL-BAD", "date": "not-a-date", "priceWithTax": {"value": 10.0}},
            self._make_invoice("2026-03-01", 20.0),
        ]

        def side_effect(path):
            if path == "/me/bill":
                return ["BILL-BAD", "BILL-2026-03-01"]
            for inv in invoices:
                if path == f"/me/bill/{inv['billId']}":
                    return inv
            return {}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_monthly_spend_history(months=6))

        months = [r["month"] for r in result]
        assert "2026-03" in months
        assert len([r for r in result if r["month"] == "2026-03"]) == 1

    def test_months_less_than_one_raises_value_error(self, billing_service, mock_ovh_client):
        with pytest.raises(ValueError):
            asyncio.run(billing_service.get_monthly_spend_history(months=0))

    def test_result_ordered_oldest_first(self, billing_service, mock_ovh_client):
        invoices = [
            self._make_invoice("2026-03-01", 30.0),
            self._make_invoice("2026-01-01", 10.0),
            self._make_invoice("2026-02-01", 20.0),
        ]

        def side_effect(path):
            if path == "/me/bill":
                return [inv["billId"] for inv in invoices]
            for inv in invoices:
                if path == f"/me/bill/{inv['billId']}":
                    return inv
            return {}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(billing_service.get_monthly_spend_history(months=6))

        assert result[0]["month"] < result[-1]["month"]


# ---------------------------------------------------------------------------
# get_cloud_cost_forecast
# ---------------------------------------------------------------------------

class TestGetCloudCostForecast:

    def test_returns_forecast_data(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "forecastedSpend": {"value": 55.0, "currencyCode": "EUR"}
        }

        result = asyncio.run(billing_service.get_cloud_cost_forecast("proj-123"))

        mock_ovh_client.get.assert_called_once_with("/cloud/project/proj-123/forecast")
        assert result["forecastedSpend"]["value"] == 55.0

    def test_api_error_returns_empty_dict(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("project not found")

        result = asyncio.run(billing_service.get_cloud_cost_forecast("proj-bad"))

        assert result == {}

    def test_empty_project_id_raises_value_error(self, billing_service, mock_ovh_client):
        with pytest.raises(ValueError):
            asyncio.run(billing_service.get_cloud_cost_forecast(""))

    def test_project_id_forwarded_correctly(self, billing_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(billing_service.get_cloud_cost_forecast("my-cloud-proj"))

        mock_ovh_client.get.assert_called_once_with(
            "/cloud/project/my-cloud-proj/forecast"
        )
