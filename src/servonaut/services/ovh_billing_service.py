"""OVHcloud billing and usage service."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)


class OVHBillingService:
    """Service for querying OVHcloud billing, invoices, and usage data."""

    def __init__(self, ovh_service: 'OVHService') -> None:
        """Initialize OVH billing service.

        Args:
            ovh_service: An initialized OVHService instance whose client will be reused.
        """
        self._ovh_service = ovh_service

    async def get_current_usage(self) -> dict:
        """Fetch current billing usage and forecast.

        Returns:
            Dict with keys: provider, current_spend, forecast.
        """
        client = self._ovh_service.client
        try:
            usage = await asyncio.to_thread(
                client.get, "/me/consumption/usage/current"
            )
        except Exception as e:
            logger.error("Error fetching OVH current usage: %s", e)
            usage = {}

        try:
            forecast = await asyncio.to_thread(
                client.get, "/me/consumption/usage/forecast"
            )
        except Exception as e:
            logger.error("Error fetching OVH usage forecast: %s", e)
            forecast = {}

        return {
            'provider': 'ovh',
            'current_spend': usage,
            'forecast': forecast,
        }

    async def get_cloud_usage(self, project_id: str) -> dict:
        """Fetch current usage for a specific Public Cloud project.

        Args:
            project_id: OVH Public Cloud project identifier.

        Returns:
            Dict with keys: provider, project_id, hourly_instances,
            monthly_instances, storage.
        """
        client = self._ovh_service.client
        try:
            usage = await asyncio.to_thread(
                client.get, f"/cloud/project/{project_id}/usage/current"
            )
        except Exception as e:
            logger.error(
                "Error fetching OVH Cloud usage for project %s: %s",
                project_id, e
            )
            usage = {}

        hourly = usage.get('hourlyUsage') or {}
        monthly = usage.get('monthlyUsage') or {}

        return {
            'provider': 'ovh-cloud',
            'project_id': project_id,
            'hourly_instances': hourly.get('instance') or [],
            'monthly_instances': monthly.get('instance') or [],
            'storage': hourly.get('storage') or [],
        }

    async def get_invoices(self, limit: int = 0) -> List[dict]:
        """Fetch OVH invoices sorted by date descending (most recent first).

        Args:
            limit: Maximum number of invoices to return. 0 means all.

        Returns:
            List of invoice dicts, newest first.
        """
        client = self._ovh_service.client
        try:
            bill_ids = await asyncio.to_thread(client.get, "/me/bill")
        except Exception as e:
            logger.error("Error fetching OVH bill list: %s", e)
            return []

        if not bill_ids:
            return []

        # OVH returns IDs in ascending order; reverse to fetch newest first
        bill_ids = list(reversed(bill_ids))
        if limit > 0:
            bill_ids = bill_ids[:limit]

        invoices = []
        for bill_id in bill_ids:
            try:
                bill = await asyncio.to_thread(client.get, f"/me/bill/{bill_id}")
                invoices.append(bill)
            except Exception as e:
                logger.error("Error fetching OVH bill %s: %s", bill_id, e)

        # Sort by date descending for consistent ordering
        def _sort_key(inv: dict) -> str:
            return inv.get("date") or inv.get("billDate") or ""

        invoices.sort(key=_sort_key, reverse=True)
        return invoices

    async def get_service_list(self) -> List[dict]:
        """Fetch all services by querying per-type endpoints and their serviceInfos.

        Queries /vps, /dedicated/server, and /ip to discover services, then
        fetches ``/.../{name}/serviceInfos`` for renewal and billing data.

        Returns:
            List of normalised service dicts with keys: name, type, status,
            creation, expiration, auto_renew.
        """
        client = self._ovh_service.client
        services: List[dict] = []

        # (endpoint, type_label, info_path_template)
        sources = [
            ("/vps", "VPS", "/vps/{name}/serviceInfos"),
            ("/dedicated/server", "Dedicated", "/dedicated/server/{name}/serviceInfos"),
        ]

        for list_endpoint, type_label, info_tpl in sources:
            try:
                names = await asyncio.to_thread(client.get, list_endpoint)
            except Exception:
                continue
            if not names:
                continue
            for name in names:
                info_path = info_tpl.format(name=name)
                try:
                    info = await asyncio.to_thread(client.get, info_path)
                    renew = info.get("renew") or {}
                    services.append({
                        "name": info.get("domain") or name,
                        "type": type_label,
                        "status": info.get("status", ""),
                        "creation": str(info.get("creation") or ""),
                        "expiration": str(info.get("expiration") or ""),
                        "auto_renew": renew.get("automatic", False),
                    })
                except Exception as e:
                    logger.error("Error fetching serviceInfos for %s: %s", name, e)
                    services.append({
                        "name": name,
                        "type": type_label,
                        "status": "",
                        "creation": "",
                        "expiration": "",
                        "auto_renew": False,
                    })

        return services

    async def get_service_details(self, service_id: str) -> dict:
        """Fetch details for a single service.

        Args:
            service_id: OVH service identifier.

        Returns:
            Service detail dict or empty dict on error.
        """
        if not service_id:
            raise ValueError("service_id must not be empty")

        client = self._ovh_service.client
        try:
            return await asyncio.to_thread(client.get, f"/service/{service_id}")
        except Exception as e:
            logger.error("Error fetching OVH service details for %s: %s", service_id, e)
            return {}

    async def get_invoice_details(self, bill_id: str) -> dict:
        """Fetch a single invoice with its line items.

        Combines GET /me/bill/{billId} with GET /me/bill/{billId}/details.

        Args:
            bill_id: OVH bill identifier (e.g. ``"BILL-001"``).

        Returns:
            Invoice dict with an additional ``line_items`` key containing the
            detail records, or empty dict on error.
        """
        if not bill_id:
            raise ValueError("bill_id must not be empty")

        client = self._ovh_service.client
        try:
            bill = await asyncio.to_thread(client.get, f"/me/bill/{bill_id}")
        except Exception as e:
            logger.error("Error fetching OVH bill %s: %s", bill_id, e)
            return {}

        try:
            detail_ids: List[str] = await asyncio.to_thread(
                client.get, f"/me/bill/{bill_id}/details"
            )
        except Exception as e:
            logger.error("Error fetching OVH bill %s details list: %s", bill_id, e)
            detail_ids = []

        line_items: List[dict] = []
        for detail_id in (detail_ids or []):
            try:
                item = await asyncio.to_thread(
                    client.get, f"/me/bill/{bill_id}/details/{detail_id}"
                )
                line_items.append(item)
            except Exception as e:
                logger.error(
                    "Error fetching OVH bill %s detail %s: %s", bill_id, detail_id, e
                )

        bill["line_items"] = line_items
        return bill

    async def get_invoice_pdf_url(self, bill_id: str) -> str:
        """Fetch the download URL for an invoice PDF.

        Args:
            bill_id: OVH bill identifier.

        Returns:
            Download URL string, or empty string on error.
        """
        if not bill_id:
            raise ValueError("bill_id must not be empty")

        client = self._ovh_service.client
        try:
            result = await asyncio.to_thread(client.get, f"/me/bill/{bill_id}/download")
        except Exception as e:
            logger.error("Error fetching OVH bill %s download URL: %s", bill_id, e)
            return ""

        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            return result.get("url", "")
        return ""

    async def get_monthly_spend_history(self, months: int = 6) -> List[dict]:
        """Aggregate invoices into per-month spend totals.

        Args:
            months: Number of recent months to return (default 6).

        Returns:
            List of ``{month, total, currency}`` dicts ordered oldest-first,
            where ``month`` is an ISO year-month string (e.g. ``"2026-03"``).
        """
        if months < 1:
            raise ValueError("months must be at least 1")

        # Fetch a larger batch so we have enough history to cover *months* months.
        invoices = await self.get_invoices(limit=months * 5)

        monthly: dict[str, dict] = {}
        for inv in invoices:
            date_str: Optional[str] = inv.get("date") or inv.get("billDate") or ""
            amount_raw = inv.get("priceWithTax") or inv.get("amount") or {}
            if isinstance(amount_raw, dict):
                value: float = float(amount_raw.get("value", 0) or 0)
                currency: str = amount_raw.get("currencyCode", "")
            else:
                value = float(amount_raw or 0)
                currency = ""

            try:
                month_key = datetime.fromisoformat(date_str[:10]).strftime("%Y-%m")
            except (ValueError, TypeError, IndexError):
                continue

            if month_key not in monthly:
                monthly[month_key] = {"month": month_key, "total": 0.0, "currency": currency}
            monthly[month_key]["total"] = round(monthly[month_key]["total"] + value, 2)
            if not monthly[month_key]["currency"] and currency:
                monthly[month_key]["currency"] = currency

        sorted_months = sorted(monthly.values(), key=lambda x: x["month"])
        return sorted_months[-months:]

    async def get_cloud_cost_forecast(self, project_id: str) -> dict:
        """Fetch the projected end-of-month cost for a Public Cloud project.

        Args:
            project_id: OVH Public Cloud project identifier.

        Returns:
            Forecast dict from OVH or empty dict on error.
        """
        if not project_id:
            raise ValueError("project_id must not be empty")

        client = self._ovh_service.client
        try:
            return await asyncio.to_thread(
                client.get, f"/cloud/project/{project_id}/forecast"
            )
        except Exception as e:
            logger.error(
                "Error fetching OVH Cloud forecast for project %s: %s", project_id, e
            )
            return {}
