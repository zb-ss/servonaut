"""OVHcloud billing and usage service."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)

# Bill details are fetched one request per invoice. One shared limit keeps a
# stalled API from filling the thread pool, however often the screen reopens.
_BILL_FETCH_CONCURRENCY = 5

# Currency codes are short letter codes ("EUR"). Anything else in that field
# is not shown: it ends up in screen text and in tool output.
_CURRENCY_CODE = re.compile(r"[A-Za-z]{1,8}")


def currency_code(value: object) -> str:
    """*value* when it is a plain currency code, else an empty string."""
    return value if isinstance(value, str) and _CURRENCY_CODE.fullmatch(value) else ""


def usage_total(payload: object) -> Optional[Tuple[float, str]]:
    """Reduce a consumption payload to ``(amount, currency)``.

    The consumption endpoints return a list of transactions, one per service,
    each carrying its amount under ``price``. The amounts are summed; an empty
    list is a valid answer meaning no consumption, so it totals zero with no
    currency. A single record (``price`` or ``total``) is accepted too.
    Returns ``None`` when no amount can be read.
    """
    if payload == []:
        return (0.0, "")
    records = payload if isinstance(payload, list) else [payload]
    amount = 0.0
    currency = ""
    found = False
    for record in records:
        if not isinstance(record, dict):
            continue
        price = record.get("price") or record.get("total")
        if not isinstance(price, dict) or price.get("value") is None:
            continue
        try:
            amount += float(price["value"])
        except (TypeError, ValueError):
            continue
        currency = currency or currency_code(price.get("currencyCode"))
        found = True
    return (round(amount, 2), currency) if found else None


def usage_figures(usage: dict) -> Tuple[str, str]:
    """Readable ``(current, forecast)`` figures from ``get_current_usage``.

    A failed call reads ``unavailable``, an unreadable payload ``n/a``. A zero
    total without a currency borrows the other figure's currency.
    """
    def total_of(key: str) -> Optional[Tuple[float, str]]:
        if usage.get(f"{key}_failed"):
            return None
        return usage_total(usage.get(key if key == "forecast" else "current_spend"))

    current, forecast = total_of("current"), total_of("forecast")
    currencies = [t[1] for t in (current, forecast) if t and t[1]]
    shared = currencies[0] if currencies else ""

    def show(key: str, total: Optional[Tuple[float, str]]) -> str:
        if usage.get(f"{key}_failed"):
            return "unavailable"
        if total is None:
            return "n/a"
        return f"{total[0]:.2f} {total[1] or shared}".strip()

    return show("current", current), show("forecast", forecast)


def spend_history_from_invoices(invoices: List[dict], months: int = 6) -> List[dict]:
    """Aggregate invoices into per-month spend totals, oldest first.

    Args:
        invoices: Bill records with ``date`` and ``priceWithTax``.
        months: Number of recent months to return.

    Returns:
        ``{month, total, currency}`` dicts where ``month`` is ``YYYY-MM``.
    """
    monthly: dict[str, dict] = {}
    for inv in invoices:
        date_str: Optional[str] = inv.get("date") or inv.get("billDate") or ""
        amount_raw = inv.get("priceWithTax") or inv.get("amount") or {}
        try:
            if isinstance(amount_raw, dict):
                value: float = float(amount_raw.get("value", 0) or 0)
                currency: str = currency_code(amount_raw.get("currencyCode"))
            else:
                value = float(amount_raw or 0)
                currency = ""
        except (TypeError, ValueError):
            continue  # a bill whose amount cannot be read adds nothing

        try:
            month_key = datetime.fromisoformat(date_str[:10]).strftime("%Y-%m")
        except (ValueError, TypeError, IndexError):
            continue

        if month_key not in monthly:
            monthly[month_key] = {"month": month_key, "total": 0.0, "currency": currency}
        monthly[month_key]["total"] = round(monthly[month_key]["total"] + value, 2)
        if not monthly[month_key]["currency"] and currency:
            monthly[month_key]["currency"] = currency

    return sorted(monthly.values(), key=lambda x: x["month"])[-months:]


class OVHBillingService:
    """Service for querying OVHcloud billing, invoices, and usage data."""

    def __init__(self, ovh_service: 'OVHService') -> None:
        """Initialize OVH billing service.

        Args:
            ovh_service: An initialized OVHService instance whose client will be reused.
        """
        self._ovh_service = ovh_service
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._bill_gate: Optional[asyncio.Semaphore] = None
        self._invoice_fetches: dict[int, asyncio.Task] = {}

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
            usage = None

        try:
            forecast = await asyncio.to_thread(
                client.get, "/me/consumption/usage/forecast"
            )
        except Exception as e:
            logger.error("Error fetching OVH usage forecast: %s", e)
            forecast = None

        return {
            'provider': 'ovh',
            'current_spend': usage if usage is not None else {},
            'forecast': forecast if forecast is not None else {},
            'current_failed': usage is None,
            'forecast_failed': forecast is None,
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

        Concurrent callers asking for the same ``limit`` share one fetch, and
        the fetch keeps running if a caller is cancelled, so reopening a screen
        during a slow API joins the work in flight instead of adding to it.

        Args:
            limit: Maximum number of invoices to return. 0 means all.

        Returns:
            List of invoice dicts, newest first.

        Raises:
            Exception: When the bill list cannot be fetched, or every bill
                request fails.
        """
        self._bind_to_running_loop()
        task = self._invoice_fetches.get(limit)
        if task is None or task.done():
            task = asyncio.ensure_future(self._fetch_invoices(limit))
            task.add_done_callback(lambda t, key=limit: self._finish_fetch(key, t))
            self._invoice_fetches[limit] = task
        return list(await asyncio.shield(task))

    def _bind_to_running_loop(self) -> None:
        """Drop loop-bound state left by another event loop.

        A semaphore or task belongs to the loop that created it; reusing the
        service from a new loop would otherwise fail once the limit is hit.
        """
        loop = asyncio.get_running_loop()
        if self._loop is loop:
            return
        self._loop = loop
        self._bill_gate = None
        self._invoice_fetches = {}

    def _finish_fetch(self, limit: int, task: asyncio.Task) -> None:
        if self._invoice_fetches.get(limit) is task:
            del self._invoice_fetches[limit]
        if not task.cancelled():
            task.exception()  # mark retrieved; callers see it through the shield

    async def _fetch_invoices(self, limit: int) -> List[dict]:
        client = self._ovh_service.client
        try:
            bill_ids = await asyncio.to_thread(client.get, "/me/bill")
        except Exception as e:
            logger.error("Error fetching OVH bill list: %s", e)
            raise

        if not bill_ids:
            return []

        # OVH returns IDs in ascending order; reverse to fetch newest first
        bill_ids = list(reversed(bill_ids))
        if limit > 0:
            bill_ids = bill_ids[:limit]

        if self._bill_gate is None:
            self._bill_gate = asyncio.Semaphore(_BILL_FETCH_CONCURRENCY)
        gate = self._bill_gate

        async def fetch(bill_id: str) -> Optional[dict]:
            async with gate:
                try:
                    return await asyncio.to_thread(client.get, f"/me/bill/{bill_id}")
                except Exception as e:
                    logger.error("Error fetching OVH bill %s: %s", bill_id, e)
                    return None

        fetched = await asyncio.gather(*(fetch(b) for b in bill_ids))
        invoices = [bill for bill in fetched if isinstance(bill, dict)]
        if not invoices:
            raise RuntimeError("No OVH bill could be fetched")

        invoices.sort(key=lambda inv: inv.get("date") or inv.get("billDate") or "", reverse=True)
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
        return spend_history_from_invoices(invoices, months)

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
