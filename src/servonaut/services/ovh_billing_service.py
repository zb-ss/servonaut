"""OVHcloud billing and usage service."""

from __future__ import annotations

import asyncio
import logging
from typing import List, TYPE_CHECKING

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

    async def get_invoices(self, limit: int = 10) -> List[dict]:
        """Fetch recent OVH invoices.

        Args:
            limit: Maximum number of invoices to return (most recent first).

        Returns:
            List of invoice dicts.
        """
        client = self._ovh_service.client
        try:
            bill_ids = await asyncio.to_thread(client.get, "/me/bill")
        except Exception as e:
            logger.error("Error fetching OVH bill list: %s", e)
            return []

        if not bill_ids:
            return []

        invoices = []
        for bill_id in bill_ids[:limit]:
            try:
                bill = await asyncio.to_thread(client.get, f"/me/bill/{bill_id}")
                invoices.append(bill)
            except Exception as e:
                logger.error("Error fetching OVH bill %s: %s", bill_id, e)

        return invoices
