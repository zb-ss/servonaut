"""CloudTrail event browsing service for Servonaut."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Optional

from servonaut.services.interfaces import CloudTrailServiceInterface


class CloudTrailService(CloudTrailServiceInterface):
    """Fetches and parses CloudTrail events via boto3."""

    def __init__(self, config_manager: object) -> None:
        self._config_manager = config_manager

    async def lookup_events(
        self,
        region: str = "",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_name: str = "",
        username: str = "",
        resource_type: str = "",
        max_results: int = 100,
    ) -> List[dict]:
        """Fetch CloudTrail events with optional filters.

        Queries one region when specified, or all available regions when empty.
        Results are sorted by event_time descending.
        """
        config = self._config_manager.get()
        target_region = region or config.cloudtrail_default_region

        if not start_time:
            lookback = config.cloudtrail_default_lookback_hours
            start_time = datetime.utcnow() - timedelta(hours=lookback)
        if not end_time:
            end_time = datetime.utcnow()

        lookup_attrs = []
        if event_name:
            lookup_attrs.append({"AttributeKey": "EventName", "AttributeValue": event_name})
        if username:
            lookup_attrs.append({"AttributeKey": "Username", "AttributeValue": username})
        if resource_type:
            lookup_attrs.append({"AttributeKey": "ResourceType", "AttributeValue": resource_type})

        loop = asyncio.get_event_loop()

        # max_results=0 means fetch all (capped at 10000)
        hard_limit = max_results if max_results > 0 else 10000

        def _fetch() -> List[dict]:
            import boto3

            regions_to_query = [target_region] if target_region else self._get_regions_sync()
            all_events: List[dict] = []

            for r in regions_to_query:
                client = boto3.client("cloudtrail", region_name=r)
                kwargs: dict = {
                    "StartTime": start_time,
                    "EndTime": end_time,
                    "MaxResults": min(hard_limit, 50),
                }
                if lookup_attrs:
                    kwargs["LookupAttributes"] = lookup_attrs

                events: List[dict] = []
                while len(events) < hard_limit:
                    response = client.lookup_events(**kwargs)
                    for event in response.get("Events", []):
                        events.append(self._parse_event(event, r))

                    next_token = response.get("NextToken")
                    if not next_token or len(events) >= hard_limit:
                        break
                    kwargs["NextToken"] = next_token

                all_events.extend(events)

            all_events.sort(key=lambda e: e["event_time"] or datetime.min, reverse=True)
            return all_events[:hard_limit]

        return await loop.run_in_executor(None, _fetch)

    def _parse_event(self, event: dict, region: str) -> dict:
        """Parse a raw boto3 CloudTrail event dict into our normalized format."""
        raw = event.get("CloudTrailEvent", "{}")
        try:
            detail = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            detail = {}

        resources = event.get("Resources") or []
        resource_type = resources[0]["ResourceType"] if resources else ""
        resource_name = resources[0]["ResourceName"] if resources else ""

        return {
            "event_time": event.get("EventTime", ""),
            "event_name": event.get("EventName", ""),
            "username": event.get("Username", ""),
            "source_ip": detail.get("sourceIPAddress", ""),
            "resource_type": resource_type,
            "resource_name": resource_name,
            "region": region,
            "error_code": detail.get("errorCode", ""),
            "raw_event": raw,
        }

    async def get_available_regions(self) -> List[str]:
        """Return all EC2-available regions (used as proxy for CloudTrail regions)."""
        loop = asyncio.get_event_loop()

        def _get() -> List[str]:
            import boto3

            client = boto3.client("ec2", region_name="us-east-1")
            response = client.describe_regions()
            return [r["RegionName"] for r in response["Regions"]]

        return await loop.run_in_executor(None, _get)

    def _get_regions_sync(self) -> List[str]:
        """Synchronous fallback region list, returns us-east-1 on error."""
        try:
            import boto3

            client = boto3.client("ec2", region_name="us-east-1")
            response = client.describe_regions()
            return [r["RegionName"] for r in response["Regions"]]
        except Exception:
            return ["us-east-1"]
