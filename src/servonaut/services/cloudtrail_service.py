"""CloudTrail event browsing service for Servonaut."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from servonaut.services.interfaces import CloudTrailServiceInterface

# CloudTrail returns at most 50 events per page.
_API_PAGE_SIZE = 50


@dataclass(frozen=True)
class LookupPage:
    """One page of events, and where to resume for the next one.

    ``next_token`` maps a region to its continuation token and is ``None``
    once every region queried is exhausted, so a caller can offer "more"
    only when there really is more.
    """

    events: List[dict] = field(default_factory=list)
    next_token: Optional[Dict[str, str]] = None
# How far to read when criteria are applied locally: a multiple of the
# caller's cap, never fewer than a few pages, never past the ceiling.
_POST_FILTER_SCAN_MULTIPLIER = 20
_POST_FILTER_SCAN_MINIMUM = 500
_POST_FILTER_SCAN_CEILING = 5000


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
        page = await self.lookup_page(
            region=region, start_time=start_time, end_time=end_time,
            event_name=event_name, username=username,
            resource_type=resource_type, max_results=max_results,
        )
        limit = max_results if max_results > 0 else len(page.events)
        return page.events[:limit]

    async def lookup_page(
        self,
        region: str = "",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_name: str = "",
        username: str = "",
        resource_type: str = "",
        max_results: int = 100,
        resume_from: Optional[Dict[str, str]] = None,
    ) -> "LookupPage":
        """Fetch one page of events and the token to continue from.

        ``resume_from`` is a previous page's ``next_token``. Reading on is
        how the browser pages through a long window without waiting for the
        whole of it up front: a day of events can be tens of thousands, and
        the API is throttled to a couple of calls a second.
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

        # CloudTrail honours only the FIRST lookup attribute and silently
        # ignores the rest, so two filters used to return results matching
        # just one of them. Send one to the API and apply the others here.
        server_attr = lookup_attrs[0] if lookup_attrs else None
        post_filters = lookup_attrs[1:]

        loop = asyncio.get_event_loop()

        # max_results=0 means fetch all (capped at 10000)
        hard_limit = max_results if max_results > 0 else 10000
        # Criteria applied locally need a wider read: a page can be mostly
        # discarded. Bounded so a narrow filter cannot page forever.
        scan_limit = hard_limit
        if post_filters:
            scan_limit = min(
                max(hard_limit * _POST_FILTER_SCAN_MULTIPLIER, _POST_FILTER_SCAN_MINIMUM),
                _POST_FILTER_SCAN_CEILING,
            )

        def _fetch() -> "LookupPage":
            import boto3

            regions_to_query = (
                [target_region] if target_region else self._get_regions_sync()
            )
            if resume_from is not None:
                # Only regions that still have a page left are worth calling.
                regions_to_query = [r for r in regions_to_query if r in resume_from]
            # One page is ``hard_limit`` events in total, shared out across the
            # regions being read, so continuing does not multiply by region
            # count and no region starves.
            per_region = (
                hard_limit
                if len(regions_to_query) <= 1
                else max(_API_PAGE_SIZE, hard_limit // max(1, len(regions_to_query)))
            )
            per_region_scan = max(per_region, scan_limit // max(1, len(regions_to_query)))

            all_events: List[dict] = []
            resume_tokens: Dict[str, str] = {}

            for r in regions_to_query:
                client = boto3.client("cloudtrail", region_name=r)
                kwargs: dict = {
                    "StartTime": start_time,
                    "EndTime": end_time,
                    "MaxResults": min(per_region_scan, _API_PAGE_SIZE),
                }
                if server_attr:
                    kwargs["LookupAttributes"] = [server_attr]
                if resume_from is not None:
                    kwargs["NextToken"] = resume_from[r]

                events: List[dict] = []
                scanned = 0
                carry: Optional[str] = None
                while len(events) < per_region and scanned < per_region_scan:
                    response = client.lookup_events(**kwargs)
                    batch = response.get("Events", [])
                    scanned += len(batch)
                    # Whole batches only: stopping mid-batch would leave events
                    # behind that the resume token has already moved past.
                    for event in batch:
                        if self._matches_attributes(event, post_filters):
                            events.append(self._parse_event(event, r))

                    carry = response.get("NextToken")
                    if not carry:
                        break
                    kwargs["NextToken"] = carry

                if carry:
                    resume_tokens[r] = carry
                all_events.extend(events)

            all_events.sort(key=lambda e: e["event_time"] or datetime.min, reverse=True)
            return LookupPage(events=all_events, next_token=resume_tokens or None)

        return await loop.run_in_executor(None, _fetch)

    @staticmethod
    def _matches_attributes(event: dict, attributes: List[dict]) -> bool:
        """Apply lookup attributes the API would not, against a raw event.

        Mirrors CloudTrail's own semantics: exact, case-sensitive matches,
        and ``ResourceType`` matches when ANY resource on the event has it.
        """
        for attribute in attributes:
            key = attribute.get("AttributeKey")
            value = attribute.get("AttributeValue")
            if key == "ResourceType":
                resources = event.get("Resources") or []
                if not any(
                    isinstance(res, dict) and res.get("ResourceType") == value
                    for res in resources
                ):
                    return False
            elif key == "EventName":
                if (event.get("EventName") or "") != value:
                    return False
            elif key == "Username":
                if (event.get("Username") or "") != value:
                    return False
        return True

    def _parse_event(self, event: dict, region: str) -> dict:
        """Parse a raw boto3 CloudTrail event dict into our normalized format."""
        raw = event.get("CloudTrailEvent", "{}")
        try:
            detail = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            detail = {}

        # CloudTrail does not guarantee either key on a resource entry
        # (some services omit ResourceType), so never index them directly.
        resources = event.get("Resources") or []
        first = resources[0] if resources and isinstance(resources[0], dict) else {}
        resource_type = str(first.get("ResourceType") or "")
        resource_name = str(first.get("ResourceName") or "")

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
