"""CloudWatch Logs service for browsing AWS CloudWatch log groups and events."""

from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional

import boto3


class CloudWatchService:
    """Service for interacting with AWS CloudWatch Logs."""

    PRIVATE_NETWORKS = [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("127.0.0.0/8"),
    ]

    async def list_log_groups(
        self, prefix: str = "", region: str = ""
    ) -> List[Dict[str, Any]]:
        """List CloudWatch log groups with optional prefix filter."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._list_log_groups_sync, prefix, region
        )

    def _list_log_groups_sync(
        self, prefix: str, region: str
    ) -> List[Dict[str, Any]]:
        kwargs: Dict[str, str] = {}
        if region:
            kwargs["region_name"] = region
        client = boto3.client("logs", **kwargs)
        groups: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {}
        if prefix:
            params["logGroupNamePrefix"] = prefix
        while True:
            response = client.describe_log_groups(**params)
            for g in response.get("logGroups", []):
                groups.append(
                    {
                        "name": g["logGroupName"],
                        "stored_bytes": g.get("storedBytes", 0),
                        "retention_days": g.get("retentionInDays"),
                    }
                )
            token = response.get("nextToken")
            if not token:
                break
            params["nextToken"] = token
        return groups

    async def get_log_events(
        self,
        log_group: str,
        start_time: datetime,
        end_time: datetime,
        filter_pattern: str = "",
        region: str = "",
        max_events: int = 500,
    ) -> List[Dict[str, Any]]:
        """Get filtered log events from a log group."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._get_log_events_sync,
            log_group,
            start_time,
            end_time,
            filter_pattern,
            region,
            max_events,
        )

    def _get_log_events_sync(
        self,
        log_group: str,
        start_time: datetime,
        end_time: datetime,
        filter_pattern: str,
        region: str,
        max_events: int,
    ) -> List[Dict[str, Any]]:
        kwargs: Dict[str, str] = {}
        if region:
            kwargs["region_name"] = region
        client = boto3.client("logs", **kwargs)
        events: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {
            "logGroupName": log_group,
            "startTime": int(start_time.timestamp() * 1000),
            "endTime": int(end_time.timestamp() * 1000),
            "limit": 10000,
        }
        if filter_pattern:
            params["filterPattern"] = filter_pattern
        # Fetch all matching events up to max_events (0 = unlimited, capped at 50k)
        hard_limit = max_events if max_events > 0 else 50000
        while len(events) < hard_limit:
            response = client.filter_log_events(**params)
            for e in response.get("events", []):
                events.append(
                    {
                        "timestamp": datetime.fromtimestamp(e["timestamp"] / 1000),
                        "message": e.get("message", ""),
                        "log_stream": e.get("logStreamName", ""),
                    }
                )
            token = response.get("nextToken")
            if not token:
                break
            params["nextToken"] = token
        return events[:hard_limit] if max_events > 0 else events

    @staticmethod
    def extract_top_ips(
        events: List[Dict[str, Any]],
        limit: int = 20,
        action_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Extract and rank top IPs from log events, filtering out private IPs.

        Args:
            events: CloudWatch log events.
            limit: Max IPs to return.
            action_filter: If set, only count events with this WAF action
                           (e.g. "ALLOW", "BLOCK"). None means all.

        Returns:
            List of dicts with keys: ip, count, allowed, blocked.
        """
        ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        total_counter: Counter = Counter()
        allow_counter: Counter = Counter()
        block_counter: Counter = Counter()

        for event in events:
            message = event.get("message", "")
            ips: List[str] = []
            action: Optional[str] = None

            # Try JSON first to extract clientIp and action (WAF/ALB structured logs)
            try:
                parsed = json.loads(message)
                client_ip = (
                    parsed.get("httpRequest", {}).get("clientIp")
                    or parsed.get("clientIp")
                    or parsed.get("client_ip")
                )
                action = parsed.get("action")
                if client_ip:
                    ips.append(client_ip)
            except (json.JSONDecodeError, AttributeError):
                ips = ip_pattern.findall(message)

            # Apply action filter if set
            if action_filter and action and action.upper() != action_filter.upper():
                continue

            for match in ips:
                try:
                    addr = ip_address(match)
                    if not any(addr in net for net in CloudWatchService.PRIVATE_NETWORKS):
                        total_counter[match] += 1
                        if action:
                            upper = action.upper()
                            if upper == "ALLOW":
                                allow_counter[match] += 1
                            elif upper == "BLOCK":
                                block_counter[match] += 1
                except ValueError:
                    continue

        return [
            {
                "ip": ip,
                "count": count,
                "allowed": allow_counter.get(ip, 0),
                "blocked": block_counter.get(ip, 0),
            }
            for ip, count in total_counter.most_common(limit)
        ]
