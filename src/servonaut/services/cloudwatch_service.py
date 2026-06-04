"""CloudWatch Logs service for browsing AWS CloudWatch log groups and events."""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections import Counter
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional

import boto3

# Single bare token (no whitespace) that contains a char CloudWatch Logs
# tokenises on (``.`` ``:`` ``/`` ``-`` etc.). Such a term MUST be double-quoted
# in a filter pattern or it silently fails to match — the bug that sent a live
# investigation toward a false "WAF bypass" hypothesis. Alphanumeric-only tokens
# (e.g. ``ERROR``) match fine unquoted, so we leave those alone.
_BARE_LITERAL_RE = re.compile(r"^[A-Za-z0-9_]+$")


class CloudWatchService:
    """Service for interacting with AWS CloudWatch Logs."""

    PRIVATE_NETWORKS = [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("127.0.0.0/8"),
    ]

    def __init__(self, client_factory=None) -> None:
        """Args:
        client_factory: Optional :class:`AWSClientFactory`. When supplied, every
            ``logs`` client is built through it — honouring the control-plane
            STS role / region pinning. When ``None`` (the default), clients are
            built off the ambient credential chain exactly as before.
        """
        self._client_factory = client_factory

    def _logs_client(self, region: str):
        """Build a CloudWatch Logs client via the factory, or boto3 directly."""
        if self._client_factory is not None:
            return self._client_factory.client("logs", region=region)
        kwargs: Dict[str, str] = {}
        if region:
            kwargs["region_name"] = region
        return boto3.client("logs", **kwargs)

    @staticmethod
    def normalize_filter_pattern(pattern: str) -> str:
        """Quote a bare literal filter term so CloudWatch matches it reliably.

        CloudWatch Logs tokenises unstructured filter terms on non-alphanumerics,
        so a bare ``9.9.9.9`` or ``/wp-login.php`` does NOT match — it has
        to be double-quoted (``"9.9.9.9"``). This helper rewrites exactly
        that case and leaves every richer form untouched:

        - ``{ $.field = "x" }`` JSON selectors — pass through.
        - ``[w1, w2, ...]`` space-delimited (metric-filter) patterns — pass.
        - already-``"quoted"`` terms — pass.
        - multi-token / operator expressions (whitespace, ``?`` ``-`` ``&&``
          present beyond a leading sign) — pass; we don't second-guess them.
        - a single bare token containing a tokeniser char — wrap in quotes
          (preserving a leading ``?`` optional / ``-`` exclusion sign).
        """
        p = pattern.strip()
        if not p:
            return ""
        if p[0] in "{[" or (p.startswith('"') and p.endswith('"')):
            return p
        # Preserve a single leading optional/exclusion sign, quote the remainder.
        sign = ""
        body = p
        if body[0] in "?-":
            sign, body = body[0], body[1:]
        # Anything with internal whitespace or filter operators is a richer
        # expression — leave it exactly as the caller wrote it.
        if (not body) or any(c.isspace() for c in body) or "&&" in body or "||" in body:
            return p
        if body.startswith('"') and body.endswith('"'):
            return p
        if _BARE_LITERAL_RE.match(body):
            return p  # plain alphanumeric token already matches unquoted
        return f'{sign}"{body}"'

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
        client = self._logs_client(region)
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
        client = self._logs_client(region)
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

    # ------------------------------------------------------------------
    # CloudWatch Logs Insights
    # ------------------------------------------------------------------

    async def run_insights_query(
        self,
        log_groups: List[str],
        query: str,
        start_time: datetime,
        end_time: datetime,
        region: str = "",
        limit: int = 1000,
        timeout_seconds: int = 60,
    ) -> Dict[str, Any]:
        """Run a CloudWatch Logs Insights query and return parsed results.

        Insights is the right primitive for aggregation (top IPs, status mix,
        URI ranking, time-bucketing) — it generalises the bespoke ``top_ips``
        parser into one interface. The query runs server-side; we poll
        ``get_query_results`` until it completes, fails, or ``timeout_seconds``
        elapses (best-effort ``stop_query`` on timeout).

        Returns ``{status, columns, rows, statistics, query_id}`` where ``rows``
        is a list of dicts keyed by Insights field name.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._run_insights_query_sync,
            log_groups,
            query,
            start_time,
            end_time,
            region,
            limit,
            timeout_seconds,
        )

    def _run_insights_query_sync(
        self,
        log_groups: List[str],
        query: str,
        start_time: datetime,
        end_time: datetime,
        region: str,
        limit: int,
        timeout_seconds: int,
    ) -> Dict[str, Any]:
        client = self._logs_client(region)
        start = client.start_query(
            logGroupNames=log_groups,
            startTime=int(start_time.timestamp()),
            endTime=int(end_time.timestamp()),
            queryString=query,
            limit=max(1, limit),
        )
        query_id = start["queryId"]
        deadline = time.time() + max(5, timeout_seconds)
        result: Dict[str, Any] = {"status": "Unknown", "query_id": query_id}
        poll_interval = 1.0
        while time.time() < deadline:
            resp = client.get_query_results(queryId=query_id)
            status = resp.get("status", "Unknown")
            result["status"] = status
            result["statistics"] = resp.get("statistics", {})
            if status in ("Complete", "Failed", "Cancelled", "Timeout"):
                rows = [
                    {col["field"]: col.get("value", "") for col in row}
                    for row in resp.get("results", [])
                ]
                result["rows"] = rows
                result["columns"] = list(rows[0].keys()) if rows else []
                return result
            time.sleep(poll_interval)
            poll_interval = min(poll_interval * 1.5, 5.0)

        # Timed out while still Running/Scheduled — stop the query best-effort.
        try:
            client.stop_query(queryId=query_id)
        except Exception:  # noqa: BLE001 - stop is best-effort cleanup
            pass
        result["status"] = "Timeout"
        result["rows"] = []
        result["columns"] = []
        return result

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

    @staticmethod
    def aggregate_events(
        events: List[Dict[str, Any]],
        group_by: str,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Rank log events by a structured field (clientIp / status / uri).

        Returns ``{group_by, total_events, total_matched, ranking}`` where
        ranking is ``[{key, count, pct}]``. Lets callers get a server-side
        ranked summary instead of dumping every raw event. ``total_matched``
        is how many events yielded a value for the requested field.
        """
        counter: Counter = Counter()
        matched = 0
        for event in events:
            message = event.get("message", "")
            try:
                parsed = json.loads(message)
            except (json.JSONDecodeError, TypeError):
                parsed = None
            value = CloudWatchService._field_value(parsed, message, group_by)
            if value is None or value == "":
                continue
            matched += 1
            counter[str(value)] += 1

        ranking = [
            {"key": key, "count": count,
             "pct": round(count / matched * 100, 1) if matched else 0.0}
            for key, count in counter.most_common(limit)
        ]
        return {
            "group_by": group_by,
            "total_events": len(events),
            "total_matched": matched,
            "ranking": ranking,
        }

    @staticmethod
    def _field_value(parsed, message: str, group_by: str):
        """Extract the requested field from a parsed WAF/ALB log record."""
        if group_by == "clientIp":
            if isinstance(parsed, dict):
                return (
                    parsed.get("httpRequest", {}).get("clientIp")
                    or parsed.get("clientIp")
                    or parsed.get("client_ip")
                )
            return None
        if group_by == "status":
            if isinstance(parsed, dict):
                return (
                    parsed.get("responseCodeSent")
                    or parsed.get("elb_status_code")
                    or parsed.get("status")
                    or parsed.get("httpResponse", {}).get("status")
                )
            return None
        if group_by == "uri":
            if isinstance(parsed, dict):
                uri = parsed.get("httpRequest", {}).get("uri")
                if uri:
                    return str(uri).split("?", 1)[0]
                # ALB "request" field: '"GET https://h:443/path HTTP/1.1"'
                req = parsed.get("request") or ""
                parts = str(req).split(" ")
                if len(parts) >= 2:
                    path = parts[1]
                    # Strip scheme/host if present.
                    if "://" in path:
                        path = "/" + path.split("://", 1)[1].split("/", 1)[-1]
                    return path.split("?", 1)[0]
            return None
        return None
