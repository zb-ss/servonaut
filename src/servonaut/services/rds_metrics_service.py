"""Read RDS instance health metrics via CloudWatch GetMetricStatistics.

Backs the ``rds_metrics`` tool. The recurring DB-saturation incidents (shared
RDS, noisy neighbour) needed CPU / connections / credit-balance / latency at a
glance — and Performance Insights was IAM-denied, so plain CloudWatch metrics
are the reliable first look.

boto3 runs in a thread (``run_in_executor``); the service never raises out of
:meth:`fetch` — failures come back in the ``errors`` list so a partial read
(e.g. CPUCreditBalance only exists for burstable classes) is still useful.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import boto3

logger = logging.getLogger(__name__)

_NAMESPACE = "AWS/RDS"

# metric name → (key in result, unit transform). Latency is seconds → ms.
_METRICS = [
    ("CPUUtilization", "cpu_pct", 1.0),
    ("DatabaseConnections", "connections", 1.0),
    ("CPUCreditBalance", "cpu_credit_balance", 1.0),
    ("ReadLatency", "read_latency_ms", 1000.0),
    ("WriteLatency", "write_latency_ms", 1000.0),
    ("FreeableMemory", "freeable_memory_mb", 1.0 / (1024 * 1024)),
]


class RDSMetricsService:
    """Fetch a snapshot of an RDS instance's CloudWatch metrics."""

    async def fetch(
        self, db_instance: str, region: str = "", window_hours: int = 3,
    ) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._fetch_sync, db_instance, region, window_hours,
        )

    def _fetch_sync(
        self, db_instance: str, region: str, window_hours: int,
    ) -> Dict[str, Any]:
        from datetime import datetime, timedelta

        result: Dict[str, Any] = {
            "db_instance": db_instance,
            "window_hours": window_hours,
            "metrics": {},
            "errors": [],
        }
        kwargs = {"region_name": region} if region else {}
        try:
            cw = boto3.client("cloudwatch", **kwargs)
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"cloudwatch client: {exc}")
            return result

        end = datetime.utcnow()
        start = end - timedelta(hours=max(int(window_hours), 1))
        # Period: keep the datapoint count sane across the window.
        period = 300 if window_hours <= 6 else 3600

        for metric_name, key, factor in _METRICS:
            try:
                resp = cw.get_metric_statistics(
                    Namespace=_NAMESPACE,
                    MetricName=metric_name,
                    Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_instance}],
                    StartTime=start, EndTime=end, Period=period,
                    Statistics=["Average", "Maximum", "Minimum"],
                )
            except Exception as exc:  # noqa: BLE001
                result["errors"].append(f"{metric_name}: {exc}")
                continue
            datapoints = resp.get("Datapoints", [])
            if not datapoints:
                continue
            result["metrics"][key] = self._summarize(datapoints, factor)

        return result

    @staticmethod
    def _summarize(datapoints: List[Dict[str, Any]], factor: float) -> Dict[str, Any]:
        avgs = [d["Average"] * factor for d in datapoints if "Average" in d]
        maxs = [d["Maximum"] * factor for d in datapoints if "Maximum" in d]
        mins = [d["Minimum"] * factor for d in datapoints if "Minimum" in d]
        latest = max(datapoints, key=lambda d: d.get("Timestamp"))
        return {
            "avg": round(sum(avgs) / len(avgs), 2) if avgs else None,
            "max": round(max(maxs), 2) if maxs else None,
            "min": round(min(mins), 2) if mins else None,
            "latest": round(
                (latest.get("Average", latest.get("Maximum", 0)) * factor), 2
            ),
        }


def format_rds_metrics(data: Dict[str, Any]) -> str:
    """Render an RDS metrics snapshot as a skimmable report."""
    m = data.get("metrics", {})
    out = [
        f"RDS metrics for {data.get('db_instance','?')} "
        f"(last {data.get('window_hours','?')}h):",
    ]
    if not m:
        out.append("  No datapoints returned. Check the DB instance identifier "
                   "and region, and that cloudwatch:GetMetricStatistics is "
                   "permitted.")

    def line(label, key, suffix=""):
        s = m.get(key)
        if not s:
            return
        out.append(
            f"  {label:<22} avg {s.get('avg')}{suffix}"
            f"  max {s.get('max')}{suffix}"
            + (f"  latest {s.get('latest')}{suffix}"
               if s.get('latest') is not None else "")
        )

    line("CPU", "cpu_pct", "%")
    line("Connections", "connections")
    line("Read latency", "read_latency_ms", "ms")
    line("Write latency", "write_latency_ms", "ms")
    line("Freeable memory", "freeable_memory_mb", "MB")
    # CPU credit balance: only meaningful for burstable (t-class); show latest/min.
    credit = m.get("cpu_credit_balance")
    if credit:
        out.append(
            f"  {'CPU credit balance':<22} latest {credit.get('latest')}"
            f"  min {credit.get('min')}"
            "   (burstable class — low/zero means CPU is throttled)"
        )

    if data.get("errors"):
        out.append("  Partial — some metrics failed (likely IAM scope or "
                   "metric not emitted for this class):")
        for e in data["errors"][:8]:
            out.append(f"    - {e}")
    return "\n".join(out)
