"""Instance monitoring data via OVHcloud API."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from servonaut.services.ovh_service import OVHService

logger = logging.getLogger(__name__)

_VALID_PERIODS = {"lastday", "lastweek", "lastmonth", "lastyear"}
_VALID_INSTANCE_NAME = re.compile(r'^[\w\-.]+$')

_DEDICATED_CHART_TYPES = [
    ("cpu", "cpu:user:max"),
    ("ram", "ram:used:max"),
    ("net_rx", "net:rx:max"),
    ("net_tx", "net:tx:max"),
]

# /vps/{serviceName}/monitoring requires one call per statistic type
# (vps.VpsStatisticTypeEnum); omitting `type` is a 400.
_VPS_STAT_TYPES = [
    ("cpu", "cpu:used"),
    ("ram", "mem:used"),
    ("net_in", "net:rx"),
    ("net_out", "net:tx"),
]


def _validate_period(period: str) -> None:
    """Raise ValueError if period is not one of the accepted values."""
    if period not in _VALID_PERIODS:
        raise ValueError(
            f"Invalid period {period!r}. Must be one of: "
            + ", ".join(sorted(_VALID_PERIODS))
        )


def _validate_name(name: str, label: str = "name") -> None:
    """Raise ValueError if name contains characters that are unsafe for URL paths."""
    if not name or not _VALID_INSTANCE_NAME.match(name):
        raise ValueError(
            f"Invalid {label} {name!r}. Only alphanumeric characters, "
            "hyphens, underscores, and dots are allowed."
        )


def _normalise_series(raw: object) -> List[dict]:
    """Coerce an API response value into a list of {timestamp, value} dicts."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        # Some endpoints return {"values": [...], "timestamps": [...]}
        timestamps: list = raw.get("timestamps") or []
        values: list = raw.get("values") or []
        if timestamps and values:
            return [
                {"timestamp": ts, "value": v}
                for ts, v in zip(timestamps, values)
            ]
        # vps.VpsMonitoringData: {"unit": ..., "values": [{timestamp, value}]}
        if values and isinstance(values[0], dict):
            return values
        # Single-point dict
        return [raw]
    return []


class OVHMonitoringService:
    """Instance monitoring data via OVHcloud API."""

    def __init__(self, ovh_service: "OVHService") -> None:
        """Initialise the monitoring service.

        Args:
            ovh_service: Shared OVHService whose client property will be used
                for all API calls.
        """
        self._ovh_service = ovh_service

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def get_vps_monitoring(
        self, vps_name: str, period: str = "lastday"
    ) -> dict:
        """Fetch CPU, RAM, and network monitoring data for a VPS.

        Calls GET /vps/{serviceName}/monitoring once per statistic type
        (``cpu:used``, ``mem:used``, ``net:rx``, ``net:tx``) — the
        endpoint rejects requests without a ``type`` parameter.

        Args:
            vps_name: VPS service name (e.g. ``vps-abc123.ovh.net``).
            period: One of ``lastday``, ``lastweek``, ``lastmonth``,
                ``lastyear``.

        Returns:
            Dict with keys ``cpu``, ``ram``, ``net_in``, ``net_out``.
            Each value is a list of ``{timestamp, value}`` dicts. A key
            whose individual fetch failed is an empty list.

        Raises:
            ValueError: If *period* or *vps_name* is invalid.
            RuntimeError: If every statistic type fails — the caller must
                see a loud failure rather than empty-but-successful data.
        """
        _validate_period(period)
        _validate_name(vps_name, "vps_name")

        client = self._ovh_service.client
        result: dict = {}
        errors: list = []

        for result_key, stat_type in _VPS_STAT_TYPES:
            try:
                raw = await asyncio.to_thread(
                    client.get,
                    f"/vps/{vps_name}/monitoring",
                    period=period,
                    type=stat_type,
                )
                result[result_key] = _normalise_series(raw)
            except Exception as exc:
                logger.error(
                    "Error fetching VPS stat %s for %s (period=%s): %s",
                    stat_type,
                    vps_name,
                    period,
                    exc,
                )
                errors.append(f"{stat_type}: {exc}")
                result[result_key] = []

        if len(errors) == len(_VPS_STAT_TYPES):
            raise RuntimeError(
                f"OVH returned no monitoring data for VPS {vps_name}: all "
                f"{len(errors)} statistic types failed (last: {errors[-1]}). "
                "The legacy /vps monitoring API may not serve metrics for "
                "current-generation VPS ranges — collect host-level metrics "
                "on the server instead."
            )

        return result

    async def get_dedicated_monitoring(
        self, server_name: str, period: str = "lastday"
    ) -> dict:
        """Fetch CPU, RAM, and network statistics for a dedicated server.

        Calls GET /dedicated/server/{serviceName}/statistics/chart for each
        of the following chart types: ``cpu:user:max``, ``ram:used:max``,
        ``net:rx:max``, ``net:tx:max``.

        Args:
            server_name: Dedicated server service name.
            period: One of ``lastday``, ``lastweek``, ``lastmonth``,
                ``lastyear``.

        Returns:
            Dict with keys ``cpu``, ``ram``, ``net_rx``, ``net_tx``.

        Raises:
            ValueError: If *period* or *server_name* is invalid.
        """
        _validate_period(period)
        _validate_name(server_name, "server_name")

        client = self._ovh_service.client
        result: dict = {}

        for result_key, chart_type in _DEDICATED_CHART_TYPES:
            try:
                raw = await asyncio.to_thread(
                    client.get,
                    f"/dedicated/server/{server_name}/statistics/chart",
                    period=period,
                    type=chart_type,
                )
                result[result_key] = _normalise_series(raw)
            except Exception as exc:
                logger.error(
                    "Error fetching dedicated chart %s for %s (period=%s): %s",
                    chart_type,
                    server_name,
                    period,
                    exc,
                )
                result[result_key] = []

        return result

    async def get_cloud_monitoring(
        self, project_id: str, instance_id: str, period: str = "lastday"
    ) -> dict:
        """Fetch CPU and network monitoring for a Public Cloud instance.

        Calls GET /cloud/project/{projectId}/instance/{instanceId}/monitoring.

        Args:
            project_id: OVH Public Cloud project identifier.
            instance_id: Instance UUID.
            period: One of ``lastday``, ``lastweek``, ``lastmonth``,
                ``lastyear``.

        Returns:
            Dict with keys ``cpu``, ``net_in``, ``net_out``.

        Raises:
            ValueError: If *period*, *project_id*, or *instance_id* is invalid.
        """
        _validate_period(period)
        _validate_name(project_id, "project_id")
        _validate_name(instance_id, "instance_id")

        client = self._ovh_service.client
        try:
            raw = await asyncio.to_thread(
                client.get,
                f"/cloud/project/{project_id}/instance/{instance_id}/monitoring",
                period=period,
            )
        except Exception as exc:
            logger.error(
                "Error fetching cloud monitoring for %s/%s (period=%s): %s",
                project_id,
                instance_id,
                period,
                exc,
            )
            raw = {}

        return {
            "cpu": _normalise_series(raw.get("cpu") or []),
            "net_in": _normalise_series(raw.get("net_in") or []),
            "net_out": _normalise_series(raw.get("net_out") or []),
        }
