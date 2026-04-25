"""DriftService + AnomalyService — stateless wrappers for server-side drift detection.

Both services are thin wrappers around the memory API endpoints for drift events
and anomaly events.  They raise domain exceptions (UpsellRequired, RateLimited)
instead of raw APIError subclasses so callers stay decoupled from HTTP details.

Worker group: ``memory_drift`` (exclusive=True per plan).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from servonaut.services.api_client import (
    ForbiddenEntitlementError,
    RateLimitedError,
)
from servonaut.services.memory.interfaces import (
    AnomalyEvent,
    DriftEvent,
    RateLimited,
    UpsellRequired,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)


def _map_403(exc: ForbiddenEntitlementError) -> UpsellRequired:
    plan = "teams" if (exc.details or {}).get("required_plan") == "teams" else "solo"
    return UpsellRequired(plan)


def _map_429(exc: RateLimitedError, endpoint: str) -> RateLimited:
    # No Retry-After header in this API — spec §6 says back off with jitter
    return RateLimited(endpoint=endpoint, retry_after_s=30.0)


class DriftService:
    """Fetch and acknowledge server-detected configuration drift events.

    Args:
        api_client: Authenticated APIClient.
        rate_limiter: Optional shared RateLimiter (defaults to a private one).
    """

    def __init__(
        self,
        api_client: "APIClient",
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self._api = api_client
        self._rate_limiter = rate_limiter or RateLimiter()

    async def list_drift(
        self,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> List[DriftEvent]:
        """GET /api/v1/memory/drift — list drift events.

        Args:
            since: ISO-8601 timestamp; only return events after this time.
            limit: Max number of events (1–200, default 100).

        Returns:
            List of DriftEvent dataclass instances.

        Raises:
            UpsellRequired: On 403 forbidden_entitlement (requires memory_drift).
            RateLimited: On 429 rate_limited.
        """
        params: Dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            data = await self._api.get("/api/v1/memory/drift", params=params)
            events = []
            for raw in data.get("drift_events", []):
                try:
                    events.append(_parse_drift_event(raw))
                except Exception as exc:
                    logger.warning("Could not parse drift event: %s — %s", raw.get("id"), exc)
            return events
        except ForbiddenEntitlementError as exc:
            raise _map_403(exc) from exc
        except RateLimitedError as exc:
            raise _map_429(exc, "/api/v1/memory/drift") from exc

    async def acknowledge_drift(self, event_id: str) -> Dict[str, str]:
        """POST /api/v1/memory/drift/{id}/ack — acknowledge a drift event.

        Args:
            event_id: UUID of the drift event to acknowledge.

        Returns:
            Dict with ``id`` and ``acknowledged_at`` keys.

        Raises:
            UpsellRequired: On 403 forbidden_entitlement.
            RateLimited: On 429.
        """
        endpoint = f"/api/v1/memory/drift/{event_id}/ack"
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            return await self._api.post(endpoint, json={})
        except ForbiddenEntitlementError as exc:
            raise _map_403(exc) from exc
        except RateLimitedError as exc:
            raise _map_429(exc, endpoint) from exc


class AnomalyService:
    """Fetch and acknowledge server-detected anomaly events.

    Args:
        api_client: Authenticated APIClient.
        rate_limiter: Optional shared RateLimiter (defaults to a private one).
    """

    def __init__(
        self,
        api_client: "APIClient",
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self._api = api_client
        self._rate_limiter = rate_limiter or RateLimiter()

    async def list_anomalies(
        self,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> List[AnomalyEvent]:
        """GET /api/v1/memory/anomalies — list anomaly events.

        Args:
            since: ISO-8601 timestamp; only return events after this time.
            limit: Max number of events (1–200, default 100).

        Returns:
            List of AnomalyEvent dataclass instances.

        Raises:
            UpsellRequired: On 403 forbidden_entitlement.
            RateLimited: On 429.
        """
        params: Dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            data = await self._api.get("/api/v1/memory/anomalies", params=params)
            events = []
            for raw in data.get("anomaly_events", []):
                try:
                    events.append(_parse_anomaly_event(raw))
                except Exception as exc:
                    logger.warning("Could not parse anomaly event: %s — %s", raw.get("id"), exc)
            return events
        except ForbiddenEntitlementError as exc:
            raise _map_403(exc) from exc
        except RateLimitedError as exc:
            raise _map_429(exc, "/api/v1/memory/anomalies") from exc

    async def acknowledge_anomaly(self, event_id: str) -> Dict[str, str]:
        """POST /api/v1/memory/anomalies/{id}/ack — acknowledge an anomaly event.

        Args:
            event_id: UUID of the anomaly event to acknowledge.

        Returns:
            Dict with ``id`` and ``acknowledged_at`` keys.

        Raises:
            UpsellRequired: On 403 forbidden_entitlement.
            RateLimited: On 429.
        """
        endpoint = f"/api/v1/memory/anomalies/{event_id}/ack"
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            return await self._api.post(endpoint, json={})
        except ForbiddenEntitlementError as exc:
            raise _map_403(exc) from exc
        except RateLimitedError as exc:
            raise _map_429(exc, endpoint) from exc


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_drift_event(raw: Dict[str, Any]) -> DriftEvent:
    return DriftEvent(
        id=raw["id"],
        instance_id=raw["instance_id"],
        module=raw["module"],
        old_hash=raw.get("old_hash"),
        new_hash=raw["new_hash"],
        probed_at=raw["probed_at"],
        detected_at=raw["detected_at"],
        severity=raw.get("severity", "low"),
        acknowledged_at=raw.get("acknowledged_at"),
        old_envelope_id=raw.get("old_envelope_id"),
        new_envelope_id=raw["new_envelope_id"],
    )


def _parse_anomaly_event(raw: Dict[str, Any]) -> AnomalyEvent:
    return AnomalyEvent(
        id=raw["id"],
        instance_id=raw["instance_id"],
        module=raw["module"],
        rule_key=raw["rule_key"],
        severity=raw.get("severity", "low"),
        summary=raw.get("summary", ""),
        detected_at=raw["detected_at"],
        acknowledged_at=raw.get("acknowledged_at"),
    )
