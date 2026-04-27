"""FleetService — reconcile local and remote fleet data.

Merges the local MemoryService index with the server-side GET /memory/fleet
response to produce a unified fleet view.  Used by FleetMemoryScreen to add
Source and Drift 7d columns.

Source values:
    ``local``  — instance exists only in local memory store.
    ``remote`` — instance exists only on the server (not yet probed locally).
    ``merged`` — exists in both local store and server fleet.

memory_age_bucket:
    ``green``   < 24h since last probe
    ``amber``   24–168h since last probe
    ``red``     ≥ 168h since last probe
    ``unknown`` never probed (probed_at is None / empty)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from servonaut.services.api_client import ForbiddenEntitlementError
from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    MemoryBackendError,
    RemoteFleet,
    RemoteFleetItem,
    UpsellRequired,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient
    from servonaut.services.memory.service import MemoryService
    from servonaut.services.memory.sync_service import MemorySyncService

logger = logging.getLogger(__name__)

# Age bucket thresholds in seconds
_BUCKET_GREEN_SECS = 24 * 3600       # < 24h
_BUCKET_AMBER_SECS = 7 * 24 * 3600  # < 7 days (168h)


class FleetService:
    """Merge local and remote fleet data into a unified row list.

    Args:
        api_client: Authenticated APIClient.
        memory_service: Local MemoryService for index reads.
        sync_service: Optional MemorySyncService (unused in current impl,
            reserved for future status injection).
    """

    def __init__(
        self,
        api_client: "APIClient",
        memory_service: "MemoryService",
        sync_service: Optional["MemorySyncService"] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self._api = api_client
        self._memory_service = memory_service
        self._sync_service = sync_service
        self._rate_limiter = rate_limiter or RateLimiter()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_remote_fleet(self) -> RemoteFleet:
        """GET /api/v1/memory/fleet — remote fleet overview.

        Raises:
            BackendMaintenance: On 503 feature_disabled.
            UpsellRequired: On 403 forbidden_entitlement.
            MemoryBackendError: On other API errors.
        """
        from servonaut.services.api_client import FeatureDisabledError, APIError
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            data = await self._api.get("/api/v1/memory/fleet")
            items: List[RemoteFleetItem] = []
            for raw in data.get("items", []):
                items.append(RemoteFleetItem(
                    instance=raw.get("instance", {}),
                    drift_count_7d=raw.get("drift_count_7d", 0),
                    memory_age=raw.get("memory_age", "unknown"),
                ))
            return RemoteFleet(
                total=data.get("total", 0),
                by_provider=data.get("by_provider", {}),
                oldest_last_probe_at=data.get("oldest_last_probe_at"),
                items=items,
            )
        except FeatureDisabledError as exc:
            raise BackendMaintenance("Server feature_disabled") from exc
        except ForbiddenEntitlementError as exc:
            plan = "teams" if (exc.details or {}).get("required_plan") == "teams" else "solo"
            raise UpsellRequired(plan) from exc
        except APIError as exc:
            raise MemoryBackendError(str(exc)) from exc

    async def get_merged_fleet(self) -> List[Dict[str, Any]]:
        """Merge local and remote fleet into a unified row list.

        Each row is a dict with keys:
            id, name, provider, status, modules, age,
            source (local|remote|merged), drift_7d (int)

        Remote errors (BackendMaintenance, UpsellRequired) result in a
        local-only list with a ``remote_error`` key set to the exception class name.
        """
        # Local index
        local_entries = self._get_local_entries()
        local_by_id: Dict[str, Dict[str, Any]] = {
            e["instance_id"]: e for e in local_entries
        }

        # Remote fleet (best-effort)
        remote_items: List[RemoteFleetItem] = []
        remote_error: Optional[str] = None
        try:
            fleet = await self.get_remote_fleet()
            remote_items = fleet.items
        except (BackendMaintenance, UpsellRequired) as exc:
            remote_error = type(exc).__name__
            logger.info("FleetService: remote fleet unavailable (%s) — local-only", remote_error)
        except Exception as exc:
            remote_error = f"error: {exc}"
            logger.warning("FleetService: remote fleet fetch failed: %s", exc)

        remote_by_id: Dict[str, RemoteFleetItem] = {}
        for item in remote_items:
            iid = item.instance.get("instance_id", item.instance.get("id", ""))
            if iid:
                remote_by_id[iid] = item

        # Union of all known IDs
        all_ids = set(local_by_id.keys()) | set(remote_by_id.keys())

        rows: List[Dict[str, Any]] = []
        for iid in all_ids:
            local = local_by_id.get(iid)
            remote = remote_by_id.get(iid)

            if local and remote:
                source = "merged"
            elif local:
                source = "local"
            else:
                source = "remote"

            if local:
                name = local.get("name", iid)
                provider = local.get("provider", "custom")
                modules_count = len(local.get("modules", []))
                probed_at = local.get("probed_at", "")
                age_bucket = self.memory_age_bucket(probed_at)
            elif remote:
                inst = remote.instance
                name = inst.get("display_name", iid)
                provider = inst.get("provider", "custom") or "custom"
                modules_count = 0
                probed_at = inst.get("last_probe_at")
                age_bucket = remote.memory_age

            drift_7d = remote.drift_count_7d if remote else 0

            row: Dict[str, Any] = {
                "id": iid,
                "name": name,
                "provider": provider,
                "source": source,
                "modules": modules_count,
                "age_bucket": age_bucket,
                "drift_7d": drift_7d,
            }
            if remote_error:
                row["remote_error"] = remote_error
            rows.append(row)

        # Sort: local/merged first (alphabetical by name), then remote-only
        rows.sort(key=lambda r: (0 if r["source"] != "remote" else 1, r["name"].lower()))
        return rows

    @staticmethod
    def memory_age_bucket(probed_at_iso: Optional[str]) -> str:
        """Classify a probed_at ISO-8601 timestamp into an age bucket.

        Args:
            probed_at_iso: ISO-8601 timestamp string, or None/empty.

        Returns:
            One of: ``"green"`` (<24h), ``"amber"`` (24–168h),
            ``"red"`` (≥168h), ``"unknown"`` (no timestamp).
        """
        if not probed_at_iso:
            return "unknown"
        try:
            probed_at = datetime.fromisoformat(probed_at_iso.rstrip("Z"))
            if not probed_at.tzinfo:
                probed_at = probed_at.replace(tzinfo=timezone.utc)
            age_secs = (datetime.now(tz=timezone.utc) - probed_at).total_seconds()
            if age_secs < _BUCKET_GREEN_SECS:
                return "green"
            if age_secs < _BUCKET_AMBER_SECS:
                return "amber"
            return "red"
        except (ValueError, TypeError):
            return "unknown"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_local_entries(self) -> List[Dict[str, Any]]:
        """Pull the local memory index via the MemoryService public API."""
        try:
            return self._memory_service.list_all()
        except Exception as exc:
            logger.warning("FleetService: could not read local index: %s", exc)
            return []
