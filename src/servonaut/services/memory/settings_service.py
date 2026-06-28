"""MemorySettingsService — fetch and patch user memory settings.

Features:
- 60-second GET cache (force-refreshable via force_refresh=True).
- PATCH with 422 → ValidationFailed domain exception.
- Local pre-validation for known fields before hitting the wire.
- Worker group: ``memory_settings`` (exclusive=True).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from servonaut.services.api_client import (
    ForbiddenEntitlementError,
    ValidationFailedError,
)
from servonaut.services.memory.interfaces import (
    AnomalyRule,
    MemorySettings,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)

# Cache TTL seconds
_SETTINGS_CACHE_TTL = 60.0

# Valid digest frequency values (spec §3.6)
_VALID_DIGEST_FREQUENCIES = frozenset({"weekly", "monthly", "off"})


class MemorySettingsService:
    """Manage user memory settings (digest, Mercure push, anomaly rules).

    Args:
        api_client: Authenticated APIClient.
        rate_limiter: Optional shared RateLimiter; defaults to a private one
            so the global ``api_global`` bucket is honoured even when this
            service is constructed in isolation.
    """

    def __init__(
        self,
        api_client: "APIClient",
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self._api = api_client
        self._rate_limiter = rate_limiter or RateLimiter()
        self._cached: Optional[MemorySettings] = None
        self._cached_at: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_settings(self, force_refresh: bool = False) -> MemorySettings:
        """GET /api/v1/memory/settings with 60s cache.

        Args:
            force_refresh: Bypass cache and fetch fresh from server.

        Returns:
            MemorySettings dataclass.

        Raises:
            UpsellRequired: On 403 forbidden_entitlement.
        """
        now = time.monotonic()
        if not force_refresh and self._cached is not None:
            if now - self._cached_at < _SETTINGS_CACHE_TTL:
                return self._cached

        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            data = await self._api.get("/api/v1/memory/settings")
        except ForbiddenEntitlementError as exc:
            plan = "teams" if (exc.details or {}).get("required_plan") == "teams" else "solo"
            raise UpsellRequired(plan) from exc

        settings = _parse_settings(data)
        self._cached = settings
        self._cached_at = now
        return settings

    async def patch_settings(self, updates: Dict[str, Any]) -> MemorySettings:
        """PATCH /api/v1/memory/settings.

        Args:
            updates: Dict of settings keys to update. Valid top-level keys:
                ``digest_frequency``, ``mercure_push_enabled``,
                ``ai_consent_mode``, ``ai_consent_modules``,
                ``ai_provider_ack_version``.
                Plus ``anomaly_rule:<rule_key>`` (bool) for rule toggles.

        Returns:
            Updated MemorySettings.

        Raises:
            ValidationFailed: On 422 with per-field errors.
            UpsellRequired: On 403 forbidden_entitlement.
        """
        try:
            await self._rate_limiter.acquire(RateLimitKey.GENERAL)
            data = await self._api.patch("/api/v1/memory/settings", json=updates)
        except ValidationFailedError as exc:
            errors = (exc.details or {}).get("errors", [])
            raise ValidationFailed(errors) from exc
        except ForbiddenEntitlementError as exc:
            plan = "teams" if (exc.details or {}).get("required_plan") == "teams" else "solo"
            raise UpsellRequired(plan) from exc

        settings = _parse_settings(data)
        self._cached = settings
        self._cached_at = time.monotonic()
        return settings

    async def set_anomaly_rule_enabled(self, rule_key: str, enabled: bool) -> MemorySettings:
        """Enable or disable a specific anomaly detection rule.

        Args:
            rule_key: Rule identifier (e.g. ``"drift.os_kernel"``).
            enabled: Whether to enable the rule.

        Returns:
            Updated MemorySettings.

        Raises:
            ValidationFailed: If the rule_key is unknown.
        """
        return await self.patch_settings({f"anomaly_rule:{rule_key}": enabled})

    async def set_digest_frequency(self, freq: str) -> MemorySettings:
        """Set the email digest frequency.

        Args:
            freq: One of ``"weekly"``, ``"monthly"``, ``"off"``.

        Returns:
            Updated MemorySettings.

        Raises:
            ValidationFailed: If *freq* is not a valid value (local pre-check).
        """
        if freq not in _VALID_DIGEST_FREQUENCIES:
            raise ValidationFailed([{
                "key": "digest_frequency",
                "error": f"must_be_weekly_monthly_or_off; got {freq!r}",
            }])
        return await self.patch_settings({"digest_frequency": freq})

    async def set_mercure_push(self, enabled: bool) -> MemorySettings:
        """Enable or disable Mercure SSE push.

        Args:
            enabled: Whether to enable Mercure push.

        Returns:
            Updated MemorySettings.

        Raises:
            ValidationFailed: If *enabled* is not a bool (local pre-check).
        """
        if not isinstance(enabled, bool):
            raise ValidationFailed([{
                "key": "mercure_push_enabled",
                "error": f"must_be_bool; got {type(enabled).__name__}",
            }])
        return await self.patch_settings({"mercure_push_enabled": enabled})

    async def set_auto_sync(self, enabled: bool) -> MemorySettings:
        """Enable or disable background auto-sync to the cloud.

        Args:
            enabled: Whether to enable auto-sync.

        Returns:
            Updated MemorySettings.

        Raises:
            ValidationFailed: If *enabled* is not a bool (local pre-check).
        """
        if not isinstance(enabled, bool):
            raise ValidationFailed([{
                "key": "auto_sync_enabled",
                "error": f"must_be_bool; got {type(enabled).__name__}",
            }])
        return await self.patch_settings({"auto_sync_enabled": enabled})


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_settings(data: Dict[str, Any]) -> MemorySettings:
    """Parse a raw settings dict into a MemorySettings dataclass."""
    anomaly_rules: Dict[str, AnomalyRule] = {}
    raw_rules = data.get("anomaly_rules", {})
    if isinstance(raw_rules, dict):
        for key, rule_data in raw_rules.items():
            if isinstance(rule_data, dict):
                anomaly_rules[key] = AnomalyRule(
                    key=key,
                    label=rule_data.get("label", key),
                    severity=rule_data.get("severity", "low"),
                    default_enabled=bool(rule_data.get("default_enabled", True)),
                    enabled=bool(rule_data.get("enabled", True)),
                )

    return MemorySettings(
        digest_frequency=data.get("digest_frequency", "off"),
        mercure_push_enabled=bool(data.get("mercure_push_enabled", False)),
        anomaly_rules=anomaly_rules,
        raw=data,
        ai_consent_mode=str(data.get("ai_consent_mode", "off") or "off"),
        auto_sync_enabled=bool(data.get("auto_sync_enabled", False)),
    )
