"""Tests for MemorySettingsService — cache, patch, ValidationFailed, UpsellRequired."""

from __future__ import annotations

import time
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

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
from servonaut.services.api_client import APIClient
from servonaut.services.memory.settings_service import MemorySettingsService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_api_client(get_return=None, get_side_effect=None,
                     patch_return=None, patch_side_effect=None):
    client = MagicMock(spec=APIClient)
    client.get = AsyncMock(return_value=get_return or {})
    client.patch = AsyncMock(return_value=patch_return or {})
    if get_side_effect:
        client.get.side_effect = get_side_effect
    if patch_side_effect:
        client.patch.side_effect = patch_side_effect
    return client


def _settings_payload(
    digest_frequency="weekly",
    mercure_push_enabled=True,
    anomaly_rules=None,
    auto_sync_enabled=False,
) -> Dict[str, Any]:
    if anomaly_rules is None:
        anomaly_rules = {
            "drift.os_kernel": {
                "label": "Kernel drift",
                "severity": "high",
                "default_enabled": True,
                "enabled": True,
            }
        }
    return {
        "digest_frequency": digest_frequency,
        "mercure_push_enabled": mercure_push_enabled,
        "anomaly_rules": anomaly_rules,
        "auto_sync_enabled": auto_sync_enabled,
    }


def _make_service(api_client=None) -> MemorySettingsService:
    return MemorySettingsService(api_client=api_client or _make_api_client())


# ---------------------------------------------------------------------------
# get_settings tests
# ---------------------------------------------------------------------------

class TestGetSettings:

    @pytest.mark.asyncio
    async def test_get_settings_parses_response(self):
        """get_settings returns a fully populated MemorySettings."""
        api = _make_api_client(get_return=_settings_payload())
        svc = _make_service(api)
        settings = await svc.get_settings()
        assert isinstance(settings, MemorySettings)
        assert settings.digest_frequency == "weekly"
        assert settings.mercure_push_enabled is True
        assert "drift.os_kernel" in settings.anomaly_rules
        rule = settings.anomaly_rules["drift.os_kernel"]
        assert isinstance(rule, AnomalyRule)
        assert rule.severity == "high"
        assert rule.enabled is True

    @pytest.mark.asyncio
    async def test_get_settings_caches_result(self):
        """get_settings uses the 60s cache on second call."""
        api = _make_api_client(get_return=_settings_payload())
        svc = _make_service(api)
        await svc.get_settings()
        await svc.get_settings()
        # API should be called only once
        assert api.get.call_count == 1

    @pytest.mark.asyncio
    async def test_get_settings_force_refresh_bypasses_cache(self):
        """force_refresh=True bypasses the cache."""
        api = _make_api_client(get_return=_settings_payload())
        svc = _make_service(api)
        await svc.get_settings()
        await svc.get_settings(force_refresh=True)
        assert api.get.call_count == 2

    @pytest.mark.asyncio
    async def test_get_settings_403_raises_upsell_required(self):
        """get_settings: 403 → UpsellRequired."""
        api = _make_api_client(get_side_effect=ForbiddenEntitlementError(
            code="forbidden_entitlement", message="upgrade", status=403
        ))
        svc = _make_service(api)
        with pytest.raises(UpsellRequired):
            await svc.get_settings()

    @pytest.mark.asyncio
    async def test_get_settings_empty_anomaly_rules(self):
        """get_settings handles empty anomaly_rules dict."""
        api = _make_api_client(get_return=_settings_payload(anomaly_rules={}))
        svc = _make_service(api)
        settings = await svc.get_settings()
        assert settings.anomaly_rules == {}


# ---------------------------------------------------------------------------
# patch_settings tests
# ---------------------------------------------------------------------------

class TestPatchSettings:

    @pytest.mark.asyncio
    async def test_patch_settings_returns_updated_settings(self):
        """patch_settings returns updated MemorySettings on success."""
        api = _make_api_client(patch_return=_settings_payload(digest_frequency="monthly"))
        svc = _make_service(api)
        settings = await svc.patch_settings({"digest_frequency": "monthly"})
        assert settings.digest_frequency == "monthly"
        api.patch.assert_called_once_with(
            "/api/v1/memory/settings",
            json={"digest_frequency": "monthly"},
        )

    @pytest.mark.asyncio
    async def test_patch_settings_422_raises_validation_failed(self):
        """patch_settings: 422 validation_failed → ValidationFailed with errors."""
        errors = [{"key": "digest_frequency", "error": "must_be_weekly_monthly_or_off"}]
        api = _make_api_client(patch_side_effect=ValidationFailedError(
            code="validation_failed",
            message="bad input",
            status=422,
            details={"errors": errors},
        ))
        svc = _make_service(api)
        with pytest.raises(ValidationFailed) as exc_info:
            await svc.patch_settings({"digest_frequency": "bad_value"})
        assert exc_info.value.errors == errors

    @pytest.mark.asyncio
    async def test_patch_settings_403_raises_upsell_required(self):
        """patch_settings: 403 → UpsellRequired."""
        api = _make_api_client(patch_side_effect=ForbiddenEntitlementError(
            code="forbidden_entitlement", message="upgrade", status=403
        ))
        svc = _make_service(api)
        with pytest.raises(UpsellRequired):
            await svc.patch_settings({"digest_frequency": "weekly"})

    @pytest.mark.asyncio
    async def test_patch_settings_updates_cache(self):
        """Successful patch_settings updates the local cache."""
        api = _make_api_client(patch_return=_settings_payload(digest_frequency="off"))
        svc = _make_service(api)
        settings = await svc.patch_settings({"digest_frequency": "off"})
        # Now get_settings should return cached (no extra API call)
        api2 = _make_api_client(get_return=_settings_payload())
        svc._api = api2
        cached = await svc.get_settings()
        assert cached.digest_frequency == "off"  # from patch cache
        api2.get.assert_not_called()


# ---------------------------------------------------------------------------
# Convenience methods
# ---------------------------------------------------------------------------

class TestConvenienceMethods:

    @pytest.mark.asyncio
    async def test_set_digest_frequency_valid_values(self):
        """set_digest_frequency accepts weekly/monthly/off."""
        for freq in ("weekly", "monthly", "off"):
            api = _make_api_client(patch_return=_settings_payload(digest_frequency=freq))
            svc = _make_service(api)
            settings = await svc.set_digest_frequency(freq)
            assert settings.digest_frequency == freq

    @pytest.mark.asyncio
    async def test_set_digest_frequency_invalid_raises_validation_failed(self):
        """set_digest_frequency: invalid value → ValidationFailed (local check)."""
        svc = _make_service()
        with pytest.raises(ValidationFailed) as exc_info:
            await svc.set_digest_frequency("daily")
        assert exc_info.value.errors[0]["key"] == "digest_frequency"

    @pytest.mark.asyncio
    async def test_set_mercure_push_bool_true(self):
        """set_mercure_push(True) sends correct patch."""
        api = _make_api_client(patch_return=_settings_payload(mercure_push_enabled=True))
        svc = _make_service(api)
        settings = await svc.set_mercure_push(True)
        assert settings.mercure_push_enabled is True

    @pytest.mark.asyncio
    async def test_set_mercure_push_non_bool_raises_validation_failed(self):
        """set_mercure_push: non-bool → ValidationFailed (local check)."""
        svc = _make_service()
        with pytest.raises(ValidationFailed) as exc_info:
            await svc.set_mercure_push("yes")  # type: ignore[arg-type]
        assert "mercure_push_enabled" in exc_info.value.errors[0]["key"]

    @pytest.mark.asyncio
    async def test_set_anomaly_rule_enabled(self):
        """set_anomaly_rule_enabled sends anomaly_rule:<key> patch."""
        payload = _settings_payload()
        payload["anomaly_rules"]["drift.os_kernel"]["enabled"] = False
        api = _make_api_client(patch_return=payload)
        svc = _make_service(api)
        settings = await svc.set_anomaly_rule_enabled("drift.os_kernel", False)
        api.patch.assert_called_once_with(
            "/api/v1/memory/settings",
            json={"anomaly_rule:drift.os_kernel": False},
        )

    @pytest.mark.asyncio
    async def test_set_auto_sync_true_sends_correct_patch(self):
        """set_auto_sync(True) sends {"auto_sync_enabled": True} via PATCH."""
        api = _make_api_client(patch_return=_settings_payload(auto_sync_enabled=True))
        svc = _make_service(api)
        settings = await svc.set_auto_sync(True)
        assert settings.auto_sync_enabled is True
        api.patch.assert_called_once_with(
            "/api/v1/memory/settings",
            json={"auto_sync_enabled": True},
        )

    @pytest.mark.asyncio
    async def test_set_auto_sync_false_sends_correct_patch(self):
        """set_auto_sync(False) sends {"auto_sync_enabled": False} via PATCH."""
        api = _make_api_client(patch_return=_settings_payload(auto_sync_enabled=False))
        svc = _make_service(api)
        settings = await svc.set_auto_sync(False)
        assert settings.auto_sync_enabled is False
        api.patch.assert_called_once_with(
            "/api/v1/memory/settings",
            json={"auto_sync_enabled": False},
        )

    @pytest.mark.asyncio
    async def test_set_auto_sync_non_bool_raises_validation_failed(self):
        """set_auto_sync: non-bool → ValidationFailed (local pre-check)."""
        svc = _make_service()
        with pytest.raises(ValidationFailed) as exc_info:
            await svc.set_auto_sync("yes")  # type: ignore[arg-type]
        assert "auto_sync_enabled" in exc_info.value.errors[0]["key"]


# ---------------------------------------------------------------------------
# auto_sync_enabled parse
# ---------------------------------------------------------------------------


class TestAutoSyncParsing:

    @pytest.mark.asyncio
    async def test_get_settings_parses_auto_sync_enabled_true(self):
        """get_settings parses auto_sync_enabled=True from the server payload."""
        api = _make_api_client(get_return=_settings_payload(auto_sync_enabled=True))
        svc = _make_service(api)
        settings = await svc.get_settings()
        assert settings.auto_sync_enabled is True

    @pytest.mark.asyncio
    async def test_get_settings_parses_auto_sync_enabled_false(self):
        """get_settings parses auto_sync_enabled=False (the default)."""
        api = _make_api_client(get_return=_settings_payload(auto_sync_enabled=False))
        svc = _make_service(api)
        settings = await svc.get_settings()
        assert settings.auto_sync_enabled is False

    @pytest.mark.asyncio
    async def test_get_settings_auto_sync_defaults_false_when_absent(self):
        """get_settings returns auto_sync_enabled=False when key is absent from response."""
        payload = {
            "digest_frequency": "weekly",
            "mercure_push_enabled": True,
            "anomaly_rules": {},
        }
        api = _make_api_client(get_return=payload)
        svc = _make_service(api)
        settings = await svc.get_settings()
        assert settings.auto_sync_enabled is False
