"""Tests for ConfigSyncService."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig, AIProviderConfig
from servonaut.services.config_sync_service import (
    ConfigSyncService,
    SENSITIVE_FIELDS,
    LOCAL_ONLY_FIELDS,
)


def _run(coro):  # type: ignore[no-untyped-def]
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


@pytest.fixture
def mock_api():
    api = MagicMock()
    api.get = AsyncMock(return_value={})
    api.post = AsyncMock(return_value={"version": 1, "config_hash": "abc123"})
    api.delete = AsyncMock(return_value={"success": True})
    return api


@pytest.fixture
def mock_config_manager():
    cm = MagicMock()
    config = AppConfig(
        default_username="ubuntu",
        ai_provider=AIProviderConfig(api_key="sk-secret-key"),
        abuseipdb_api_key="abuse-key-123",
    )
    cm.get.return_value = config
    cm._deserialize.return_value = config
    return cm


@pytest.fixture
def sync_service(mock_api, mock_config_manager):
    return ConfigSyncService(mock_api, mock_config_manager)


class TestConfigSyncService:
    def test_push_calls_api(self, sync_service, mock_api):
        result = _run(sync_service.push())
        assert result["version"] == 1
        mock_api.post.assert_called_once()
        call_args = mock_api.post.call_args
        assert call_args[0][0] == "/api/v1/configs/snapshots"

    def test_pull_calls_api(self, sync_service, mock_api):
        mock_api.get.return_value = {"config_data": {}, "version": 5}
        result = _run(sync_service.pull())
        assert result["version"] == 5

    def test_list_snapshots(self, sync_service, mock_api):
        mock_api.get.return_value = {"snapshots": [{"version": 1}, {"version": 2}]}
        result = _run(sync_service.list_snapshots())
        assert len(result) == 2


class TestSensitiveFieldStripping:
    def test_strip_removes_sensitive_fields(self, sync_service):
        config = AppConfig(
            ai_provider=AIProviderConfig(api_key="secret"),
            abuseipdb_api_key="also-secret",
        )
        data = asdict(config)
        stripped = sync_service._strip_sensitive(data)
        # api_key inside ai_provider should be gone
        assert "api_key" not in stripped.get("ai_provider", {})
        # abuseipdb_api_key should be gone
        assert "abuseipdb_api_key" not in stripped

    def test_strip_removes_local_only_fields(self, sync_service):
        config = AppConfig()
        data = asdict(config)
        stripped = sync_service._strip_sensitive(data)
        for field_name in LOCAL_ONLY_FIELDS:
            assert field_name not in stripped


class TestHashComputation:
    def test_same_config_same_hash(self, sync_service):
        h1 = sync_service.compute_local_hash()
        h2 = sync_service.compute_local_hash()
        assert h1 == h2

    def test_hash_is_deterministic(self, sync_service):
        config = AppConfig(default_username="test")
        data = sync_service._strip_sensitive(asdict(config))
        h1 = sync_service._compute_hash(data)
        h2 = sync_service._compute_hash(data)
        assert h1 == h2


class TestDiff:
    def test_diff_detects_changes(self, sync_service, mock_config_manager):
        remote_data = asdict(AppConfig(default_username="different-user"))
        changes = sync_service.diff(remote_data)
        assert "default_username" in changes

    def test_diff_ignores_local_only_fields(self, sync_service):
        remote_data = asdict(AppConfig())
        remote_data["instance_keys"] = {"i-123": "/different/key"}
        changes = sync_service.diff(remote_data)
        assert "instance_keys" not in changes
