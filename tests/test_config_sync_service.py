"""Tests for ConfigSyncService."""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, AIProviderConfig, CustomServer, OVHConfig
from servonaut.services.config_sync_service import (
    ConfigSyncService,
    SENSITIVE_FIELDS,
    LOCAL_ONLY_FIELDS,
    PRESERVE_ON_EMPTY_FIELDS,
)
from servonaut.services import config_crypto
from servonaut.services.config_crypto import DecryptionError


PASS = "secure-passphrase-long"

CANNED_ENVELOPE = {
    "encryption": "aes-256-gcm",
    "data": "ZGF0YQ==",
    "salt": "c2FsdA==",
    "iv": "aXZpdg==",
    "tag": "dGFn",
}


def _run(coro):  # type: ignore[no-untyped-def]
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


@pytest.fixture
def mock_api():
    """Mock APIClient with a real spec so positional payload calls fail.

    Without ``spec=APIClient``, MagicMock would silently accept
    ``api.post(path, payload)`` and the test would pass — only to break
    in production where the real method enforces ``json=`` as
    keyword-only. Pinning the spec catches that regression at test time.
    """
    from servonaut.services.api_client import APIClient
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value={})
    api.post = AsyncMock(return_value={"version": 1, "id": "snap-1", "label": "host"})
    api.patch = AsyncMock(return_value={"id": "snap-1", "label": "new"})
    api.delete = AsyncMock(return_value={"success": True})
    return api


@pytest.fixture
def mock_config_manager():
    cm = MagicMock()
    config = AppConfig(
        default_username="ubuntu",
        ai_provider=AIProviderConfig(api_key="sk-secret-key"),
        abuseipdb_api_key="abuse-key-123",
        ovh=OVHConfig(application_key="ovh-ak", application_secret="ovh-as"),
    )
    cm.get.return_value = config
    cm._deserialize.return_value = config
    return cm


@pytest.fixture
def sync_service(mock_api, mock_config_manager):
    return ConfigSyncService(mock_api, mock_config_manager)


def _plaintext_sha256(config_data: dict) -> str:
    data_json = json.dumps(config_data, sort_keys=True, default=str)
    return hashlib.sha256(data_json.encode()).hexdigest()


# ---------------------------------------------------------------------------
# SENSITIVE_FIELDS coverage
# ---------------------------------------------------------------------------


class TestSensitiveFields:
    def test_includes_ovh_credentials(self):
        for field in (
            "ovh.application_key",
            "ovh.application_secret",
            "ovh.consumer_key",
            "ovh.client_id",
            "ovh.client_secret",
        ):
            assert field in SENSITIVE_FIELDS

    def test_includes_ai_and_abuseipdb(self):
        assert "ai_provider.api_key" in SENSITIVE_FIELDS
        assert "abuseipdb_api_key" in SENSITIVE_FIELDS

    def test_strip_removes_ovh_credentials(self, sync_service):
        config = AppConfig(ovh=OVHConfig(application_key="k", application_secret="s"))
        data = asdict(config)
        stripped = sync_service._strip_sensitive(data)
        assert "application_key" not in stripped.get("ovh", {})
        assert "application_secret" not in stripped.get("ovh", {})

    def test_strip_removes_local_only_fields(self, sync_service):
        data = asdict(AppConfig())
        stripped = sync_service._strip_sensitive(data)
        for field_name in LOCAL_ONLY_FIELDS:
            assert field_name not in stripped


# ---------------------------------------------------------------------------
# Apply remote config preserves sensitive + local-only fields
# ---------------------------------------------------------------------------


class TestApplyRemoteConfigPreservation:
    def test_ovh_credentials_preserved_when_remote_empty(self, mock_api):
        """Pulling an older snapshot (empty OVH) must not wipe local OVH creds."""
        cm = MagicMock()
        local_config = AppConfig(
            ovh=OVHConfig(application_key="local-ak", consumer_key="local-ck")
        )
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d  # return the dict we built
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig())  # empty OVH
        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        assert saved["ovh"]["application_key"] == "local-ak"
        assert saved["ovh"]["consumer_key"] == "local-ck"

    def test_custom_servers_preserved_when_remote_empty(self, mock_api):
        """Pulling an older snapshot (empty custom_servers) must not wipe local."""
        cm = MagicMock()
        local_config = AppConfig(
            custom_servers=[CustomServer(name="srv1", host="h1")],
        )
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig())  # empty custom_servers
        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        assert len(saved["custom_servers"]) == 1
        assert saved["custom_servers"][0]["name"] == "srv1"

    def test_custom_servers_overwritten_when_remote_non_empty(self, mock_api):
        """When remote has values, remote wins (last-push-wins semantics)."""
        cm = MagicMock()
        local_config = AppConfig(
            custom_servers=[CustomServer(name="local-srv", host="h-local")],
        )
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig(
            custom_servers=[CustomServer(name="remote-srv", host="h-remote")],
        ))
        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        assert len(saved["custom_servers"]) == 1
        assert saved["custom_servers"][0]["name"] == "remote-srv"

    def test_preserve_on_empty_fields_covers_expected_keys(self):
        for field in ("custom_servers", "scan_rules", "connection_profiles",
                      "connection_rules", "ip_ban_configs"):
            assert field in PRESERVE_ON_EMPTY_FIELDS


# ---------------------------------------------------------------------------
# Push — encryption is mandatory
# ---------------------------------------------------------------------------


class TestPush:
    def test_push_requires_passphrase(self, sync_service):
        sync_service._cached_passphrase = None
        with pytest.raises(ValueError, match="passphrase"):
            _run(sync_service.push())

    def test_push_encrypts_and_posts_envelope(self, sync_service, mock_api):
        with patch.object(config_crypto, "encrypt", return_value=CANNED_ENVELOPE):
            with patch.object(sync_service, "_save_probe"):
                _run(sync_service.push(passphrase=PASS, label="zbox"))

        payload = mock_api.post.call_args.kwargs["json"]
        assert mock_api.post.call_args[0][0] == "/api/v1/configs"
        assert payload["encryption"] == "aes-256-gcm"
        assert payload["data"] == CANNED_ENVELOPE["data"]
        assert payload["salt"] == CANNED_ENVELOPE["salt"]
        assert payload["iv"] == CANNED_ENVELOPE["iv"]
        assert payload["tag"] == CANNED_ENVELOPE["tag"]
        assert payload["label"] == "zbox"

    def test_push_hash_is_plaintext_sha256(self, sync_service, mock_api):
        with patch.object(config_crypto, "encrypt", return_value=CANNED_ENVELOPE):
            with patch.object(sync_service, "_save_probe"):
                _run(sync_service.push(passphrase=PASS))

        payload = mock_api.post.call_args.kwargs["json"]
        config = sync_service._config_manager.get()
        stripped = sync_service._strip_sensitive(asdict(config))
        assert payload["hash"] == _plaintext_sha256(stripped)

    def test_push_defaults_label_to_hostname(self, sync_service, mock_api):
        with patch.object(config_crypto, "encrypt", return_value=CANNED_ENVELOPE):
            with patch.object(sync_service, "_save_probe"):
                with patch("servonaut.services.config_sync_service.socket.gethostname",
                           return_value="test-host"):
                    _run(sync_service.push(passphrase=PASS))

        payload = mock_api.post.call_args.kwargs["json"]
        assert payload["label"] == "test-host"

    def test_push_caches_passphrase_on_success(self, sync_service):
        sync_service._cached_passphrase = None
        with patch.object(config_crypto, "encrypt", return_value=CANNED_ENVELOPE):
            with patch.object(sync_service, "_save_probe"):
                _run(sync_service.push(passphrase=PASS))
        assert sync_service._cached_passphrase == PASS

    def test_push_writes_probe_on_success(self, sync_service):
        with patch.object(config_crypto, "encrypt", return_value=CANNED_ENVELOPE):
            with patch.object(sync_service, "_save_probe") as mock_save_probe:
                _run(sync_service.push(passphrase=PASS))
        mock_save_probe.assert_called_once_with(PASS)

    def test_push_sanitizes_label(self, sync_service, mock_api):
        with patch.object(config_crypto, "encrypt", return_value=CANNED_ENVELOPE):
            with patch.object(sync_service, "_save_probe"):
                _run(sync_service.push(passphrase=PASS, label="  my\tdevice  "))

        payload = mock_api.post.call_args.kwargs["json"]
        assert payload["label"] == "mydevice" or payload["label"] == "my device"
        assert len(payload["label"]) <= 100


# ---------------------------------------------------------------------------
# Pull / restore — rejects legacy; requires passphrase
# ---------------------------------------------------------------------------


class TestPullAndRestore:
    def test_pull_legacy_raises(self, sync_service, mock_api):
        """Encrypt-only mode: a response without `encryption` is rejected."""
        mock_api.get.return_value = {"config_data": {"foo": "bar"}, "version": 3}
        with pytest.raises(DecryptionError):
            _run(sync_service.pull(passphrase=PASS))

    def test_pull_encrypted_calls_decrypt(self, sync_service, mock_api):
        mock_api.get.return_value = CANNED_ENVELOPE.copy()
        sync_service._cached_passphrase = None
        with patch.object(config_crypto, "decrypt", return_value='{"a": 1}') as mock_decrypt:
            with patch.object(sync_service, "_load_probe", return_value=None):
                result = _run(sync_service.pull(passphrase=PASS))
        mock_decrypt.assert_called_once()
        assert result == {"a": 1}

    def test_pull_wrong_passphrase_propagates(self, sync_service, mock_api):
        mock_api.get.return_value = CANNED_ENVELOPE.copy()
        with patch.object(config_crypto, "decrypt", side_effect=DecryptionError("bad")):
            with patch.object(sync_service, "_load_probe", return_value=None):
                with pytest.raises(DecryptionError):
                    _run(sync_service.pull(passphrase=PASS))

    def test_pull_requires_passphrase(self, sync_service, mock_api):
        mock_api.get.return_value = CANNED_ENVELOPE.copy()
        sync_service._cached_passphrase = None
        with pytest.raises(ValueError, match="passphrase"):
            _run(sync_service.pull(passphrase=None))

    def test_restore_by_id_calls_get_and_decrypt(self, sync_service, mock_api):
        mock_api.get.return_value = CANNED_ENVELOPE.copy()
        with patch.object(config_crypto, "decrypt", return_value='{"x": 2}'):
            with patch.object(sync_service, "_load_probe", return_value=None):
                result = _run(sync_service.restore_by_id("snap-42", passphrase=PASS))
        assert mock_api.get.call_args[0][0] == "/api/v1/configs/snap-42"
        assert result == {"x": 2}


# ---------------------------------------------------------------------------
# Snapshot list / rename / delete
# ---------------------------------------------------------------------------


class TestSnapshotManagement:
    def test_list_snapshots(self, sync_service, mock_api):
        mock_api.get.return_value = {"snapshots": [{"id": "a"}, {"id": "b"}]}
        result = _run(sync_service.list_snapshots())
        assert mock_api.get.call_args[0][0] == "/api/v1/configs?limit=30"
        assert len(result) == 2

    def test_rename_snapshot_calls_patch(self, sync_service, mock_api):
        _run(sync_service.rename_snapshot("snap-99", "Work Laptop"))
        mock_api.patch.assert_called_once()
        assert mock_api.patch.call_args[0][0] == "/api/v1/configs/snap-99"
        assert mock_api.patch.call_args.kwargs["json"] == {"label": "Work Laptop"}

    def test_rename_snapshot_empty_label_raises(self, sync_service):
        with pytest.raises(ValueError, match="empty"):
            _run(sync_service.rename_snapshot("snap-99", "   "))

    def test_rename_snapshot_trims_label(self, sync_service, mock_api):
        _run(sync_service.rename_snapshot("snap-99", "  Padded  "))
        assert mock_api.patch.call_args.kwargs["json"] == {"label": "Padded"}

    def test_delete_snapshot_calls_delete(self, sync_service, mock_api):
        result = _run(sync_service.delete_snapshot("snap-7"))
        mock_api.delete.assert_called_once()
        assert mock_api.delete.call_args[0][0] == "/api/v1/configs/snap-7"
        assert result["success"] is True


# ---------------------------------------------------------------------------
# Hash / diff / session helpers
# ---------------------------------------------------------------------------


class TestHashComputation:
    def test_hash_is_deterministic(self, sync_service):
        h1 = sync_service.compute_local_hash()
        h2 = sync_service.compute_local_hash()
        assert h1 == h2


class TestDiff:
    def test_diff_detects_changes(self, sync_service):
        remote_data = asdict(AppConfig(default_username="different-user"))
        changes = sync_service.diff(remote_data)
        assert "default_username" in changes

    def test_diff_ignores_local_only_fields(self, sync_service):
        remote_data = asdict(AppConfig())
        remote_data["instance_keys"] = {"i-123": "/different/key"}
        changes = sync_service.diff(remote_data)
        assert "instance_keys" not in changes


class TestSessionManagement:
    def test_clear_session_nulls_cached_passphrase(self, sync_service):
        sync_service._cached_passphrase = PASS
        sync_service.clear_session()
        assert sync_service._cached_passphrase is None

    def test_has_probe_true_when_probe_exists(self, sync_service):
        with patch.object(sync_service, "_load_probe", return_value="a" * 64):
            assert sync_service.has_probe() is True

    def test_has_probe_false_when_none(self, sync_service):
        with patch.object(sync_service, "_load_probe", return_value=None):
            assert sync_service.has_probe() is False


# ---------------------------------------------------------------------------
# Label sanitization
# ---------------------------------------------------------------------------


class TestLabelSanitization:
    def test_sanitize_trims(self):
        assert ConfigSyncService._sanitize_label("  host  ") == "host"

    def test_sanitize_truncates_to_100(self):
        label = "x" * 200
        assert len(ConfigSyncService._sanitize_label(label)) == 100

    def test_sanitize_strips_control_chars(self):
        label = "host\x00\x1bname"
        sanitized = ConfigSyncService._sanitize_label(label)
        assert "\x00" not in sanitized
        assert "\x1b" not in sanitized

    def test_sanitize_empty(self):
        assert ConfigSyncService._sanitize_label("") == ""
        assert ConfigSyncService._sanitize_label(None) == ""
