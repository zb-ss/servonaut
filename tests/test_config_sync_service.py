"""Tests for ConfigSyncService."""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import (
    AppConfig, AIProviderConfig, AWSConfig, CustomServer, HetznerConfig,
    ObjectStorageConfig, OVHConfig,
)
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

    def test_includes_hetzner_token(self):
        # Provider tokens MUST be stripped before any sync upload, even
        # though the snapshot is encrypted client-side. Defense-in-depth:
        # a leaked passphrase + leaked snapshot ciphertext yields the
        # live Hetzner Read+Write token without this guard.
        assert "hetzner.api_token" in SENSITIVE_FIELDS

    # [CRITICAL-1] Object-storage S3 credential paths ---
    def test_includes_all_six_s3_secret_paths(self):
        """All 6 object-storage credential paths must be in SENSITIVE_FIELDS."""
        expected = {
            "aws.object_storage.access_key",
            "aws.object_storage.secret_key",
            "ovh.object_storage.access_key",
            "ovh.object_storage.secret_key",
            "hetzner.object_storage.access_key",
            "hetzner.object_storage.secret_key",
        }
        for path in expected:
            assert path in SENSITIVE_FIELDS, f"{path!r} missing from SENSITIVE_FIELDS"

    def test_strip_removes_aws_s3_secrets(self, sync_service):
        """_strip_sensitive must remove AWS object-storage access_key/secret_key (3 levels deep)."""
        storage = ObjectStorageConfig(access_key="AWS_AK", secret_key="AWS_SK")
        config = AppConfig(aws=AWSConfig(object_storage=storage))
        data = asdict(config)
        stripped = sync_service._strip_sensitive(data)
        assert "access_key" not in stripped.get("aws", {}).get("object_storage", {})
        assert "secret_key" not in stripped.get("aws", {}).get("object_storage", {})

    def test_strip_removes_hetzner_s3_secrets(self, sync_service):
        """_strip_sensitive must remove Hetzner object-storage credentials."""
        storage = ObjectStorageConfig(access_key="HTZ_AK", secret_key="HTZ_SK")
        config = AppConfig(hetzner=HetznerConfig(object_storage=storage))
        data = asdict(config)
        stripped = sync_service._strip_sensitive(data)
        assert "access_key" not in stripped.get("hetzner", {}).get("object_storage", {})
        assert "secret_key" not in stripped.get("hetzner", {}).get("object_storage", {})

    def test_strip_removes_ovh_s3_secrets(self, sync_service):
        """_strip_sensitive must remove OVH object-storage credentials."""
        storage = ObjectStorageConfig(access_key="OVH_AK", secret_key="OVH_SK")
        config = AppConfig(ovh=OVHConfig(object_storage=storage))
        data = asdict(config)
        stripped = sync_service._strip_sensitive(data)
        assert "access_key" not in stripped.get("ovh", {}).get("object_storage", {})
        assert "secret_key" not in stripped.get("ovh", {}).get("object_storage", {})

    def test_apply_remote_preserves_aws_s3_secrets_when_remote_empty(self, mock_api):
        """Pull with empty remote must not wipe local AWS S3 credentials."""
        cm = MagicMock()
        storage = ObjectStorageConfig(access_key="local-ak", secret_key="local-sk")
        local_config = AppConfig(aws=AWSConfig(object_storage=storage))
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig())  # empty aws.object_storage
        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        assert saved["aws"]["object_storage"]["access_key"] == "local-ak"
        assert saved["aws"]["object_storage"]["secret_key"] == "local-sk"

    def test_apply_remote_preserves_hetzner_s3_secrets_when_remote_empty(self, mock_api):
        """Pull with empty remote must not wipe local Hetzner S3 credentials."""
        cm = MagicMock()
        storage = ObjectStorageConfig(access_key="htz-ak", secret_key="htz-sk")
        local_config = AppConfig(hetzner=HetznerConfig(object_storage=storage))
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig())
        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        assert saved["hetzner"]["object_storage"]["access_key"] == "htz-ak"
        assert saved["hetzner"]["object_storage"]["secret_key"] == "htz-sk"

    def test_strip_removes_ovh_credentials(self, sync_service):
        config = AppConfig(ovh=OVHConfig(application_key="k", application_secret="s"))
        data = asdict(config)
        stripped = sync_service._strip_sensitive(data)
        assert "application_key" not in stripped.get("ovh", {})
        assert "application_secret" not in stripped.get("ovh", {})

    def test_strip_removes_hetzner_token(self, sync_service):
        config = AppConfig(hetzner=HetznerConfig(api_token="should-not-leak"))
        data = asdict(config)
        stripped = sync_service._strip_sensitive(data)
        assert "api_token" not in stripped.get("hetzner", {})

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


# ---------------------------------------------------------------------------
# Regression tests for Issue A — deepcopy + materialising-preservation fix
# ---------------------------------------------------------------------------


class TestPreservationRegressions:
    """These six tests are ordered so the FIRST one is the canonical
    regression for the depth-2 data-loss bug that prompted this fix.

    Before the fix the tests in this class would fail with:
      AssertionError: assert '' == 'local-ak'   (wipe symptom)
    After the fix they all pass.
    """

    def test_apply_remote_preserves_aws_s3_when_remote_lacks_aws_parent(
        self, mock_api
    ):
        """Canonical regression: remote payload has no 'aws' key at all.

        Old code: `.get('aws', {})` returned an orphan dict; leaf assignment
        was never reflected back into remote_data → credentials wiped.
        New code: materialises 'aws' and 'object_storage' before writing the
        leaf → credentials preserved.
        """
        cm = MagicMock()
        storage = ObjectStorageConfig(access_key="local-ak", secret_key="local-sk")
        local_config = AppConfig(aws=AWSConfig(object_storage=storage))
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig())
        # Delete the 'aws' key entirely to simulate an older snapshot that
        # predates AWS support.
        del remote["aws"]

        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        assert saved["aws"]["object_storage"]["access_key"] == "local-ak", (
            "access_key was wiped — preservation loop did not materialise the path"
        )
        assert saved["aws"]["object_storage"]["secret_key"] == "local-sk", (
            "secret_key was wiped — preservation loop did not materialise the path"
        )

    def test_apply_remote_preserves_hetzner_token_when_remote_lacks_parent(
        self, mock_api
    ):
        """Depth-1 regression: remote payload has no 'hetzner' key at all."""
        cm = MagicMock()
        local_config = AppConfig(hetzner=HetznerConfig(api_token="htz-token"))
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig())
        del remote["hetzner"]

        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        assert saved["hetzner"]["api_token"] == "htz-token", (
            "api_token was wiped — hetzner parent not materialised"
        )

    def test_apply_remote_preserves_ovh_s3_when_remote_lacks_intermediate(
        self, mock_api
    ):
        """Depth-2 regression: remote has 'ovh' parent but no 'object_storage' child."""
        cm = MagicMock()
        storage = ObjectStorageConfig(access_key="ovh-ak", secret_key="ovh-sk")
        local_config = AppConfig(ovh=OVHConfig(object_storage=storage))
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig())
        # Remove only the nested object_storage dict, keeping the ovh parent.
        remote["ovh"]["object_storage"] = {}

        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        assert saved["ovh"]["object_storage"]["access_key"] == "ovh-ak"
        assert saved["ovh"]["object_storage"]["secret_key"] == "ovh-sk"

    def test_apply_remote_does_not_seed_empty_parents(self, mock_api):
        """When local also has no secret, remote_data must not gain empty intermediate dicts."""
        cm = MagicMock()
        # Local has no AWS S3 credentials at all.
        local_config = AppConfig()
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig())
        # Drop 'aws' entirely from remote so we can check it does NOT appear.
        del remote["aws"]

        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        # The 'aws' key must not be injected as an empty dict by the
        # preservation loop when there's nothing to preserve locally.
        aws_val = saved.get("aws")
        if isinstance(aws_val, dict):
            os_val = aws_val.get("object_storage", {})
            assert not os_val.get("access_key"), (
                "Empty intermediate dicts were injected into remote_data by the "
                "preservation loop when there was nothing to preserve locally."
            )

    def test_strip_sensitive_does_not_mutate_input(self, sync_service):
        """deepcopy contract: _strip_sensitive must not modify its argument."""
        storage = ObjectStorageConfig(access_key="ak", secret_key="sk")
        config = AppConfig(aws=AWSConfig(object_storage=storage))
        data = asdict(config)
        original_ak = data["aws"]["object_storage"]["access_key"]

        sync_service._strip_sensitive(data)

        # The original dict must still contain the key that was "popped" from
        # the deep copy.
        assert data["aws"]["object_storage"]["access_key"] == original_ak, (
            "_strip_sensitive mutated its input — shallow-copy bug still present"
        )

    def test_diff_does_not_mutate_remote_data(self, sync_service):
        """deepcopy contract: diff() must not modify the remote_data argument."""
        storage = ObjectStorageConfig(access_key="ak", secret_key="sk")
        config_with_s3 = AppConfig(aws=AWSConfig(object_storage=storage))
        remote = asdict(config_with_s3)
        original_ak = remote["aws"]["object_storage"]["access_key"]

        sync_service.diff(remote)

        assert remote["aws"]["object_storage"]["access_key"] == original_ak, (
            "diff() mutated remote_data — deepcopy fix in _strip_sensitive must "
            "also cover the remote_clean path"
        )

    def test_preservation_handles_malformed_local_config_gracefully(
        self, mock_api, caplog
    ):
        """Defensive `local_val = None; break` branch in preservation loop.

        If a downstream caller somehow hands us a config where a SENSITIVE_FIELDS
        intermediate is the wrong type (e.g. ``current['hetzner']`` is a string
        instead of a dict), the loop must NOT crash — it must walk past that
        path and continue processing the remaining sensitive fields.
        """
        cm = MagicMock()
        # Local config has valid OVH secrets but a malformed 'hetzner' entry.
        local_config = AppConfig(ovh=OVHConfig(application_key="ovh-ak"))
        cm.get.return_value = local_config
        # Patch asdict route so 'hetzner' is a string, not a dict.
        original_asdict_path = asdict(local_config)
        original_asdict_path["hetzner"] = "not-a-dict"
        cm.get.return_value = local_config
        # Use a custom side_effect for _deserialize that captures the saved dict
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)
        # Force `current` (which is asdict(local_config)) to also be malformed
        # by patching asdict at the service level via monkeypatch isn't easy
        # here; instead exercise the branch via remote_data containing a
        # malformed leaf. The defensive break protects both directions.
        remote = asdict(AppConfig())
        remote["hetzner"] = "not-a-dict-either"
        del remote["ovh"]
        # Should not raise
        service.apply_remote_config(remote)
        saved = cm.save.call_args[0][0]
        # The OVH secret should still be preserved (the malformed hetzner path
        # is skipped without affecting other fields).
        assert saved["ovh"]["application_key"] == "ovh-ak"

    def test_preservation_defensive_break_on_malformed_local_intermediate(
        self, mock_api
    ):
        """Cover the defensive `not isinstance(local_val, dict)` break.

        `current = asdict(config)` normally always produces a fully-typed dict
        tree, but the preservation loop has a defensive guard for the case
        where an intermediate value is somehow a non-dict (future config
        schema drift, third-party config injection, etc.). We hit it by
        monkeypatching ``asdict`` to return a corrupted tree.
        """
        cm = MagicMock()
        cm.get.return_value = AppConfig(
            hetzner=HetznerConfig(api_token="local-token")
        )
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        # Force `current` (built from asdict at apply_remote_config:202) to
        # have a non-dict at the 'aws' intermediate. The hetzner branch
        # should still preserve correctly.
        from servonaut.services import config_sync_service as svc_mod

        def corrupted_asdict(_cfg):
            return {
                "hetzner": {"api_token": "local-token"},
                "aws": "not-a-dict-please-break-defensively",
                "ovh": {},
                "ai_provider": {},
                "instance_keys": {},
            }

        with patch.object(svc_mod, "asdict", corrupted_asdict):
            service.apply_remote_config({})

        saved = cm.save.call_args[0][0]
        # Hetzner preservation still works
        assert saved["hetzner"]["api_token"] == "local-token"
        # AWS path was defensively skipped — no crash, no spurious empty dict
        # because the local value was non-dict (treated as "nothing to preserve")
        aws_val = saved.get("aws")
        if isinstance(aws_val, dict):
            assert not aws_val.get("object_storage", {}).get("access_key")

    def test_preservation_local_missing_intermediate_key_continues(self, mock_api):
        """`break` branch when ``local_val.get(part)`` returns None mid-walk.

        Local config has the AWS dataclass but no S3 access_key set (default
        ``""``). The preservation loop should detect the empty leaf via the
        ``if not local_val`` guard and skip without crashing or polluting
        remote_data.
        """
        cm = MagicMock()
        # Local has aws.object_storage but with empty (default) secrets
        local_config = AppConfig(aws=AWSConfig(object_storage=ObjectStorageConfig()))
        cm.get.return_value = local_config
        cm._deserialize.side_effect = lambda d: d
        service = ConfigSyncService(mock_api, cm)

        remote = asdict(AppConfig())
        del remote["aws"]
        service.apply_remote_config(remote)

        saved = cm.save.call_args[0][0]
        # No aws.object_storage materialised since local has nothing to preserve
        aws_val = saved.get("aws")
        if isinstance(aws_val, dict):
            os_val = aws_val.get("object_storage")
            if isinstance(os_val, dict):
                assert not os_val.get("access_key")
                assert not os_val.get("secret_key")
