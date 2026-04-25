"""Unit tests for services/memory/export_service.py.

Covers:
- export(): entitlement gate, rate limiter acquired, tarball saved with
  correct path + permissions, Content-Disposition filename parsing,
  fallback filename generation
- get_signing_key(): cache hit, cache miss (fetches from server),
  key_id=None (latest), rotation mismatch
- verify_export(): valid signature → True, tampered sig → SignatureMismatchError,
  missing manifest → KeyError
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import io
import json
import os
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

import pytest

from servonaut.services.memory.export_service import (
    KeyRotationMismatchError,
    MemoryExportService,
    SignatureMismatchError,
    SigningKey,
    _parse_content_disposition,
)
from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    BetaWaitlist,
    UpsellRequired,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter
from servonaut.services.api_client import (
    ForbiddenEntitlementError,
    FeatureDisabledError,
    FeatureNotAvailableError,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_api():
    api = MagicMock()
    api.get = AsyncMock()
    api.get_bytes = AsyncMock()
    return api


@pytest.fixture
def mock_rate_limiter():
    rl = MagicMock(spec=RateLimiter)
    rl.acquire = AsyncMock()
    return rl


@pytest.fixture
def mock_auth():
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=True)
    return auth


@pytest.fixture
def service(mock_api, mock_rate_limiter, mock_auth, tmp_path):
    svc = MemoryExportService(
        api_client=mock_api,
        rate_limiter=mock_rate_limiter,
        auth_service=mock_auth,
    )
    # Override paths to use tmp_path for test isolation
    svc.EXPORT_DIR = tmp_path / "exports"
    svc.SIGNING_KEY_CACHE = tmp_path / "memory" / "signing_keys.json"
    return svc


@pytest.fixture
def service_no_entitlement(mock_api, mock_rate_limiter, tmp_path):
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=False)
    svc = MemoryExportService(
        api_client=mock_api,
        rate_limiter=mock_rate_limiter,
        auth_service=auth,
    )
    svc.EXPORT_DIR = tmp_path / "exports"
    svc.SIGNING_KEY_CACHE = tmp_path / "memory" / "signing_keys.json"
    return svc


def _make_tar_gz(members: dict) -> bytes:
    """Build an in-memory .tar.gz from a {name: bytes} dict."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_signing_key_response(key_id="key-1"):
    priv_key = b"\x01" * 32
    from nacl.signing import SigningKey as NaclSigningKey
    nacl_sk = NaclSigningKey(priv_key)
    vk_bytes = bytes(nacl_sk.verify_key)
    return {
        "key_id": key_id,
        "public_key_b64": base64.b64encode(vk_bytes).decode(),
        "algorithm": "ed25519",
    }, nacl_sk


# ---------------------------------------------------------------------------
# _parse_content_disposition (unit helper)
# ---------------------------------------------------------------------------

class TestParseContentDisposition:
    def test_quoted_filename(self):
        headers = {"content-disposition": 'attachment; filename="memory-export-user-2026-04-25.tar.gz"'}
        assert _parse_content_disposition(headers) == "memory-export-user-2026-04-25.tar.gz"

    def test_unquoted_filename(self):
        headers = {"content-disposition": "attachment; filename=export.tar.gz"}
        assert _parse_content_disposition(headers) == "export.tar.gz"

    def test_missing_header_returns_none(self):
        assert _parse_content_disposition({}) is None

    def test_empty_header_returns_none(self):
        assert _parse_content_disposition({"content-disposition": ""}) is None

    def test_special_chars_sanitised(self):
        headers = {"content-disposition": 'attachment; filename="../../evil.tar.gz"'}
        result = _parse_content_disposition(headers)
        # The path separators should be replaced with underscores
        assert result is not None
        assert "/" not in result


# ---------------------------------------------------------------------------
# export()
# ---------------------------------------------------------------------------

class TestExport:
    def test_entitlement_gate(self, service_no_entitlement):
        with pytest.raises(UpsellRequired) as exc_info:
            run(service_no_entitlement.export())
        assert exc_info.value.plan == "memory_compliance_export"

    def test_rate_limiter_acquired(self, service, mock_api, mock_rate_limiter):
        tarball = _make_tar_gz({"manifest.json": b"{}"})
        mock_api.get_bytes.return_value = (tarball, {"content-disposition": 'attachment; filename="test.tar.gz"'})
        run(service.export())
        mock_rate_limiter.acquire.assert_called_once_with(RateLimitKey.EXPORT)

    def test_tarball_saved_correct_path(self, service, mock_api, tmp_path):
        tarball_bytes = _make_tar_gz({"manifest.json": b"{}"})
        mock_api.get_bytes.return_value = (
            tarball_bytes,
            {"content-disposition": 'attachment; filename="myexport.tar.gz"'},
        )
        dest = run(service.export())
        assert dest == service.EXPORT_DIR / "myexport.tar.gz"
        assert dest.exists()
        assert dest.read_bytes() == tarball_bytes

    def test_tarball_file_permissions(self, service, mock_api, tmp_path):
        tarball_bytes = _make_tar_gz({"manifest.json": b"{}"})
        mock_api.get_bytes.return_value = (
            tarball_bytes,
            {"content-disposition": 'attachment; filename="myexport.tar.gz"'},
        )
        dest = run(service.export())
        mode = oct(os.stat(dest).st_mode & 0o777)
        assert mode == oct(0o600), f"Expected 0600, got {mode}"

    def test_fallback_filename_when_no_content_disposition(self, service, mock_api, tmp_path):
        tarball_bytes = _make_tar_gz({"manifest.json": b"{}"})
        mock_api.get_bytes.return_value = (tarball_bytes, {})
        dest = run(service.export())
        assert dest.name.startswith("memory-export-")
        assert dest.name.endswith(".tar.gz")

    def test_from_to_params_forwarded(self, service, mock_api):
        tarball_bytes = _make_tar_gz({"manifest.json": b"{}"})
        mock_api.get_bytes.return_value = (tarball_bytes, {"content-disposition": 'attachment; filename="e.tar.gz"'})
        run(service.export(from_="2026-01-01T00:00:00Z", to_="2026-04-25T23:59:59Z"))
        mock_api.get_bytes.assert_called_once_with(
            "/api/v1/memory/export",
            params={"from": "2026-01-01T00:00:00Z", "to": "2026-04-25T23:59:59Z"},
        )

    def test_no_params_when_none(self, service, mock_api):
        tarball_bytes = _make_tar_gz({"manifest.json": b"{}"})
        mock_api.get_bytes.return_value = (tarball_bytes, {"content-disposition": 'attachment; filename="e.tar.gz"'})
        run(service.export())
        mock_api.get_bytes.assert_called_once_with(
            "/api/v1/memory/export",
            params=None,
        )

    def test_forbidden_entitlement_from_api(self, service, mock_api):
        mock_api.get_bytes.side_effect = ForbiddenEntitlementError(
            code="forbidden_entitlement", message="no", status=403
        )
        with pytest.raises(UpsellRequired):
            run(service.export())

    def test_feature_disabled(self, service, mock_api):
        mock_api.get_bytes.side_effect = FeatureDisabledError(
            code="feature_disabled", message="maint", status=503
        )
        with pytest.raises(BackendMaintenance):
            run(service.export())

    def test_beta_waitlist(self, service, mock_api):
        mock_api.get_bytes.side_effect = FeatureNotAvailableError(
            code="feature_not_available", message="beta", status=403
        )
        with pytest.raises(BetaWaitlist):
            run(service.export())


# ---------------------------------------------------------------------------
# get_signing_key()
# ---------------------------------------------------------------------------

class TestGetSigningKey:
    def test_cache_miss_fetches_from_server_latest(self, service, mock_api):
        server_resp, nacl_sk = _make_signing_key_response("key-1")
        mock_api.get.return_value = server_resp

        result = run(service.get_signing_key(key_id=None))

        assert result.key_id == "key-1"
        assert isinstance(result.public_key, bytes)
        mock_api.get.assert_called_once_with("/api/v1/memory/export-signing-key")

    def test_cache_hit_skips_server(self, service, mock_api, tmp_path):
        # Pre-populate cache
        _, nacl_sk = _make_signing_key_response("key-1")
        vk_bytes = bytes(nacl_sk.verify_key)
        cache_data = {
            "key-1": {
                "public_key_b64": base64.b64encode(vk_bytes).decode(),
                "algorithm": "ed25519",
                "fetched_at": "2026-04-25T10:00:00",
            }
        }
        service.SIGNING_KEY_CACHE.parent.mkdir(parents=True, exist_ok=True)
        service.SIGNING_KEY_CACHE.write_text(json.dumps(cache_data))

        result = run(service.get_signing_key(key_id="key-1"))

        assert result.key_id == "key-1"
        mock_api.get.assert_not_called()

    def test_key_id_none_always_fetches(self, service, mock_api, tmp_path):
        # Even with a populated cache, key_id=None always fetches
        _, nacl_sk = _make_signing_key_response("key-2")
        vk_bytes = bytes(nacl_sk.verify_key)
        cache_data = {
            "key-1": {
                "public_key_b64": base64.b64encode(vk_bytes).decode(),
                "algorithm": "ed25519",
                "fetched_at": "2026-04-25T10:00:00",
            }
        }
        service.SIGNING_KEY_CACHE.parent.mkdir(parents=True, exist_ok=True)
        service.SIGNING_KEY_CACHE.write_text(json.dumps(cache_data))

        server_resp, _ = _make_signing_key_response("key-2")
        mock_api.get.return_value = server_resp

        result = run(service.get_signing_key(key_id=None))
        assert result.key_id == "key-2"
        mock_api.get.assert_called_once()

    def test_rotation_mismatch_raises(self, service, mock_api):
        # Request key-1, server returns key-2 (rotation happened)
        server_resp, _ = _make_signing_key_response("key-2")
        mock_api.get.return_value = server_resp

        with pytest.raises(KeyRotationMismatchError) as exc_info:
            run(service.get_signing_key(key_id="key-1"))

        assert exc_info.value.requested_key_id == "key-1"
        assert exc_info.value.received_key_id == "key-2"

    def test_rotation_mismatch_new_key_cached(self, service, mock_api):
        server_resp, _ = _make_signing_key_response("key-2")
        mock_api.get.return_value = server_resp

        try:
            run(service.get_signing_key(key_id="key-1"))
        except KeyRotationMismatchError:
            pass

        # key-2 should now be in the cache
        assert service.SIGNING_KEY_CACHE.exists()
        cache = json.loads(service.SIGNING_KEY_CACHE.read_text())
        assert "key-2" in cache

    def test_fetched_key_written_to_cache(self, service, mock_api):
        server_resp, _ = _make_signing_key_response("key-1")
        mock_api.get.return_value = server_resp

        run(service.get_signing_key(key_id=None))

        assert service.SIGNING_KEY_CACHE.exists()
        cache = json.loads(service.SIGNING_KEY_CACHE.read_text())
        assert "key-1" in cache

    def test_corrupt_cache_falls_back_to_server(self, service, mock_api):
        service.SIGNING_KEY_CACHE.parent.mkdir(parents=True, exist_ok=True)
        service.SIGNING_KEY_CACHE.write_text("not valid json {{{")

        server_resp, _ = _make_signing_key_response("key-1")
        mock_api.get.return_value = server_resp

        result = run(service.get_signing_key(key_id=None))
        assert result.key_id == "key-1"


# ---------------------------------------------------------------------------
# verify_export()
# ---------------------------------------------------------------------------

class TestVerifyExport:
    def _make_signed_tarball(self, tmp_path: Path, key_id: str = "key-1") -> tuple:
        """Return (tarball_path, nacl_signing_key) for a valid tarball."""
        from nacl.signing import SigningKey as NaclSigningKey

        priv_key = b"\x01" * 32
        nacl_sk = NaclSigningKey(priv_key)

        manifest = json.dumps({"signing_key_id": key_id, "count": 1}).encode()
        sig = bytes(nacl_sk.sign(manifest).signature)

        tarball_bytes = _make_tar_gz({
            "manifest.json": manifest,
            "manifest.sig": sig,
        })
        dest = tmp_path / "export.tar.gz"
        dest.write_bytes(tarball_bytes)
        return dest, nacl_sk

    def test_valid_signature_returns_true(self, service, mock_api, tmp_path):
        from nacl.signing import SigningKey as NaclSigningKey

        dest, nacl_sk = self._make_signed_tarball(tmp_path)
        vk_bytes = bytes(nacl_sk.verify_key)

        mock_api.get.return_value = {
            "key_id": "key-1",
            "public_key_b64": base64.b64encode(vk_bytes).decode(),
            "algorithm": "ed25519",
        }

        result = run(service.verify_export(dest))
        assert result is True

    def test_tampered_signature_raises(self, service, mock_api, tmp_path):
        from nacl.signing import SigningKey as NaclSigningKey

        _, nacl_sk = self._make_signed_tarball(tmp_path)
        vk_bytes = bytes(nacl_sk.verify_key)

        # Build tarball with a corrupted signature
        manifest = b'{"signing_key_id": "key-1", "count": 1}'
        bad_sig = b"\xff" * 64  # invalid signature

        tarball_bytes = _make_tar_gz({
            "manifest.json": manifest,
            "manifest.sig": bad_sig,
        })
        dest = tmp_path / "bad_export.tar.gz"
        dest.write_bytes(tarball_bytes)

        mock_api.get.return_value = {
            "key_id": "key-1",
            "public_key_b64": base64.b64encode(vk_bytes).decode(),
            "algorithm": "ed25519",
        }

        with pytest.raises(SignatureMismatchError):
            run(service.verify_export(dest))

    def test_missing_manifest_raises_key_error(self, service, mock_api, tmp_path):
        tarball_bytes = _make_tar_gz({"README.txt": b"hello"})
        dest = tmp_path / "no_manifest.tar.gz"
        dest.write_bytes(tarball_bytes)

        mock_api.get.return_value = {
            "key_id": "key-1",
            "public_key_b64": base64.b64encode(b"\x01" * 32).decode(),
            "algorithm": "ed25519",
        }

        with pytest.raises(KeyError):
            run(service.verify_export(dest))

    def test_manifest_without_signing_key_id_uses_latest(self, service, mock_api, tmp_path):
        from nacl.signing import SigningKey as NaclSigningKey

        priv_key = b"\x02" * 32
        nacl_sk = NaclSigningKey(priv_key)
        vk_bytes = bytes(nacl_sk.verify_key)

        # manifest without signing_key_id
        manifest = json.dumps({"count": 1}).encode()
        sig = bytes(nacl_sk.sign(manifest).signature)

        tarball_bytes = _make_tar_gz({"manifest.json": manifest, "manifest.sig": sig})
        dest = tmp_path / "export_nokey.tar.gz"
        dest.write_bytes(tarball_bytes)

        mock_api.get.return_value = {
            "key_id": "latest-key",
            "public_key_b64": base64.b64encode(vk_bytes).decode(),
            "algorithm": "ed25519",
        }

        result = run(service.verify_export(dest))
        assert result is True
        # Should have called get_signing_key with key_id=None
        mock_api.get.assert_called_once_with("/api/v1/memory/export-signing-key")
