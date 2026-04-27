"""Tests for AuthService."""
from __future__ import annotations

import asyncio
import json
import os
import stat
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.auth_service import AuthService, AuthToken, AUTH_FILE


def run(coro):
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


@pytest.fixture
def auth_service(tmp_path, monkeypatch):
    """AuthService with temp auth file."""
    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
    return AuthService()


@pytest.fixture
def authenticated_service(tmp_path, monkeypatch):
    """AuthService with a valid token pre-loaded."""
    auth_file = tmp_path / "auth.json"
    token_data = {
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "expires_at": time.time() + 3600,
        "plan": "solo",
        "entitlements": {
            "plan": "solo",
            "features": {
                "config_sync": True,
                "premium_ai": True,
                "gcp_support": True,
                "azure_support": True,
            },
        },
        "entitlements_fetched_at": time.time(),
    }
    auth_file.write_text(json.dumps(token_data))
    monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
    return AuthService()


class TestAuthServiceBasic:
    def test_unauthenticated_by_default(self, auth_service):
        assert not auth_service.is_authenticated
        assert auth_service.plan == "free"
        assert auth_service.access_token is None

    def test_has_feature_when_unauthenticated(self, auth_service):
        assert not auth_service.has_feature("config_sync")

    def test_authenticated_state(self, authenticated_service):
        assert authenticated_service.is_authenticated
        assert authenticated_service.plan == "solo"
        assert authenticated_service.access_token == "test-access-token"

    def test_has_feature_when_authenticated(self, authenticated_service):
        assert authenticated_service.has_feature("config_sync")
        assert authenticated_service.has_feature("premium_ai")
        assert not authenticated_service.has_feature("team_workspace")

    def test_has_feature_against_real_staging_payload(self, tmp_path, monkeypatch):
        """Regression: gates broke when staging started shipping flat
        entitlements alongside numeric quotas. Pin the real shape so a
        future "simplification" of the merge can't silently re-hide
        Memory Sync from a paying user.
        """
        staging_payload = {
            "config_snapshots": 30,
            "ai_requests_per_day": 50,
            "mcp_connections": 1,
            "team_members": 0,
            "ovh_mcp_operations": 50,
            "memory_sync": 1,
            "memory_drift": 1,
            "memory_digest": 1,
        }
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "access_token": "stg",
            "refresh_token": "stg-r",
            "expires_at": time.time() + 3600,
            "plan": "solo",
            "entitlements": staging_payload,
            "entitlements_fetched_at": time.time(),
        }))
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE", auth_file
        )
        svc = AuthService()
        assert svc.has_feature("memory_sync")
        assert svc.has_feature("memory_drift")
        assert svc.has_feature("memory_digest")
        # Plan-default fallback still applies for keys the backend
        # didn't enumerate (config_sync isn't in this payload).
        assert svc.has_feature("config_sync")
        # Numeric quotas (>1) must NOT be promoted to features.
        assert not svc.has_feature("config_snapshots")
        assert not svc.has_feature("ai_requests_per_day")

    def test_get_status_unauthenticated(self, auth_service):
        status = auth_service.get_status()
        assert not status["authenticated"]
        assert status["plan"] == "free"

    def test_get_status_authenticated(self, authenticated_service):
        status = authenticated_service.get_status()
        assert status["authenticated"]
        assert status["plan"] == "solo"


class TestAuthTokenPersistence:
    def test_token_saved_and_loaded(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)

        svc = AuthService()
        svc._token = AuthToken(
            access_token="abc",
            refresh_token="def",
            expires_at=time.time() + 3600,
            plan="solo",
        )
        svc._save_token()

        assert auth_file.exists()
        data = json.loads(auth_file.read_text())
        assert data["access_token"] == "abc"

        # Load in new instance
        svc2 = AuthService()
        assert svc2._token.access_token == "abc"

    def test_expired_token_not_authenticated(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        token_data = {
            "access_token": "expired",
            "refresh_token": "ref",
            "expires_at": time.time() - 100,
            "plan": "solo",
            "entitlements": {},
            "entitlements_fetched_at": 0,
        }
        auth_file.write_text(json.dumps(token_data))
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        assert not svc.is_authenticated

    def test_corrupt_auth_file(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        auth_file.write_text("not json")
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        assert not svc.is_authenticated


class TestAuthTokenFilePermissions:
    """auth.json holds bearer + refresh tokens; on-disk mode must be 0600."""

    def test_saved_file_is_mode_0600(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        svc._token = AuthToken(
            access_token="a", refresh_token="r",
            expires_at=time.time() + 3600, plan="solo",
        )
        svc._save_token()
        mode = auth_file.stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_startup_fixup_rechmods_world_readable_file(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        token_data = {
            "access_token": "a", "refresh_token": "r",
            "expires_at": time.time() + 3600, "plan": "solo",
            "entitlements": {}, "entitlements_fetched_at": 0,
        }
        auth_file.write_text(json.dumps(token_data))
        os.chmod(auth_file, 0o644)
        assert (auth_file.stat().st_mode & 0o777) == 0o644

        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        AuthService()  # triggers _load_token -> _ensure_secure_mode

        assert (auth_file.stat().st_mode & 0o777) == 0o600

    def test_atomic_write_leaves_no_tmp_file_on_success(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        svc._token = AuthToken(
            access_token="a", refresh_token="r",
            expires_at=time.time() + 3600, plan="solo",
        )
        svc._save_token()
        tmp = auth_file.with_suffix(auth_file.suffix + ".tmp")
        assert not tmp.exists(), "tmp file should have been replaced"
        assert auth_file.exists()

    def test_interrupted_write_preserves_original_file(self, tmp_path, monkeypatch):
        """Failure during write must not clobber the previous good token."""
        auth_file = tmp_path / "auth.json"
        # Seed a known-good token file first.
        good = {
            "access_token": "keep-me", "refresh_token": "keep-me-too",
            "expires_at": time.time() + 3600, "plan": "solo",
            "entitlements": {}, "entitlements_fetched_at": 0,
        }
        auth_file.write_text(json.dumps(good))
        os.chmod(auth_file, 0o600)
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)

        svc = AuthService()
        svc._token = AuthToken(
            access_token="NEW", refresh_token="NEW-REF",
            expires_at=time.time() + 3600, plan="solo",
        )
        # Force os.replace to blow up mid-save; original file must survive.
        with patch("servonaut.services.auth_service.os.replace",
                   side_effect=OSError("boom")):
            svc._save_token()

        data = json.loads(auth_file.read_text())
        assert data["access_token"] == "keep-me"
        tmp = auth_file.with_suffix(auth_file.suffix + ".tmp")
        # tmp may or may not exist depending on where OSError was raised; the
        # invariant we care about is that the live file wasn't partially written.


class TestAuthServiceLogout:
    def test_logout_clears_token(self, authenticated_service, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        # Re-save so the file exists
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        authenticated_service._save_token()

        with patch("servonaut.services.auth_service.HAS_HTTPX", False):
            run(authenticated_service.logout())

        assert not authenticated_service.is_authenticated
        assert authenticated_service._token is None
