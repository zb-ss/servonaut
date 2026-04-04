"""Tests for AuthService."""
from __future__ import annotations

import asyncio
import json
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
