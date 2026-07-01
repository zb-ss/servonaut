"""Tests for the personal (user-scope) secrets-config plumbing — Layer A2.

Mirrors the team-scope suites (test_secrets_config_cache /
test_secrets_config_api_client / test_secret_provider_resolver) for the
new ``/api/v1/me/secrets-config`` path:

- :meth:`APIClient.get_user_secrets_config` — wire-contract translation
  (200 → dict, 404 → None, 402 → PaymentRequiredError, 403 →
  ForbiddenError). No slug; the ``/me`` route is keyed on the bearer.
- :class:`AuthService` personal cache helpers — TTL / presence / persist
  / clear, all backed by the isolated ``user_*`` fields.
- Precedence (``cached_secrets_config`` / ``secrets_config_source``):
  team-in-team-context → personal → LocalProvider — plus the critical
  cache-ISOLATION property (a personal 402/403 must NOT clear the team
  cache, and vice versa).
- :func:`fetch_and_apply_user_secrets_config` /
  :func:`refresh_all_secrets_configs` — status-code handling + fan-out.
- ``config_source`` surfaced through :func:`compute_secrets_status`.

All against a MOCKED endpoint (no network).
"""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.api_client import (
    APIClient,
    APIError,
    ForbiddenError,
    PaymentRequiredError,
)
from servonaut.services.auth_service import (
    SECRETS_CACHE_TTL,
    SECRETS_PAYLOAD_MAX_BYTES,
    AuthService,
    AuthToken,
)
from servonaut.services.secret_provider_resolver import (
    fetch_and_apply_user_secrets_config,
    refresh_all_secrets_configs,
)


def run(coro):
    return asyncio.run(coro)


_USER_WIRE = {
    "provider": "bitwarden",
    "config": {
        "project_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "token_env_var": "BWS_ACCESS_TOKEN",
    },
    "updated_at": "2026-06-30T12:00:00Z",
}
_TEAM_WIRE = {
    "provider": "bitwarden",
    "config": {
        "project_id": "11111111-2222-3333-4444-555555555555",
        "token_env_var": "BWS_ACCESS_TOKEN",
    },
    "updated_at": "2026-06-30T09:00:00Z",
}


# ---------------------------------------------------------------------------
# APIClient.get_user_secrets_config — wire contract translation
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code, body=None, *, text="", content_type="application/json"):
        self.status_code = status_code
        self._body = body
        self.text = text if text else (json.dumps(body) if body is not None else "")
        self.headers = {"content-type": content_type}

    def json(self):
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body


def _patch_httpx_with(response: _FakeResponse):
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.request = AsyncMock(return_value=response)
    return patch(
        "servonaut.services.api_client.httpx.AsyncClient",
        return_value=client,
    )


@pytest.fixture
def api_client() -> APIClient:
    auth = MagicMock()
    auth.access_token = "my-bearer-token"  # placeholder; value is irrelevant to the mock
    auth.refresh_token = AsyncMock(return_value=False)
    return APIClient(auth)


class TestGetUserSecretsConfig:
    def test_returns_parsed_payload_on_200(self, api_client):
        with _patch_httpx_with(_FakeResponse(200, _USER_WIRE)):
            result = run(api_client.get_user_secrets_config())
        assert result == _USER_WIRE

    def test_url_path_is_me_secrets_config(self, api_client):
        """Pin the ``/api/v1/me/secrets-config`` path — a future refactor
        must not silently point the personal fetch at the team route."""
        with _patch_httpx_with(_FakeResponse(200, {
            "provider": "local", "config": {}, "updated_at": "",
        })) as patched:
            run(api_client.get_user_secrets_config())
        call_args = patched.return_value.request.call_args
        url = call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs["url"]
        assert "/api/v1/me/secrets-config" in url
        assert "/teams/" not in url

    def test_404_returns_none(self, api_client):
        with _patch_httpx_with(_FakeResponse(
            404, {"error": {"code": "not_found", "message": "No config"}},
        )):
            result = run(api_client.get_user_secrets_config())
        assert result is None

    def test_402_raises_payment_required_with_upgrade_url(self, api_client):
        body = {
            "error": "payment_required",
            "message": "Secrets management requires a Solo or Teams subscription.",
            "required_tier": "solo",
            "upgrade_url": "https://servonaut.dev/pricing",
            "doc_url": "https://servonaut.dev/docs/secrets-management",
        }
        with _patch_httpx_with(_FakeResponse(402, body)):
            with pytest.raises(PaymentRequiredError) as exc_info:
                run(api_client.get_user_secrets_config())
        assert exc_info.value.status == 402
        assert exc_info.value.upgrade_url == "https://servonaut.dev/pricing"

    def test_403_raises_forbidden(self, api_client):
        with _patch_httpx_with(_FakeResponse(
            403, {"error": "forbidden", "message": "nope"},
        )):
            with pytest.raises(ForbiddenError):
                run(api_client.get_user_secrets_config())


# ---------------------------------------------------------------------------
# AuthService personal-cache helpers + backward compat
# ---------------------------------------------------------------------------


class TestAuthTokenUserSecretsFields:
    def test_defaults_present(self):
        tok = AuthToken(
            access_token="a", refresh_token="r",
            expires_at=time.time() + 3600, plan="solo",
        )
        assert tok.user_secrets_config == {}
        assert tok.user_secrets_fetched_at == 0.0

    def test_legacy_auth_json_loads_with_defaults(self, tmp_path, monkeypatch):
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "access_token": "abc", "refresh_token": "def",
            "expires_at": time.time() + 3600, "plan": "solo",
            # No user_secrets_* — pre-A2.
        }))
        monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
        svc = AuthService()
        assert svc.is_authenticated
        assert svc._token.user_secrets_config == {}
        assert svc._token.user_secrets_fetched_at == 0.0


@pytest.fixture
def authed_service(tmp_path, monkeypatch) -> AuthService:
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({
        "access_token": "A", "refresh_token": "R",
        "expires_at": time.time() + 3600, "plan": "solo",
        "entitlements": {}, "entitlements_fetched_at": 0,
    }))
    monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", auth_file)
    return AuthService()


class TestUserSecretsCacheHelpers:
    def test_not_present_initially(self, authed_service):
        assert authed_service.is_user_secrets_cache_present() is False
        assert authed_service.is_user_secrets_cache_fresh() is False

    def test_apply_persists_to_disk(self, authed_service):
        authed_service.apply_user_secrets_config(_USER_WIRE)
        assert authed_service.is_user_secrets_cache_present() is True
        cfg = authed_service.cached_user_secrets_config()
        assert cfg.provider == "bitwarden"
        assert cfg.config["project_id"] == _USER_WIRE["config"]["project_id"]
        # Re-instantiate against the same on-disk file — proves persistence.
        reloaded = AuthService()
        assert reloaded.is_user_secrets_cache_present() is True
        assert reloaded.cached_user_secrets_config().provider == "bitwarden"

    def test_fresh_within_ttl(self, authed_service):
        authed_service.apply_user_secrets_config({
            "provider": "local", "config": {}, "updated_at": "",
        })
        assert authed_service.is_user_secrets_cache_fresh() is True

    def test_stale_past_ttl_still_present(self, authed_service):
        authed_service.apply_user_secrets_config({
            "provider": "local", "config": {}, "updated_at": "",
        })
        authed_service._token.user_secrets_fetched_at = (
            time.time() - SECRETS_CACHE_TTL - 1
        )
        assert authed_service.is_user_secrets_cache_fresh() is False
        assert authed_service.is_user_secrets_cache_present() is True

    def test_apply_defensive_copy(self, authed_service):
        payload = dict(_USER_WIRE)
        authed_service.apply_user_secrets_config(payload)
        payload["provider"] = "POISONED"
        assert authed_service.cached_user_secrets_config().provider == "bitwarden"

    def test_apply_rejects_oversize(self, authed_service):
        big = {"provider": "local", "config": {"x": "y" * SECRETS_PAYLOAD_MAX_BYTES}}
        authed_service.apply_user_secrets_config(big)
        # Refused — nothing persisted.
        assert authed_service.is_user_secrets_cache_present() is False

    def test_clear(self, authed_service):
        authed_service.apply_user_secrets_config(_USER_WIRE)
        authed_service.clear_user_secrets_cache()
        assert authed_service.is_user_secrets_cache_present() is False
        assert authed_service.cached_user_secrets_config().provider == "local"


# ---------------------------------------------------------------------------
# Precedence: team-in-team-context → personal → LocalProvider
# ---------------------------------------------------------------------------


class TestPrecedence:
    def test_local_default_when_both_empty(self, authed_service):
        assert authed_service.secrets_config_source() is None
        assert authed_service.cached_secrets_config().provider == "local"

    def test_personal_wins_when_no_team(self, authed_service):
        authed_service.apply_user_secrets_config(_USER_WIRE)
        assert authed_service.secrets_config_source() == "user"
        cfg = authed_service.cached_secrets_config()
        assert cfg.config["project_id"] == _USER_WIRE["config"]["project_id"]

    def test_team_wins_over_personal(self, authed_service):
        authed_service.apply_user_secrets_config(_USER_WIRE)
        authed_service.apply_secrets_config(_TEAM_WIRE)
        assert authed_service.secrets_config_source() == "team"
        cfg = authed_service.cached_secrets_config()
        assert cfg.config["project_id"] == _TEAM_WIRE["config"]["project_id"]

    def test_falls_back_to_personal_when_team_cleared(self, authed_service):
        authed_service.apply_user_secrets_config(_USER_WIRE)
        authed_service.apply_secrets_config(_TEAM_WIRE)
        authed_service.clear_secrets_cache()  # team gone
        assert authed_service.secrets_config_source() == "user"
        cfg = authed_service.cached_secrets_config()
        assert cfg.config["project_id"] == _USER_WIRE["config"]["project_id"]


class TestCacheIsolation:
    """The property the precedence layer depends on: the two caches are
    fully independent — clearing/applying one never touches the other."""

    def test_clear_personal_leaves_team_intact(self, authed_service):
        authed_service.apply_secrets_config(_TEAM_WIRE)
        authed_service.apply_user_secrets_config(_USER_WIRE)
        authed_service.clear_user_secrets_cache()
        assert authed_service.is_secrets_cache_present() is True
        assert authed_service.is_user_secrets_cache_present() is False

    def test_clear_team_leaves_personal_intact(self, authed_service):
        authed_service.apply_secrets_config(_TEAM_WIRE)
        authed_service.apply_user_secrets_config(_USER_WIRE)
        authed_service.clear_secrets_cache()
        assert authed_service.is_user_secrets_cache_present() is True
        assert authed_service.is_secrets_cache_present() is False


# ---------------------------------------------------------------------------
# fetch_and_apply_user_secrets_config
# ---------------------------------------------------------------------------


def _client(return_value=None, side_effect=None) -> MagicMock:
    client = MagicMock()
    if side_effect is not None:
        client.get_user_secrets_config = AsyncMock(side_effect=side_effect)
    else:
        client.get_user_secrets_config = AsyncMock(return_value=return_value)
    return client


class TestFetchAndApplyUser:
    def test_200_applies(self, authed_service):
        client = _client(return_value=_USER_WIRE)
        ok = run(fetch_and_apply_user_secrets_config(authed_service, client))
        assert ok is True
        assert authed_service.is_user_secrets_cache_present() is True

    def test_404_clears_personal_only(self, authed_service):
        authed_service.apply_secrets_config(_TEAM_WIRE)
        authed_service.apply_user_secrets_config(_USER_WIRE)
        client = _client(return_value=None)
        ok = run(fetch_and_apply_user_secrets_config(authed_service, client))
        assert ok is True
        assert authed_service.is_user_secrets_cache_present() is False
        # Isolation: team cache survives.
        assert authed_service.is_secrets_cache_present() is True

    def test_402_clears_personal_only(self, authed_service):
        authed_service.apply_secrets_config(_TEAM_WIRE)
        authed_service.apply_user_secrets_config(_USER_WIRE)
        err = PaymentRequiredError(code="payment_required", message="upgrade", status=402)
        client = _client(side_effect=err)
        ok = run(fetch_and_apply_user_secrets_config(authed_service, client))
        assert ok is True
        assert authed_service.is_user_secrets_cache_present() is False
        assert authed_service.is_secrets_cache_present() is True

    def test_403_clears_personal_only(self, authed_service):
        authed_service.apply_secrets_config(_TEAM_WIRE)
        authed_service.apply_user_secrets_config(_USER_WIRE)
        err = ForbiddenError(code="forbidden", message="no", status=403)
        client = _client(side_effect=err)
        ok = run(fetch_and_apply_user_secrets_config(authed_service, client))
        assert ok is True
        assert authed_service.is_user_secrets_cache_present() is False
        assert authed_service.is_secrets_cache_present() is True

    def test_transient_api_error_keeps_cache(self, authed_service):
        authed_service.apply_user_secrets_config(_USER_WIRE)
        err = APIError(code="server_error", message="boom", status=503)
        client = _client(side_effect=err)
        ok = run(fetch_and_apply_user_secrets_config(authed_service, client))
        assert ok is False
        assert authed_service.is_user_secrets_cache_present() is True

    def test_user_id_echo_mismatch_still_applies(self, authed_service):
        authed_service._token.user_id = 42
        payload = dict(_USER_WIRE, user_id=99)
        client = _client(return_value=payload)
        ok = run(fetch_and_apply_user_secrets_config(authed_service, client))
        assert ok is True  # never a hard failure
        assert authed_service.is_user_secrets_cache_present() is True


# ---------------------------------------------------------------------------
# refresh_all_secrets_configs — fan-out + isolation
# ---------------------------------------------------------------------------


class _DualClient:
    def __init__(self, *, user=None, user_exc=None, team=None, team_exc=None):
        self._user, self._user_exc = user, user_exc
        self._team, self._team_exc = team, team_exc

    async def get_user_secrets_config(self):
        if self._user_exc is not None:
            raise self._user_exc
        return self._user

    async def get_team_secrets_config(self, slug):
        if self._team_exc is not None:
            raise self._team_exc
        return self._team


class TestRefreshAll:
    def test_fetches_both_when_slug_present(self, authed_service):
        client = _DualClient(user=_USER_WIRE, team=_TEAM_WIRE)
        run(refresh_all_secrets_configs(authed_service, client, slug="acme"))
        assert authed_service.is_user_secrets_cache_present() is True
        assert authed_service.is_secrets_cache_present() is True

    def test_personal_only_when_no_slug(self, authed_service):
        client = _DualClient(user=_USER_WIRE)
        # get_team should never be called — omit it from the client entirely.
        client.get_team_secrets_config = AsyncMock(
            side_effect=AssertionError("team fetch must not run without a slug")
        )
        run(refresh_all_secrets_configs(authed_service, client, slug=None))
        assert authed_service.is_user_secrets_cache_present() is True
        assert authed_service.is_secrets_cache_present() is False

    def test_personal_403_does_not_clear_team(self, authed_service):
        """The headline isolation case: a personal-scope 403 during a
        parallel refresh must leave a freshly-fetched team config intact."""
        authed_service.apply_user_secrets_config(_USER_WIRE)
        err = ForbiddenError(code="forbidden", message="no", status=403)
        client = _DualClient(user_exc=err, team=_TEAM_WIRE)
        run(refresh_all_secrets_configs(authed_service, client, slug="acme"))
        assert authed_service.is_user_secrets_cache_present() is False
        assert authed_service.is_secrets_cache_present() is True
        # Precedence still resolves to the team config.
        assert authed_service.secrets_config_source() == "team"


# ---------------------------------------------------------------------------
# config_source surfaced through the status summary
# ---------------------------------------------------------------------------


class TestStatusSource:
    def test_status_reports_personal_source(self, authed_service):
        from servonaut.services.entitlement_guard import EntitlementGuard
        from servonaut.services.secrets_status import compute_secrets_status

        authed_service.apply_user_secrets_config(_USER_WIRE)
        guard = EntitlementGuard(authed_service)
        summary = compute_secrets_status(authed_service, guard)
        assert summary.config_source == "user"

    def test_status_reports_team_source(self, authed_service):
        from servonaut.services.entitlement_guard import EntitlementGuard
        from servonaut.services.secrets_status import compute_secrets_status

        authed_service.apply_secrets_config(_TEAM_WIRE)
        guard = EntitlementGuard(authed_service)
        summary = compute_secrets_status(authed_service, guard)
        assert summary.config_source == "team"
