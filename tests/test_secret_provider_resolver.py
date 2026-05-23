"""Tests for the Step 6 wiring — :mod:`servonaut.services.secret_provider_resolver`.

The resolver is the single source of truth for "which
:class:`SecretProvider` is active right now". Every branch maps to
a kickoff-doc-locked semantic that we don't want a future refactor
to silently change:

- Unauthenticated → None (legacy ~/.ssh).
- Free tier → None (kickoff §Tier gating).
- Solo / Teams with no cached config → LocalProvider.
- Solo / Teams with cached provider="bitwarden" + project_id →
  BitwardenProvider.
- Solo / Teams with cached provider="bitwarden" but missing
  project_id → LocalProvider with a WARNING (team admin's setup is
  incomplete).

Plus the async :func:`fetch_and_apply_secrets_config` paths:
200 → apply, 404 → clear, 402/403 → clear, 5xx/transient → keep
existing cache. These mirror the philosophy of
:meth:`AuthService.refresh_token`.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import SecretsConfig
from servonaut.services.bitwarden_provider import BitwardenProvider
from servonaut.services.secret_provider import LocalProvider
from servonaut.services.secret_provider_resolver import (
    FAKE_CLIENT_ENV_VAR,
    fetch_and_apply_secrets_config,
    is_fake_client_env_enabled,
    resolve_secret_provider,
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_unauthenticated() -> MagicMock:
    auth = MagicMock()
    auth.is_authenticated = False
    auth.cached_secrets_config = MagicMock(
        return_value=SecretsConfig.local_default(),
    )
    return auth


def _auth_authenticated(
    plan: str = "solo",
    cached: SecretsConfig | None = None,
) -> MagicMock:
    auth = MagicMock()
    auth.is_authenticated = True
    auth.plan = plan
    auth.cached_secrets_config = MagicMock(
        return_value=cached if cached is not None else SecretsConfig.local_default(),
    )
    auth.apply_secrets_config = MagicMock()
    auth.clear_secrets_cache = MagicMock()
    return auth


def _guard_allows(allow: bool) -> MagicMock:
    guard = MagicMock()
    guard.check = MagicMock(
        return_value=(allow, "OK" if allow else "Requires upgrade"),
    )
    return guard


# ---------------------------------------------------------------------------
# resolve_secret_provider — decision matrix
# ---------------------------------------------------------------------------


class TestResolverUnauthenticated:
    def test_unauthenticated_returns_none(self):
        """Pre-login state. SSHService falls back to legacy ~/.ssh,
        exactly as a fresh install behaved before secrets-management
        shipped."""
        auth = _auth_unauthenticated()
        guard = _guard_allows(True)
        assert resolve_secret_provider(auth, guard) is None


class TestResolverEntitlementGate:
    def test_free_tier_returns_none(self):
        """Kickoff §Tier gating: Free is excluded.
        Even returning LocalProvider here would be wrong — it'd give
        Free users a feature their plan doesn't include."""
        auth = _auth_authenticated(plan="free")
        guard = _guard_allows(False)  # entitlement check refuses
        assert resolve_secret_provider(auth, guard) is None
        # And entitlement_guard.check WAS consulted — not just the
        # plan field — so the entitlements API can override the
        # default plan→feature mapping if needed.
        guard.check.assert_called_once_with("secrets_management")

    def test_solo_with_no_team_config_returns_local(self):
        """Solo user, no team config (cache empty / 404) →
        LocalProvider. Personal-secrets store available to anyone on
        a paid plan."""
        auth = _auth_authenticated(plan="solo")
        guard = _guard_allows(True)
        provider = resolve_secret_provider(auth, guard)
        assert isinstance(provider, LocalProvider)


class TestResolverBitwardenPath:
    def test_bitwarden_with_project_id(self):
        cached = SecretsConfig(
            provider="bitwarden",
            config={
                "project_id": "11111111-2222-3333-4444-555555555555",
                "token_env_var": "BWS_ACCESS_TOKEN",
            },
            updated_at="2026-05-17T00:00:00Z",
        )
        auth = _auth_authenticated(plan="teams", cached=cached)
        guard = _guard_allows(True)
        provider = resolve_secret_provider(auth, guard)
        assert isinstance(provider, BitwardenProvider)
        assert provider.project_id == "11111111-2222-3333-4444-555555555555"

    def test_bitwarden_custom_token_env_var(self):
        cached = SecretsConfig(
            provider="bitwarden",
            config={
                "project_id": "abc",
                "token_env_var": "MY_TEAM_BWS_TOKEN",
            },
            updated_at="",
        )
        auth = _auth_authenticated(plan="teams", cached=cached)
        provider = resolve_secret_provider(auth, _guard_allows(True))
        assert isinstance(provider, BitwardenProvider)
        # Implementation detail surface used by status output:
        assert provider._token_env_var == "MY_TEAM_BWS_TOKEN"

    def test_bitwarden_missing_project_id_falls_back_to_local(self):
        """Team admin started Bitwarden setup but didn't fill in
        project_id. Resolver MUST NOT crash; falls back to
        LocalProvider with a WARNING. The team admin needs to finish
        setup, but the user's CLI keeps working."""
        cached = SecretsConfig(
            provider="bitwarden",
            config={"token_env_var": "BWS_ACCESS_TOKEN"},  # no project_id
            updated_at="",
        )
        auth = _auth_authenticated(plan="teams", cached=cached)
        provider = resolve_secret_provider(auth, _guard_allows(True))
        assert isinstance(provider, LocalProvider)

    def test_bitwarden_empty_project_id_falls_back_to_local(self):
        cached = SecretsConfig(
            provider="bitwarden",
            config={"project_id": "", "token_env_var": "BWS_ACCESS_TOKEN"},
            updated_at="",
        )
        auth = _auth_authenticated(plan="teams", cached=cached)
        provider = resolve_secret_provider(auth, _guard_allows(True))
        assert isinstance(provider, LocalProvider)

    def test_bitwarden_with_no_token_env_var_uses_default(self):
        # If the team config omitted token_env_var, fall back to the
        # MVP-locked default "BWS_ACCESS_TOKEN".
        cached = SecretsConfig(
            provider="bitwarden",
            config={"project_id": "abc"},
            updated_at="",
        )
        auth = _auth_authenticated(plan="teams", cached=cached)
        provider = resolve_secret_provider(auth, _guard_allows(True))
        assert isinstance(provider, BitwardenProvider)
        assert provider._token_env_var == "BWS_ACCESS_TOKEN"


class TestResolverLocalPath:
    def test_explicit_local_provider(self):
        cached = SecretsConfig(provider="local", config={}, updated_at="")
        auth = _auth_authenticated(plan="solo", cached=cached)
        provider = resolve_secret_provider(auth, _guard_allows(True))
        assert isinstance(provider, LocalProvider)


# ---------------------------------------------------------------------------
# Env-var seam
# ---------------------------------------------------------------------------


class TestFakeClientEnvVar:
    @pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "ON"])
    def test_truthy_values_recognised(self, truthy, monkeypatch):
        monkeypatch.setenv(FAKE_CLIENT_ENV_VAR, truthy)
        assert is_fake_client_env_enabled() is True

    @pytest.mark.parametrize("falsy", ["0", "false", "no", "off", "", "bogus"])
    def test_falsy_values_recognised(self, falsy, monkeypatch):
        monkeypatch.setenv(FAKE_CLIENT_ENV_VAR, falsy)
        assert is_fake_client_env_enabled() is False

    def test_unset_returns_false(self, monkeypatch):
        monkeypatch.delenv(FAKE_CLIENT_ENV_VAR, raising=False)
        assert is_fake_client_env_enabled() is False


# ---------------------------------------------------------------------------
# fetch_and_apply_secrets_config
# ---------------------------------------------------------------------------


def _client_with(return_value=None, side_effect=None) -> MagicMock:
    client = MagicMock()
    if side_effect is not None:
        client.get_team_secrets_config = AsyncMock(side_effect=side_effect)
    else:
        client.get_team_secrets_config = AsyncMock(return_value=return_value)
    return client


class TestFetchAndApply200:
    def test_200_calls_apply_and_returns_true(self):
        auth = _auth_authenticated()
        payload = {
            "provider": "bitwarden",
            "config": {"project_id": "abc", "token_env_var": "BWS_ACCESS_TOKEN"},
            "updated_at": "2026-05-17T00:00:00Z",
        }
        client = _client_with(return_value=payload)
        ok = run(fetch_and_apply_secrets_config(
            auth, client, slug="acme-corp",
        ))
        assert ok is True
        auth.apply_secrets_config.assert_called_once_with(payload)


class TestFetchAndApply404:
    def test_404_clears_cache_and_returns_true(self):
        # client returning None == endpoint returned 404
        auth = _auth_authenticated()
        client = _client_with(return_value=None)
        ok = run(fetch_and_apply_secrets_config(auth, client, slug="acme"))
        assert ok is True
        auth.clear_secrets_cache.assert_called_once()
        auth.apply_secrets_config.assert_not_called()


class TestFetchAndApplyHardErrors:
    def test_402_clears_cache(self):
        from servonaut.services.api_client import PaymentRequiredError
        auth = _auth_authenticated()
        err = PaymentRequiredError(
            code="payment_required", message="upgrade", status=402,
        )
        client = _client_with(side_effect=err)
        ok = run(fetch_and_apply_secrets_config(auth, client, slug="acme"))
        assert ok is True
        auth.clear_secrets_cache.assert_called_once()

    def test_403_clears_cache(self):
        from servonaut.services.api_client import ForbiddenError
        auth = _auth_authenticated()
        err = ForbiddenError(
            code="forbidden", message="not a member", status=403,
        )
        client = _client_with(side_effect=err)
        ok = run(fetch_and_apply_secrets_config(auth, client, slug="acme"))
        assert ok is True
        auth.clear_secrets_cache.assert_called_once()


class TestFetchAndApplyTransient:
    def test_5xx_keeps_cache_and_returns_false(self):
        from servonaut.services.api_client import APIError
        auth = _auth_authenticated()
        err = APIError(
            code="unknown", message="server fault", status=503,
        )
        client = _client_with(side_effect=err)
        ok = run(fetch_and_apply_secrets_config(auth, client, slug="acme"))
        assert ok is False
        auth.clear_secrets_cache.assert_not_called()
        auth.apply_secrets_config.assert_not_called()

    def test_transport_error_keeps_cache(self):
        # E.g. httpx.ConnectError / generic OSError — should not log
        # the user out of their team's secrets store.
        auth = _auth_authenticated()
        client = _client_with(side_effect=RuntimeError("network down"))
        ok = run(fetch_and_apply_secrets_config(auth, client, slug="acme"))
        assert ok is False
        auth.clear_secrets_cache.assert_not_called()
        auth.apply_secrets_config.assert_not_called()
