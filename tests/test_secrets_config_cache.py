"""Tests for the secrets-management Step 2 cache wiring.

Covers:
- :class:`servonaut.config.schema.SecretsConfig` round-trip parse / dump
  against the locked wire format (kickoff doc §Contract → API endpoint).
- :class:`AuthToken` gains ``secrets_config`` + ``secrets_fetched_at``
  with defaults that don't break legacy on-disk auth.json files.
- :class:`AuthService` cache helpers: ``cached_secrets_config`` falls
  back to LocalProvider default when nothing is cached; freshness
  honours :data:`SECRETS_CACHE_TTL`; ``apply_secrets_config`` flushes
  to disk so a crash post-fetch doesn't lose the team config.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from servonaut.config.schema import SecretsConfig
from servonaut.services.auth_service import (
    AUTH_FILE,
    SECRETS_CACHE_TTL,
    AuthService,
    AuthToken,
)


# ---------------------------------------------------------------------------
# SecretsConfig wire-format
# ---------------------------------------------------------------------------


class TestSecretsConfigDataclass:
    def test_local_default_is_safe(self):
        """LocalProvider default must always be valid — it's the
        fallback returned to consumers when no cache exists yet, so
        any guard here would surface as an "anonymous user can't
        boot" bug."""
        cfg = SecretsConfig.local_default()
        assert cfg.provider == "local"
        assert cfg.config == {}
        assert cfg.updated_at == ""

    def test_from_wire_parses_contract_shape(self):
        """The exact shape locked with servonaut-web-backend on
        thread secrets-management-kickoff. If this test changes,
        notify the web side on the same thread BEFORE landing."""
        wire = {
            "provider": "bitwarden",
            "config": {
                "project_id": "11111111-2222-3333-4444-555555555555",
                "token_env_var": "BWS_ACCESS_TOKEN",
            },
            "updated_at": "2026-05-16T16:00:00Z",
        }
        cfg = SecretsConfig.from_wire(wire)
        assert cfg.provider == "bitwarden"
        assert cfg.config["project_id"] == "11111111-2222-3333-4444-555555555555"
        assert cfg.config["token_env_var"] == "BWS_ACCESS_TOKEN"
        assert cfg.updated_at == "2026-05-16T16:00:00Z"

    def test_from_wire_round_trips(self):
        wire = {
            "provider": "bitwarden",
            "config": {"project_id": "abc", "token_env_var": "BWS_ACCESS_TOKEN"},
            "updated_at": "2026-05-16T16:00:00Z",
        }
        assert SecretsConfig.from_wire(wire).to_wire() == wire

    def test_from_wire_tolerates_unknown_keys(self):
        """Forward-compat: the server may grow new optional fields
        before the CLI ships a matching release. Drop unknown keys,
        keep the known ones."""
        wire = {
            "provider": "bitwarden",
            "config": {"project_id": "abc"},
            "updated_at": "2026-05-16T16:00:00Z",
            "future_field_servonaut_doesnt_know": "ignore me",
        }
        cfg = SecretsConfig.from_wire(wire)
        assert cfg.provider == "bitwarden"
        # The unknown top-level field is dropped, NOT preserved.
        assert "future_field_servonaut_doesnt_know" not in cfg.to_wire()

    def test_from_wire_handles_missing_keys(self):
        """A 404-fallback path may hand us a partial dict — degrade
        gracefully to local defaults rather than KeyError."""
        cfg = SecretsConfig.from_wire({})
        assert cfg.provider == "local"
        assert cfg.config == {}
        assert cfg.updated_at == ""

    def test_from_wire_coerces_bad_config_shape(self):
        """If the server hands back ``config: null`` or ``config: [1,2]``,
        the CLI must not propagate that into the cache where it would
        break later consumers — coerce to ``{}``."""
        for bogus in (None, [1, 2, 3], "not-a-dict", 42):
            cfg = SecretsConfig.from_wire({"provider": "bitwarden", "config": bogus})
            assert cfg.config == {}, f"bad config={bogus!r} should coerce to empty dict"


# ---------------------------------------------------------------------------
# AuthToken defaults — backward compat
# ---------------------------------------------------------------------------


class TestAuthTokenSecretsFields:
    def test_defaults_present(self):
        """New fields must have safe defaults — a legacy auth.json
        written by an older CLI must load cleanly via the existing
        ``AuthToken(**data)`` path."""
        tok = AuthToken(
            access_token="a", refresh_token="r",
            expires_at=time.time() + 3600, plan="solo",
        )
        assert tok.secrets_config == {}
        assert tok.secrets_fetched_at == 0.0

    def test_legacy_auth_json_loads_with_defaults(self, tmp_path, monkeypatch):
        """Forward-compat in reverse: a CLI with the new dataclass
        loads an auth.json written by a pre-Step-2 build. The
        unknown-keys filter in ``_load_token`` already protects
        against extra keys; here we pin the missing-keys path."""
        auth_file = tmp_path / "auth.json"
        legacy_payload = {
            "access_token": "abc",
            "refresh_token": "def",
            "expires_at": time.time() + 3600,
            "plan": "solo",
            # NB: no secrets_config / secrets_fetched_at — pre-Step-2.
        }
        auth_file.write_text(json.dumps(legacy_payload))
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE", auth_file
        )
        svc = AuthService()
        assert svc.is_authenticated
        assert svc._token.secrets_config == {}
        assert svc._token.secrets_fetched_at == 0.0


# ---------------------------------------------------------------------------
# AuthService cache helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def authed_service(tmp_path, monkeypatch) -> AuthService:
    """AuthService with a valid (not-yet-fetched) token pre-loaded.

    The token's secrets cache starts empty so each test exercises a
    well-defined initial state."""
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({
        "access_token": "A",
        "refresh_token": "R",
        "expires_at": time.time() + 3600,
        "plan": "team",
        "entitlements": {},
        "entitlements_fetched_at": 0,
    }))
    monkeypatch.setattr(
        "servonaut.services.auth_service.AUTH_FILE", auth_file
    )
    return AuthService()


class TestSecretsCacheHelpers:
    def test_cached_returns_local_default_when_empty(self, authed_service):
        cfg = authed_service.cached_secrets_config()
        assert cfg.provider == "local"
        assert cfg.config == {}

    def test_cache_not_present_initially(self, authed_service):
        assert authed_service.is_secrets_cache_present() is False
        assert authed_service.is_secrets_cache_fresh() is False

    def test_apply_persists_to_disk(self, authed_service, tmp_path, monkeypatch):
        """A successful fetch must hit disk synchronously — a crash
        post-fetch must not silently throw the result away. Reload
        with a fresh AuthService instance to prove the persistence."""
        payload = {
            "provider": "bitwarden",
            "config": {"project_id": "abc", "token_env_var": "BWS_ACCESS_TOKEN"},
            "updated_at": "2026-05-16T16:00:00Z",
        }
        authed_service.apply_secrets_config(payload)

        # Confirm the in-memory view first.
        cfg = authed_service.cached_secrets_config()
        assert cfg.provider == "bitwarden"
        assert cfg.config["project_id"] == "abc"

        # Re-instantiate against the same on-disk file.
        reloaded = AuthService()
        cfg2 = reloaded.cached_secrets_config()
        assert cfg2.provider == "bitwarden"
        assert cfg2.config["project_id"] == "abc"
        assert reloaded.is_secrets_cache_present() is True

    def test_cache_fresh_within_ttl(self, authed_service):
        authed_service.apply_secrets_config({
            "provider": "local", "config": {}, "updated_at": "",
        })
        assert authed_service.is_secrets_cache_fresh() is True

    def test_cache_stale_past_ttl(self, authed_service):
        authed_service.apply_secrets_config({
            "provider": "local", "config": {}, "updated_at": "",
        })
        # Force the stored timestamp into the past.
        authed_service._token.secrets_fetched_at = (
            time.time() - SECRETS_CACHE_TTL - 1
        )
        assert authed_service.is_secrets_cache_fresh() is False
        # Even stale, the cache is still PRESENT — consumers should
        # serve from cache + kick a refetch (stale-while-revalidate),
        # not treat stale as missing.
        assert authed_service.is_secrets_cache_present() is True

    def test_apply_defensive_copy(self, authed_service):
        """``apply_secrets_config`` must NOT alias the dict the caller
        keeps mutating after the call — that would silently corrupt
        the on-disk cache."""
        payload = {
            "provider": "bitwarden",
            "config": {"project_id": "abc", "token_env_var": "BWS_ACCESS_TOKEN"},
            "updated_at": "2026-05-16T16:00:00Z",
        }
        authed_service.apply_secrets_config(payload)
        # Caller mutates their own dict after the call.
        payload["provider"] = "POISONED"
        payload["config"]["project_id"] = "POISONED"
        # Our cache must not have followed along.
        cfg = authed_service.cached_secrets_config()
        assert cfg.provider == "bitwarden"

    def test_clear_drops_cache(self, authed_service):
        authed_service.apply_secrets_config({
            "provider": "bitwarden",
            "config": {"project_id": "abc"},
            "updated_at": "2026-05-16T16:00:00Z",
        })
        assert authed_service.is_secrets_cache_present() is True
        authed_service.clear_secrets_cache()
        assert authed_service.is_secrets_cache_present() is False
        # And on reload, the cleared state survives.
        reloaded = AuthService()
        assert reloaded.is_secrets_cache_present() is False

    def test_cached_recovers_from_malformed_disk_payload(self, authed_service):
        """A future CLI version might write a shape we don't
        understand. Don't crash the boot path — log + fall back to
        LocalProvider default."""
        # Force a bogus shape into the token without going through
        # apply_secrets_config (simulating an externally edited file).
        authed_service._token.secrets_config = {"provider": 42, "config": "nope"}
        cfg = authed_service.cached_secrets_config()
        # ``from_wire`` coerces non-dict config to {} and stringifies
        # the provider, but the test guards against a future stricter
        # parser by accepting either coerced or local fallback.
        assert cfg.provider in ("42", "local")
        assert cfg.config == {}

    def test_apply_with_no_token_is_safe(self, tmp_path, monkeypatch):
        """A pre-login call must not crash. The service silently
        no-ops because there's no token to hang state off of."""
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE", tmp_path / "absent.json"
        )
        svc = AuthService()
        assert svc._token is None
        # Should not raise.
        svc.apply_secrets_config({"provider": "bitwarden", "config": {}})
        svc.clear_secrets_cache()
        assert svc.cached_secrets_config().provider == "local"

    def test_freshness_injectable_clock(self, authed_service):
        """Tests pin wall-clock behaviour via the ``now`` injection
        rather than monkeypatching :mod:`time` — see helper docstring."""
        authed_service.apply_secrets_config({
            "provider": "local", "config": {}, "updated_at": "",
        })
        fetched_at = authed_service._token.secrets_fetched_at
        # Exactly TTL seconds later → stale boundary (strictly less than).
        assert authed_service.is_secrets_cache_fresh(
            now=fetched_at + SECRETS_CACHE_TTL - 1
        ) is True
        assert authed_service.is_secrets_cache_fresh(
            now=fetched_at + SECRETS_CACHE_TTL
        ) is False
