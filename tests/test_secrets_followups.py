"""Tests for the UX Step 9 follow-ups servonaut-dev signed off on:

1. Slug-consistency WARNING — if the server's response body
   includes ``team_slug`` AND it doesn't match the URL slug we used,
   log WARNING (do NOT raise; user's session keeps working).

2. ``AuthService.list_teams`` cached with :data:`TEAMS_CACHE_TTL`
   (3600s, matching entitlements + secrets-config). Cache hit
   within the TTL skips the network. ``force_refresh=True`` bypasses.

Both kicked off by the kickoff-thread message from servonaut-dev
on 2026-05-17 15:39 UTC.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.auth_service import (
    AuthService,
    AuthToken,
    TEAMS_CACHE_TTL,
)
from servonaut.services.secret_provider_resolver import (
    fetch_and_apply_secrets_config,
)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def authed_service(tmp_path, monkeypatch) -> AuthService:
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({
        "access_token": "A",
        "refresh_token": "R",
        "expires_at": time.time() + 3600,
        "plan": "teams",
        "entitlements": {},
        "entitlements_fetched_at": 0,
    }))
    monkeypatch.setattr(
        "servonaut.services.auth_service.AUTH_FILE", auth_file,
    )
    return AuthService()


# ---------------------------------------------------------------------------
# Slug-consistency warning
# ---------------------------------------------------------------------------


class TestSlugConsistencyWarning:
    """Log WARNING (do NOT raise) when the server echoes a team_slug
    that doesn't match the URL slug. The locked behaviour:
    URL-side is authoritative; we don't break the session over a
    server-side inconsistency the user can't fix."""

    def test_matching_slug_no_warning(self, authed_service, caplog):
        client = MagicMock()
        client.get_team_secrets_config = AsyncMock(return_value={
            "provider": "local",
            "config": {},
            "team_slug": "acme",  # MATCHES the requested slug
            "updated_at": "2026-05-17T16:00:00Z",
        })
        with caplog.at_level(logging.WARNING):
            ok = run(fetch_and_apply_secrets_config(
                authed_service, client, slug="acme",
            ))
        assert ok is True
        # No mismatch warning emitted.
        assert not any(
            "team_slug=" in (rec.message or "") and "match" in (rec.message or "").lower()
            for rec in caplog.records
        )

    def test_mismatched_slug_logs_warning(self, authed_service, caplog):
        client = MagicMock()
        client.get_team_secrets_config = AsyncMock(return_value={
            "provider": "local",
            "config": {},
            "team_slug": "ROGUE-slug-from-server",  # DOES NOT match
            "updated_at": "2026-05-17T16:00:00Z",
        })
        with caplog.at_level(logging.WARNING):
            ok = run(fetch_and_apply_secrets_config(
                authed_service, client, slug="acme",
            ))
        # MUST still succeed — URL slug is authoritative for caching.
        assert ok is True
        # WARNING was logged with both slugs visible for operator grep.
        warnings = [
            rec for rec in caplog.records
            if rec.levelno >= logging.WARNING
            and "ROGUE-slug-from-server" in rec.message
        ]
        assert warnings, (
            "Mismatched team_slug echo must emit a WARNING log line "
            "with both slugs included for operator grepping."
        )

    def test_missing_team_slug_in_response_no_warning(self, authed_service, caplog):
        # Pre-patch contract: server doesn't echo team_slug yet. Must
        # not emit a spurious warning.
        client = MagicMock()
        client.get_team_secrets_config = AsyncMock(return_value={
            "provider": "local",
            "config": {},
            "updated_at": "2026-05-17T16:00:00Z",
        })
        with caplog.at_level(logging.WARNING):
            run(fetch_and_apply_secrets_config(
                authed_service, client, slug="acme",
            ))
        assert not any(
            "match URL slug" in (rec.message or "")
            for rec in caplog.records
        )

    def test_apply_persists_payload_even_on_mismatch(self, authed_service, caplog):
        # Mismatch logs but doesn't block persistence.
        client = MagicMock()
        client.get_team_secrets_config = AsyncMock(return_value={
            "provider": "bitwarden",
            "config": {"project_id": "abc"},
            "team_slug": "different",
            "updated_at": "2026-05-17T16:00:00Z",
        })
        run(fetch_and_apply_secrets_config(
            authed_service, client, slug="acme",
        ))
        cfg = authed_service.cached_secrets_config()
        assert cfg.provider == "bitwarden"
        assert cfg.config.get("project_id") == "abc"


# ---------------------------------------------------------------------------
# list_teams TTL cache
# ---------------------------------------------------------------------------


class TestListTeamsTTLCache:
    """3600s TTL matching entitlements + secrets-config. Cache hit
    skips the network; force_refresh bypasses; cold start fetches."""

    @pytest.fixture(autouse=True)
    def _has_httpx(self, monkeypatch):
        # Ensure HAS_HTTPX path is the active one — the cache feature
        # is only exercised when network IS in scope.
        monkeypatch.setattr(
            "servonaut.services.auth_service.HAS_HTTPX", True,
        )

    def _mock_httpx_returning(self, payload, status: int = 200) -> MagicMock:
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        resp = MagicMock()
        resp.status_code = status
        resp.json = MagicMock(return_value=payload)
        client.get = AsyncMock(return_value=resp)
        return client

    def test_first_call_fetches_and_caches(self, authed_service):
        client = self._mock_httpx_returning([
            {"slug": "alpha", "name": "Alpha", "role": "owner"},
            {"slug": "beta", "name": "Beta", "role": "member"},
        ])
        with patch(
            "servonaut.services.auth_service.httpx.AsyncClient",
            return_value=client,
        ):
            teams = run(authed_service.list_teams())
        assert len(teams) == 2
        assert teams[0]["slug"] == "alpha"
        # Cache populated on the token.
        assert authed_service._token.teams_fetched_at > 0
        assert len(authed_service._token.teams_cached) == 2

    def test_second_call_within_ttl_skips_network(self, authed_service):
        # Pre-seed the cache.
        authed_service._token.teams_cached = [
            {"slug": "cached-team", "name": "Cached", "role": "owner"},
        ]
        authed_service._token.teams_fetched_at = time.time() - 60  # 1m old

        # If the cache hit path is broken, httpx.AsyncClient would be
        # entered — patch with a sentinel that fails the test if used.
        sentinel = MagicMock(
            side_effect=AssertionError("network call should not happen"),
        )
        with patch(
            "servonaut.services.auth_service.httpx.AsyncClient", sentinel,
        ):
            teams = run(authed_service.list_teams())
        assert teams == [
            {"slug": "cached-team", "name": "Cached", "role": "owner"},
        ]

    def test_stale_cache_past_ttl_refetches(self, authed_service):
        # Seed expired cache.
        authed_service._token.teams_cached = [
            {"slug": "old", "name": "Old", "role": "owner"},
        ]
        authed_service._token.teams_fetched_at = time.time() - TEAMS_CACHE_TTL - 1

        client = self._mock_httpx_returning([
            {"slug": "fresh", "name": "Fresh", "role": "owner"},
        ])
        with patch(
            "servonaut.services.auth_service.httpx.AsyncClient",
            return_value=client,
        ):
            teams = run(authed_service.list_teams())
        # Got the fresh data, not the stale cache.
        assert teams == [{"slug": "fresh", "name": "Fresh", "role": "owner"}]

    def test_force_refresh_bypasses_fresh_cache(self, authed_service):
        # Cache is "fresh" but force_refresh fetches anyway.
        authed_service._token.teams_cached = [
            {"slug": "cached", "name": "Cached", "role": "owner"},
        ]
        authed_service._token.teams_fetched_at = time.time() - 60

        client = self._mock_httpx_returning([
            {"slug": "refreshed", "name": "Refreshed", "role": "owner"},
        ])
        with patch(
            "servonaut.services.auth_service.httpx.AsyncClient",
            return_value=client,
        ):
            teams = run(authed_service.list_teams(force_refresh=True))
        assert teams == [
            {"slug": "refreshed", "name": "Refreshed", "role": "owner"},
        ]

    def test_unauthenticated_returns_empty_no_fetch(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE",
            tmp_path / "absent.json",
        )
        svc = AuthService()
        assert not svc.is_authenticated

        # If the no-auth short-circuit is broken, httpx.AsyncClient
        # would be invoked — pin via a sentinel that raises.
        sentinel = MagicMock(
            side_effect=AssertionError("must not network when unauthenticated"),
        )
        with patch(
            "servonaut.services.auth_service.httpx.AsyncClient", sentinel,
        ):
            assert run(svc.list_teams()) == []

    def test_cached_list_defensive_copy_on_return(self, authed_service):
        # Cache hit — caller mutating the returned list must NOT
        # poison the cache for subsequent calls.
        authed_service._token.teams_cached = [
            {"slug": "a", "name": "A", "role": "owner"},
        ]
        authed_service._token.teams_fetched_at = time.time() - 30

        teams = run(authed_service.list_teams())
        teams[0]["slug"] = "POISONED"
        teams2 = run(authed_service.list_teams())
        assert teams2[0]["slug"] == "a"

    def test_cache_persists_across_authservice_reload(
        self, tmp_path, monkeypatch,
    ):
        # Round-trip through auth.json: write cache, construct fresh
        # AuthService against the same file, verify cache loaded.
        auth_file = tmp_path / "auth.json"
        token_data = {
            "access_token": "A",
            "refresh_token": "R",
            "expires_at": time.time() + 3600,
            "plan": "teams",
            "entitlements": {},
            "entitlements_fetched_at": 0,
            "teams_cached": [
                {"slug": "persisted", "name": "P", "role": "owner"},
            ],
            "teams_fetched_at": time.time() - 30,
        }
        auth_file.write_text(json.dumps(token_data))
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE", auth_file,
        )
        svc = AuthService()
        assert svc.is_authenticated
        # Fresh process reads the cache — no network needed.
        sentinel = MagicMock(
            side_effect=AssertionError("cache should hit, not fetch"),
        )
        with patch(
            "servonaut.services.auth_service.httpx.AsyncClient", sentinel,
        ):
            teams = run(svc.list_teams())
        assert teams == [{"slug": "persisted", "name": "P", "role": "owner"}]
