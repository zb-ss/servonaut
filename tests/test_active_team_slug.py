"""Tests for ``AuthService.active_team_slug()`` helper.

Resolution policy:

1. Cached team_slug from the secrets-config payload — wins.
2. Bootstrap from :meth:`list_teams` — owner role first, else first.
3. None when user has no teams or isn't authenticated.

Plus the edge case:

- Stale cached slug for a team the user no longer has access to →
  403/404 path inside ``fetch_and_apply_secrets_config`` clears the
  cache → next ``active_team_slug()`` re-bootstraps from
  ``list_teams`` → returns the user's CURRENT team, not the dead
  cached one. No manual intervention.
"""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import ForbiddenError
from servonaut.services.auth_service import AuthService, AuthToken
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
# Cached path — fastest, no network
# ---------------------------------------------------------------------------


class TestCachedSlug:
    def test_returns_cached_team_slug_when_present(self, authed_service):
        # Simulate the server having sent the additive team_slug field.
        # Once the server change ships, the production
        # apply_secrets_config persists it through the same dict.
        authed_service.apply_secrets_config({
            "provider": "bitwarden",
            "config": {"project_id": "abc", "token_env_var": "BWS_ACCESS_TOKEN"},
            "team_slug": "acme-corp",
            "updated_at": "2026-05-17T15:00:00Z",
        })
        slug = run(authed_service.active_team_slug())
        assert slug == "acme-corp"

    def test_empty_cached_slug_falls_through_to_list(self, authed_service):
        # Empty string in the cache shouldn't be treated as a valid
        # slug — fall back to list_teams.
        authed_service.apply_secrets_config({
            "provider": "bitwarden",
            "config": {"project_id": "abc"},
            "team_slug": "",
            "updated_at": "",
        })
        authed_service.list_teams = AsyncMock(return_value=[
            {"slug": "owner-team", "name": "Owner", "role": "owner"},
        ])
        slug = run(authed_service.active_team_slug())
        assert slug == "owner-team"

    def test_non_string_cached_slug_falls_through(self, authed_service):
        # Forward-compat: a future server sends ``team_slug: 42``
        # (shouldn't happen, but cheap to guard). Fall through.
        authed_service.apply_secrets_config({
            "provider": "bitwarden",
            "config": {"project_id": "abc"},
            "team_slug": 42,
            "updated_at": "",
        })
        authed_service.list_teams = AsyncMock(return_value=[
            {"slug": "fallback", "name": "Fallback", "role": "member"},
        ])
        slug = run(authed_service.active_team_slug())
        assert slug == "fallback"


# ---------------------------------------------------------------------------
# Bootstrap from list_teams — owner-role first, then first-in-list
# ---------------------------------------------------------------------------


class TestBootstrapFromListTeams:
    def test_owner_role_wins_over_member(self, authed_service):
        # User is owner of one team, member of two others. Owner wins.
        authed_service.list_teams = AsyncMock(return_value=[
            {"slug": "team-a", "name": "A", "role": "member"},
            {"slug": "team-b", "name": "B", "role": "owner"},
            {"slug": "team-c", "name": "C", "role": "admin"},
        ])
        slug = run(authed_service.active_team_slug())
        assert slug == "team-b"

    def test_falls_back_to_first_when_no_owner_role(self, authed_service):
        # User has no owner role — pick the deterministic first.
        authed_service.list_teams = AsyncMock(return_value=[
            {"slug": "team-x", "name": "X", "role": "member"},
            {"slug": "team-y", "name": "Y", "role": "admin"},
        ])
        slug = run(authed_service.active_team_slug())
        assert slug == "team-x"

    def test_empty_team_list_returns_none(self, authed_service):
        authed_service.list_teams = AsyncMock(return_value=[])
        slug = run(authed_service.active_team_slug())
        assert slug is None

    def test_malformed_team_entry_skipped(self, authed_service):
        # A response item that's not a dict (server bug, partial
        # parse) shouldn't crash the resolver.
        authed_service.list_teams = AsyncMock(return_value=[
            "this is not a dict",
            {"slug": "real-team", "name": "Real", "role": "owner"},
        ])
        slug = run(authed_service.active_team_slug())
        assert slug == "real-team"


# ---------------------------------------------------------------------------
# Unauthenticated / no token
# ---------------------------------------------------------------------------


class TestUnauthenticated:
    def test_unauthenticated_returns_none(self, tmp_path, monkeypatch):
        # Fresh service with no auth.json.
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE",
            tmp_path / "absent.json",
        )
        svc = AuthService()
        assert not svc.is_authenticated
        assert run(svc.active_team_slug()) is None


# ---------------------------------------------------------------------------
# Stale-cache edge case
# ---------------------------------------------------------------------------


class TestStaleCacheReBootstrap:
    """The user used to be in team-x; their cache says team-x. They've
    since been removed (or the team deleted). Calling
    ``fetch_and_apply_secrets_config`` for the cached slug returns
    403/404 → clears cache → next ``active_team_slug()`` re-bootstraps
    from ``list_teams()`` → returns their CURRENT team."""

    def test_403_clears_cache_then_re_bootstraps_to_current_team(
        self, authed_service,
    ):
        # 1. Cache says team-x (stale).
        authed_service.apply_secrets_config({
            "provider": "bitwarden",
            "config": {"project_id": "stale"},
            "team_slug": "old-team-revoked",
            "updated_at": "2026-01-01T00:00:00Z",
        })
        assert run(authed_service.active_team_slug()) == "old-team-revoked"

        # 2. Server says 403 when the CLI asks for old-team-revoked.
        client = MagicMock()
        client.get_team_secrets_config = AsyncMock(
            side_effect=ForbiddenError(
                code="forbidden",
                message="You are not a member of this team.",
                status=403,
            ),
        )
        ok = run(fetch_and_apply_secrets_config(
            authed_service, client, slug="old-team-revoked",
        ))
        assert ok is True  # 403 returns True per the server contract
        assert not authed_service.is_secrets_cache_present()

        # 3. list_teams now returns the user's CURRENT team.
        authed_service.list_teams = AsyncMock(return_value=[
            {"slug": "current-team", "name": "Current", "role": "owner"},
        ])

        # 4. active_team_slug re-bootstraps cleanly.
        slug = run(authed_service.active_team_slug())
        assert slug == "current-team"
