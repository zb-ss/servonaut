"""Tests for EntitlementGuard."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from servonaut.services.entitlement_guard import EntitlementGuard, FEATURE_PLANS


def run(coro):
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


@pytest.fixture
def free_guard():
    auth = MagicMock()
    auth.has_feature.return_value = False
    auth.plan = "free"
    return EntitlementGuard(auth)


@pytest.fixture
def solo_guard():
    auth = MagicMock()
    auth.has_feature.return_value = False
    auth.plan = "solo"
    return EntitlementGuard(auth)


@pytest.fixture
def teams_guard():
    auth = MagicMock()
    auth.has_feature.return_value = False
    auth.plan = "teams"
    return EntitlementGuard(auth)


class TestEntitlementGuard:
    def test_free_user_blocked_from_solo_features(self, free_guard):
        allowed, reason = free_guard.check("config_sync")
        assert not allowed
        assert reason == (
            "Config sync across machines needs the Solo plan. "
            "Compare plans and upgrade at https://servonaut.dev/pricing."
        )

    def test_free_user_blocked_from_team_features(self, free_guard):
        allowed, reason = free_guard.check("team_workspace")
        assert not allowed

    def test_solo_user_allowed_solo_features(self, solo_guard):
        allowed, reason = solo_guard.check("config_sync")
        assert allowed

    def test_solo_user_blocked_from_team_features(self, solo_guard):
        allowed, reason = solo_guard.check("team_workspace")
        assert not allowed
        assert reason == (
            "This feature needs the Teams plan; you are on Solo. "
            "Upgrade at https://servonaut.dev/pricing."
        )

    def test_refusal_names_the_feature_as_the_account_screen_does(self, solo_guard):
        allowed, reason = solo_guard.check("team_vault")
        assert not allowed
        assert reason.startswith("Team vault shared with your team needs the Teams plan;")
        assert "team_vault" not in reason

    def test_refusal_never_names_a_command_that_does_not_exist(self, free_guard):
        for feature in FEATURE_PLANS:
            _, reason = free_guard.check(feature)
            assert "--subscribe" not in reason and "_" not in reason.split(" needs ")[0], reason

    def test_teams_user_allowed_all_features(self, teams_guard):
        for feature in FEATURE_PLANS:
            allowed, _ = teams_guard.check(feature)
            assert allowed, f"teams user should have access to {feature}"

    def test_unknown_feature_allowed(self, free_guard):
        allowed, _ = free_guard.check("nonexistent_feature")
        assert allowed

    def test_server_side_entitlement_overrides(self):
        auth = MagicMock()
        auth.has_feature.return_value = True  # server says OK
        auth.plan = "free"
        guard = EntitlementGuard(auth)
        allowed, _ = guard.check("config_sync")
        assert allowed

    @pytest.mark.parametrize(
        ("feature", "minimum_plan"),
        [
            ("personal_vault", "solo"),
            ("team_vault", "teams"),
            ("ssh_ca", "teams"),
        ],
    )
    def test_vault_feature_plan_requirements(self, free_guard, solo_guard, teams_guard, feature, minimum_plan):
        assert FEATURE_PLANS[feature] == minimum_plan
        assert not free_guard.check(feature)[0]
        assert solo_guard.check(feature)[0] is (minimum_plan == "solo")
        assert teams_guard.check(feature)[0]


class TestRequireDecorator:
    def test_require_blocks_unauthorized(self, free_guard):
        @free_guard.require("config_sync")
        async def premium_action(screen):
            return "success"

        mock_screen = MagicMock()
        mock_screen.notify = MagicMock()

        result = run(premium_action(mock_screen))
        assert result is None
        mock_screen.notify.assert_called_once()

    def test_require_allows_authorized(self, solo_guard):
        @solo_guard.require("config_sync")
        async def premium_action(screen):
            return "success"

        result = run(premium_action(MagicMock()))
        assert result == "success"
