"""Tests for ``servonaut secrets setup`` — the guided bws wizard (B1).

Drives :func:`_run_setup_async` end-to-end with every side-effecting
dependency mocked (auth, entitlement, bws subprocess helpers, the PUT
client). Pins the wizard contract:

- gated on auth + the ``secrets_management`` entitlement;
- refuses to proceed without bws installed / token set;
- picks a project by name, TESTS the connection, and only then PUTs;
- a test-connection failure saves NOTHING;
- the persisted config carries the token env-var NAME, never a token.
"""
from __future__ import annotations

import argparse
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.cli.secrets import (
    _EXIT_GENERIC_ERROR,
    _EXIT_NOT_FOUND,
    _EXIT_SUCCESS,
    _run_setup_async,
)
from servonaut.services.bws_onboarding import BwsOnboardingError, BwsProject


def run(coro):
    return asyncio.run(coro)


def _args(**kw) -> argparse.Namespace:
    base = {"token_env": None, "project_id": "", "yes": True}
    base.update(kw)
    return argparse.Namespace(**base)


class _Ctx:
    """Bundle of patches for a wizard run. Attributes expose the mocks
    so tests can assert against them."""

    def __init__(
        self,
        *,
        authenticated=True,
        entitled=True,
        installed=True,
        token_set=True,
        projects=None,
        test_count=3,
        test_exc=None,
        put_return=None,
    ):
        self.auth = MagicMock()
        self.auth.is_authenticated = authenticated
        self.auth.apply_user_secrets_config = MagicMock()
        self.guard = MagicMock()
        self.guard.check = MagicMock(
            return_value=(entitled, "OK" if entitled else "needs upgrade")
        )
        self.api = MagicMock()
        self.api.put_user_secrets_config = AsyncMock(
            return_value=put_return
            if put_return is not None
            else {
                "provider": "bitwarden",
                "config": {"project_id": "p1", "token_env_var": "BWS_ACCESS_TOKEN"},
                "updated_at": "2026-06-30T12:00:00Z",
                "created": True,
            }
        )
        self._installed = installed
        self._token_set = token_set
        self._projects = projects if projects is not None else [
            BwsProject("p1", "prod"),
        ]
        self._test_count = test_count
        self._test_exc = test_exc

    def __enter__(self):
        self._patches = [
            patch("servonaut.services.auth_service.AuthService", return_value=self.auth),
            patch("servonaut.services.entitlement_guard.EntitlementGuard", return_value=self.guard),
            patch("servonaut.services.api_client.APIClient", return_value=self.api),
            patch("servonaut.services.bws_onboarding.bws_installed", return_value=self._installed),
            patch("servonaut.services.bws_onboarding.token_is_set", return_value=self._token_set),
            patch(
                "servonaut.services.bws_onboarding.list_bws_projects",
                AsyncMock(return_value=self._projects),
            ),
            patch(
                "servonaut.services.bws_onboarding.bws_test_connection",
                AsyncMock(
                    side_effect=self._test_exc,
                    return_value=self._test_count,
                )
                if self._test_exc is None
                else AsyncMock(side_effect=self._test_exc),
            ),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        return False


class TestSetupGates:
    def test_unauthenticated_exits(self):
        with _Ctx(authenticated=False) as ctx:
            rc = run(_run_setup_async(_args()))
        assert rc == _EXIT_NOT_FOUND
        ctx.api.put_user_secrets_config.assert_not_awaited()

    def test_not_entitled_exits(self):
        with _Ctx(entitled=False) as ctx:
            rc = run(_run_setup_async(_args()))
        assert rc == _EXIT_NOT_FOUND
        ctx.api.put_user_secrets_config.assert_not_awaited()

    def test_bws_not_installed_exits(self):
        with _Ctx(installed=False) as ctx:
            rc = run(_run_setup_async(_args()))
        assert rc == _EXIT_NOT_FOUND
        ctx.api.put_user_secrets_config.assert_not_awaited()

    def test_token_unset_exits(self):
        with _Ctx(token_set=False) as ctx:
            rc = run(_run_setup_async(_args()))
        assert rc == _EXIT_NOT_FOUND
        ctx.api.put_user_secrets_config.assert_not_awaited()


class TestSetupHappyPath:
    def test_auto_selects_single_project_and_persists(self):
        with _Ctx() as ctx:
            rc = run(_run_setup_async(_args()))
        assert rc == _EXIT_SUCCESS
        ctx.api.put_user_secrets_config.assert_awaited_once()
        provider, config = ctx.api.put_user_secrets_config.call_args.args
        assert provider == "bitwarden"
        assert config["project_id"] == "p1"
        assert config["token_env_var"] == "BWS_ACCESS_TOKEN"
        # No token value anywhere in the persisted config.
        assert all("token" not in str(v).lower() or "env" in k for k, v in config.items())
        # Local cache primed so the provider is active immediately.
        ctx.auth.apply_user_secrets_config.assert_called_once()

    def test_explicit_project_id_skips_listing(self):
        with _Ctx(projects=[]) as ctx:  # listing would be empty
            rc = run(_run_setup_async(_args(project_id="explicit-uuid")))
        assert rc == _EXIT_SUCCESS
        _, config = ctx.api.put_user_secrets_config.call_args.args
        assert config["project_id"] == "explicit-uuid"

    def test_custom_token_env_var(self):
        with _Ctx() as ctx:
            rc = run(_run_setup_async(_args(token_env="MY_BWS_TOKEN")))
        assert rc == _EXIT_SUCCESS
        _, config = ctx.api.put_user_secrets_config.call_args.args
        assert config["token_env_var"] == "MY_BWS_TOKEN"


class TestSetupFailurePaths:
    def test_test_connection_failure_saves_nothing(self):
        with _Ctx(test_exc=BwsOnboardingError("cannot reach project")) as ctx:
            rc = run(_run_setup_async(_args()))
        assert rc == _EXIT_GENERIC_ERROR
        ctx.api.put_user_secrets_config.assert_not_awaited()
        ctx.auth.apply_user_secrets_config.assert_not_called()

    def test_no_projects_visible_exits(self):
        with _Ctx(projects=[]) as ctx:
            rc = run(_run_setup_async(_args()))
        assert rc == _EXIT_NOT_FOUND
        ctx.api.put_user_secrets_config.assert_not_awaited()

    def test_put_api_error_reported(self):
        from servonaut.services.api_client import APIError

        with _Ctx() as ctx:
            ctx.api.put_user_secrets_config = AsyncMock(
                side_effect=APIError(code="validation_failed", message="bad", status=422)
            )
            with patch("servonaut.services.api_client.APIClient", return_value=ctx.api):
                rc = run(_run_setup_async(_args()))
        assert rc == _EXIT_GENERIC_ERROR
        ctx.auth.apply_user_secrets_config.assert_not_called()
