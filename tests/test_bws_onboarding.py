"""Tests for the guided bws onboarding helpers + personal PUT — Layer B1.

Covers:
- :func:`bws_onboarding.list_bws_projects` — parses ``bws project list``
  JSON, fails cleanly (token unset / bws missing / non-zero exit with the
  token scrubbed) without ever putting the token on argv.
- :func:`bws_onboarding.bws_test_connection` — reuses BitwardenProvider to
  validate a project, returns the secret count.
- :meth:`APIClient.put_user_secrets_config` — PUTs ``{provider, config}``
  to ``/api/v1/me/secrets-config`` and NEVER sends the token value.

All subprocess / network IO is mocked — nothing real runs.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services import bws_onboarding as bws
from servonaut.services.bws_onboarding import BwsOnboardingError, BwsProject


def run(coro):
    return asyncio.run(coro)


def _fake_proc(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.returncode = returncode
    proc.kill = MagicMock()
    return proc


# ---------------------------------------------------------------------------
# list_bws_projects
# ---------------------------------------------------------------------------


class TestListProjects:
    def test_parses_project_list(self, monkeypatch):
        monkeypatch.setattr(bws.shutil, "which", lambda _: "/usr/bin/bws")
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok-secret")
        payload = json.dumps([
            {"id": "p1", "name": "prod"},
            {"id": "p2", "name": "staging"},
            {"id": "", "name": "skip-me"},  # no id → dropped
            "not-a-dict",                     # skipped
        ]).encode()
        with patch(
            "asyncio.create_subprocess_exec",
            AsyncMock(return_value=_fake_proc(stdout=payload)),
        ):
            projects = run(bws.list_bws_projects("BWS_ACCESS_TOKEN"))
        assert projects == [BwsProject("p1", "prod"), BwsProject("p2", "staging")]

    def test_token_never_on_argv(self, monkeypatch):
        """The token must be injected via env, never as a CLI arg."""
        monkeypatch.setattr(bws.shutil, "which", lambda _: "/usr/bin/bws")
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok-secret")
        spy = AsyncMock(return_value=_fake_proc(stdout=b"[]"))
        with patch("asyncio.create_subprocess_exec", spy):
            run(bws.list_bws_projects("BWS_ACCESS_TOKEN"))
        called_args = spy.call_args.args
        assert "tok-secret" not in called_args
        # The token IS present in the subprocess env, though.
        env = spy.call_args.kwargs["env"]
        assert env["BWS_ACCESS_TOKEN"] == "tok-secret"

    def test_missing_bws_raises(self, monkeypatch):
        monkeypatch.setattr(bws.shutil, "which", lambda _: None)
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
        with pytest.raises(BwsOnboardingError, match="not installed"):
            run(bws.list_bws_projects("BWS_ACCESS_TOKEN"))

    def test_unset_token_raises(self, monkeypatch):
        monkeypatch.setattr(bws.shutil, "which", lambda _: "/usr/bin/bws")
        monkeypatch.delenv("BWS_ACCESS_TOKEN", raising=False)
        with pytest.raises(BwsOnboardingError, match="not set"):
            run(bws.list_bws_projects("BWS_ACCESS_TOKEN"))

    def test_nonzero_exit_scrubs_token(self, monkeypatch):
        monkeypatch.setattr(bws.shutil, "which", lambda _: "/usr/bin/bws")
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok-secret")
        proc = _fake_proc(stderr=b"auth failed for tok-secret", returncode=1)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            with pytest.raises(BwsOnboardingError) as exc:
                run(bws.list_bws_projects("BWS_ACCESS_TOKEN"))
        assert "tok-secret" not in str(exc.value)
        assert "<redacted-token>" in str(exc.value)


# ---------------------------------------------------------------------------
# bws_test_connection
# ---------------------------------------------------------------------------


class TestTestConnection:
    def test_returns_secret_count(self, monkeypatch):
        fake_provider = MagicMock()
        fake_provider.list_secrets = AsyncMock(return_value=["db/a", "db/b"])
        with patch(
            "servonaut.services.bitwarden_provider.BitwardenProvider",
            return_value=fake_provider,
        ):
            count = run(bws.bws_test_connection("p1", "BWS_ACCESS_TOKEN"))
        assert count == 2

    def test_zero_is_healthy(self, monkeypatch):
        fake_provider = MagicMock()
        fake_provider.list_secrets = AsyncMock(return_value=[])
        with patch(
            "servonaut.services.bitwarden_provider.BitwardenProvider",
            return_value=fake_provider,
        ):
            count = run(bws.bws_test_connection("p1"))
        assert count == 0

    def test_empty_project_id_raises(self):
        with pytest.raises(BwsOnboardingError, match="project_id is required"):
            run(bws.bws_test_connection("  "))

    def test_provider_error_wrapped(self):
        from servonaut.services.bitwarden_provider import BitwardenAPIError

        fake_provider = MagicMock()
        fake_provider.list_secrets = AsyncMock(
            side_effect=BitwardenAPIError("bws boom")
        )
        with patch(
            "servonaut.services.bitwarden_provider.BitwardenProvider",
            return_value=fake_provider,
        ):
            with pytest.raises(BwsOnboardingError):
                run(bws.bws_test_connection("p1"))


# ---------------------------------------------------------------------------
# APIClient.put_user_secrets_config
# ---------------------------------------------------------------------------


class TestPutUserSecretsConfig:
    def test_puts_provider_and_config_never_token(self):
        from servonaut.services.api_client import APIClient

        auth = MagicMock()
        auth.access_token = "bearer"
        auth.refresh_token = AsyncMock(return_value=False)
        client = APIClient(auth)
        client.put = AsyncMock(return_value={
            "provider": "bitwarden",
            "config": {"project_id": "p1", "token_env_var": "BWS_ACCESS_TOKEN"},
            "updated_at": "2026-06-30T12:00:00Z",
            "created": True,
        })
        config = {"project_id": "p1", "token_env_var": "BWS_ACCESS_TOKEN"}
        body = run(client.put_user_secrets_config("bitwarden", config))

        # Path + json= keyword-only body.
        client.put.assert_awaited_once()
        call = client.put.call_args
        assert call.args[0] == "/api/v1/me/secrets-config"
        sent = call.kwargs["json"]
        assert sent == {"provider": "bitwarden", "config": config}
        # Only the env-var NAME crosses the wire — never a token value.
        assert "token_env_var" in sent["config"]
        assert "BWS_ACCESS_TOKEN" == sent["config"]["token_env_var"]
        assert body["created"] is True
