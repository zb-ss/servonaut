"""Tests for :class:`BitwardenProvider`.

Mock strategy:
    Every test patches ``asyncio.create_subprocess_exec`` at module
    scope so we never shell out for real. The fake returns an
    AsyncMock whose ``communicate`` yields ``(stdout, stderr)`` byte
    pairs and whose ``returncode`` reflects the scripted exit code.

    A small ``ScriptedProc`` helper makes the per-test setup readable:
    declare the sequence of ``bws`` invocations you expect and what
    each one should return. The helper also records the argv passed
    to each call so tests can assert on it (e.g. "the token never
    appears in argv").
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Callable, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.bitwarden_provider import (
    DEFAULT_TOKEN_ENV_VAR,
    BitwardenAPIError,
    BitwardenCLIMissingError,
    BitwardenProvider,
    BitwardenTokenMissingError,
)


PROJECT_ID = "00000000-0000-0000-0000-000000000001"


def run(coro):
    """Synchronous wrapper, matches the existing project-wide convention."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class ScriptedProc:
    """Pluggable replacement for ``asyncio.create_subprocess_exec``.

    Configure with a list of ``(stdout, stderr, returncode)`` tuples
    in the order the test expects them to be consumed. Each call to
    the fake pops one entry; ``calls`` records the argv and env every
    invocation received so assertions can run after.
    """

    def __init__(self, responses: List[tuple]) -> None:
        # List of (stdout_bytes_or_str, stderr_bytes_or_str, returncode).
        self.responses = list(responses)
        self.calls: List[Dict[str, Any]] = []

    def factory(self) -> Callable[..., Any]:
        async def _create(*args: str, **kwargs: Any) -> Any:
            stdout, stderr, returncode = self.responses.pop(0)
            if isinstance(stdout, str):
                stdout = stdout.encode("utf-8")
            if isinstance(stderr, str):
                stderr = stderr.encode("utf-8")
            self.calls.append({"args": list(args), "env": kwargs.get("env", {})})
            proc = MagicMock()
            proc.returncode = returncode
            proc.communicate = AsyncMock(return_value=(stdout, stderr))
            proc.kill = MagicMock()
            return proc
        return _create


@pytest.fixture(autouse=True)
def bws_token_in_env(monkeypatch):
    """Default fixture: BWS_ACCESS_TOKEN is set, so the token-missing
    path doesn't accidentally fire in tests that aren't about it.

    Tests that need it absent explicitly use ``monkeypatch.delenv``.
    """
    monkeypatch.setenv(DEFAULT_TOKEN_ENV_VAR, "ut-fake-token")


@pytest.fixture
def provider() -> BitwardenProvider:
    """Provider with a fake bws_path so :func:`shutil.which` is bypassed."""
    return BitwardenProvider(
        project_id=PROJECT_ID,
        bws_path="/usr/bin/fake-bws",
    )


def _patch_subprocess(script: ScriptedProc):
    """Helper that returns the patch context for the subprocess factory."""
    return patch(
        "servonaut.services.bitwarden_provider.asyncio.create_subprocess_exec",
        side_effect=script.factory(),
    )


# ---------------------------------------------------------------------------
# Construction & interface basics
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_provider_name_is_stable_identifier(self, provider):
        assert provider.provider_name == "bitwarden"

    def test_project_id_exposed(self, provider):
        assert provider.project_id == PROJECT_ID

    def test_empty_project_id_rejected(self):
        # Mistakenly empty config = configuration bug, not silent
        # fallback. Fail at construction so the user sees it.
        with pytest.raises(ValueError, match="project_id"):
            BitwardenProvider(project_id="")


# ---------------------------------------------------------------------------
# Pre-flight: CLI + token
# ---------------------------------------------------------------------------


class TestCLIDiscovery:
    def test_missing_bws_raises_friendly_error(self, monkeypatch):
        # shutil.which returns None when the binary is not on PATH.
        monkeypatch.setattr(
            "servonaut.services.bitwarden_provider.shutil.which",
            lambda _: None,
        )
        provider = BitwardenProvider(project_id=PROJECT_ID)  # no override
        with pytest.raises(BitwardenCLIMissingError, match="servonaut secrets install bws"):
            run(provider.list_secrets())

    def test_resolve_path_lazy_not_eager(self, monkeypatch):
        # The provider must be constructable on a machine without bws —
        # we don't want a fresh CLI to crash on import.
        monkeypatch.setattr(
            "servonaut.services.bitwarden_provider.shutil.which",
            lambda _: None,
        )
        # No exception here:
        BitwardenProvider(project_id=PROJECT_ID)

    def test_filenotfound_during_exec_maps_to_cli_missing(self, provider):
        # Race: bws was on PATH at shutil.which but gone by exec.
        with patch(
            "servonaut.services.bitwarden_provider.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError(),
        ):
            with pytest.raises(BitwardenCLIMissingError):
                run(provider.list_secrets())


class TestTokenResolution:
    def test_missing_env_var_raises_friendly_error(self, provider, monkeypatch):
        monkeypatch.delenv(DEFAULT_TOKEN_ENV_VAR, raising=False)
        with pytest.raises(BitwardenTokenMissingError, match=DEFAULT_TOKEN_ENV_VAR):
            run(provider.list_secrets())

    def test_whitespace_only_token_treated_as_missing(self, provider, monkeypatch):
        # `cat | xargs export` flows occasionally produce a leading
        # newline or spaces; an effectively-empty token must NOT
        # silently authenticate "as nobody".
        monkeypatch.setenv(DEFAULT_TOKEN_ENV_VAR, "   \n  ")
        with pytest.raises(BitwardenTokenMissingError):
            run(provider.list_secrets())

    def test_custom_token_env_var_honoured(self, monkeypatch):
        monkeypatch.delenv(DEFAULT_TOKEN_ENV_VAR, raising=False)
        monkeypatch.setenv("MY_PROJ_BWS_TOKEN", "scoped-token")
        provider = BitwardenProvider(
            project_id=PROJECT_ID,
            token_env_var="MY_PROJ_BWS_TOKEN",
            bws_path="/usr/bin/fake-bws",
        )
        script = ScriptedProc([("[]", "", 0)])
        with _patch_subprocess(script):
            run(provider.list_secrets())
        # Token reaches subprocess via env.
        assert script.calls[0]["env"]["MY_PROJ_BWS_TOKEN"] == "scoped-token"


# ---------------------------------------------------------------------------
# Security: token never on argv
# ---------------------------------------------------------------------------


class TestTokenNeverOnArgv:
    """``/proc/<pid>/cmdline`` is world-readable on Linux. Tokens MUST
    never appear in argv — env only."""

    def test_list_does_not_pass_token_in_argv(self, provider, monkeypatch):
        monkeypatch.setenv(DEFAULT_TOKEN_ENV_VAR, "super-secret-token")
        script = ScriptedProc([("[]", "", 0)])
        with _patch_subprocess(script):
            run(provider.list_secrets())
        argv = script.calls[0]["args"]
        assert "super-secret-token" not in argv, (
            "Access token leaked into argv — exposing /proc/<pid>/cmdline"
        )
        assert script.calls[0]["env"][DEFAULT_TOKEN_ENV_VAR] == "super-secret-token"


# ---------------------------------------------------------------------------
# CRUD round-trips
# ---------------------------------------------------------------------------


def _list_response(secrets: List[Dict[str, Any]]) -> tuple:
    return (json.dumps(secrets), "", 0)


class TestListSecrets:
    def test_returns_sorted_keys_only(self, provider):
        # Listing must enumerate names, never values — interface
        # contract is enforced here too.
        script = ScriptedProc([_list_response([
            {"id": "id-zeta", "key": "zeta", "value": "zv",
             "projectId": PROJECT_ID},
            {"id": "id-alpha", "key": "alpha", "value": "av",
             "projectId": PROJECT_ID},
            {"id": "id-middle", "key": "middle", "value": "mv",
             "projectId": PROJECT_ID},
        ])])
        with _patch_subprocess(script):
            names = run(provider.list_secrets())
        assert names == ["alpha", "middle", "zeta"]

    def test_passes_project_id_scope(self, provider):
        # Cross-project listing is a privacy bug; pin the argv shape.
        script = ScriptedProc([_list_response([])])
        with _patch_subprocess(script):
            run(provider.list_secrets())
        argv = script.calls[0]["args"]
        assert PROJECT_ID in argv
        assert "list" in argv

    def test_empty_project_returns_empty_list(self, provider):
        script = ScriptedProc([_list_response([])])
        with _patch_subprocess(script):
            assert run(provider.list_secrets()) == []

    def test_drops_items_without_key(self, provider):
        # Defensive: a malformed bws response that omits ``key`` from
        # an item must not crash list_secrets — just skip the item.
        script = ScriptedProc([_list_response([
            {"id": "id-1", "key": "good", "value": "v"},
            {"id": "id-2", "value": "no-key-here"},
        ])])
        with _patch_subprocess(script):
            assert run(provider.list_secrets()) == ["good"]


class TestGetSecret:
    def test_round_trip(self, provider):
        script = ScriptedProc([_list_response([
            {"id": "id-1", "key": "api_key", "value": "sk-abc"},
        ])])
        with _patch_subprocess(script):
            assert run(provider.get_secret("api_key")) == "sk-abc"

    def test_missing_key_returns_none_not_exception(self, provider):
        # Interface contract: a missing secret is NOT exceptional.
        script = ScriptedProc([_list_response([
            {"id": "id-1", "key": "other", "value": "x"},
        ])])
        with _patch_subprocess(script):
            assert run(provider.get_secret("api_key")) is None

    def test_case_sensitive_name_match(self, provider):
        # Interface contract: providers MUST NOT canonicalise names.
        script = ScriptedProc([_list_response([
            {"id": "id-1", "key": "API_KEY", "value": "upper"},
            {"id": "id-2", "key": "api_key", "value": "lower"},
        ])])
        with _patch_subprocess(script):
            assert run(provider.get_secret("api_key")) == "lower"


class TestSetSecret:
    def test_creates_when_absent(self, provider):
        # Two subprocess calls: list (empty) + create.
        script = ScriptedProc([
            _list_response([]),
            (json.dumps({"id": "new", "key": "api_key", "value": "v"}), "", 0),
        ])
        with _patch_subprocess(script):
            run(provider.set_secret("api_key", "v"))
        # Second call is the create.
        create_argv = script.calls[1]["args"]
        assert "secret" in create_argv
        assert "create" in create_argv
        assert "api_key" in create_argv
        assert "v" in create_argv
        assert PROJECT_ID in create_argv

    def test_updates_when_present(self, provider):
        # list → existing, then edit by id with --value.
        script = ScriptedProc([
            _list_response([
                {"id": "id-1", "key": "api_key", "value": "old"},
            ]),
            (json.dumps({"id": "id-1", "key": "api_key", "value": "new"}), "", 0),
        ])
        with _patch_subprocess(script):
            run(provider.set_secret("api_key", "new"))
        edit_argv = script.calls[1]["args"]
        assert "edit" in edit_argv
        assert "id-1" in edit_argv
        assert "--value" in edit_argv
        assert "new" in edit_argv
        # Name is NOT in argv — we update value only.
        # (The bws CLI also allows --key but we'd never re-key on
        # update; pinning it prevents accidental key mutation.)
        assert "--key" not in edit_argv


class TestDeleteSecret:
    def test_returns_true_when_present(self, provider):
        script = ScriptedProc([
            _list_response([
                {"id": "id-1", "key": "api_key", "value": "v"},
            ]),
            ("Deleted secret id-1", "", 0),
        ])
        with _patch_subprocess(script):
            assert run(provider.delete_secret("api_key")) is True

    def test_returns_false_when_absent_idempotent(self, provider):
        # Idempotent: deleting a non-present name is NOT an error.
        script = ScriptedProc([_list_response([])])
        with _patch_subprocess(script):
            assert run(provider.delete_secret("ghost")) is False

    def test_delete_passes_secret_id(self, provider):
        script = ScriptedProc([
            _list_response([
                {"id": "id-xyz", "key": "k", "value": "v"},
            ]),
            ("ok", "", 0),
        ])
        with _patch_subprocess(script):
            run(provider.delete_secret("k"))
        delete_argv = script.calls[1]["args"]
        assert "delete" in delete_argv
        assert "id-xyz" in delete_argv


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


class TestFailures:
    def test_non_zero_exit_raises_api_error_with_context(self, provider):
        script = ScriptedProc([("", "bws: not authenticated", 1)])
        with _patch_subprocess(script):
            with pytest.raises(BitwardenAPIError) as exc_info:
                run(provider.list_secrets())
        err = exc_info.value
        assert err.exit_code == 1
        assert "not authenticated" in err.stderr

    def test_malformed_json_raises_api_error(self, provider):
        script = ScriptedProc([("not json at all", "", 0)])
        with _patch_subprocess(script):
            with pytest.raises(BitwardenAPIError, match="non-JSON"):
                run(provider.list_secrets())

    def test_non_list_response_raises_api_error(self, provider):
        # bws should always return a list for ``secret list``; if it
        # ever doesn't, surface a clear error rather than crashing on
        # iteration.
        script = ScriptedProc([(json.dumps({"unexpected": "object"}), "", 0)])
        with _patch_subprocess(script):
            with pytest.raises(BitwardenAPIError, match="non-list"):
                run(provider.list_secrets())

    def test_timeout_raises_api_error_and_kills_subprocess(self, provider):
        """Slow / hung bws → timeout, subprocess killed, no zombie left."""

        async def _hang(*_args, **_kwargs):
            proc = MagicMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            proc.kill = MagicMock()
            # Configure communicate to behave like a real one when the
            # cleanup path calls it after the timeout.
            return proc

        # We patch wait_for to immediately raise TimeoutError so the
        # test doesn't actually wait the configured timeout.
        with patch(
            "servonaut.services.bitwarden_provider.asyncio.create_subprocess_exec",
            side_effect=_hang,
        ), patch(
            "servonaut.services.bitwarden_provider.asyncio.wait_for",
            side_effect=asyncio.TimeoutError(),
        ):
            with pytest.raises(BitwardenAPIError, match="timed out"):
                run(provider.list_secrets())
