"""Tests for ``servonaut login`` / ``servonaut logout`` CLI handlers.

Drives :func:`servonaut.cli.login.handle_login_command` and
:func:`handle_logout_command` directly with constructed Namespaces, patching
``AuthService`` at the module seam so no network or filesystem I/O happens.
"""
from __future__ import annotations

import argparse
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.cli import login as cli_login


def _ns(**kwargs) -> argparse.Namespace:
    base = {"no_browser": True, "force": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


def _make_auth(
    *,
    authenticated: bool = False,
    flow: dict | None = None,
    poll_result: bool = True,
):
    auth = MagicMock()
    auth.is_authenticated = authenticated
    auth.plan = "solo"
    auth.start_device_flow = AsyncMock(
        return_value=flow if flow is not None else {
            "device_code": "dev-123",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://servonaut.dev/activate",
            "interval": 1,
            "expires_in": 60,
        }
    )
    auth.poll_for_token = AsyncMock(return_value=poll_result)
    auth.logout = AsyncMock(return_value=None)
    return auth


def _patch_auth(monkeypatch, auth):
    import servonaut.services.auth_service as auth_mod
    monkeypatch.setattr(auth_mod, "AuthService", lambda: auth)


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


def test_login_already_authenticated_short_circuits(monkeypatch, capsys):
    auth = _make_auth(authenticated=True)
    _patch_auth(monkeypatch, auth)

    rc = cli_login.handle_login_command(_ns())

    assert rc == 0
    out = capsys.readouterr().out
    assert "Already signed in" in out
    assert "--force" in out
    auth.start_device_flow.assert_not_awaited()


def test_login_force_runs_flow_despite_session(monkeypatch, capsys):
    auth = _make_auth(authenticated=True)
    _patch_auth(monkeypatch, auth)

    rc = cli_login.handle_login_command(_ns(force=True))

    assert rc == 0
    auth.start_device_flow.assert_awaited_once()
    auth.poll_for_token.assert_awaited_once()


def test_login_success_prints_url_code_and_plan(monkeypatch, capsys):
    auth = _make_auth()
    _patch_auth(monkeypatch, auth)

    rc = cli_login.handle_login_command(_ns())

    assert rc == 0
    out = capsys.readouterr().out
    assert "https://servonaut.dev/activate" in out
    assert "ABCD-EFGH" in out
    assert "plan: solo" in out
    # expires_in (60s) bounds the poll budget, not the 120s default.
    kwargs = auth.poll_for_token.call_args.kwargs
    assert kwargs["max_wait_seconds"] == 60
    assert kwargs["interval"] == 1


def test_login_denied_or_timeout_exits_1(monkeypatch, capsys):
    auth = _make_auth(poll_result=False)
    _patch_auth(monkeypatch, auth)

    rc = cli_login.handle_login_command(_ns())

    assert rc == 1
    assert "not completed" in capsys.readouterr().err


def test_login_initiation_failure_exits_1(monkeypatch, capsys):
    auth = _make_auth()
    auth.start_device_flow = AsyncMock(
        side_effect=RuntimeError("Device flow initiation failed: HTTP 503")
    )
    _patch_auth(monkeypatch, auth)

    rc = cli_login.handle_login_command(_ns())

    assert rc == 1
    assert "HTTP 503" in capsys.readouterr().err


def test_login_malformed_flow_response_exits_1(monkeypatch, capsys):
    auth = _make_auth(flow={"interval": 5})
    _patch_auth(monkeypatch, auth)

    rc = cli_login.handle_login_command(_ns())

    assert rc == 1
    assert "missing" in capsys.readouterr().err


def test_login_opens_browser_unless_no_browser(monkeypatch, capsys):
    auth = _make_auth(flow={
        "device_code": "dev-123",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://servonaut.dev/activate",
        "verification_uri_complete": "https://servonaut.dev/activate?code=ABCD-EFGH",
        "interval": 1,
        "expires_in": 60,
    })
    _patch_auth(monkeypatch, auth)
    opened: list[str] = []
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)

    rc = cli_login.handle_login_command(_ns(no_browser=False))

    assert rc == 0
    # Prefers verification_uri_complete when the server provides it.
    assert opened == ["https://servonaut.dev/activate?code=ABCD-EFGH"]

    opened.clear()
    rc = cli_login.handle_login_command(_ns(no_browser=True))
    assert rc == 0
    assert opened == []


def test_login_ctrl_c_aborts_with_130(monkeypatch, capsys):
    """Ctrl+C while waiting for approval → 'Sign-in aborted.' + exit 130."""
    auth = _make_auth()
    auth.start_device_flow = AsyncMock(side_effect=KeyboardInterrupt)
    _patch_auth(monkeypatch, auth)

    rc = cli_login.handle_login_command(_ns())

    assert rc == 130
    assert "aborted" in capsys.readouterr().err


def test_login_loads_secrets_env_overrides(monkeypatch):
    """login/logout must load ~/.secrets/servonaut.env (SERVONAUT_API_URL
    et al.) — they build no ConfigManager, which is where every other entry
    point gets it. Regression: device flow targeted production despite a
    staging override in the env file."""
    import servonaut.config.secrets as secrets_mod
    calls: list[str] = []
    monkeypatch.setattr(
        secrets_mod, "load_secrets_env", lambda *a, **k: calls.append("loaded")
    )
    auth = _make_auth(authenticated=True)
    _patch_auth(monkeypatch, auth)

    assert cli_login.handle_login_command(_ns()) == 0
    assert cli_login.handle_logout_command(_ns()) == 0
    assert calls == ["loaded", "loaded"]


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------


def test_logout_not_signed_in_is_noop(monkeypatch, capsys):
    auth = _make_auth(authenticated=False)
    _patch_auth(monkeypatch, auth)

    rc = cli_login.handle_logout_command(_ns())

    assert rc == 0
    assert "Not signed in" in capsys.readouterr().out
    auth.logout.assert_not_awaited()


def test_logout_revokes_and_reports(monkeypatch, capsys):
    auth = _make_auth(authenticated=True)
    _patch_auth(monkeypatch, auth)

    rc = cli_login.handle_logout_command(_ns())

    assert rc == 0
    assert "Signed out" in capsys.readouterr().out
    auth.logout.assert_awaited_once()
