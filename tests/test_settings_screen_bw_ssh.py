"""Tests for the Bitwarden SSH Vault section in SettingsScreen.

Covers:
- Status line renders "Not configured" when get_personal_config returns None
- Status line renders "Configured" when a config is returned
- Edit button reveals the form
- Cancel button hides the form without an API call
- Save with empty vault_url: notify error, no API call
- Save with invalid URL (no http/https prefix): notify error, no API call
- Save success: calls put_personal_config with correct body, hides form
- Save 402: notify warning, form stays open
- Save generic error: notify verbatim (markup=False)
- Provider is locked to BITWARDEN_PM_PROVIDER in the PUT body
- Re-rendering after save shows the new vault_url in the status line
- Demo-mode: vault_url is redacted in the status line when demo_mode=True
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.screens.settings import SettingsScreen
from servonaut.services.api_client import APIError
from servonaut.services.bw_ssh_config_service import BITWARDEN_PM_PROVIDER


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeWidget:
    """Minimal stand-in for a Textual Static / Input / Button widget."""

    def __init__(self, value: str = "", display: bool = True) -> None:
        self.value = value
        self.display = display
        self._updates: list[str] = []
        self.disabled = False

    def update(self, markup: str) -> None:
        self._updates.append(markup)

    def focus(self) -> None:
        pass

    @property
    def last_update(self) -> str:
        return self._updates[-1] if self._updates else ""


class _FakeScreen:
    """Duck-typed stand-in for SettingsScreen targeting BW SSH vault methods.

    All BW SSH vault methods from SettingsScreen are called via
    ``SettingsScreen.<method>(self_fake, ...)`` so they receive the right
    ``self`` without relying on MRO binding.
    """

    def __init__(
        self,
        *,
        bw_config: Optional[Dict[str, Any]] = None,
        put_result: Optional[Dict[str, Any]] = None,
        put_exc: Optional[Exception] = None,
        demo_mode: bool = False,
        vault_url_input_value: str = "",
        collection_input_value: str = "",
    ) -> None:
        self._bw_ssh_config: Optional[Dict[str, Any]] = bw_config

        # Fake widgets
        self._status_widget = _FakeWidget()
        self._form_container = _FakeWidget(display=False)
        self._vault_url_input = _FakeWidget(value=vault_url_input_value)
        self._collection_input = _FakeWidget(value=collection_input_value)

        # Capture notify calls
        self._notifications: list[dict] = []

        # Build service mock
        svc = MagicMock()
        svc.get_personal_config = AsyncMock(return_value=bw_config)
        if put_exc is not None:
            svc.put_personal_config = AsyncMock(side_effect=put_exc)
        else:
            svc.put_personal_config = AsyncMock(return_value=put_result or {})

        # Build app mock
        app = MagicMock()
        app.bw_ssh_config_service = svc
        app.demo_mode = demo_mode
        app.redaction_service = MagicMock() if demo_mode else None
        app.notify = self._capture_notify
        self.app = app

    def _capture_notify(
        self,
        message: str,
        *,
        severity: str = "information",
        markup: bool = True,
    ) -> None:
        self._notifications.append(
            {"message": message, "severity": severity, "markup": markup}
        )

    def query_one(self, selector: str, widget_type: type = None) -> Any:
        mapping = {
            "#bw_ssh_vault_status": self._status_widget,
            "#bw_ssh_vault_form": self._form_container,
            "#bw_ssh_vault_url": self._vault_url_input,
            "#bw_ssh_default_collection_id": self._collection_input,
        }
        widget = mapping.get(selector)
        if widget is None:
            raise LookupError(f"No fake widget for selector {selector!r}")
        return widget

    def run_worker(
        self, coro, *, group: str = "", name: str = "", exclusive: bool = False
    ) -> None:
        """Run the coroutine synchronously in tests (no Textual event loop).

        Uses ``asyncio.run`` rather than ``get_event_loop().run_until_complete``
        so each invocation gets a fresh loop — prior tests in the suite that
        close/exhaust the default loop don't pollute this one.
        """
        asyncio.run(coro)

    # Wire in the real async worker method so _save_bw_ssh_config can
    # call self._do_save_bw_ssh_config(...) correctly.
    _do_save_bw_ssh_config = SettingsScreen._do_save_bw_ssh_config
    _refresh_bw_ssh_status = SettingsScreen._refresh_bw_ssh_status
    _hide_bw_ssh_form = SettingsScreen._hide_bw_ssh_form


# Shortcuts so tests can call the real method with the fake self.

def _refresh_status(fake: _FakeScreen) -> None:
    SettingsScreen._refresh_bw_ssh_status(fake)  # type: ignore[arg-type]


def _show_form(fake: _FakeScreen) -> None:
    SettingsScreen._show_bw_ssh_form(fake)  # type: ignore[arg-type]


def _hide_form(fake: _FakeScreen) -> None:
    SettingsScreen._hide_bw_ssh_form(fake)  # type: ignore[arg-type]


def _save(fake: _FakeScreen) -> None:
    SettingsScreen._save_bw_ssh_config(fake)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Status line rendering
# ---------------------------------------------------------------------------


class TestBwSshVaultStatusLine:
    def test_not_configured_when_none(self) -> None:
        fake = _FakeScreen(bw_config=None)
        _refresh_status(fake)
        assert "Not configured" in fake._status_widget.last_update

    def test_configured_shows_vault_url(self) -> None:
        fake = _FakeScreen(
            bw_config={
                "provider": "bitwarden_pm",
                "config": {"vault_url": "https://vault.example.com"},
                "updated_at": "2026-05-01T12:00:00Z",
            }
        )
        _refresh_status(fake)
        assert "Configured" in fake._status_widget.last_update
        assert "https://vault.example.com" in fake._status_widget.last_update

    def test_configured_shows_updated_at(self) -> None:
        fake = _FakeScreen(
            bw_config={
                "provider": "bitwarden_pm",
                "config": {"vault_url": "https://vault.example.com"},
                "updated_at": "2026-05-01T12:00:00Z",
            }
        )
        _refresh_status(fake)
        assert "2026-05-01T12:00:00Z" in fake._status_widget.last_update

    def test_configured_without_updated_at_still_shows_configured(self) -> None:
        fake = _FakeScreen(
            bw_config={
                "provider": "bitwarden_pm",
                "config": {"vault_url": "https://vault.example.com"},
            }
        )
        _refresh_status(fake)
        assert "Configured" in fake._status_widget.last_update
        assert "https://vault.example.com" in fake._status_widget.last_update


# ---------------------------------------------------------------------------
# Demo-mode redaction
# ---------------------------------------------------------------------------


class TestBwSshVaultDemoMode:
    def test_vault_url_redacted_in_demo_mode(self) -> None:
        fake = _FakeScreen(
            bw_config={
                "provider": "bitwarden_pm",
                "config": {"vault_url": "https://internal-vault.corp.example.com"},
                "updated_at": "2026-05-01T12:00:00Z",
            },
            demo_mode=True,
        )
        _refresh_status(fake)
        last = fake._status_widget.last_update
        assert "internal-vault.corp.example.com" not in last
        assert "[redacted]" in last

    def test_vault_url_shown_when_demo_mode_false(self) -> None:
        fake = _FakeScreen(
            bw_config={
                "provider": "bitwarden_pm",
                "config": {"vault_url": "https://vault.example.com"},
                "updated_at": "2026-05-01T12:00:00Z",
            },
            demo_mode=False,
        )
        _refresh_status(fake)
        last = fake._status_widget.last_update
        assert "vault.example.com" in last
        assert "[redacted]" not in last


# ---------------------------------------------------------------------------
# Form visibility
# ---------------------------------------------------------------------------


class TestBwSshVaultFormVisibility:
    def test_edit_reveals_form(self) -> None:
        fake = _FakeScreen(bw_config=None)
        assert fake._form_container.display is False
        _show_form(fake)
        assert fake._form_container.display is True

    def test_edit_populates_vault_url_from_config(self) -> None:
        fake = _FakeScreen(
            bw_config={
                "provider": "bitwarden_pm",
                "config": {
                    "vault_url": "https://vault.example.com",
                    "default_collection_id": "col-abc",
                },
            }
        )
        _show_form(fake)
        assert fake._vault_url_input.value == "https://vault.example.com"
        assert fake._collection_input.value == "col-abc"

    def test_edit_blank_inputs_when_not_configured(self) -> None:
        fake = _FakeScreen(bw_config=None)
        _show_form(fake)
        assert fake._vault_url_input.value == ""
        assert fake._collection_input.value == ""

    def test_cancel_hides_form(self) -> None:
        fake = _FakeScreen(bw_config=None)
        fake._form_container.display = True
        _hide_form(fake)
        assert fake._form_container.display is False

    def test_cancel_makes_no_api_call(self) -> None:
        fake = _FakeScreen(bw_config=None)
        fake._form_container.display = True
        _hide_form(fake)
        fake.app.bw_ssh_config_service.put_personal_config.assert_not_called()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestBwSshVaultValidation:
    def test_empty_vault_url_triggers_error_notify(self) -> None:
        fake = _FakeScreen(vault_url_input_value="")
        fake._form_container.display = True
        _save(fake)
        assert any(n["severity"] == "error" for n in fake._notifications)

    def test_empty_vault_url_keeps_form_open(self) -> None:
        fake = _FakeScreen(vault_url_input_value="")
        fake._form_container.display = True
        _save(fake)
        assert fake._form_container.display is True

    def test_empty_vault_url_no_api_call(self) -> None:
        fake = _FakeScreen(vault_url_input_value="")
        _save(fake)
        fake.app.bw_ssh_config_service.put_personal_config.assert_not_called()

    def test_url_without_http_prefix_triggers_error(self) -> None:
        fake = _FakeScreen(vault_url_input_value="vault.example.com")
        _save(fake)
        assert any(n["severity"] == "error" for n in fake._notifications)
        fake.app.bw_ssh_config_service.put_personal_config.assert_not_called()

    def test_http_prefix_is_accepted(self) -> None:
        result = {
            "provider": "bitwarden_pm",
            "config": {"vault_url": "http://local.vault"},
        }
        fake = _FakeScreen(put_result=result, vault_url_input_value="http://local.vault")
        fake._form_container.display = True
        _save(fake)
        fake.app.bw_ssh_config_service.put_personal_config.assert_called_once()

    def test_https_prefix_is_accepted(self) -> None:
        result = {
            "provider": "bitwarden_pm",
            "config": {"vault_url": "https://vault.example.com"},
        }
        fake = _FakeScreen(
            put_result=result, vault_url_input_value="https://vault.example.com"
        )
        fake._form_container.display = True
        _save(fake)
        fake.app.bw_ssh_config_service.put_personal_config.assert_called_once()


# ---------------------------------------------------------------------------
# Save success
# ---------------------------------------------------------------------------


class TestBwSshVaultSaveSuccess:
    def test_save_success_hides_form(self) -> None:
        result = {
            "provider": "bitwarden_pm",
            "config": {"vault_url": "https://vault.example.com"},
            "updated_at": "2026-05-01T12:00:00Z",
        }
        fake = _FakeScreen(
            put_result=result, vault_url_input_value="https://vault.example.com"
        )
        fake._form_container.display = True
        _save(fake)
        assert fake._form_container.display is False

    def test_save_success_status_shows_configured(self) -> None:
        result = {
            "provider": "bitwarden_pm",
            "config": {"vault_url": "https://vault.example.com"},
            "updated_at": "2026-05-01T12:00:00Z",
        }
        fake = _FakeScreen(
            put_result=result, vault_url_input_value="https://vault.example.com"
        )
        fake._form_container.display = True
        _save(fake)
        last = fake._status_widget.last_update
        assert "Configured" in last
        assert "https://vault.example.com" in last

    def test_save_uses_bitwarden_pm_provider(self) -> None:
        result = {
            "provider": "bitwarden_pm",
            "config": {"vault_url": "https://vault.example.com"},
        }
        fake = _FakeScreen(
            put_result=result, vault_url_input_value="https://vault.example.com"
        )
        _save(fake)
        kwargs = fake.app.bw_ssh_config_service.put_personal_config.call_args.kwargs
        assert kwargs.get("provider") == BITWARDEN_PM_PROVIDER

    def test_save_passes_vault_url(self) -> None:
        result = {
            "provider": "bitwarden_pm",
            "config": {"vault_url": "https://vault.example.com"},
        }
        fake = _FakeScreen(
            put_result=result, vault_url_input_value="https://vault.example.com"
        )
        _save(fake)
        kwargs = fake.app.bw_ssh_config_service.put_personal_config.call_args.kwargs
        assert kwargs.get("vault_url") == "https://vault.example.com"

    def test_save_passes_none_for_empty_collection_id(self) -> None:
        result = {
            "provider": "bitwarden_pm",
            "config": {"vault_url": "https://vault.example.com"},
        }
        fake = _FakeScreen(
            put_result=result,
            vault_url_input_value="https://vault.example.com",
            collection_input_value="",
        )
        _save(fake)
        kwargs = fake.app.bw_ssh_config_service.put_personal_config.call_args.kwargs
        assert kwargs.get("default_collection_id") is None

    def test_save_passes_collection_id_when_provided(self) -> None:
        result = {
            "provider": "bitwarden_pm",
            "config": {
                "vault_url": "https://vault.example.com",
                "default_collection_id": "col-123",
            },
        }
        fake = _FakeScreen(
            put_result=result,
            vault_url_input_value="https://vault.example.com",
            collection_input_value="col-123",
        )
        _save(fake)
        kwargs = fake.app.bw_ssh_config_service.put_personal_config.call_args.kwargs
        assert kwargs.get("default_collection_id") == "col-123"


# ---------------------------------------------------------------------------
# 402 gate
# ---------------------------------------------------------------------------


class TestBwSshVaultSave402:
    def test_402_notifies_warning(self) -> None:
        exc = APIError(
            code="payment_required",
            message="Payment required",
            status=402,
        )
        fake = _FakeScreen(
            put_exc=exc, vault_url_input_value="https://vault.example.com"
        )
        fake._form_container.display = True
        _save(fake)
        assert any(n["severity"] == "warning" for n in fake._notifications)

    def test_402_form_stays_open(self) -> None:
        exc = APIError(
            code="payment_required",
            message="Payment required",
            status=402,
        )
        fake = _FakeScreen(
            put_exc=exc, vault_url_input_value="https://vault.example.com"
        )
        fake._form_container.display = True
        _save(fake)
        assert fake._form_container.display is True

    def test_402_message_mentions_paid_plan(self) -> None:
        exc = APIError(
            code="payment_required",
            message="Payment required",
            status=402,
        )
        fake = _FakeScreen(
            put_exc=exc, vault_url_input_value="https://vault.example.com"
        )
        _save(fake)
        warning_msgs = [
            n["message"]
            for n in fake._notifications
            if n["severity"] == "warning"
        ]
        assert any("paid plan" in m or "Upgrade" in m for m in warning_msgs)


# ---------------------------------------------------------------------------
# Generic / network errors
# ---------------------------------------------------------------------------


class TestBwSshVaultSaveGenericError:
    def test_generic_api_error_notifies_error(self) -> None:
        exc = APIError(
            code="internal_error",
            message="Internal Server Error",
            status=500,
        )
        fake = _FakeScreen(
            put_exc=exc, vault_url_input_value="https://vault.example.com"
        )
        fake._form_container.display = True
        _save(fake)
        assert any(n["severity"] == "error" for n in fake._notifications)

    def test_generic_api_error_markup_false(self) -> None:
        exc = APIError(
            code="internal_error",
            message="Internal Server Error",
            status=500,
        )
        fake = _FakeScreen(
            put_exc=exc, vault_url_input_value="https://vault.example.com"
        )
        _save(fake)
        for n in fake._notifications:
            if n["severity"] == "error":
                assert n["markup"] is False, (
                    f"Expected markup=False on error notify, got {n!r}"
                )

    def test_network_error_notifies_error(self) -> None:
        fake = _FakeScreen(
            put_exc=OSError("Network unreachable"),
            vault_url_input_value="https://vault.example.com",
        )
        fake._form_container.display = True
        _save(fake)
        assert any(n["severity"] == "error" for n in fake._notifications)

    def test_network_error_form_stays_open(self) -> None:
        fake = _FakeScreen(
            put_exc=OSError("Network unreachable"),
            vault_url_input_value="https://vault.example.com",
        )
        fake._form_container.display = True
        _save(fake)
        assert fake._form_container.display is True
