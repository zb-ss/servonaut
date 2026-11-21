"""Startup handling for the optional native Vault background worker."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from servonaut.app import ServonautApp
from servonaut.services.api_client import ClientUpdateRequiredError
from servonaut.services.vault.crypto import IntegrityError


class _UnavailableVault:
    async def discover(self) -> bool:
        raise httpx.ConnectError("loopback endpoint refused")


class _IntegrityFailureVault:
    async def discover(self) -> bool:
        raise IntegrityError("server signature did not verify")


class _UpdateRequiredVault:
    async def discover(self) -> bool:
        raise ClientUpdateRequiredError(details={"minimum_version": "99.0.0"})


def test_vault_startup_ignores_only_typed_transport_failure() -> None:
    """A local API outage must not terminate the rest of the TUI startup."""
    app = ServonautApp()
    app.vault_command_service = _UnavailableVault()

    asyncio.run(app._run_vault_background())

    assert app.vault_available is False


def test_vault_startup_surfaces_integrity_failure() -> None:
    """Integrity failures remain visible and never look like feature absence."""
    app = ServonautApp()
    app.vault_command_service = _IntegrityFailureVault()
    app.notify = Mock()

    asyncio.run(app._run_vault_background())

    app.notify.assert_called_once()
    assert app.notify.call_args.kwargs["severity"] == "warning"


def test_vault_startup_keeps_navigation_and_surfaces_the_update_required_notice() -> None:
    app = ServonautApp()
    app.vault_command_service = _UpdateRequiredVault()
    app.notify = Mock()

    asyncio.run(app._run_vault_background())

    assert app.vault_available is False
    assert app.vault_update_required is True
    app.notify.assert_called_once()
    assert app.notify.call_args.kwargs["title"] == "Vault"
    assert "Update to 99.0.0" in app.notify.call_args.args[0]


@pytest.mark.asyncio
async def test_proxy_426_follows_ordinary_vault_startup_warning(proxy_426) -> None:
    app = ServonautApp()
    app.vault_command_service = Mock(discover=AsyncMock(side_effect=proxy_426))
    app.notify = Mock()

    await app._run_vault_background()

    assert app.vault_available is False
    assert app.vault_update_required is False
    assert app.notify.call_args.args == ("Vault background access needs attention. Open Vault to review it.",)


@pytest.mark.asyncio
async def test_after_a_successful_vault_refresh_discovery_resumes_polling(monkeypatch) -> None:
    app = ServonautApp()
    service = Mock(discover=AsyncMock(return_value=True))
    app.vault_command_service = service
    app.vault_update_required = True
    poll = AsyncMock()
    monkeypatch.setattr("servonaut.services.vault.background.poll_vault", poll)
    app.run_worker = Mock()

    app.resume_vault_after_update_refusal()
    worker = app.run_worker.call_args
    assert worker.kwargs["group"] == "vault_background"
    assert worker.kwargs["exclusive"] is True
    await worker.args[0]

    assert app.vault_available is True
    assert app.vault_update_required is False
    service.discover.assert_awaited_once()
    poll.assert_awaited_once_with(service, discovered=True)
