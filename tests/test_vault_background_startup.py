"""Startup handling for the optional native Vault background worker."""

from __future__ import annotations

import asyncio
from unittest.mock import Mock

import httpx

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


def test_vault_startup_leaves_update_required_to_shared_notice() -> None:
    app = ServonautApp()
    app.vault_command_service = _UpdateRequiredVault()
    app.notify = Mock()

    asyncio.run(app._run_vault_background())

    app.notify.assert_not_called()
