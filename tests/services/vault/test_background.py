"""Headless startup reads verified state and always releases its leases."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.vault.background import (
    poll_vault, run_relay_with_vault, unlock_vault_for_startup,
)
from servonaut.services.vault.crypto import VaultCryptoError
from servonaut.services.vault.identity_store import IdentityStoreError


@pytest.mark.parametrize("error", [IdentityStoreError, VaultCryptoError])
def test_locked_custody_does_not_break_startup_or_disclose_error(error, caplog):
    service = SimpleNamespace(
        unlock_existing_identity=MagicMock(side_effect=error("secret-bearing detail")),
        close=MagicMock(),
    )
    assert unlock_vault_for_startup(service) is False
    assert error.__name__ in caplog.text
    assert "secret-bearing detail" not in caplog.text
    service.close.assert_not_called()
    # Startup only isolates the refusal; actual vault access still rejects it.
    with pytest.raises(error):
        service.unlock_existing_identity()


def test_unexpected_startup_errors_are_not_silenced():
    service = SimpleNamespace(
        unlock_existing_identity=MagicMock(side_effect=RuntimeError("bug")),
    )
    with pytest.raises(RuntimeError, match="bug"):
        unlock_vault_for_startup(service)


def test_default_factory_keeps_locked_runtime_available_for_recovery(monkeypatch, tmp_path):
    from servonaut.config.manager import ConfigManager
    from servonaut.services.vault import command_service

    manager = ConfigManager(tmp_path / "config.yaml")
    manager.load()
    monkeypatch.setattr(command_service, "ConfigManager", lambda: manager)
    monkeypatch.setattr(command_service, "AuthService", lambda: SimpleNamespace(
        is_authenticated=True, user_id=1,
    ))
    monkeypatch.setattr(
        command_service.VaultCommandService, "unlock_existing_identity",
        MagicMock(side_effect=IdentityStoreError("locked custody")),
    )
    service = command_service.VaultCommandService.from_local_session()
    try:
        assert service.identity is not None
        assert service.store.identity is None
        with pytest.raises(IdentityStoreError):
            service.unlock_existing_identity()
    finally:
        service.close()


def test_absent_feature_never_unlocks_or_grants():
    service = SimpleNamespace(discover=AsyncMock(return_value=False), unlock_existing_identity=MagicMock(), process_grants=AsyncMock())
    asyncio.run(poll_vault(service))
    service.unlock_existing_identity.assert_not_called()
    service.process_grants.assert_not_awaited()


def test_startup_polls_verified_access_and_shutdown_cancels_polling():
    async def scenario():
        service = SimpleNamespace(discover=AsyncMock(return_value=True), unlock_existing_identity=MagicMock(return_value=True), process_grants=AsyncMock(), poll_interval_seconds=60, close=MagicMock())
        class Listener:
            async def run(self):
                while not service.process_grants.await_count:
                    await asyncio.sleep(0)
        await run_relay_with_vault(Listener(), service)
        service.process_grants.assert_awaited_once_with(interactive=False)
        service.close.assert_called_once()
        assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    asyncio.run(scenario())


def test_listener_failure_still_releases_runtime():
    service = SimpleNamespace(discover=AsyncMock(return_value=False), close=MagicMock())
    listener = SimpleNamespace(run=AsyncMock(side_effect=RuntimeError("connection failed")))
    try:
        asyncio.run(run_relay_with_vault(listener, service))
    except RuntimeError:
        pass
    service.close.assert_called_once()
