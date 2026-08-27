"""Regression coverage for enabling remembered Memory Sync unlock."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import (
    DEFAULT_REMEMBER_TTL_DAYS,
    AppConfig,
    MemoryConfig,
)
from servonaut.screens.memory_keys import PassphraseResult
from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen


def _make_screen_stub(
    *,
    passphrase: str = "test-passphrase",
    can_unwrap: bool = True,
    update_side_effect: Exception | None = None,
) -> SimpleNamespace:
    """Build only the collaborators used by ``_do_remember``."""
    config_manager = MagicMock()
    config_manager.get.return_value = AppConfig(memory=MemoryConfig())
    config_manager.update.side_effect = update_side_effect

    sync = MagicMock()
    sync.is_configured = True
    sync.can_unwrap_local.return_value = can_unwrap

    app = SimpleNamespace(
        memory_sync_service=sync,
        config_manager=config_manager,
        notify=MagicMock(),
        push_screen_wait=AsyncMock(
            return_value=PassphraseResult(passphrase=passphrase, remember=True)
        ),
    )
    stub = SimpleNamespace(app=app, _render_state=MagicMock())
    stub._store_remembered_passphrase = (  # type: ignore[attr-defined]
        lambda candidate: MemorySyncSetupScreen._store_remembered_passphrase(
            stub, candidate
        )
    )
    return stub


@pytest.mark.asyncio
async def test_remember_verified_passphrase_stores_keychain_and_stamps_expiry() -> None:
    """A verified passphrase enables the 30-day, device-local opt-in."""
    import servonaut.services.memory.passphrase_store as passphrase_store

    stub = _make_screen_stub()
    before = datetime.now(timezone.utc)

    with (
        patch.object(passphrase_store, "keyring_available", return_value=True),
        patch.object(passphrase_store, "store_passphrase", return_value=True) as store,
    ):
        await MemorySyncSetupScreen._do_remember(stub)  # type: ignore[arg-type]

    stub.app.memory_sync_service.can_unwrap_local.assert_called_once_with(
        "test-passphrase"
    )
    store.assert_called_once_with("test-passphrase")
    assert stub.app.push_screen_wait.call_args.args[0]._remember_default is True

    updated_memory = stub.app.config_manager.update.call_args.kwargs["memory"]
    assert updated_memory.sync_remember_device is True
    expiry = datetime.fromisoformat(updated_memory.sync_remember_expires_at)
    expected = before + timedelta(days=DEFAULT_REMEMBER_TTL_DAYS)
    assert expected - timedelta(seconds=2) <= expiry <= expected + timedelta(seconds=2)
    stub._render_state.assert_called_once()


@pytest.mark.asyncio
async def test_remember_wrong_passphrase_never_stores_or_updates_config() -> None:
    """An unverified passphrase never reaches the OS keychain."""
    import servonaut.services.memory.passphrase_store as passphrase_store

    stub = _make_screen_stub(can_unwrap=False)
    with patch.object(passphrase_store, "store_passphrase") as store:
        await MemorySyncSetupScreen._do_remember(stub)  # type: ignore[arg-type]

    store.assert_not_called()
    stub.app.config_manager.update.assert_not_called()
    stub._render_state.assert_not_called()
    assert any(
        "Wrong passphrase" in call.args[0] for call in stub.app.notify.call_args_list
    )


@pytest.mark.asyncio
async def test_remember_without_trusted_keychain_keeps_config_unchanged() -> None:
    """Auto-unlock remains off when this device has no trusted keychain."""
    import servonaut.services.memory.passphrase_store as passphrase_store

    stub = _make_screen_stub()
    with (
        patch.object(passphrase_store, "keyring_available", return_value=False),
        patch.object(passphrase_store, "store_passphrase") as store,
    ):
        await MemorySyncSetupScreen._do_remember(stub)  # type: ignore[arg-type]

    store.assert_not_called()
    stub.app.config_manager.update.assert_not_called()
    stub._render_state.assert_not_called()
    assert any(
        "No trusted OS keychain" in call.args[0]
        for call in stub.app.notify.call_args_list
    )


@pytest.mark.asyncio
async def test_remember_config_failure_clears_newly_stored_passphrase() -> None:
    """A config write failure leaves no passphrase stored in the keychain."""
    import servonaut.services.memory.passphrase_store as passphrase_store

    stub = _make_screen_stub(update_side_effect=OSError("config unavailable"))
    with (
        patch.object(passphrase_store, "keyring_available", return_value=True),
        patch.object(passphrase_store, "store_passphrase", return_value=True) as store,
        patch.object(passphrase_store, "clear_passphrase") as clear,
    ):
        await MemorySyncSetupScreen._do_remember(stub)  # type: ignore[arg-type]

    store.assert_called_once_with("test-passphrase")
    clear.assert_called_once()
    stub._render_state.assert_not_called()
    assert any(
        "no passphrase was retained" in call.args[0]
        for call in stub.app.notify.call_args_list
    )
