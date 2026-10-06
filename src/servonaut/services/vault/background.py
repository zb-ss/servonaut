"""Verified polling for headless and interactive vault sessions."""
from __future__ import annotations

import asyncio
import logging

from .crypto import VaultCryptoError
from .identity_store import IdentityStoreError

logger = logging.getLogger(__name__)


def unlock_vault_for_startup(service) -> bool:
    """Keep unrelated services available while custody remains fail closed."""
    try:
        return service.unlock_existing_identity()
    except (IdentityStoreError, VaultCryptoError) as exc:
        logger.warning("Vault startup needs attention: %s", type(exc).__name__)
        return False


async def poll_vault(service, *, discovered: bool = False) -> None:
    """Refresh access without treating event hints as authorization."""
    if not discovered and not await service.discover():
        return
    while True:
        try:
            if service.unlock_existing_identity():
                await service.process_grants(interactive=False)
        except Exception as exc:
            # Never auto-grant from a failed custody or integrity check. Keep
            # listening so signed REST can recover from a transient refusal.
            logger.warning("Vault polling needs attention: %s", type(exc).__name__)
        await asyncio.sleep(service.poll_interval_seconds)


async def run_relay_with_vault(listener, service=None) -> None:
    """Own polling cancellation and all agent leases for a relay lifetime."""
    polling = asyncio.create_task(poll_vault(service)) if service is not None else None
    try:
        await listener.run()
    finally:
        if polling is not None:
            polling.cancel()
            await asyncio.gather(polling, return_exceptions=True)
        if service is not None:
            service.close()
