from __future__ import annotations

import asyncio

from servonaut.services.vault.provider import ServonautVaultProvider


def test_provider_returns_none_for_unknown_reference() -> None:
    provider = ServonautVaultProvider(None, None, lambda _name: None)
    assert asyncio.run(provider.get_secret("known-name")) is None
