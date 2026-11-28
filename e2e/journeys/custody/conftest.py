"""Fixtures shared by the vault-custody journeys.

``custody_device`` gives the in-process app and every child the throwaway
vault device key and the null keyring (the Vault journeys' test custody), so a
journey can set the vault up in the in-process home with a child command and
then open the TUI on it.
"""

from __future__ import annotations

import base64
from typing import Any, Callable

import pytest

from e2e.harness import fleet
from e2e.harness.known_bugs import ProductBug, known_bug
from e2e.harness.session_seed import seed_session

DEVICE_KEY_ENV = "SERVONAUT_VAULT_DEVICE_KEY"
KEYRING_ENV = "PYTHON_KEYRING_BACKEND"
NULL_KEYRING = "keyring.backends.null.Keyring"


@pytest.fixture
def custody_device(journey: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """The test vault custody for this process and its children."""
    from e2e.journeys.vault.test_cli_vault import _configure_test_custody

    _configure_test_custody(journey)
    monkeypatch.setenv(DEVICE_KEY_ENV, base64.b64encode(b"\0" * 32).decode("ascii"))
    monkeypatch.setenv(KEYRING_ENV, NULL_KEYRING)


@pytest.fixture
def signed_in_home(seed: Any, fake_cloud: Any) -> Callable[..., Any]:
    """Sign the in-process home in with the fleet cache; the relay stays off."""

    def prepare(**config: Any) -> Any:
        fake_cloud.configure(mcp_connections=0)
        seed.config(**config)
        seed.cache(fleet.cache_rows(), fresh=True)
        seed_session(seed.home, fake_cloud)
        return seed

    return prepare


# Set True while hunting for what else a journey finds behind the limiter bug.
LIFT_KEYS_ME_LIMITER = False


class KeysMeLimiterBlocks(ProductBug):
    """Set-up waits on the client's ``GET /keys/me`` limiter (3 per hour) instead of finishing."""


KEYS_ME_LIMITER_BUG = known_bug(
    "the client limiter for GET /keys/me blocks in acquire after about three resolves, so "
    "set-up in the vault never finishes",
    raises=KeysMeLimiterBlocks,
)


@pytest.fixture
def keys_me_limiter_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probing aid for the known limiter bug: flip LIFT_KEYS_ME_LIMITER to see the rest of a journey."""
    if not LIFT_KEYS_ME_LIMITER:
        return
    from servonaut.services.memory import rate_limiter

    monkeypatch.setitem(
        rate_limiter._LIMITS, rate_limiter.RateLimitKey.KEYS_ME,
        rate_limiter._Window(capacity=500, period_seconds=3600.0),
    )


async def wait_for_active_toast(t: Any, *, seconds: float = 25.0) -> None:
    """Wait for "Memory Sync is now active."; a stall becomes the known limiter bug."""
    from e2e.harness.pilot import JourneyTimeout

    try:
        await t.wait_for_toast(r"^Memory Sync is now active\.$", timeout=seconds)
    except JourneyTimeout as exc:
        if "Setting up Memory Sync" in t.rendered_text():
            raise KeysMeLimiterBlocks(str(exc)) from exc
        raise
