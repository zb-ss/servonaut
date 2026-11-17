"""The Secrets hub and the SSH Keys screen at both sizes."""
from __future__ import annotations

from typing import Any

import pytest

from . import _harness
from tests.test_secrets_screen import _mock_auth, _mock_guard
from .test_screens import _capture, _navigate


async def _secrets(pilot: Any) -> None:
    pilot.app.auth_service = _mock_auth(plan="solo")
    pilot.app.entitlement_guard = _mock_guard(allow_secrets=True)
    screen = await _navigate(pilot, "nav_secrets", "SecretsScreen")
    await _harness.wait_until(
        pilot, lambda: bool(screen.query("ActionButton")), "the secrets actions",
    )
    screen.query_one("#secrets_body").scroll_end(animate=False, immediate=True)


async def _ssh_keys(pilot: Any) -> None:
    screen = await _navigate(pilot, "nav_keys", "KeyManagementScreen")
    await _harness.wait_until(
        pilot, lambda: screen.query_one("#available_keys_table").row_count >= 0, "the key tables",
    )


@pytest.mark.parametrize("size", list(_harness.SIZES))
def test_secrets_hub(screen_snapshot, size) -> None:
    _capture(screen_snapshot, size, _secrets)


@pytest.mark.parametrize("size", list(_harness.SIZES))
def test_ssh_keys(screen_snapshot, size) -> None:
    _capture(screen_snapshot, size, _ssh_keys)
