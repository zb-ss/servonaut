"""The OVH firewall toggle confirmation states what will happen, not a template."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.ovh_firewall import OVHFirewallScreen


async def _consequences(firewall_enabled: bool) -> list:
    push_screen_wait = AsyncMock(return_value=False)  # user cancels
    fake_screen = SimpleNamespace(
        _firewall_enabled=firewall_enabled,
        _ip="10.0.0.5",
        _display_ip="10.0.0.5",
        app=SimpleNamespace(push_screen_wait=push_screen_wait, ovh_audit=None),
        run_worker=MagicMock(),
    )

    await OVHFirewallScreen._on_toggle_firewall(fake_screen)

    confirm = push_screen_wait.await_args.args[0]
    assert isinstance(confirm, ConfirmActionScreen)
    fake_screen.run_worker.assert_not_called()
    return confirm._consequences


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "firewall_enabled, expected",
    [
        (False, "Traffic filtering rules will take effect"),
        (True, "Traffic filtering rules will be suspended"),
    ],
)
async def test_toggle_confirmation_names_the_outcome(firewall_enabled, expected):
    consequences = await _consequences(firewall_enabled)

    assert expected in consequences
    assert not any("{" in line or "}" in line for line in consequences)
