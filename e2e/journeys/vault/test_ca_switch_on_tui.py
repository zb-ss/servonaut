"""A team owner switches SSH certificates on from the SSH Certificates screen.

The screen runs on a real vault service against the hermetic FakeCloud. The
team's certificate authorities exist only after the owner confirms.
"""
from __future__ import annotations

from typing import Any

import pytest
from textual.app import App
from textual.widgets import Button, Static

from e2e.harness.fake_cloud.routes_vault import TEAM_SLUG
from e2e.harness.waits import wait_for_async
from e2e.journeys.vault.test_cli_vault import _VAULT_TEAM
from e2e.journeys.vault.test_native_import import _native_service
from servonaut.screens.ca import CaEnableConfirmModal, CaScreen

pytestmark = [pytest.mark.e2e_pr]

_CA_ACTIONS = ("#ca_audit", "#ca_enroll", "#ca_krl", "#ca_break_glass_scan")


class _CaHost(App):
    def __init__(self, service: Any) -> None:
        self.vault_command_service = service
        self.vault_available = True
        super().__init__()

    def on_mount(self) -> None:
        self.push_screen(CaScreen())


def _status(screen: CaScreen) -> str:
    return str(screen.query_one("#ca_status", Static).render())


def _ready_modal(app: App) -> Any:
    """The switch-on confirmation once its buttons are mounted (a pushed screen composes later)."""
    screen = app.screen
    if not isinstance(screen, CaEnableConfirmModal):
        return None
    return screen if screen.query("#ca_enable_cancel") and screen.query("#ca_enable_confirm") else None


async def _modal(app: App, *, open_: bool) -> Any:
    return await wait_for_async(
        (lambda: _ready_modal(app)) if open_ else (lambda: not isinstance(app.screen, CaEnableConfirmModal)),
        desc="the switch-on confirmation" + ("" if open_ else " to close"),
    )


@pytest.mark.asyncio
async def test_the_ssh_certificates_screen_switches_certificates_on_after_confirming(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_cloud.account.configure(teams=[_VAULT_TEAM])
    sandbox = account_home("ca-switch-on-tui")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    app = _CaHost(service)

    async with app.run_test(size=(160, 50)):
        screen = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, CaScreen) else None, desc="the SSH Certificates screen",
        )
        # The only team is chosen for the user; its certificates are off.
        await wait_for_async(lambda: "not switched on for this team" in _status(screen), desc="the switched-off status")
        enable = screen.query_one("#ca_enable", Button)
        await wait_for_async(lambda: enable.display and not enable.disabled, desc="the switch-on button")
        assert all(screen.query_one(selector, Button).disabled for selector in _CA_ACTIONS)

        # Cancelling changes nothing on the service.
        enable.press()
        (await _modal(app, open_=True)).query_one("#ca_enable_cancel", Button).press()
        await _modal(app, open_=False)
        assert fake_cloud.vault.ca_payload(TEAM_SLUG)["enabled"] is False
        # The cancelled action ends after its dialog closes; until then the button stays held back.
        await wait_for_async(lambda: enable.display and not enable.disabled, desc="the switch-on button again")

        enable.press()
        (await _modal(app, open_=True)).query_one("#ca_enable_confirm", Button).press()
        await _modal(app, open_=False)

        await wait_for_async(
            lambda: _status(screen).startswith("SSH certificates are on for this team."), desc="the switched-on status",
        )
        assert fake_cloud.vault.ca_payload(TEAM_SLUG)["enabled"] is True
        assert "User CA: SHA256:" in _status(screen) and "Host CA: SHA256:" in _status(screen)
        assert not enable.display
        await wait_for_async(
            lambda: not screen.query_one("#ca_audit", Button).disabled, desc="the CA actions to be offered",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(("refusal", "reason"), [
    ("frozen", "switching on SSH certificates is paused on the Servonaut service for now; nothing is wrong with "
               "your setup, so contact support at https://servonaut.dev/contact to ask for them for your team"),
    ("busy", "the Servonaut service is busy switching on SSH certificates; nothing is wrong with your setup, "
             "so try again in a minute"),
])
async def test_a_refused_switch_on_says_why_and_leaves_certificates_off(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch, refusal: str, reason: str,
) -> None:
    fake_cloud.account.configure(teams=[_VAULT_TEAM])
    fake_cloud.vault.refuse_ca_activation(refusal)
    sandbox = account_home(f"ca-switch-on-{refusal}")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    app = _CaHost(service)

    async with app.run_test(size=(160, 50)):
        screen = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, CaScreen) else None, desc="the SSH Certificates screen",
        )
        enable = screen.query_one("#ca_enable", Button)
        await wait_for_async(lambda: enable.display and not enable.disabled, desc="the switch-on button")

        enable.press()
        (await _modal(app, open_=True)).query_one("#ca_enable_confirm", Button).press()
        await _modal(app, open_=False)

        toasts = await wait_for_async(
            lambda: [(n.severity, str(n.message)) for n in app._notifications] or None,  # noqa: SLF001 - own host
            desc="the refusal toast",
        )
        assert toasts == [("error", f"Switching on SSH certificates failed ({reason}).")]
        assert fake_cloud.vault.ca_payload(TEAM_SLUG)["enabled"] is False
        assert "not switched on for this team" in _status(screen)
        # Nothing changed, so switching on stays on offer for a later try.
        await wait_for_async(lambda: enable.display and not enable.disabled, desc="the switch-on button again")
