"""A new vault user is told their next step at each stage, in the CLI and the TUI.

The CLI part starts real child commands with production configuration,
custody and signing; the TUI part hosts the Vault screen on a real vault
service. Both run against the hermetic FakeCloud on the default solo plan.
"""
from __future__ import annotations

from typing import Any

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Static

from e2e.harness.waits import wait_for_async
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from e2e.journeys.vault.test_native_import import _native_service
from servonaut.screens.vault import VaultCreateModal, VaultScreen

pytestmark = [pytest.mark.e2e_pr]


def _next_step(result) -> str:
    assert result.returncode == 0, result.describe()
    lines = [line for line in result.stdout.splitlines() if line.startswith(("Next step:", "  Run:"))]
    return "\n".join(lines)


def test_solo_user_is_guided_from_setup_to_a_personal_vault(journey, fake_cloud, cli, account_home, servonaut_cmd):
    fake_cloud.vault.identity_confirmation = "email"
    _configure_test_custody(journey)
    home = account_home("vault-onboarding")
    user_id = fake_cloud.entitlements()["user_id"]

    assert _next_step(cli(home, "vault", "status")) == (
        "Next step: Create your vault identity and write down its recovery key.\n"
        "  Run: servonaut vault setup"
    )

    setup, _recovery_key = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    assert "Confirm your vault identity: open the link we e-mailed to you" in setup.text
    assert "servonaut vault identity confirm" in _next_step(cli(home, "vault", "status"))

    confirm = cli(home, "vault", "identity", "confirm")
    assert confirm.returncode == 0, confirm.describe()
    assert "We e-mailed you a new confirmation link" in confirm.stdout

    fake_cloud.vault.confirm_identity(user_id)  # the user opens the e-mailed link
    assert _next_step(cli(home, "vault", "status")) == (
        "Next step: Create your personal vault to keep SSH keys and secrets encrypted.\n"
        "  Run: servonaut vault create --name Personal"
    )

    created = cli(home, "vault", "create", "--name", "Personal")
    assert created.returncode == 0, created.describe()
    assert _next_step(cli(home, "vault", "status")) == ""


class _VaultHost(App):
    def __init__(self, service: Any) -> None:
        self.vault_command_service = service
        self.vault_available = True
        super().__init__()

    def on_mount(self) -> None:
        self.push_screen(VaultScreen())


def _status(screen: VaultScreen) -> str:
    return str(screen.query_one("#vault_status", Static).render())


async def _wait(app: App, screen: VaultScreen, condition, desc: str) -> None:
    """Wait for *condition*; on timeout, say what the screen and the fake saw."""
    try:
        await wait_for_async(condition, desc=desc)
    except AssertionError as exc:
        requests = [f"{row.get('method')} {row.get('path')} {row.get('status')}"
                    for row in getattr(app, "fake_requests", lambda: [])()]
        stack = [type(item).__name__ for item in app.screen_stack]
        raise AssertionError(
            f"{exc}; status: {_status(screen)!r}; screens: {stack}; requests: {requests[-8:]!r}"
        ) from exc


async def _wait_for_status(app: App, screen: VaultScreen, text: str) -> None:
    await _wait(app, screen, lambda: text in _status(screen), f"status {text!r}")


@pytest.mark.asyncio
async def test_vault_screen_confirms_the_identity_and_creates_the_personal_vault(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = account_home("vault-onboarding-tui")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    fake_cloud.vault.identity_confirmation = "mfa"
    fake_cloud.vault.require_confirmation(fake_cloud.entitlements()["user_id"])
    app = _VaultHost(service)
    app.fake_requests = fake_cloud.requests  # diagnostics on a timed-out wait

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultScreen) else None, desc="the Vault screen",
        )
        await _wait_for_status(app, screen, "Confirm your vault identity")

        # Press rather than click: a click aimed while the screen re-lays out
        # (the status line grows, a modal opens) can land on another widget.
        screen.query_one("#vault_confirm_identity", Button).press()
        await _wait_for_status(app, screen, "Create your personal vault")

        screen.query_one("#vault_create", Button).press()
        # The modal focuses its picker once its widgets are mounted.
        modal = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultCreateModal) and app.screen.focused is not None
            and app.screen.focused.id == "vault_create_target" else None,
            desc="the create-vault picker",
        )
        modal.query_one("#vault_create_confirm", Button).press()

        table = screen.query_one("#vault_table", DataTable)
        await _wait(app, screen, lambda: app.screen is screen and table.row_count == 1, "the new personal vault row")
        assert "Personal" in str(table.get_row_at(0))
        assert "Create your personal vault" not in _status(screen)
