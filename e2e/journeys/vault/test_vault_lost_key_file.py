"""A computer whose vault key file went missing is told so, and Recover brings it back.

The vault is set up with the real CLI child (production custody and signing),
its key file is then deleted, and the Vault screen, hosted on a real vault
service for the same home, recovers it with the recovery key. All against the
hermetic FakeCloud.
"""
from __future__ import annotations

from typing import Any

import pytest
from textual.app import App
from textual.widgets import Button, Input

from e2e.harness.waits import wait_for_async
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from e2e.journeys.vault.test_native_import import _vault_config
from e2e.journeys.vault.test_vault_onboarding import _status, _VaultHost, _wait_for_status
from servonaut.screens.vault import VaultScreen, VaultSecretPromptModal
from servonaut.services.api_client import APIClient
from servonaut.services.auth_service import AuthService
from servonaut.services.vault.command_service import VaultCommandService
from servonaut.widgets.busy_indicator import BusyIndicator

pytestmark = [pytest.mark.e2e_pr]


class _NotingVaultHost(_VaultHost):
    def __init__(self, service: Any) -> None:
        self.notes: list[str] = []
        super().__init__(service)

    def notify(self, message, *args, **kwargs):  # type: ignore[override]
        self.notes.append(str(message))
        return super().notify(message, *args, **kwargs)


async def _recover_with(app: App, screen: VaultScreen, recovery_key: str) -> None:
    """Choose Recover and enter *recovery_key*, as a user would."""
    await wait_for_async(lambda: not screen.query_one("#vault_recover", Button).disabled, desc="Recover available")
    screen.query_one("#vault_recover", Button).press()
    prompt = await wait_for_async(
        lambda: app.screen if isinstance(app.screen, VaultSecretPromptModal)
        and app.screen.query("#vault_secret_input") else None,
        desc="the recovery-key prompt",
    )
    prompt.query_one("#vault_secret_input", Input).value = recovery_key
    prompt.query_one("#vault_secret_continue", Button).press()


def _next_step(result) -> str:
    assert result.returncode == 0, result.describe()
    return "\n".join(line for line in result.stdout.splitlines() if line.startswith(("Next step:", "  Run:")))


def _service_for(journey: Any, home: Any, monkeypatch: pytest.MonkeyPatch) -> VaultCommandService:
    """The in-process vault service of the TUI, on the child's home and test custody."""
    import servonaut.services.auth_service as auth_module

    monkeypatch.setenv("HOME", str(home.home))
    monkeypatch.setenv("SERVONAUT_VAULT_DEVICE_KEY", journey.env_overrides["SERVONAUT_VAULT_DEVICE_KEY"])
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", journey.env_overrides["PYTHON_KEYRING_BACKEND"])
    monkeypatch.setattr(auth_module, "AUTH_FILE", home.home / ".servonaut" / "auth.json")
    auth = AuthService()
    return VaultCommandService(APIClient(auth), auth, _vault_config())


@pytest.mark.asyncio
async def test_a_lost_key_file_is_named_and_recover_unlocks_the_vault_again(
    journey: Any, fake_cloud: Any, cli: Any, account_home: Any, servonaut_cmd: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_test_custody(journey)
    home = account_home("vault-lost-key-file")
    setup, recovery_key = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    custody = home.home / ".servonaut" / "vault" / "vault_keys.json"
    assert custody.exists()

    custody.unlink()  # the key file goes missing; the identity stays on the server

    assert _next_step(cli(home, "vault", "status")) == (
        "Next step: This computer used your vault before, but its vault key file is missing. "
        "Recover it with your recovery key: your vaults and items are safe on the server.\n"
        "  Run: servonaut vault recover"
    )

    app = _NotingVaultHost(_service_for(journey, home, monkeypatch))
    async with app.run_test(size=(160, 50)):
        screen = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, VaultScreen) else None, desc="the Vault screen",
        )
        await _wait_for_status(app, screen, "vault key file is missing")
        assert not screen.query_one("#vault_recover", Button).disabled

        # A mistyped key is refused as a typo, before any device is registered for it.
        registrations = len(fake_cloud.requests("/api/v1/vault/devices", method="POST"))
        typo = recovery_key[:-1] + ("0" if recovery_key[-1] != "0" else "1")
        await _recover_with(app, screen, typo)
        await wait_for_async(lambda: any("has a typo" in note for note in app.notes), desc="the typo message")
        assert len(fake_cloud.requests("/api/v1/vault/devices", method="POST")) == registrations
        assert "vault key file is missing" in _status(screen)

        await _recover_with(app, screen, recovery_key)

        await _wait_for_status(app, screen, "Identity fingerprint")
        assert not screen.query_one("#vault_busy", BusyIndicator).is_active
        assert screen.query_one("#vault_recover", Button).disabled
        assert "key file is missing" not in _status(screen)

    assert custody.exists()
    assert "Recover it with your recovery key" not in _next_step(cli(home, "vault", "status"))
