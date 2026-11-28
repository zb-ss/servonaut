"""Journey: set up Memory Sync in the vault from the desktop window.

A signed-in user whose vault was set up with the CLI opens Memory Sync in the
desktop frontend (the app's terminal drawn in headless Chromium). The card
says the key will be kept in the vault and no passphrase is needed; one click
makes the key, keeps it in the vault and registers it with the service in the
vault shape. The window then shows the key as kept in the vault, with no
passphrase dialog opened, and the page reports no error.
"""

from __future__ import annotations

import pytest

from e2e.harness.desktop import click_widget, nav, open_session
from e2e.harness.fake_cloud.routes_memory import KEYS_PATH
from e2e.harness.vault_custody import setup_vault

pytestmark = [
    pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio,
    pytest.mark.xdist_group("custody-desktop"),
]


async def test_memory_sync_is_set_up_in_the_vault_from_the_desktop_window(
    desktop, seed, fake_cloud, journey, servonaut_cmd, monkeypatch,
):
    from e2e.harness import fleet
    from e2e.harness.session_seed import seed_session
    from e2e.journeys.vault.test_cli_vault import _configure_test_custody

    # The test vault custody (throwaway device key, null keyring) for this
    # process, which hosts the app, and for the CLI child that sets the vault up.
    _configure_test_custody(journey)
    for name in ("SERVONAUT_VAULT_DEVICE_KEY", "PYTHON_KEYRING_BACKEND"):
        monkeypatch.setenv(name, journey.env_overrides[name])
    fake_cloud.configure(mcp_connections=0)
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    seed_session(seed.home, fake_cloud)
    setup_vault(journey, journey.ctx.sandbox, servonaut_cmd)
    user_id = fake_cloud.entitlements()["user_id"]

    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await open_session(browser, app)
        tui = app.tui
        await tui.wait_until(lambda: app.app.auth_service.is_authenticated, desc="signed in")
        await nav(page, app, "nav_memory_sync")
        await tui.wait_for_screen("MemorySyncSetupScreen")
        await page.wait_for_text("Your key will be kept in your vault")

        await tui.wait_until(
            lambda: tui.find("#msync_btn_setup") and not tui.find("#msync_btn_setup")[0].disabled,
            desc="the set-up button",
        )
        await click_widget(page, app, tui.on_screen("#msync_btn_setup"))
        await tui.wait_until(
            lambda: bool(tui.find("#msync_key_value")), desc="the active card with its key row",
        )
        await page.wait_for_text("Memory Sync is now active")
        assert [name for name in tui.opened_screens() if "Passphrase" in name] == []
        assert page.errors() == []

    key = fake_cloud.memory.enrolled_key()
    assert key["custody"] == "vault" and key["wrapped_private_key"] is None
    assert fake_cloud.vault.app_key_fingerprints(user_id, "memory_key") == [key["fingerprint"]]
    assert [(r["status"], r["body"]["custody"]) for r in fake_cloud.requests(KEYS_PATH, "POST")] == [(201, "vault")]
