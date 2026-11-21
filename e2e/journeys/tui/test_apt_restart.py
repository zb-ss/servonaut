"""A running installed application can finish a deliberate package restart."""

from __future__ import annotations

import pytest
from textual import events

from e2e.harness import fleet
from servonaut import get_version
from servonaut.screens.snapshot_manager import ConfirmModal
from servonaut.services.apt_runtime import (
    APT_RESTART_EXIT_CODE,
    APT_RUNTIME_POLL_ENV,
    AptBuildIdentity,
    AptChange,
    AptRuntimeMonitor,
    AptUpgradeState,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


class PackageMonitor:
    def __init__(self) -> None:
        self.running = AptBuildIdentity(get_version(), "first", 1, (1, 10))
        self.state = AptUpgradeState(AptChange.UNCHANGED, self.running)

    def check(self, *, force: bool = False) -> AptUpgradeState:
        return self.state


@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_restart_notice_transaction_and_confirmation(tui, seed, monkeypatch, size):
    monitor = PackageMonitor()
    monkeypatch.setattr(AptRuntimeMonitor, "for_runtime", classmethod(lambda _cls, _runtime: monitor))
    monkeypatch.setenv(APT_RUNTIME_POLL_ENV, "600")
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui(size=size) as t:
        async def observe(state: AptUpgradeState) -> None:
            monitor.state = state
            t.app.post_message(events.AppFocus())
            await t.wait_until(lambda: t.app.apt_upgrade_state == state, desc=state.change.value)

        await t.wait_until(lambda: t.app.apt_upgrade_state == monitor.state, desc="running package observed")
        await t.nav("nav_settings")
        await t.wait_for_screen("SettingsScreen")
        await t.click("#navbtn_updates")
        await t.wait_for_text("Running")

        await observe(AptUpgradeState(AptChange.DEFERRED))
        await t.wait_for_text("finish configuring")
        assert not t.on_screen("#updates_btn_restart").display

        installed = AptBuildIdentity(monitor.running.product_version, "second", 2, (1, 11))
        changed = AptUpgradeState(AptChange.RESTART_REQUIRED, installed)
        await observe(changed)
        await t.wait_for_text("Servonaut was updated.", "updated build.")

        t.app.push_screen(ConfirmModal("Confirm action", "Continue?"))
        await t.wait_for_screen("ConfirmModal")
        t.app.request_apt_restart()
        await t.wait_for_toast("Close the current dialog before restarting Servonaut")
        await t.press("n")
        await t.wait_for_screen("SettingsScreen")

        await t.click("#updates_btn_restart")
        await t.wait_for_screen("ConfirmModal")
        await t.click("#btn_confirm_no")
        await t.wait_for_screen("SettingsScreen")
        assert t.app.return_code is None

        await t.click("#updates_btn_restart")
        await t.wait_for_screen("ConfirmModal")
        monitor.state = AptUpgradeState(AptChange.REMOVED)
        await t.click("#btn_confirm_yes")
        await t.wait_for_text("The Servonaut package was removed")
        assert not t.on_screen("#updates_btn_restart").display
        assert t.app.return_code is None

        await observe(changed)
        assert sum("Servonaut was updated." in text for _, text in t.toasts()) == 1
        await t.click("#updates_btn_restart")
        await t.wait_for_screen("ConfirmModal")
        await t.click("#btn_confirm_yes")
        await t.wait_until(lambda: t.app.return_code == APT_RESTART_EXIT_CODE, desc="graceful restart exit")
