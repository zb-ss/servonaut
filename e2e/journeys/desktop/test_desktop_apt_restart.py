"""The desktop terminal offers a restart when a newer package is configured."""

from unittest.mock import Mock

import pytest
from textual.events import AppFocus

from e2e.harness import fleet
from e2e.harness.desktop import click_widget, nav, open_session
from servonaut import get_version
from servonaut.services.apt_runtime import (
    APT_RUNTIME_POLL_ENV, AptBuildIdentity, AptChange, AptRuntimeMonitor, AptUpgradeState,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio]


async def test_packaged_update_notice_and_cancel_restart(desktop, seed, monkeypatch):
    running = AptBuildIdentity(get_version(), "fixture-running", 1, (1, 10))
    check = Mock(return_value=AptUpgradeState(AptChange.UNCHANGED, running))
    monitor = Mock(check=check)
    monkeypatch.setattr(AptRuntimeMonitor, "for_runtime", classmethod(lambda _cls, _runtime: monitor))
    monkeypatch.setenv(APT_RUNTIME_POLL_ENV, "600")
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with desktop.in_process() as desktop_app, desktop.browser() as browser:
        page = await open_session(browser, desktop_app)
        tui = desktop_app.tui
        await tui.wait_until(lambda: tui.app.apt_upgrade_state == check.return_value, desc="running build detected")
        await nav(page, desktop_app, "nav_settings")
        await tui.wait_for_screen("SettingsScreen")
        await click_widget(page, desktop_app, tui.on_screen("#navbtn_updates"))
        await tui.wait_for_text("Running")

        installed = AptBuildIdentity("2.35.0rc10", "fixture-installed", 1, (1, 11))
        check.return_value = AptUpgradeState(AptChange.RESTART_REQUIRED, installed)
        mark = page.output_mark()
        tui.app.post_message(AppFocus())
        await page.wait_for_text("Servonaut was updated.", since=mark)
        await tui.wait_for_text("Restart to use version 2.35.0rc10.")
        assert str(tui.on_screen("#nav_update").label) == "Restart to update"
        await page.press("Control+p")
        await page.type("Restart Servonaut")
        await tui.wait_for_text("start the installed version")
        await page.press("Enter")
        await tui.wait_for_screen("ConfirmModal")
        await page.press("n")
        await tui.wait_for_screen("SettingsScreen")
        assert tui.app.return_code is None
        assert "-closed" not in await page.body_classes()
        assert page.errors() == []
