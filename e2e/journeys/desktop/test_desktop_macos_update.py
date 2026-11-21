"""Exercise the desktop installer choice through the authenticated terminal."""

from dataclasses import replace
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from e2e.harness import fleet
from e2e.harness.desktop import click_widget, nav, open_session
from servonaut import app as app_module, runtime
from servonaut.app import ServonautApp
from servonaut.desktop import host
from servonaut.screens.settings.panels.updates import UpdatesPanel
from servonaut.services.update_service import UpdateCheckResult, UpdateService
from servonaut.updates import macos_install

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio]


async def test_desktop_stays_open_when_another_accounts_macos_journal_is_unreadable(
    desktop, seed, monkeypatch,
):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    installation = macos_install.Installation(seed.home / macos_install.BUNDLE_NAME)
    installation.bundle.mkdir()
    monkeypatch.setattr(app_module, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(macos_install.Installation, "from_runtime", lambda _: installation)
    journal = installation.transaction.journal_path
    denied = Event()
    original = Path.is_file

    def inaccessible(path):
        if path == journal:
            denied.set()
            raise PermissionError("another account owns the update work directory")
        return original(path)

    monkeypatch.setattr(Path, "is_file", inaccessible)

    async with desktop.in_process() as desktop_app, desktop.browser() as browser:
        factory = desktop_app.host.app_factory

        def window_app(transport):
            app = factory(transport)
            app.client_kind = "desktop"
            return app

        desktop_app.host.app_factory = window_app
        page = await open_session(browser, desktop_app)
        tui = desktop_app.tui
        await tui.wait_until(denied.is_set, desc="the post-refresh callback probed the unreadable journal")
        await nav(page, desktop_app, "nav_settings")
        await tui.wait_for_screen("SettingsScreen")
        assert tui.app.return_code is None
        assert page.errors() == []


@pytest.mark.parametrize("confirm", [False, True, None], ids=["cancel", "confirm", "guided"])
async def test_desktop_quit_to_install_requires_confirmation(desktop, seed, monkeypatch, confirm):
    # Model the selected release on the Linux runner. The native workflow
    # separately exercises Darwin locking, disk image operations and exchange.
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    simulated = replace(runtime.detect_runtime(), kind=runtime.DistributionKind.PACKAGED_DESKTOP)
    monkeypatch.setattr(runtime, "detect_runtime", lambda: simulated)
    monkeypatch.setattr(UpdatesPanel, "_effective_apt_managed", lambda *_: False)
    monkeypatch.setattr(ServonautApp, "can_install_macos_update", lambda _app: confirm is not None)
    monkeypatch.setattr(macos_install.Installation, "from_runtime", lambda _: SimpleNamespace(validate_offer=Mock()))
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="darwin"))

    def check(service):
        service._last_result = UpdateCheckResult.UPDATE_AVAILABLE
        return "900.1.0"

    monkeypatch.setattr(UpdateService, "check_for_update", check)
    staged = object()
    finish_download = Event()

    def download():
        if not finish_download.wait(10):
            raise TimeoutError("fixture did not observe the download progress")
        return staged

    stage = Mock(side_effect=download)
    request = Mock()
    monkeypatch.setattr(UpdateService, "stage_macos_desktop_update", stage)
    monkeypatch.setattr(macos_install, "request_on_quit", request)

    async with desktop.in_process() as desktop_app, desktop.browser() as browser:
        page = await open_session(browser, desktop_app)
        tui = desktop_app.tui
        await nav(page, desktop_app, "nav_settings")
        await tui.wait_for_screen("SettingsScreen")
        await click_widget(page, desktop_app, tui.on_screen("#navbtn_updates"))
        await tui.wait_for_text("Check now")
        await click_widget(page, desktop_app, tui.on_screen("#updates_btn_check"))
        if confirm is None:
            await tui.wait_for_text("900.1.0 is available", "Download and install")
            assert not tui.on_screen("#updates_btn_macos_install").display
            stage.assert_not_called()
            request.assert_not_called()
            assert page.errors() == []
            return
        await tui.wait_for_text("Install on quit")
        await click_widget(page, desktop_app, tui.on_screen("#updates_btn_macos_install"))
        await tui.wait_for_screen("ConfirmModal")
        await click_widget(page, desktop_app, tui.on_screen("#btn_confirm_yes" if confirm else "#btn_confirm_no"))
        if confirm:
            try:
                await tui.wait_for_text("Downloading verified update")
            finally:
                finish_download.set()
            await tui.wait_until(
                lambda: desktop_app.host.macos_install_requested,
                desc="desktop host received the installer quit code",
            )
            assert tui.app.return_code == macos_install.INSTALL_QUIT_CODE
            stage.assert_called_once()
            request.assert_called_once_with(tui.app.runtime_layout, staged)
        else:
            await tui.wait_for_screen("SettingsScreen")
            assert "-closed" not in await page.body_classes()
            assert tui.app.return_code is None
            assert not desktop_app.host.macos_install_requested
            stage.assert_not_called()
            request.assert_not_called()
        assert page.errors() == []
