"""Remote Settings keep reachable controls and asynchronous save contracts."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from textual import events
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input, Select, Static, Switch

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.shell import DiscardChangesModal, SettingsScreen
from servonaut.services.api_client import APIError
from servonaut.services.bw_session_service import BwAuthState
from servonaut.services.bw_ssh_config_service import BITWARDEN_PM_PROVIDER
from servonaut.services.memory.interfaces import MemorySettings
from tests._async_bounds import wait_until


SIZES = [(160, 50), (100, 30)]
PANELS = ["bw_ssh", "memory_sync"]
BW_CONFIG = {"config": {"vault_url": "https://vault.example.test", "default_collection_id": "collection-example"}}


@pytest.fixture(autouse=True)
def _terminal_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME", "BW_SESSION"):
        monkeypatch.delenv(name, raising=False)


class _Remote:
    """In-memory API with controllable response boundaries; never uses IO."""

    def __init__(self) -> None:
        self.release_load = asyncio.Event()
        self.release_load.set()
        self.started = asyncio.Event()
        self.release_save = asyncio.Event()
        self.release_save.set()
        self.save_started = asyncio.Event()
        self.load_error: Exception | None = None
        self.save_error: Exception | None = None
        self.bw_config: dict[str, Any] | None = BW_CONFIG
        self.settings = MemorySettings("weekly", True, {}, {}, "client", False)
        self.loads: list[bool] = []
        self.saves: list[dict[str, Any]] = []
        self.folder_at_put: str | None = None
        self.manager: ConfigManager | None = None

    async def _load(self) -> None:
        self.started.set()
        await self.release_load.wait()
        if self.load_error:
            raise self.load_error

    async def get_personal_config(self) -> dict[str, Any] | None:
        await self._load()
        return self.bw_config

    async def get_settings(self, force_refresh: bool = False) -> MemorySettings:
        self.loads.append(force_refresh)
        await self._load()
        return self.settings

    async def _save(self, values: dict[str, Any]) -> None:
        self.saves.append(values)
        self.save_started.set()
        await self.release_save.wait()
        if self.save_error:
            raise self.save_error

    async def put_personal_config(self, **values: Any) -> dict[str, Any]:
        assert self.manager is not None
        self.folder_at_put = self.manager.get().bw_vault_folder
        await self._save(values)
        return {"config": values}

    async def patch_settings(self, delta: dict[str, Any]) -> MemorySettings:
        await self._save(dict(delta))
        self.settings = replace(self.settings, **delta)
        return self.settings


class _Session:
    async def status(self) -> BwAuthState:
        return BwAuthState.LOCKED


class _RemoteApp(ServonautApp):
    """Use the real Settings shell with temporary config and fake services."""

    def __init__(
        self, manager: ConfigManager, remote: _Remote, panel_id: str,
        navigation: bool, *, entitled: bool = True, enrolled: bool = True,
    ) -> None:
        super().__init__()
        self.config_manager = manager
        remote.manager = manager
        self.bw_ssh_config_service = remote
        self.bw_session_service = _Session()
        self.memory_settings_service = remote
        self.memory_sync_service = SimpleNamespace(is_configured=enrolled)
        self.auth_service = SimpleNamespace(
            is_authenticated=False,
            has_feature=lambda feature: entitled and feature == "memory_sync",
        )
        self.cache_service = SimpleNamespace(
            is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [],
        )
        self.workspace_state.navigation_visible = navigation
        self.panel_id = panel_id
        self.notes: list[str] = []
        self.loop_refreshes = 0

    def provider_inventory(self, *args: Any, **kwargs: Any) -> None:
        return None

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(SettingsScreen(self.panel_id))

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()

    async def _refresh_memory_sync_loop(self) -> None:
        self.loop_refreshes += 1

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(AppConfig(bw_vault_folder="Example folder"))
    manager.load()
    return manager


async def _panel(app: _RemoteApp, pilot: Pilot) -> SettingsPanel:
    await pilot.pause()
    await wait_until(lambda: isinstance(app.screen, SettingsScreen))
    await wait_until(lambda: app.screen._current_panel() is not None)
    return app.screen._current_panel()


async def _settled(panel: SettingsPanel) -> None:
    await wait_until(lambda: panel._loaded and not panel._settling)


def _text(panel: SettingsPanel, selector: str) -> str:
    return panel.query_one(selector, Static).render().plain


def _exposed(app: _RemoteApp, widget: Widget) -> bool:
    return (
        widget.region.width > 0 and widget.region.height > 0
        and app.screen.region.contains_region(widget.region)
        and app.get_widget_at(*widget.region.center)[0] in {widget, *widget.query("*")}
    )


async def _click(app: _RemoteApp, pilot: Pilot, button: Button) -> None:
    await wait_until(lambda: not button.has_class("-active"))
    button.scroll_visible(animate=False)
    await pilot.pause()
    await wait_until(lambda: _exposed(app, button))
    assert await pilot.click(button)


async def _tab_to(app: _RemoteApp, pilot: Pilot, widget: Widget) -> None:
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is widget:
            await wait_until(lambda: _exposed(app, widget))
            assert _exposed(app, widget), f"Focused control is clipped: {widget.id}"
            return
        await pilot.press("tab")
    pytest.fail(f"Tab never reached {widget.id}")


async def _loaded(app: _RemoteApp, pilot: Pilot) -> SettingsPanel:
    panel = await _panel(app, pilot)
    if panel.PANEL_ID == "bw_ssh":
        await wait_until(lambda: "Configured." in _text(panel, "#bw_ssh_status"))
    else:
        await wait_until(lambda: panel._original_settings is not None)
    await _settled(panel)
    return panel


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("panel_id", PANELS)
async def test_remote_fields_and_actions_remain_reachable(
    manager, size, navigation, panel_id,
) -> None:
    remote = _Remote()
    app = _RemoteApp(manager, remote, panel_id, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _loaded(app, pilot)
        if panel_id == "bw_ssh":
            assert not panel.query_one("#bw_ssh_vault_form").display
            assert "Vault locked" in _text(panel, "#bw_session_status")
            await _click(app, pilot, panel.query_one("#btn_bw_ssh_edit", Button))
            fields = ["bw_ssh_vault_url", "bw_ssh_default_collection_id", "bw_ssh_vault_folder"]
            actions = ["btn_bw_ssh_cancel", "save_bw_ssh"]
            assert panel.query_one("#bw_ssh_vault_folder", Input).value == "Example folder"
        else:
            fields = ["settings_msync_digest", "settings_msync_mercure", "settings_msync_auto_sync", "settings_msync_ai_mode"]
            actions = ["btn_msync_save", "btn_msync_reload"]
        for field_id in fields:
            field = panel.query_one(f"#{field_id}")
            assert field.parent.has_class("settings-scalar-row")
            await _tab_to(app, pilot, field)
        for action_id in actions:
            await _tab_to(app, pilot, panel.query_one(f"#{action_id}", Button))
        assert not panel.is_dirty()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("panel_id", PANELS)
async def test_slow_remote_load_has_feedback_and_settles_without_dirty(
    manager, size, navigation, panel_id,
) -> None:
    remote = _Remote()
    remote.release_load.clear()
    if panel_id == "bw_ssh":
        remote.bw_config = None
    app = _RemoteApp(manager, remote, panel_id, navigation)
    if panel_id == "bw_ssh":
        app.bw_session_service = None
    async with app.run_test(size=size) as pilot:
        panel = await _panel(app, pilot)
        await wait_until(remote.started.is_set)
        status_id = "#bw_ssh_status" if panel_id == "bw_ssh" else "#settings_msync_status"
        assert "loading" in _text(panel, status_id).lower()
        assert not panel.is_dirty()
        if panel_id == "bw_ssh":
            assert not panel.query_one("#bw_ssh_vault_form").display
            await wait_until(lambda: "unavailable" in _text(panel, "#bw_session_status"))
        remote.release_load.set()
        expected = "Not configured" if panel_id == "bw_ssh" else "Loaded"
        await wait_until(lambda: expected in _text(panel, status_id))
        await _settled(panel)
        assert not panel.is_dirty()
        app.screen._request_switch("general")
        await wait_until(lambda: app.screen._active_id == "general")
        assert not isinstance(app.screen, DiscardChangesModal)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("paid", [True, False])
async def test_bw_folder_is_persisted_before_remote_save_even_on_402(
    manager, size, navigation, paid,
) -> None:
    remote = _Remote()
    remote.release_save.clear()
    if not paid:
        remote.save_error = APIError(code="payment_required", message="Upgrade required", status=402)
    app = _RemoteApp(manager, remote, "bw_ssh", navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _loaded(app, pilot)
        await _click(app, pilot, panel.query_one("#btn_bw_ssh_edit", Button))
        await _settled(panel)
        panel.query_one("#bw_ssh_vault_folder", Input).value = "Saved example folder"
        await pilot.pause()
        assert panel.is_dirty()
        await _click(app, pilot, panel.query_one("#save_bw_ssh", Button))
        await wait_until(remote.save_started.is_set)
        assert remote.folder_at_put == "Saved example folder"
        assert remote.saves == [{
            "vault_url": "https://vault.example.test",
            "default_collection_id": "collection-example",
            "provider": BITWARDEN_PM_PROVIDER,
        }]
        reloaded = ConfigManager(config_path=manager._config_path)
        assert reloaded.load().bw_vault_folder == "Saved example folder"
        remote.release_save.set()
        if paid:
            await wait_until(lambda: "Bitwarden SSH vault config saved." in app.notes)
            await _settled(panel)
            assert not panel.query_one("#bw_ssh_vault_form").display
            assert not panel.is_dirty()
        else:
            await wait_until(lambda: any("requires a paid plan" in note for note in app.notes))
            assert panel.query_one("#bw_ssh_vault_form").display
            assert panel.is_dirty()
            assert "Bitwarden SSH vault config saved." not in app.notes
        assert _exposed(app, panel.query_one("#save_bw_ssh", Button))


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_bw_inline_save_uses_the_same_local_first_pipeline(manager, size, navigation) -> None:
    remote = _Remote()
    app = _RemoteApp(manager, remote, "bw_ssh", navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _loaded(app, pilot)
        await _click(app, pilot, panel.query_one("#btn_bw_ssh_edit", Button))
        await _settled(panel)
        panel.query_one("#bw_ssh_vault_folder", Input).value = "Inline example folder"
        await pilot.pause()
        await _click(app, pilot, panel.query_one("#btn_bw_ssh_save", Button))
        await wait_until(remote.save_started.is_set)
        await wait_until(lambda: "Bitwarden SSH vault config saved." in app.notes)
        assert remote.folder_at_put == "Inline example folder"
        assert len(remote.saves) == 1
        assert remote.saves[0]["provider"] == BITWARDEN_PM_PROVIDER
        await _settled(panel)
        assert not panel.is_dirty()
        assert not panel.query_one("#bw_ssh_vault_form").display


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("entitled,enrolled", [(False, True), (True, False)])
async def test_memory_gates_preserve_hidden_or_disabled_controls(
    manager, size, navigation, entitled, enrolled,
) -> None:
    remote = _Remote()
    app = _RemoteApp(manager, remote, "memory_sync", navigation, entitled=entitled, enrolled=enrolled)
    async with app.run_test(size=size) as pilot:
        panel = await _panel(app, pilot)
        await _settled(panel)
        section = panel.query_one("#settings_msync_section")
        assert section.display is entitled
        assert not remote.loads and not remote.saves
        assert not panel.is_dirty()
        if entitled:
            assert "locked on this device" in _text(panel, "#settings_msync_status")
            for selector in ("#settings_msync_digest", "#settings_msync_ai_mode", "#btn_msync_save", "#btn_msync_reload"):
                widget = panel.query_one(selector)
                assert widget.disabled
                widget.scroll_visible(animate=False)
                await pilot.pause()
                assert _exposed(app, widget)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("succeeds", [True, False])
async def test_memory_patch_failure_and_reload_keep_the_original_dirty_baseline(
    manager, size, navigation, succeeds,
) -> None:
    remote = _Remote()
    remote.release_save.clear()
    if not succeeds:
        remote.save_error = RuntimeError("fabricated save failure [example]")
    app = _RemoteApp(manager, remote, "memory_sync", navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _loaded(app, pilot)
        panel.query_one("#settings_msync_auto_sync", Switch).value = True
        await pilot.pause()
        assert panel.is_dirty()
        await _click(app, pilot, panel.query_one("#btn_msync_save", Button))
        await wait_until(remote.save_started.is_set)
        assert remote.saves == [{"auto_sync_enabled": True}]
        assert "Saving" in _text(panel, "#settings_msync_status")
        remote.release_save.set()
        await wait_until(lambda: ("Saved" if succeeds else "Save failed") in _text(panel, "#settings_msync_status"))
        if succeeds:
            await _settled(panel)
            assert not panel.is_dirty()
            assert app.loop_refreshes == 1
        else:
            assert panel.is_dirty()
            assert app.loop_refreshes == 0
            assert "fabricated save failure [example]" in _text(panel, "#settings_msync_status")
        await _click(app, pilot, panel.query_one("#btn_msync_reload", Button))
        await wait_until(lambda: remote.loads == [False, True])
        await wait_until(lambda: "Loaded" in _text(panel, "#settings_msync_status"))
        await _settled(panel)
        assert not panel.is_dirty()
        await _click(app, pilot, panel.query_one("#btn_msync_save", Button))
        await wait_until(lambda: "No changes to save" in _text(panel, "#settings_msync_status"))
        assert len(remote.saves) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("panel_id", PANELS)
async def test_leaving_while_remote_load_is_pending_never_prompts_or_mounts_late(
    manager, navigation, panel_id,
) -> None:
    remote = _Remote()
    remote.release_load.clear()
    app = _RemoteApp(manager, remote, panel_id, navigation)
    async with app.run_test(size=(100, 30)) as pilot:
        await _panel(app, pilot)
        await wait_until(remote.started.is_set)
        settings = app.screen
        settings.action_back()
        await wait_until(lambda: app.screen is not settings)
        assert not isinstance(app.screen, DiscardChangesModal)
        remote.release_load.set()
        await pilot.pause()
        assert app.screen is not settings
        assert not remote.saves


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_memory_fetch_error_is_literal_and_reload_recovers(manager, size, navigation) -> None:
    remote = _Remote()
    remote.load_error = RuntimeError("fabricated load failure [example]")
    app = _RemoteApp(manager, remote, "memory_sync", navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _panel(app, pilot)
        await wait_until(lambda: "Could not load" in _text(panel, "#settings_msync_status"))
        assert "fabricated load failure [example]" in _text(panel, "#settings_msync_status")
        assert not panel.is_dirty()
        remote.load_error = None
        await _click(app, pilot, panel.query_one("#btn_msync_reload", Button))
        await wait_until(lambda: panel._original_settings is not None)
        await _settled(panel)
        assert remote.loads == [False, True]
        assert not panel.is_dirty()


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("api_error", [True, False])
async def test_bw_load_failure_finishes_feedback_and_keeps_local_edit_cancel_available(
    manager, navigation, api_error,
) -> None:
    remote = _Remote()
    message = "fabricated vault load failure [example]"
    remote.load_error = (
        APIError(code="unavailable", message=message, status=503)
        if api_error else RuntimeError(message)
    )
    app = _RemoteApp(manager, remote, "bw_ssh", navigation)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _panel(app, pilot)
        await wait_until(remote.started.is_set)
        await wait_until(lambda: "Could not load" in _text(panel, "#bw_ssh_status"))
        assert message in _text(panel, "#bw_ssh_status")
        assert "Loading" not in _text(panel, "#bw_ssh_status")
        await _click(app, pilot, panel.query_one("#btn_bw_ssh_edit", Button))
        await _settled(panel)
        assert panel.query_one("#bw_ssh_vault_folder", Input).value == "Example folder"
        await _click(app, pilot, panel.query_one("#btn_bw_ssh_cancel", Button))
        assert not panel.query_one("#bw_ssh_vault_form").display
        assert not remote.saves and not panel.is_dirty()


async def _attempt_native_memory_save(app: _RemoteApp, pilot: Pilot, trigger: str) -> None:
    button = app.screen.query_one("#btn_msync_save", Button)
    button.scroll_visible(animate=False)
    await pilot.pause()
    assert _exposed(app, button)
    if trigger == "mouse":
        await pilot.click(button)
    else:
        app.set_focus(None)
        button.focus()
        await pilot.pause()
        await pilot.press("enter")
    await pilot.pause()


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ["mouse", "enter"])
async def test_memory_failed_first_load_cannot_patch_defaults_and_reload_recovers(manager, trigger) -> None:
    remote = _Remote()
    remote.release_load.clear()
    remote.load_error = RuntimeError("Example first fetch failure [details]")
    app = _RemoteApp(manager, remote, "memory_sync", False)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _panel(app, pilot)
        await wait_until(remote.started.is_set)
        remote.release_load.set()
        await wait_until(lambda: "Could not load" in _text(panel, "#settings_msync_status"))
        assert panel._original_settings is None
        # Valid choices still must not overwrite the unknown server checkbox.
        panel.query_one("#settings_msync_digest", Select).value = "weekly"
        panel.query_one("#settings_msync_ai_mode", Select).value = "client"
        assert remote.settings.mercure_push_enabled
        await _attempt_native_memory_save(app, pilot, trigger)
        assert remote.saves == [], {
            "patches": remote.saves,
            "stored_mercure": remote.settings.mercure_push_enabled,
        }
        assert panel.query_one("#btn_msync_save", Button).disabled
        assert not panel.query_one("#btn_msync_reload", Button).disabled
        remote.load_error = None
        await _click(app, pilot, panel.query_one("#btn_msync_reload", Button))
        await wait_until(lambda: panel._original_settings is not None)
        await _settled(panel)
        assert remote.loads == [False, True]
        assert not panel.query_one("#btn_msync_save", Button).disabled
        panel.query_one("#settings_msync_auto_sync", Switch).value = True
        await pilot.pause()
        await _attempt_native_memory_save(app, pilot, trigger)
        await wait_until(remote.save_started.is_set)
        assert remote.saves == [{"auto_sync_enabled": True}]


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ["mouse", "enter"])
async def test_memory_initial_loading_cannot_patch_or_cancel_its_pending_fetch(manager, trigger) -> None:
    remote = _Remote()
    remote.release_load.clear()
    app = _RemoteApp(manager, remote, "memory_sync", False)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _panel(app, pilot)
        await wait_until(remote.started.is_set)
        await _attempt_native_memory_save(app, pilot, trigger)
        assert remote.saves == [], remote.saves
        assert panel.query_one("#btn_msync_save", Button).disabled
        remote.release_load.set()
        await wait_until(lambda: panel._original_settings is not None)
        await _settled(panel)
        assert remote.loads == [False]
        assert not panel.query_one("#btn_msync_save", Button).disabled
        assert not panel.is_dirty()


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ["mouse", "enter"])
async def test_memory_failed_later_reload_retains_baseline_draft_and_normal_patch(manager, trigger) -> None:
    remote = _Remote()
    app = _RemoteApp(manager, remote, "memory_sync", False)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _loaded(app, pilot)
        original = panel._original_settings
        panel.query_one("#settings_msync_auto_sync", Switch).value = True
        await pilot.pause()
        assert panel.is_dirty()
        remote.load_error = RuntimeError("Example later reload failure [details]")
        await _click(app, pilot, panel.query_one("#btn_msync_reload", Button))
        await wait_until(lambda: "Could not load" in _text(panel, "#settings_msync_status"))
        assert panel._original_settings is original
        assert panel.query_one("#settings_msync_auto_sync", Switch).value
        assert panel.is_dirty() and not remote.saves
        assert not panel.query_one("#btn_msync_save", Button).disabled
        await _attempt_native_memory_save(app, pilot, trigger)
        await wait_until(remote.save_started.is_set)
        assert remote.saves == [{"auto_sync_enabled": True}]


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ["mouse", "enter"])
async def test_memory_cleared_optional_selects_patch_off_as_serializable_values(manager, trigger) -> None:
    remote = _Remote()
    app = _RemoteApp(manager, remote, "memory_sync", False)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _loaded(app, pilot)
        panel.query_one("#settings_msync_digest", Select).clear()
        panel.query_one("#settings_msync_ai_mode", Select).clear()
        await pilot.pause()
        assert panel.is_dirty()
        await _attempt_native_memory_save(app, pilot, trigger)
        await wait_until(remote.save_started.is_set)
        delta = remote.saves[0]
        try:
            serialized = json.dumps(delta)
        except TypeError as exc:
            pytest.fail(f"PATCH cannot be JSON serialized: {delta!r}: {exc}")
        assert json.loads(serialized) == {
            "digest_frequency": "off", "ai_consent_mode": "off",
        }
        await wait_until(lambda: "Saved" in _text(panel, "#settings_msync_status"))
        assert remote.settings.mercure_push_enabled
        assert not remote.settings.auto_sync_enabled


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 24), (100, 30), (160, 50)], ids=["80x24", "100x30", "160x50"])
async def test_bw_inline_short_captions_fit_with_both_navigation_rails(manager, size) -> None:
    from servonaut.widgets.sidebar import Sidebar
    from tests._workspace_reflow_conformance import assert_button_label_painted

    remote = _Remote()
    app = _RemoteApp(manager, remote, "bw_ssh", True)
    before = asdict(manager.get())
    async with app.run_test(size=size) as pilot:
        panel = await _loaded(app, pilot)
        assert app.screen.query_one(Sidebar).display
        assert app.screen.query_one("#settings-nav").display
        await _click(app, pilot, panel.query_one("#btn_bw_ssh_edit", Button))
        vault_url = panel.query_one("#bw_ssh_vault_url", Input)
        await _tab_to(app, pilot, vault_url)
        await pilot.press("ctrl+shift+a", "backspace")
        await wait_until(lambda: vault_url.value == "")
        buttons = [panel.query_one("#btn_bw_ssh_" + action, Button) for action in ("save", "cancel")]
        body = panel.query_one(".panel-body")
        for button, caption in zip(buttons, ("Save", "Cancel")):
            await _tab_to(app, pilot, button)
            await pilot.wait_for_scheduled_animations()
            await pilot.pause()
            assert button.label.plain == caption
            assert button.content_region.height == 1, (caption, button.content_region)
            assert body.scrollable_content_region.contains_region(button.region)
            assert_button_label_painted(app, button)
        if size[0] == 80:
            assert buttons[0].region.bottom <= buttons[1].region.y
        else:
            assert buttons[0].region.y == buttons[1].region.y
        await _click(app, pilot, buttons[0])
        await wait_until(lambda: "Vault URL is required." in _text(panel, "#status_bw_ssh"))
        assert panel.query_one("#bw_ssh_vault_form").display
        assert remote.saves == [] and asdict(manager.get()) == before
        await _click(app, pilot, buttons[1])
        await wait_until(lambda: not panel.query_one("#bw_ssh_vault_form").display)
        assert remote.saves == [] and asdict(manager.get()) == before
        assert app._exception is None
