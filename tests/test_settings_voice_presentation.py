"""Voice Settings presentation exercised without audio, packages or models."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from textual import events
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input, ProgressBar, Select, Static

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, VoiceConfig
from servonaut.screens.settings.panels.voice import VoicePanel
from servonaut.screens.settings.shell import SettingsScreen
from servonaut.screens.voice_model_cleanup_modal import VoiceModelCleanupModal
from servonaut.services import voice_engines
from servonaut.services.voice_setup_service import InstalledModel, VoiceReadiness
from tests._async_bounds import wait_until


SIZES = [(160, 50), (100, 30)]
DOWNLOADS = [
    ("model", "voice_btn_download"),
    ("tts", "voice_btn_tts_download"),
    ("vad", "voice_btn_vad_download"),
]
INSTALLS = [("packages", "voice_btn_install"), ("tts_packages", "voice_btn_tts_install")]
FIELDS = [
    "voice_enabled", "voice_engine", "voice_model_size", "voice_latency",
    "voice_language", "voice_input_device", "voice_max_recording_seconds",
    "voice_auto_submit", "voice_tts_enabled", "voice_tts_voice",
    "voice_tts_speed", "voice_output_device", "voice_conversation_mode",
    "voice_vad_silence_ms", "voice_conversation_idle_seconds", "voice_barge_in",
]


class _Setup:
    """Explicit in-memory setup seam: every operation only records and waits."""

    package_install_available = True
    runtime_maintenance_available = False
    runtime = SimpleNamespace(is_frozen=False)

    def __init__(self, config: VoiceConfig) -> None:
        self._config = config
        self.probes: list[bool] = []
        self.inventories = 0
        self.calls: list[str] = []
        self.cancelled: list[str] = []
        self.release = asyncio.Event()
        self.release.set()
        self.started = asyncio.Event()
        self.present = {"model": False, "tts": False, "vad": False}
        self.packages = True
        self.tts_packages = True
        self.error: Exception | None = None
        self.probe_error: Exception | None = None
        self.stale: list[InstalledModel] = []
        self.removed: list[InstalledModel] = []

    def use_config(self, config: VoiceConfig) -> None:
        self._config = config

    def probe(self, force: bool = False) -> VoiceReadiness:
        self.probes.append(force)
        if self.probe_error:
            raise self.probe_error
        return VoiceReadiness(
            packages_ok=self.packages, portaudio_ok=True, device_ok=True,
            model_ok=self.present["model"], model_size=self._config.model_size,
            engine=self._config.engine, tts_packages_ok=self.tts_packages,
            tts_model_ok=self.present["tts"], vad_model_ok=self.present["vad"],
        )

    def installed_models(self, **kwargs: Any) -> list[InstalledModel]:
        self.inventories += 1
        return list(self.stale)

    def stale_models(self, **kwargs: Any) -> list[InstalledModel]:
        return list(self.stale)

    def remove_installed(self, model: InstalledModel) -> tuple[bool, str]:
        self.removed.append(model)
        self.stale.remove(model)
        return True, "Removed fake model"

    def is_model_present_for(self, engine: str, **kwargs: Any) -> bool:
        return self.present["model"]

    def can_download_model_for(self, engine: str) -> bool:
        return True

    def download_size_hint_for(self, engine: str, **kwargs: Any) -> str:
        return "~121 MB"

    def packages_size_hint(self, engine: str) -> str:
        return "~200 MB"

    def model_bytes_for(self, engine: str, **kwargs: Any) -> int:
        return 4096

    def is_tts_model_present(self) -> bool:
        return self.present["tts"]

    def is_vad_model_present(self) -> bool:
        return self.present["vad"]

    def tts_download_size_hint(self) -> str:
        return "~301 MB"

    def vad_download_size_hint(self) -> str:
        return "~3 MB"

    def tts_model_bytes(self) -> int:
        return 4096

    def vad_model_bytes(self) -> int:
        return 4096

    def manual_install_command(self) -> str:
        return "example install command"

    def tts_manual_install_command(self) -> str:
        return "example speech install command"

    def portaudio_command(self) -> str:
        return "example system package command"

    async def _operation(self, kind: str, progress: Any) -> tuple[bool, str]:
        self.calls.append(kind)
        self.started.set()
        progress(f"Fake {kind} [example]", 1024, 4096)
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.append(kind)
            raise
        if self.error:
            raise self.error
        if kind in self.present:
            self.present[kind] = True
        elif kind == "packages":
            self.packages = True
        elif kind == "tts_packages":
            self.tts_packages = True
        return True, f"Fake {kind} finished"

    async def download_model(self, size: str, *, progress: Any) -> tuple[bool, str]:
        assert size == self._config.model_size
        return await self._operation("model", progress)

    async def download_tts_model(self, *, progress: Any) -> tuple[bool, str]:
        return await self._operation("tts", progress)

    async def download_vad_model(self, *, progress: Any) -> tuple[bool, str]:
        return await self._operation("vad", progress)

    async def install_packages(self, *, progress: Any) -> tuple[bool, str]:
        return await self._operation("packages", progress)

    async def install_tts_packages(self, *, progress: Any) -> tuple[bool, str]:
        return await self._operation("tts_packages", progress)


class _SilentAudio:
    """Factory result that cannot capture, synthesise or play sound."""

    def is_available(self) -> bool:
        return False

    def reset_availability(self) -> None:
        pass

    def close(self) -> None:
        pass

    def stop(self, **kwargs: Any) -> None:
        pass

    def start(self, *args: Any, **kwargs: Any) -> None:
        pytest.fail("Settings must not start audio")

    def speak(self, *args: Any, **kwargs: Any) -> None:
        pytest.fail("Settings must not synthesise or play audio")


@pytest.fixture(autouse=True)
def audio_factories(monkeypatch):
    for name in (
        "build_voice_input_service", "build_voice_output_service",
        "build_voice_conversation_service",
    ):
        monkeypatch.setattr(voice_engines, name, lambda *args, **kwargs: _SilentAudio())


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(AppConfig(voice=VoiceConfig(enabled=False)))
    manager.load()
    return manager


class _VoiceApp(ServonautApp):
    def __init__(self, manager: ConfigManager, setup: _Setup | None, navigation: bool) -> None:
        super().__init__()
        self.config_manager = manager
        self.voice_setup_service = setup
        self.voice_input_service = _SilentAudio()
        self.voice_output_service = _SilentAudio()
        self.voice_conversation_service = _SilentAudio()
        self.cache_service = SimpleNamespace(
            is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [],
        )
        self.workspace_state.navigation_visible = navigation
        self.notes: list[str] = []

    def provider_inventory(self, *args: Any, **kwargs: Any) -> None:
        return None

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(SettingsScreen("voice"))

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)


async def _ready(app: _VoiceApp, pilot: Pilot) -> VoicePanel:
    await pilot.pause()
    await wait_until(lambda: isinstance(app.screen, SettingsScreen))
    await wait_until(lambda: app.screen._current_panel() is not None)
    panel = app.screen._current_panel()
    assert isinstance(panel, VoicePanel)
    await wait_until(lambda: panel._loaded and not panel._settling)
    await pilot.pause()
    return panel


def _exposed(app: _VoiceApp, widget: Widget) -> bool:
    hit, _ = app.get_widget_at(*widget.region.center)
    return (
        widget.region.width > 0 and widget.region.height > 0
        and app.screen.region.contains(*widget.region.center)
        and (hit is widget or widget in hit.ancestors)
    )


async def _click(app: _VoiceApp, pilot: Pilot, button: Button) -> None:
    await wait_until(lambda: not button.has_class("-active"))
    button.scroll_visible(animate=False)
    await pilot.pause()
    await wait_until(lambda: _exposed(app, button))
    assert await pilot.click(button)


async def _tab_to(app: _VoiceApp, pilot: Pilot, widget: Widget) -> None:
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is widget:
            assert _exposed(app, widget), f"Focused control clipped: {widget.id}"
            return
        await pilot.press("tab")
    pytest.fail(f"Tab never reached {widget.id}")


def _text(panel: VoicePanel, selector: str) -> str:
    return panel.query_one(selector, Static).render().plain


def _idle(setup: _Setup) -> None:
    assert not setup.calls, "Opening/navigation must not start setup operations"
    assert not setup.removed


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_opening_and_cached_voice_navigation_only_inspect_status(manager, size, navigation) -> None:
    setup = _Setup(manager.get().voice)
    app = _VoiceApp(manager, setup, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        assert setup.probes and setup.inventories
        assert not panel._busy
        assert panel.query_one("#voice_download_row").has_class("hidden")
        _idle(setup)
        app.screen._request_switch("general")
        await wait_until(lambda: app.screen._active_id == "general")
        app.screen._request_switch("voice")
        await wait_until(lambda: app.screen._active_id == "voice")
        assert app.screen._current_panel() is panel
        assert not panel.is_dirty()
        _idle(setup)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("engine", ["whisper", "nemotron"])
async def test_voice_scalar_rows_and_last_control_keep_native_tab_and_save(
    manager, size, navigation, engine,
) -> None:
    manager.update(voice=replace(manager.get().voice, engine=engine))
    setup = _Setup(manager.get().voice)
    app = _VoiceApp(manager, setup, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        for field_id in FIELDS:
            assert panel.query_one(f"#{field_id}").parent.has_class("settings-scalar-row")
        assert panel.query_one("#voice_model_size").parent.display is (engine == "whisper")
        assert panel.query_one("#voice_latency").parent.display is (engine == "nemotron")
        for selector in ("#voice_engine", "#voice_tts_voice", "#voice_barge_in", "#save_voice"):
            await _tab_to(app, pilot, panel.query_one(selector))
        assert _exposed(app, panel.query_one("#save_voice"))
        _idle(setup)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("kind,button_id", DOWNLOADS)
async def test_explicit_download_shows_size_progress_and_blocks_overlap(
    manager, size, navigation, kind, button_id,
) -> None:
    setup = _Setup(manager.get().voice)
    setup.release.clear()
    app = _VoiceApp(manager, setup, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        button = panel.query_one(f"#{button_id}", Button)
        assert "MB" in str(button.label)
        assert any(char.isdigit() for char in str(button.label))
        button.scroll_visible(animate=False)
        await pilot.pause()
        await wait_until(lambda: _exposed(app, button))
        strips = app.screen._compositor.render_strips()
        painted = "".join(
            strips[y].crop(max(0, button.region.x), min(app.size.width, button.region.right)).text
            for y in range(max(0, button.region.y), min(app.size.height, button.region.bottom))
        )
        assert "MB" in painted, "Download cost must be painted before the explicit action"
        displayed_cost = button.label.plain.rsplit("(", 1)[-1].rstrip(")")
        assert displayed_cost in painted, "The complete download amount and unit must be painted"
        _idle(setup)
        await _click(app, pilot, button)
        await wait_until(setup.started.is_set)
        assert setup.calls == [kind]
        assert panel._busy
        assert not panel.query_one("#voice_download_row").has_class("hidden")
        assert "[example]" in _text(panel, "#voice_download_label")
        bar = panel.query_one("#voice_download_bar", ProgressBar)
        assert bar.total == 4096 and bar.progress == 1024
        bar.scroll_visible(animate=False)
        await pilot.pause()
        assert _exposed(app, bar)
        assert _exposed(app, panel.query_one("#save_voice"))
        actions = list(panel.query(".voice-action-row Button"))
        assert actions and all(action.disabled for action in actions)
        button.scroll_visible(animate=False)
        await pilot.pause()
        await wait_until(lambda: _exposed(app, button))
        await pilot.click(button)
        assert setup.calls == [kind]
        setup.release.set()
        await wait_until(lambda: not panel._busy)
        await wait_until(lambda: panel.query_one("#voice_download_row").has_class("hidden"))
        assert f"Fake {kind} finished" in app.notes
        assert setup.present[kind]
        await pilot.pause()
        assert all(not action.disabled for action in panel.query(".voice-action-row Button"))


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("kind,button_id", DOWNLOADS)
async def test_closing_settings_cancels_only_the_fake_download(manager, navigation, kind, button_id) -> None:
    setup = _Setup(manager.get().voice)
    setup.release.clear()
    app = _VoiceApp(manager, setup, navigation)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        settings = app.screen
        await _click(app, pilot, panel.query_one(f"#{button_id}", Button))
        await wait_until(setup.started.is_set)
        settings.action_back()
        await wait_until(lambda: app.screen is not settings)
        await wait_until(lambda: kind in setup.cancelled)
        assert not panel._busy
        assert not setup.present[kind]
        assert f"Fake {kind} finished" not in app.notes


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_fake_download_failure_clears_progress_and_restores_actions(manager, size, navigation) -> None:
    setup = _Setup(manager.get().voice)
    setup.error = RuntimeError("fabricated download failure [example]")
    app = _VoiceApp(manager, setup, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        await _click(app, pilot, panel.query_one("#voice_btn_download", Button))
        await wait_until(lambda: any("fabricated download failure" in note for note in app.notes))
        assert not panel._busy
        assert not setup.present["model"]
        assert panel.query_one("#voice_download_row").has_class("hidden")
        await pilot.pause()
        assert all(not button.disabled for button in panel.query(".voice-action-row Button"))
        assert _exposed(app, panel.query_one("#save_voice"))
        assert "Fake model finished" not in app.notes


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("kind,button_id", INSTALLS)
async def test_explicit_fake_install_survives_navigation_without_overlap(
    manager, size, navigation, kind, button_id,
) -> None:
    setup = _Setup(manager.get().voice)
    setup.packages = kind != "packages"
    setup.tts_packages = kind != "tts_packages"
    setup.release.clear()
    app = _VoiceApp(manager, setup, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        settings = app.screen
        _idle(setup)
        await _click(app, pilot, panel.query_one(f"#{button_id}", Button))
        await wait_until(setup.started.is_set)
        assert setup.calls == [kind]
        assert panel._busy
        assert _exposed(app, panel.query_one("#save_voice"))
        assert all(button.disabled for button in panel.query(".voice-action-row Button"))
        settings.action_back()
        await wait_until(lambda: app.screen is not settings)
        assert not setup.cancelled
        setup.release.set()
        await wait_until(lambda: f"Fake {kind} finished" in app.notes)
        assert not setup.cancelled and setup.calls == [kind]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_voice_validation_and_save_preserve_config_without_audio(manager, size, navigation) -> None:
    original = manager.get().voice
    setup = _Setup(original)
    app = _VoiceApp(manager, setup, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        panel.query_one("#voice_max_recording_seconds", Input).value = "0"
        await pilot.pause()
        await _click(app, pilot, panel.query_one("#save_voice", Button))
        await wait_until(lambda: app.focused is panel.query_one("#voice_max_recording_seconds"))
        assert manager.get().voice == original
        panel.query_one("#voice_max_recording_seconds", Input).value = str(original.max_recording_seconds)
        panel.query_one("#voice_tts_speed", Input).value = "1.25"
        await pilot.pause()
        assert panel.is_dirty()
        await _click(app, pilot, panel.query_one("#save_voice", Button))
        await wait_until(lambda: "Saved" in app.notes)
        await wait_until(lambda: not panel._settling)
        expected = replace(original, tts_speed=1.25)
        assert manager.get().voice == expected
        assert ConfigManager(config_path=manager._config_path).load().voice == expected
        assert setup._config == expected
        assert not panel.is_dirty()
        _idle(setup)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("remove", [False, True])
async def test_voice_save_cleanup_requires_actual_modal_consent(
    manager, tmp_path, size, navigation, remove,
) -> None:
    setup = _Setup(manager.get().voice)
    stale = InstalledModel("whisper", "Whisper example [unused]", "tiny", tmp_path / "not-created", 4096, False)
    setup.stale = [stale]
    app = _VoiceApp(manager, setup, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        panel.query_one("#voice_model_size", Select).value = "base"
        await pilot.pause()
        await _click(app, pilot, panel.query_one("#save_voice", Button))
        await wait_until(lambda: isinstance(app.screen, VoiceModelCleanupModal))
        modal = app.screen
        # Screen activation precedes mounting and the modal's safe-focus handler.
        await wait_until(lambda: (
            app.screen is modal and modal.is_mounted
            and bool(modal.query("#vmc_keep"))
            and app.focused is modal.query_one("#vmc_keep", Button)
        ))
        assert not setup.removed
        assert app.focused is app.screen.query_one("#vmc_keep")
        if remove:
            await _click(app, pilot, app.screen.query_one("#vmc_remove", Button))
        else:
            await pilot.press("escape")
        await wait_until(lambda: isinstance(app.screen, SettingsScreen))
        assert setup.removed == ([stale] if remove else [])
        assert manager.get().voice.model_size == "base"
        assert not (tmp_path / "not-created").exists()
        assert not setup.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_unavailable_readiness_keeps_last_control_and_save_reachable(manager, size, navigation) -> None:
    setup = _Setup(manager.get().voice)
    setup.probe_error = RuntimeError("fabricated readiness failure [example]")
    app = _VoiceApp(manager, setup, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        assert "unavailable" in _text(panel, "#voice_status_banner")
        assert "[example]" in _text(panel, "#voice_status_banner")
        await _tab_to(app, pilot, panel.query_one("#voice_barge_in"))
        await _tab_to(app, pilot, panel.query_one("#save_voice"))
        assert not panel._busy
        _idle(setup)


@pytest.mark.asyncio
async def test_readiness_failure_survives_edits_until_successful_recheck(manager) -> None:
    original = manager.get().voice
    setup = _Setup(original)
    setup.present = {kind: True for kind in setup.present}
    app = _VoiceApp(manager, setup, True)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        assert "Set up, but switched off" in _text(panel, "#voice_status_banner")
        last_readiness = panel._readiness
        setup.probe_error = RuntimeError("fabricated re-check failure [example]")
        await _click(app, pilot, panel.query_one("#voice_btn_recheck", Button))
        assert "fabricated re-check failure [example]" in _text(panel, "#voice_status_banner")
        assert panel._readiness is last_readiness

        enabled = panel.query_one("#voice_enabled")
        enabled.scroll_visible(animate=False)
        await pilot.pause()
        assert await pilot.click(enabled)
        await wait_until(lambda: enabled.value)
        await pilot.pause()
        assert "unavailable" in _text(panel, "#voice_status_banner")

        model = panel.query_one("#voice_model_size", Select)
        await _tab_to(app, pilot, model)
        await pilot.press("enter", "home", "down", "enter")
        await wait_until(lambda: model.value == "base")
        await pilot.pause()
        assert "fabricated re-check failure [example]" in _text(panel, "#voice_status_banner")
        banner = panel.query_one("#voice_status_banner", Static)
        banner.scroll_visible(animate=False)
        await pilot.pause()
        assert _exposed(app, banner)

        setup.probe_error = None
        await _click(app, pilot, panel.query_one("#voice_btn_recheck", Button))
        await wait_until(lambda: "Ready —" in _text(panel, "#voice_status_banner"))
        assert "unavailable" not in _text(panel, "#voice_status_banner")
        assert enabled.value and model.value == "base"
        assert manager.get().voice == original
        _idle(setup)
