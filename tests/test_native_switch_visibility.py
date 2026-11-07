"""Native switches keep visible state, input semantics and Settings behavior."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict
import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from rich.console import Console
from rich.style import Style
from textual import events
from textual.app import ComposeResult
from textual.pilot import Pilot
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Button, Input, Switch

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.memory_keys import PassphraseEnrolModal
from servonaut.screens.settings.shell import DiscardChangesModal
from servonaut.services.memory import passphrase_store
from servonaut.styles.themes import SERVONAUT_ANSI_DARK, SERVONAUT_ANSI_LIGHT
from tests._async_bounds import wait_until
from tests.test_navigation_dialog_contrast import PALETTES, _contrast, _paint_colours
from tests.test_settings_presentation import _Host as _SettingsHost, _ready, _tab_to


THEMES = ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"]


@pytest.fixture(autouse=True)
def _isolated_services(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    violations = []

    def refuse(*args: object, **kwargs: object) -> None:
        violations.append("external operation")
        raise AssertionError("Unexpected external operation")

    # The actual modal constructor checks availability. No real keychain is
    # consulted, and Cancel must never reach get/store/clear or a backend.
    monkeypatch.setattr(passphrase_store, "keyring_available", lambda: True)
    for name in ("get_passphrase", "store_passphrase", "clear_passphrase"):
        monkeypatch.setattr(passphrase_store, name, refuse)
    backend = Mock()
    for name in ("get_password", "set_password", "delete_password", "get_keyring"):
        setattr(backend, name, refuse)
    monkeypatch.setattr(passphrase_store, "_keyring", backend)
    monkeypatch.setattr("socket.create_connection", refuse)
    monkeypatch.setattr("httpx.Client.send", refuse)
    monkeypatch.setattr("httpx.AsyncClient.send", refuse)
    yield
    assert not violations


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = AppConfig()
    config.vault.strict_verification = True
    config.vault.auto_grant = False
    config.vault.allow_file_key_store = False
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(config)
    manager.load()
    return manager


class _ControlsHost(ServonautApp):
    """Use the full application stylesheet without starting its services."""

    def __init__(self, theme: str = "servonaut") -> None:
        super().__init__()
        self.changes: list[tuple[Switch, bool]] = []
        self.theme = theme

    def compose(self) -> ComposeResult:
        yield Input(value="before", id="before")
        yield Switch(False, id="off")
        yield Switch(True, id="on")
        yield Switch(False, disabled=True, id="disabled-off")
        yield Switch(True, disabled=True, id="disabled-on")
        yield Input(value="after", id="after")

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.screen.query_one("#before", Input).focus()

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        self.changes.append((event.switch, event.value))


class _VaultHost(_SettingsHost):
    def __init__(self, manager: ConfigManager, navigation_visible: bool) -> None:
        super().__init__(manager, "vault", navigation_visible=navigation_visible)
        self.changes: list[tuple[Switch, bool]] = []

    def on_switch_changed(self, event: Switch.Changed) -> None:
        self.changes.append((event.switch, event.value))


async def _settle(pilot: Pilot, switch: Switch) -> None:
    await pilot.wait_for_scheduled_animations()
    await pilot.pause()
    await wait_until(lambda: switch.has_class("-on") is switch.value)


def _cell(app: ServonautApp, x: int, y: int) -> tuple[str, Style]:
    """Read the final composed cell, including native reverse-fill style."""
    row = app.screen._compositor.render_strips()[y]
    offset = 0
    for segment in row:
        end = offset + segment.cell_length
        if offset <= x < end:
            return row.crop(x, x + 1).text, segment.style or Style()
        offset = end
    raise AssertionError(f"No painted cell at {(x, y)}")


def _sample(app: ServonautApp, switch: Switch) -> dict[str, Any]:
    region = switch.content_region
    assert region.width == 4 and region.height == 1
    assert app.screen.region.contains_region(switch.region)
    cells = [_cell(app, x, region.y) for x in range(region.x, region.right)]
    assert all(glyph == " " for glyph, _ in cells)
    assert all(app.get_widget_at(x, region.y)[0] is switch for x in range(region.x, region.right))
    thumb = (2, 3) if switch.value else (0, 1)
    track = (0, 1) if switch.value else (2, 3)
    # Native ScrollBarRender draws stable endpoints using blank-cell fills.
    # Reverse must be resolved before choosing the VISIBLE background color.
    surround = _cell(app, region.x - 1, region.y)[1]
    palette_rows = {}
    for name, palette in PALETTES.items():
        fills = [_paint_colours(style, palette)[1] for _, style in cells]
        assert fills[thumb[0]] == fills[thumb[1]]
        assert fills[track[0]] == fills[track[1]]
        thumb_fill, track_fill = fills[thumb[0]], fills[track[0]]
        surface = _paint_colours(surround, palette)[1]
        palette_rows[name] = {
            "thumb": list(thumb_fill), "track": list(track_fill),
            "surround": list(surface),
            "thumb_track": _contrast(thumb_fill, track_fill),
            "thumb_surround": _contrast(thumb_fill, surface),
        }
    return {
        "theme": app.theme,
        "id": switch.id, "value": switch.value, "disabled": switch.disabled,
        "focused": app.focused is switch, "hovered": switch.mouse_hover,
        "region": list(switch.region), "content_region": list(region),
        "thumb_cells": list(thumb), "track_cells": list(track),
        "cells": [{"glyph": glyph, "style": str(style)} for glyph, style in cells],
        "border_cells": [str(_cell(app, x, switch.region.y))
                         for x in range(switch.region.x, switch.region.right)],
        "palettes": palette_rows,
    }


def _capture(app: ServonautApp, tmp_path: Path, name: str, data: object) -> None:
    console = Console(
        width=app.size.width, height=app.size.height, file=io.StringIO(),
        record=True, force_terminal=True, color_system="truecolor",
        legacy_windows=False, safe_box=False,
    )
    console.print(app.screen._compositor.render_update(
        full=True, screen_stack=app._background_screens, simplify=False,
    ))
    palette = SERVONAUT_ANSI_DARK if app.current_theme.dark else SERVONAUT_ANSI_LIGHT
    tmp_path.joinpath(name + ".svg").write_text(
        console.export_svg(title=name, theme=palette, clear=False), encoding="utf-8",
    )
    tmp_path.joinpath(name + ".json").write_text(json.dumps(data, indent=2) + "\n")


async def _click(app: ServonautApp, pilot: Pilot, target: Widget) -> None:
    target.scroll_visible(animate=False, immediate=True)
    await pilot.pause()
    assert app.get_widget_at(*target.region.center)[0] is target
    offset = (target.region.width // 2, target.region.height // 2)
    assert await pilot.click(target, offset=offset)
    await pilot.pause()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_registered_theme_native_switch_paint_census(
    size: tuple[int, int], tmp_path: Path,
) -> None:
    # Enabled controls use the registered theme's matching terminal palette.
    # Other palettes and disabled decoration remain separate diagnostics.
    names = tuple(sorted(_ControlsHost().available_themes))
    records = []
    for name in names:
        app = _ControlsHost(name)
        async with app.run_test(size=size) as pilot:
            matching_palette = "servonaut-dark" if app.current_theme.dark else "servonaut-light"
            after = app.screen.query_one("#after", Input)
            for control_id in ("off", "on"):
                switch = app.screen.query_one(f"#{control_id}", Switch)
                await _settle(pilot, switch)
                geometry = switch.region, switch.content_region
                for state in ("blur", "focus", "hover"):
                    after.focus()
                    assert await pilot.hover(after)
                    if state == "focus":
                        switch.focus()
                    elif state == "hover":
                        assert await pilot.hover(switch)
                    await pilot.pause()
                    sample = _sample(app, switch)
                    assert sample["focused"] is (state == "focus")
                    assert sample["hovered"] is (state == "hover")
                    assert switch.value is (control_id == "on")
                    records.append({"state": state, "matching_palette": matching_palette, **sample})
                    assert (switch.region, switch.content_region) == geometry
            for control_id in ("disabled-off", "disabled-on"):
                switch = app.screen.query_one(f"#{control_id}", Switch)
                await _settle(pilot, switch)
                assert switch.disabled and switch.value is (control_id == "disabled-on")
                records.append({"state": "disabled-diagnostic", "matching_palette": matching_palette,
                                **_sample(app, switch)})
            assert app.changes == [] and app._exception is None
    assert len(records) == len(names) * 8
    failures: dict[str, list[object]] = {"contrast": [], "hover": []}
    enabled = [record for record in records if not record["disabled"]]
    for record in enabled:
        colors = record["palettes"][record["matching_palette"]]
        if min(colors["thumb_track"], colors["thumb_surround"]) < 3:
            failures["contrast"].append((record["theme"], record["state"], record["value"], colors))
    for name in names:
        for value in (False, True):
            pair = [record for record in enabled
                    if record["theme"] == name and record["value"] is value]
            normal = next(record for record in pair if record["state"] == "blur")
            hover = next(record for record in pair if record["state"] == "hover")
            palette = normal["matching_palette"]
            if normal["palettes"][palette]["thumb"] == hover["palettes"][palette]["thumb"]:
                failures["hover"].append((name, value, palette))
    tmp_path.joinpath("registered-switch-paint.json").write_text(json.dumps({
        "themes": names, "viewport": size, "observations": records,
        "contrast_policy": "enabled matching palette: three-to-one thumb/track and surface; native hover cue",
        "diagnostics": "alternate palettes and disabled decoration are recorded separately",
        "failures": failures,
    }, indent=2) + "\n")
    assert not any(failures.values()), failures


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_native_switch_keyboard_pointer_focus_and_disabled_events(
    theme: str, size: tuple[int, int], tmp_path: Path,
) -> None:
    app = _ControlsHost(theme)
    async with app.run_test(size=size) as pilot:
        off, on = app.screen.query_one("#off", Switch), app.screen.query_one("#on", Switch)
        before, after = app.screen.query_one("#before", Input), app.screen.query_one("#after", Input)
        await _settle(pilot, off)
        assert app.focused is before and app.changes == []
        original = off.region, off.content_region
        pointer = off.region.center
        await pilot.press("tab")
        assert app.focused is off
        samples = [_sample(app, off)]
        for key, value in (("space", True), ("enter", False)):
            await pilot.press(key)
            await _settle(pilot, off)
            assert off.value is value and app.focused is off
            samples.append(_sample(app, off))
        for value in (True, False):
            assert app.get_widget_at(*pointer)[0] is off
            assert await pilot.click(offset=tuple(pointer))
            await _settle(pilot, off)
            assert off.value is value
            samples.append(_sample(app, off))
        assert app.changes == [(off, True), (off, False), (off, True), (off, False)]
        assert (off.region, off.content_region) == original
        await pilot.press("tab")
        assert app.focused is on
        await pilot.press("tab")
        assert app.focused is after  # Native disabled controls are not Tab stops.
        await pilot.press("shift+tab", "shift+tab")
        assert app.focused is off
        for control_id, value in (("disabled-off", False), ("disabled-on", True)):
            after.focus()
            await pilot.pause()
            assert app.focused is after
            disabled = app.screen.query_one(f"#{control_id}", Switch)
            disabled.focus()
            await pilot.pause()
            assert app.focused is after
            await pilot.click(disabled, offset=(disabled.region.width // 2, disabled.region.height // 2))
            await pilot.press("space", "enter")
            await _settle(pilot, disabled)
            assert disabled.value is value
        assert len(app.changes) == 4 and app._exception is None
        _capture(app, tmp_path, "native-switch-interaction", samples)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_vault_dark_off_native_thumb_visibility(
    manager: ConfigManager, size: tuple[int, int], navigation_visible: bool, tmp_path: Path,
) -> None:
    app = _VaultHost(manager, navigation_visible)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        switch = panel.query_one("#vault_allow_file_key_store", Switch)
        switch.scroll_visible(animate=False, immediate=True)
        app.screen.query_one("#settings-search", Input).focus()
        assert await pilot.hover(app.screen.query_one("#settings-search"))
        await _settle(pilot, switch)
        assert not switch.value and app.focused is not switch
        sample = _sample(app, switch)
        _capture(app, tmp_path, "vault-off-original-lead", sample)
        # Probe three-to-one non-text contrast in the normal OFF state.
        # Capture native baseline paint before changing shared roles.
        for name, colors in sample["palettes"].items():
            assert colors["thumb_track"] >= 3, (name, colors)
            assert colors["thumb_surround"] >= 3, (name, colors)
        assert not panel.has_unsaved_changes()


async def _settings_destination(pilot: Pilot, panel_id: str) -> None:
    await pilot.press("ctrl+f", "ctrl+shift+a", *panel_id)
    button = pilot.app.screen.query_one(f"#navbtn_{panel_id}", Button)
    await _tab_to(pilot, button)
    await pilot.press("enter")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_vault_switch_save_reload_keep_and_discard_use_native_controls(
    manager: ConfigManager, size: tuple[int, int], navigation_visible: bool, tmp_path: Path,
) -> None:
    app = _VaultHost(manager, navigation_visible)
    expected = asdict(manager.get())
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        screen = app.screen
        allow = panel.query_one("#vault_allow_file_key_store", Switch)
        auto = panel.query_one("#vault_auto_grant", Switch)
        await _settle(pilot, allow)
        app.changes.clear()
        await _click(app, pilot, allow)
        await _settle(pilot, allow)
        await _tab_to(pilot, auto)
        await pilot.press("space")
        await _settle(pilot, auto)
        assert app.changes == [(allow, True), (auto, True)]
        await wait_until(panel.has_unsaved_changes)
        await _click(app, pilot, panel.query_one("#save_vault", Button))
        await wait_until(lambda: not panel.has_unsaved_changes())
        expected["vault"]["allow_file_key_store"] = True
        expected["vault"]["auto_grant"] = True
        assert asdict(ConfigManager(config_path=tmp_path / "config.json").load()) == expected
        saved = (tmp_path / "config.json").read_bytes()
        await _tab_to(pilot, allow)
        await pilot.press("space")
        await _settle(pilot, allow)
        assert not allow.value and panel.has_unsaved_changes()
        await _settings_destination(pilot, "general")
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        await _click(app, pilot, app.screen.query_one("#discard-cancel", Button))
        await wait_until(lambda: app.screen is screen)
        assert screen._active_id == "vault"
        assert not allow.value and panel.has_unsaved_changes()
        assert app.focused is not None and screen.region.contains_region(app.focused.region)
        assert (tmp_path / "config.json").read_bytes() == saved
        await _settings_destination(pilot, "general")
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        await _click(app, pilot, app.screen.query_one("#discard-confirm", Button))
        await wait_until(lambda: screen._active_id == "general")
        assert (tmp_path / "config.json").read_bytes() == saved
        await _settings_destination(pilot, "vault")
        await wait_until(lambda: screen._active_id == "vault")
        await _ready(app, pilot)
        assert allow.value and not panel.has_unsaved_changes()
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
@pytest.mark.parametrize("remember_default", [False, True])
async def test_passphrase_remember_switch_cancel_never_uses_keychain(
    theme: str, remember_default: bool, tmp_path: Path,
) -> None:
    app = _ControlsHost(theme)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        # A modal above a normal screen uses the application's ordinary pop;
        # dismissing at depth two intentionally navigates to the fleet instead.
        origin_screen = Screen()
        await app.push_screen(origin_screen)
        origin = Input(id="origin")
        await origin_screen.mount(origin)
        origin.focus()
        await pilot.pause()
        assert app.focused is origin
        modal = PassphraseEnrolModal(remember_default=remember_default)
        await app.push_screen(modal, results.append)
        switch = modal.query_one("#enrol-remember", Switch)
        await _settle(pilot, switch)
        assert switch.display and switch.value is remember_default
        app.changes.clear()
        await _tab_to(pilot, switch)
        assert app.focused is switch
        # Native focus first reveals the control inside an overflowing body.
        await _settle(pilot, switch)
        assert app.get_widget_at(*switch.region.center)[0] is switch
        initial = switch.region, switch.content_region
        await pilot.press("space")
        await _settle(pilot, switch)
        assert switch.value is not remember_default
        await _click(app, pilot, switch)
        await _settle(pilot, switch)
        assert switch.value is remember_default
        assert app.changes == [(switch, not remember_default), (switch, remember_default)]
        assert (switch.region, switch.content_region) == initial
        assert modal.query_one("#enrol-btn-confirm", Button).disabled
        _capture(app, tmp_path, "remember-switch-cancel", _sample(app, switch))
        await _click(app, pilot, modal.query_one("#enrol-btn-cancel", Button))
        await wait_until(lambda: bool(results))
        assert results == [None] and app.focused is origin
        assert app._exception is None
