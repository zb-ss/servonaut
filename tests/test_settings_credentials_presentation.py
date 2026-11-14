"""Credential rows keep native reveal, hints and raw save semantics."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from textual import events
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Static

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.shell import SettingsScreen
from servonaut.screens.settings.widgets import EnvVarInput
from servonaut.widgets.secret_input import SecretInput
from tests._async_bounds import wait_until

pytestmark = pytest.mark.usefixtures("navigation_open")


VARIABLE = "SERVONAUT_S2A_TEST_KEY"
RESOLVED_FIXTURE = "fabricated-resolved-value-51a2"
FIELDS = [
    ("ip_lookup", "ip_lookup_abuseipdb_key", "abuseipdb_api_key"),
    ("ai_provider", "ai_provider_openai_key", "openai_api_key"),
    ("ai_provider", "ai_provider_anthropic_key", "anthropic_api_key"),
    ("ai_provider", "ai_provider_gemini_key", "gemini_api_key"),
    ("ai_provider", "ai_provider_ollama_key", "ollama_api_key"),
]


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = AppConfig()
    config.abuseipdb_api_key = f"${VARIABLE}"
    config.ai_provider = replace(
        config.ai_provider,
        openai_api_key=f"${VARIABLE}", anthropic_api_key=f"${VARIABLE}",
        gemini_api_key=f"${VARIABLE}", ollama_api_key=f"${VARIABLE}",
        dismissed_banners=["example-dismissal"],
    )
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(config)
    manager.load()
    return manager


class _CredentialsApp(ServonautApp):
    """Mount the real Settings shell and panel without external services."""

    def __init__(
        self, manager: ConfigManager, panel_id: str, navigation_visible: bool,
    ) -> None:
        super().__init__()
        self.config_manager = manager
        self.panel_id = panel_id
        self.workspace_state.navigation_visible = navigation_visible
        self.notes: list[str] = []

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(SettingsScreen(self.panel_id))

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)


async def _ready(app: _CredentialsApp, pilot: Pilot) -> SettingsPanel:
    await pilot.pause()
    await wait_until(lambda: isinstance(app.screen, SettingsScreen))
    await wait_until(lambda: app.screen._current_panel() is not None)
    panel = app.screen._current_panel()
    await wait_until(lambda: panel._loaded and not panel._settling)
    return panel


def _assert_exposed(app: _CredentialsApp, widget: Widget) -> None:
    assert widget.region.width > 0 and widget.region.height > 0
    assert app.screen.region.contains(*widget.region.center)
    assert app.get_widget_at(*widget.region.center)[0] is widget


async def _click_reveal(app: _CredentialsApp, pilot: Pilot, reveal: Button) -> None:
    await wait_until(lambda: not reveal.has_class("-active"))
    reveal.scroll_visible(animate=False)
    await pilot.pause()
    _assert_exposed(app, reveal)
    assert await pilot.click(reveal)


async def _assert_reveal_and_demo_contract(
    app: _CredentialsApp, pilot: Pilot, secret: SecretInput,
) -> None:
    reveal = secret.query_one(Button)
    inner = secret.input
    await _click_reveal(app, pilot, reveal)
    assert secret.revealed
    inner.focus()
    await pilot.press("ctrl+r")
    assert not secret.revealed
    await pilot.press("ctrl+r")
    assert secret.revealed
    app.demo_mode = True
    secret.refresh_after_demo_toggle()
    assert not secret.revealed
    await _click_reveal(app, pilot, reveal)
    assert not secret.revealed
    inner.focus()
    await pilot.press("ctrl+r")
    assert not secret.revealed
    assert "Secrets stay hidden in demo mode." in app.notes
    assert not reveal.can_focus and reveal not in app.screen.focus_chain
    await pilot.press("tab")
    assert app.focused is not reveal


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("panel_id,field_id,config_key", FIELDS)
async def test_secret_rows_keep_reveal_hint_and_single_tab_stop(
    manager: ConfigManager, monkeypatch: pytest.MonkeyPatch,
    size: tuple[int, int], navigation_visible: bool,
    panel_id: str, field_id: str, config_key: str,
) -> None:
    monkeypatch.setenv(VARIABLE, RESOLVED_FIXTURE)
    app = _CredentialsApp(manager, panel_id, navigation_visible)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        assert not panel.is_dirty()
        field = panel.query_one(f"#{field_id}", EnvVarInput)
        secret = field.query_one(SecretInput)
        inner = secret.input
        field.focus()
        field.scroll_visible(animate=False)
        await pilot.pause()
        row = field.parent
        assert row.has_class("settings-scalar-row")
        label = row.query_one(".label", Static)
        original_label = label.render().plain
        label.update("[red]Literal label[/red]")
        assert label.render().plain == "[red]Literal label[/red]"
        label.update(original_label)
        hint = field.query_one(".envvar-hint", Static)
        assert hint.render().plain == f"↳ ${VARIABLE} → set"
        assert hint.region.y >= inner.region.bottom
        _assert_exposed(app, hint)
        assert RESOLVED_FIXTURE not in app.export_screenshot()
        await _assert_reveal_and_demo_contract(app, pilot, secret)
        assert field.value == f"${VARIABLE}"
        assert panel.current_values()[config_key] == f"${VARIABLE}"
        monkeypatch.delenv(VARIABLE)
        field.value = f"${VARIABLE}"
        await pilot.pause()
        assert hint.render().plain == f"↳ ${VARIABLE} → MISSING"
        assert RESOLVED_FIXTURE not in app.export_screenshot()
        assert not panel.is_dirty()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("panel_id", ["ip_lookup", "ai_provider"])
async def test_credential_save_keeps_raw_reference_and_other_provider_keys(
    manager: ConfigManager, size: tuple[int, int], panel_id: str,
) -> None:
    app = _CredentialsApp(manager, panel_id, False)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        field_id = "ip_lookup_abuseipdb_key" if panel_id == "ip_lookup" else "ai_provider_openai_key"
        field = panel.query_one(f"#{field_id}", EnvVarInput)
        field.value = "  $SERVONAUT_S2A_CHANGED_KEY  "
        await wait_until(panel.is_dirty)
        save = panel.query_one(f"#save_{panel_id}", Button)
        _assert_exposed(app, save)
        assert await pilot.click(save)
        await wait_until(lambda: not panel.is_dirty())
        saved = manager.get()
        if panel_id == "ip_lookup":
            assert saved.abuseipdb_api_key == "$SERVONAUT_S2A_CHANGED_KEY"
        else:
            assert saved.ai_provider.openai_api_key == "$SERVONAUT_S2A_CHANGED_KEY"
            assert saved.ai_provider.anthropic_api_key == f"${VARIABLE}"
            assert saved.ai_provider.gemini_api_key == f"${VARIABLE}"
            assert saved.ai_provider.ollama_api_key == f"${VARIABLE}"
            assert saved.ai_provider.dismissed_banners == ["example-dismissal"]
            status = panel.query_one("#ai_provider_servonaut_status", Static).render().plain
            assert "Login required" in status and "tokens left" not in status


def _painted_text(widget: Widget) -> str:
    return "\n".join(strip.text for strip in widget.render_lines(widget.region.size.region))


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("panel_id,field_id", [
    ("ip_lookup", "ip_lookup_abuseipdb_key"),
    ("ai_provider", "ai_provider_openai_key"),
])
async def test_literal_secret_paint_requires_reveal_and_demo_remasks(
    manager: ConfigManager, navigation_visible: bool, panel_id: str, field_id: str,
) -> None:
    literal = "qa-secret-57"
    app = _CredentialsApp(manager, panel_id, navigation_visible)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        field = panel.query_one(f"#{field_id}", EnvVarInput)
        field.value = literal
        field.focus()
        field.scroll_visible(animate=False)
        await pilot.pause()
        secret = field.query_one(SecretInput)
        inner = secret.input
        reveal = secret.query_one(Button)
        assert field.query_one(".envvar-hint", Static).render().plain == ""
        assert not secret.revealed and literal not in _painted_text(inner)
        await _click_reveal(app, pilot, reveal)
        await pilot.pause()
        assert secret.revealed and literal in _painted_text(inner)
        inner.focus()
        await pilot.press("ctrl+shift+d")
        await pilot.pause()
        assert app.demo_mode and not secret.revealed
        assert literal not in _painted_text(inner)
        await _click_reveal(app, pilot, reveal)
        await pilot.pause()
        assert not secret.revealed and literal not in _painted_text(inner)
        assert field.value == literal
