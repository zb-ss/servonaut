"""ANSI full screens cover prior views and user messages retain readable paint."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console
from textual.widgets import Input, Select, Static, TextArea

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.settings.shell import SettingsScreen
from servonaut.services.chat_service import ChatMessage, ChatSession
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests._native_actions import click_action
from tests.test_navigation_dialog_contrast import _assert_readable
from tests.test_server_tool_identity_contrast import (
    _no_external_operations as _no_external_operations,
)
from tests.test_settings_presentation import _tab_to
from tests.test_workspace_pilot import _Host


def _native_frame(app: _Host, target: Path) -> str:
    """Capture exactly the native screen stack, including transparent underlays."""
    console = Console(
        width=app.size.width, height=app.size.height, file=io.StringIO(),
        force_terminal=True, color_system="truecolor", record=True,
        legacy_windows=False, safe_box=False,
    )
    console.print(app.screen._compositor.render_update(
        full=True, screen_stack=app._background_screens, simplify=False,
    ))
    target.write_text(
        console.export_svg(title=target.stem, theme=app.ansi_theme, clear=False),
        encoding="utf-8",
    )
    return console.export_text(clear=False)


def _host(tmp_path: Path, theme: str) -> _Host:
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(AppConfig(theme=theme))
    app = _Host(navigation_visible=False)
    app.config_manager = manager
    app.theme = theme
    return app


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["ansi-dark", "ansi-light"])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_ansi_user_message_has_readable_native_composed_paint(
    tmp_path: Path, theme: str, size: tuple[int, int],
) -> None:
    app = _host(tmp_path, theme)
    message = "Check web-1 [literal] Ω"
    async with app.run_test(size=size) as pilot:
        await pilot.press("f2")
        await pilot.pause()
        panel = app.screen.query_one(ChatPanel)
        panel._session = ChatSession(messages=[ChatMessage("user", message)])
        panel._refresh_messages()
        await wait_until(lambda: bool(panel.query(".chat-message-user")))
        await pilot.pause()
        user = panel.query_one(".chat-message-user", Static)
        frame = _native_frame(app, tmp_path / "chat.svg")
        assert message in frame
        # Read the composed terminal cells, not the declared CSS color pair.
        rows = app.screen._compositor.render_strips()
        bounds = user.region.intersection(app.screen.region)
        for y in range(bounds.y, bounds.bottom):
            line = rows[y].crop(bounds.x, bounds.right).text
            offset = line.find(message)
            if offset < 0:
                continue
            styles = [app.screen._compositor.get_style_at(x, y) for x in range(
                bounds.x + offset, bounds.x + offset + len(message),
            )]
            _assert_readable(styles, context=f"{theme} user message {size}")
            break
        else:
            pytest.fail("Complete user message is missing from native paint")
        editor = panel.query_one("#chat-input", TextArea)
        assert app.screen.region.contains_region(editor.region)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["ansi-dark", "ansi-light"])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_ansi_settings_covers_prior_fleet_but_confirmation_stays_transparent(
    tmp_path: Path, theme: str, size: tuple[int, int],
) -> None:
    app = _host(tmp_path, theme)
    # All four native detail rows are beneath Settings' unused bottom band.
    sentinel = "PRIOR-FLEET-DETAIL-ONLY"
    async with app.run_test(size=size) as pilot:
        fleet = app.screen
        fleet.query_one("#instance_detail", TextArea).load_text(
            "\n".join([sentinel] * 4),
        )
        await pilot.pause()
        assert sentinel in _native_frame(app, tmp_path / "fleet.svg")
        await app.push_screen(SettingsScreen("general"))
        await wait_until(lambda: app.screen._current_panel() is not None)
        panel = app.screen._current_panel()
        await wait_until(lambda: panel._loaded and not panel._settling)
        await pilot.pause()
        settings = app.screen
        frame = _native_frame(app, tmp_path / "settings.svg")
        assert "Default username" in frame
        assert sentinel not in frame, "Prior fleet details bleed through Settings"
        assert settings.region == fleet.region
        assert settings.styles.background.a == 1
        assert settings.styles.background.ansi == -1
        # A native dropdown opens over the panel; the prior screen stays hidden.
        settings.show_panel("aws")
        await wait_until(lambda: settings._current_panel() is not panel)
        await wait_until(lambda: bool(settings.query("#aws_s3_region")))
        aws_panel = settings._current_panel()
        await wait_until(lambda: aws_panel._loaded and not aws_panel._settling)
        selector = settings.query_one("#aws_s3_region", Select)
        selector.focus()
        await pilot.press("enter")
        await wait_until(lambda: selector.expanded)
        await pilot.pause()
        assert sentinel not in _native_frame(app, tmp_path / "settings-selector.svg")
        await pilot.press("escape")
        await wait_until(lambda: not selector.expanded)
        settings.show_panel("general")
        await wait_until(lambda: settings._current_panel() is panel)
        username = settings.query_one("#general_username", Input)
        await _tab_to(pilot, username)
        await pilot.press("ctrl+a", "ctrl+k")
        assert username.value == ""
        await wait_until(panel.is_dirty)
        await click_action(pilot, "#save_general")
        await wait_until(lambda: "Username cannot be empty" in str(
            panel.query_one("#status_general", Static).render(),
        ))
        validation = _native_frame(app, tmp_path / "settings-validation.svg")
        assert "Username cannot be empty" in validation and sentinel not in validation
        await app.push_screen(ConfirmActionScreen(
            "Review change", "Confirm this action.", ["A setting changes."],
            "confirm", "Confirm",
        ))
        await pilot.pause()
        assert app.screen.styles.background.is_transparent
        assert settings in app._background_screens
        # Workspace's opaque ANSI background must not make its modal opaque.
        assert sentinel not in _native_frame(app, tmp_path / "confirmation.svg")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is settings)
        assert username.value == "" and panel.is_dirty()
        assert app._exception is None
