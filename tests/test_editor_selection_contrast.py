"""Native editor selections stay legible without changing documents or copy payloads."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import webbrowser
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import create_autospec

import httpx
import keyring
import pytest
from rich.style import Style
from rich.terminal_theme import TerminalTheme
from textual import constants
from textual.containers import ScrollableContainer
from textual.pilot import Pilot
from textual.screen import Screen
from textual.widgets import Button, TextArea

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.ai_analysis import AIAnalysisScreen
from servonaut.screens.bug_report import BugReportScreen
from servonaut.screens.bug_report_consent_modal import BugReportConsentModal
from servonaut.screens.copy_mode import CopyModeScreen
from servonaut.screens.custom_servers import CustomServersScreen
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.text_editor_modal import TextEditorModal
from servonaut.services.ai_analysis_service import AIAnalysisService
from servonaut.services.bug_report_service import BugReportPayload, BugReportService
from servonaut.services.custom_server_service import CustomServerService
from tests._async_bounds import wait_until
from tests.test_navigation_dialog_contrast import _contrast, _paint_colours
from tests.test_selection_copy import _Clipboard, clipboard  # noqa: F401
from tests.test_settings_presentation import _Host as _SettingsHost
from tests.test_settings_presentation import _ready, _tab_to
from tests.test_workspace_pilot import _Host


DRAFT = "Keep this draft Ω [literal] café\n  Preserve trailing space  "
SELECTION = "this draft Ω [literal] café"
TARGETS = {
    "copy-mode": "copy-mode-text",
    "text-editor": "text-editor-area",
    "custom-servers": "input_extra_ssh_options",
    "analysis-input": "ai_text_input",
    "analysis-output": "ai_output",
    "bug-report": "description",
    "analysis-prompt": "ai_chat_system_prompt",
    "chat-prompt": "ai_chat_chat_system_prompt",
}


@pytest.fixture(autouse=True)
def _isolated_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The shared conftest isolates HOME before product modules are imported."""
    for name in ("NO_COLOR", "FORCE_COLOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    monkeypatch.setenv("TERM", "xterm-256color")
    assert not constants.FILTERS, "Clear TEXTUAL_FILTERS before process import"
    assert constants.COLOR_SYSTEM in {"auto", "truecolor"}, "Clear TEXTUAL_COLOR_SYSTEM before process import"
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    refused: list[str] = []

    def refuse(*args: Any, **kwargs: Any) -> None:
        refused.append("external operation")
        raise AssertionError("Replace the external boundary with a local fake")

    async def refuse_async(*args: Any, **kwargs: Any) -> None:
        refuse()

    monkeypatch.setattr(httpx.Client, "send", refuse)
    monkeypatch.setattr(httpx.AsyncClient, "send", refuse_async)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", refuse_async)
    monkeypatch.setattr(webbrowser, "open", refuse)
    monkeypatch.setattr(webbrowser, "open_new_tab", refuse)
    for name in ("get_password", "get_credential", "set_password", "delete_password"):
        monkeypatch.setattr(keyring, name, refuse)
    yield
    assert not refused, "An external-operation refusal was swallowed"


def _assert_colour_mode(app: _Host | _SettingsHost) -> None:
    assert not app.no_color and not app.console.no_color
    assert not constants.FILTERS
    assert app.console.color_system == "truecolor"


def _active_palette(app: _Host | _SettingsHost) -> TerminalTheme:
    # Both hosts inherit the application's real theme/palette selection.
    palette = app.ansi_theme
    expected = app._textual_ansi_themes[0 if app.current_theme.dark else 1]
    assert palette is expected
    return palette


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = AppConfig()
    config.ai_provider.provider = "ollama"
    # A fixture label avoids consulting provider defaults or loading any model.
    config.ai_provider.model = "example-model"
    config.ai_system_prompt = DRAFT
    config.chat_system_prompt = DRAFT
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(config)
    manager.load()
    return manager


@dataclass
class _Services:
    analysis: Any
    reports: Any
    servers: Any


@pytest.fixture
def services() -> Iterator[_Services]:
    """Autospec preserves the real sync/async service signatures without I/O."""
    analysis = create_autospec(AIAnalysisService, instance=True, spec_set=True)
    analysis.estimate_tokens.return_value = 7
    analysis.chunk_text.return_value = [DRAFT]
    analysis.analyze_text.return_value = {"content": DRAFT, "model": "example-model"}
    reports = create_autospec(BugReportService, instance=True, spec_set=True)
    reports.collect_diagnostics.return_value = BugReportPayload(
        servonaut_version="test", python_version="test", os_release="test",
        textual_version="test", install_method="unknown", auth_state="anonymous",
        instance_count_by_provider={}, last_traceback=None, log_excerpt=None,
        config_snapshot=None, redacted_categories_found=[],
    )
    reports.render_preview.return_value = "Local preview"
    servers = create_autospec(CustomServerService, instance=True, spec_set=True)
    servers.list_servers.return_value = []
    servers.list_as_instances.return_value = []
    yield _Services(analysis, reports, servers)
    reports.submit.assert_not_called()
    reports.submit.assert_not_awaited()
    for name in ("add_server", "update_server", "remove_server"):
        getattr(servers, name).assert_not_called()


async def _mount_target(
    app: _Host | _SettingsHost, pilot: Pilot, target: str, services: _Services,
    results: list[str | None],
) -> tuple[Screen, SettingsPanel | None]:
    if target in ("analysis-prompt", "chat-prompt"):
        panel = await _ready(app, pilot)
        return app.screen, panel
    if target == "copy-mode":
        screen: Screen = CopyModeScreen(DRAFT, title="Local text")
    elif target == "text-editor":
        screen = TextEditorModal(DRAFT, title="Local text")
    elif target == "custom-servers":
        screen = CustomServersScreen()
    elif target.startswith("analysis-"):
        screen = AIAnalysisScreen(text=DRAFT)
    else:
        screen = BugReportScreen()
    await app.push_screen(screen, callback=results.append)
    await pilot.pause()
    if target == "custom-servers":
        await pilot.press("n")
        await wait_until(lambda: screen.query_one("#add_form").display)
    elif target == "analysis-output":
        await pilot.press("f5")
        await wait_until(lambda: screen.query_one("#ai_output", TextArea).text == DRAFT)
        await wait_until(lambda: not screen.query_one("#btn_analyze", Button).disabled)
        services.analysis.analyze_text.assert_awaited_once_with(DRAFT, system_prompt="")
    elif target == "bug-report":
        await wait_until(lambda: isinstance(app.screen, BugReportConsentModal))
        services.reports.collect_diagnostics.assert_not_called()
        assert await pilot.click("#continue")
        await wait_until(lambda: app.screen is screen and screen._payload is not None)
        services.reports.collect_diagnostics.assert_called_once()
        assert services.reports.collect_diagnostics.call_args.kwargs["consent"] is screen._consent
    editor = screen.query_one(f"#{TARGETS[target]}", TextArea)
    if target in ("custom-servers", "bug-report"):
        editor.load_text(DRAFT)
    await pilot.pause()
    return screen, None


def _painted_glyphs(editor: TextArea, label: str) -> list[tuple[str, Style]]:
    """Inspect actual compositor cells, including occlusion and final ANSI styles."""
    region = editor.content_region
    rows = editor.screen._compositor.render_strips()
    left = max(0, region.x)
    for y in range(max(0, region.y), min(len(rows), region.bottom)):
        strip = rows[y].crop(left, region.right)
        start = strip.text.find(label)
        if start < 0:
            continue
        offset = 0
        glyphs: list[tuple[str, Style]] = []
        for segment in strip:
            end = offset + len(segment.text)
            if offset < start + len(label) and end > start:
                visible = segment.text[max(0, start - offset):start + len(label) - offset]
                glyphs.extend((char, segment.style or Style()) for char in visible)
            offset = end
        assert "".join(char for char, _ in glyphs) == label
        # The fixture uses only single-cell glyphs, including Ω and é.
        for x in range(left + start, left + start + len(label)):
            assert editor.app.get_widget_at(x, y)[0] is editor
        return glyphs
    pytest.fail(f"Complete {label!r} is absent from the visible editor {editor.id!r}")


async def _select_with_keys(editor: TextArea, pilot: Pilot) -> None:
    editor.focus()
    await pilot.pause()
    assert pilot.app.focused is editor
    editor.move_cursor((0, 0))
    await pilot.press("home", *(["right"] * 5), *(["shift+right"] * len(SELECTION)))
    await pilot.pause()
    assert editor.selected_text == SELECTION


@pytest.mark.asyncio
@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("theme", ["ansi-dark", "ansi-light"])
@pytest.mark.parametrize("focused", [True, False], ids=["focused", "blurred"])
async def test_native_editor_selection_paint_and_copy_preserve_document(
    manager: ConfigManager, services: _Services, clipboard: _Clipboard,
    tmp_path: Path, record_property: Callable[[str, Any], None],
    target: str, theme: str, focused: bool,
) -> None:
    manager.get().theme = theme
    app = (
        _SettingsHost(manager, "ai_chat", navigation_visible=False)
        if target in ("analysis-prompt", "chat-prompt") else _Host(navigation_visible=False)
    )
    app.config_manager = manager
    app.ai_analysis_service = services.analysis
    app.bug_report_service = services.reports
    app.custom_server_service = services.servers
    app.theme = theme
    persisted = (tmp_path / "config.json").read_bytes()
    results: list[str | None] = []
    clipboard.succeeds = False
    async with app.run_test(size=(160, 50)) as pilot:
        _assert_colour_mode(app)
        screen, panel = await _mount_target(app, pilot, target, services, results)
        editor = screen.query_one(f"#{TARGETS[target]}", TextArea)
        assert editor.text == DRAFT
        document = editor.document
        flags = editor.read_only, editor.soft_wrap, editor.show_line_numbers
        dirty = panel.has_unsaved_changes() if panel else None
        if panel:
            editor.focus()
            await pilot.pause()
            editor.move_cursor((0, 0))
            await pilot.press("home", "f6")
            assert editor.selected_text == DRAFT.splitlines()[0]
            await pilot.press("f7")
            assert editor.selected_text == DRAFT
        await _select_with_keys(editor, pilot)
        selection = editor.selection
        region, scroll = editor.region, editor.scroll_offset
        if not focused:
            # Public blur keeps the same viewport, including the read-only modal
            # whose only focus stop is the editor; no private focus hooks.
            screen.set_focus(None, scroll_visible=False)
        await pilot.pause()
        assert editor.has_focus is focused
        assert editor.selection == selection and editor.region == region
        selected = _painted_glyphs(editor, SELECTION)
        adjacent = _painted_glyphs(editor, "Keep ")
        palette = _active_palette(app)
        selected_pairs = [_paint_colours(style, palette) for _, style in selected]
        adjacent_pairs = {_paint_colours(style, palette) for _, style in adjacent}
        record_property("selection_paint", json.dumps({
            "target": target, "theme": theme, "focused": focused,
            "colour_system": app.console.color_system,
            "no_color": app.no_color, "console_no_color": app.console.no_color,
            "filters": constants.FILTERS, "requested_colour_system": constants.COLOR_SYSTEM,
            "palette": {
                "basis": "active app.ansi_theme", "theme_dark": app.current_theme.dark,
                "default_foreground": list(palette.foreground_color),
                "default_background": list(palette.background_color),
                "ansi_colours": [list(palette.ansi_colors[index]) for index in range(16)],
            },
            "glyphs": [{"glyph": char, "style": str(style),
                        "foreground": list(pair[0]), "background": list(pair[1]),
                        "contrast": _contrast(*pair)}
                       for (char, style), pair in zip(selected, selected_pairs)],
            "adjacent_pairs": [[list(fg), list(bg)] for fg, bg in sorted(adjacent_pairs)],
        }))
        editor.focus()
        await pilot.pause()
        await pilot.press("y" if target == "copy-mode" else "ctrl+c")
        await pilot.pause()
        assert app.clipboard == SELECTION
        assert clipboard.calls == ([SELECTION] if target == "copy-mode" else [])
        assert editor.document is document and editor.text == DRAFT
        assert editor.selection == selection and editor.scroll_offset == scroll
        assert (editor.read_only, editor.soft_wrap, editor.show_line_numbers) == flags
        if panel:
            assert panel.has_unsaved_changes() == dirty
            assert manager.get().ai_system_prompt == manager.get().chat_system_prompt == DRAFT
        if target in ("copy-mode", "text-editor"):
            await pilot.press("escape")
            await wait_until(lambda: app.screen is not screen)
            if target == "text-editor":
                assert results == [None]
        elif target == "custom-servers":
            assert await pilot.click("#btn_cancel_form")
            await wait_until(lambda: not screen.query_one("#add_form").display)
        elif target == "analysis-input":
            services.analysis.analyze_text.assert_not_awaited()
        elif target == "analysis-output":
            assert screen._output_text == DRAFT
        elif target == "bug-report":
            services.reports.submit.assert_not_awaited()
        assert (tmp_path / "config.json").read_bytes() == persisted
        # Assert paint after document/copy checks so a contrast regression does
        # not hide whether the same native interaction preserved its payload.
        assert all(style.reverse for _, style in selected)
        assert set(selected_pairs).isdisjoint(adjacent_pairs), "Selection highlight is invisible"
        assert min(_contrast(*pair) for pair in selected_pairs) >= 4.5


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["ansi-dark", "ansi-light"])
@pytest.mark.parametrize("focused", [True, False], ids=["focused", "blurred"])
async def test_narrow_custom_options_editor_paints_document_and_cancel_keeps_config(
    manager: ConfigManager, services: _Services, clipboard: _Clipboard,
    tmp_path: Path, theme: str, focused: bool,
) -> None:
    manager.get().theme = theme
    app = _Host(navigation_visible=False)
    app.config_manager = manager
    app.ai_analysis_service = services.analysis
    app.bug_report_service = services.reports
    app.custom_server_service = services.servers
    app.theme = theme
    persisted = (tmp_path / "config.json").read_bytes()
    async with app.run_test(size=(100, 30)) as pilot:
        _assert_colour_mode(app)
        screen, _ = await _mount_target(app, pilot, "custom-servers", services, [])
        editor = screen.query_one("#input_extra_ssh_options", TextArea)
        await _tab_to(pilot, editor)
        await pilot.pause()
        assert app.focused is editor
        await _select_with_keys(editor, pilot)
        document, selection = editor.document, editor.selection
        if not focused:
            screen.set_focus(None, scroll_visible=False)
            await pilot.pause()
        assert editor.has_focus is focused
        body = screen.query_one("#custom_servers_container", ScrollableContainer)
        assert body.scrollable_content_region.contains_region(editor.region)
        assert screen.region.contains_region(editor.region)
        assert editor.content_region.height >= len(DRAFT.splitlines())
        styles = [style for line in DRAFT.splitlines()
                  for _, style in _painted_glyphs(editor, line)]
        palette = _active_palette(app)
        assert min(_contrast(*_paint_colours(style, palette)) for style in styles) >= 4.5
        editor.focus()
        await pilot.pause()
        await pilot.press("ctrl+c")
        await pilot.pause()
        assert app.clipboard == SELECTION and clipboard.calls == []
        assert editor.document is document and editor.text == DRAFT
        assert editor.selection == selection
        cancel = screen.query_one("#btn_cancel_form", Button)
        assert screen.region.contains_region(cancel.region)
        assert app.get_widget_at(*cancel.region.center)[0] is cancel
        assert await pilot.click(cancel)
        await wait_until(lambda: not screen.query_one("#add_form").display)
        assert (tmp_path / "config.json").read_bytes() == persisted
