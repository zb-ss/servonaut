"""Chat close cleanup, screen ownership, and inherited text-editing keys."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from textual import events
from textual.app import ComposeResult
from textual.pilot import Pilot
from textual.screen import Screen
from textual.widgets import Input, TextArea

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.log_picker import LogPickerModal, ManagePathsModal
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until


class _ContentScreen(Screen):
    CSS = """
    _ContentScreen > Input { width: 30; }
    _ContentScreen > TextArea { width: 45; height: 5; }
    """

    def compose(self) -> ComposeResult:
        yield Input(id="content-input")
        yield TextArea("first café\nsecond Ω", read_only=True, id="detail")


class _WorkspaceApp(ServonautApp):
    """Use real chat widgets and keys with no provider or audio runtime."""

    CSS = "ToastRack { display: none; }"

    def __init__(self) -> None:
        super().__init__()
        self.config_manager = SimpleNamespace(get=AppConfig)
        self.voice_input_service = None
        self.voice_output_service = None
        self.voice_conversation_service = None

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(_ContentScreen())

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()


async def _open_chat(app: _WorkspaceApp, pilot: Pilot, key: str) -> ChatPanel:
    await pilot.press(key)
    await wait_until(lambda: bool(app.screen.query(ChatPanel)))
    panel = app.screen.query_one(ChatPanel)
    editor = panel.query_one("#chat-input", TextArea)
    await wait_until(lambda: app.focused is editor)
    return panel


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["f2", "ctrl+g"])
async def test_toggle_collapses_panel_and_restores_unsent_draft(
    key: str,
) -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(160, 50)) as pilot:
        original = await _open_chat(app, pilot, key)
        await pilot.press(*"unsent draft")
        assert original.query_one("#chat-input", TextArea).text == "unsent draft"
        await pilot.press(key)
        await wait_until(lambda: original._collapsed)
        assert original.is_attached
        assert app.focused is None or app.focused not in original.walk_children()
        reopened = await _open_chat(app, pilot, key)
        assert reopened is original
        assert reopened.query_one("#chat-input", TextArea).text == "unsent draft"


@pytest.mark.asyncio
@pytest.mark.parametrize("close", ["f3", "button"])
@pytest.mark.parametrize("capture", ["recording", "starting"])
async def test_end_routes_cancel_owned_work_and_stop_audio(
    close: str, capture: str,
) -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        app.voice_input_service = MagicMock(spec=["cancel_recording"])
        app.voice_output_service = MagicMock(spec=["stop"])
        app.voice_conversation_service = MagicMock(spec=[
            "set_state_callback", "set_transcript_callback", "set_error_callback",
            "set_stopped_callback", "stop",
        ])
        panel._recording = capture == "recording"
        panel._starting = capture == "starting"
        panel._conversation_active = True
        panel._conversation_state = "listening"
        panel._speaking = True
        started, cancelled = asyncio.Event(), asyncio.Event()

        async def held_turn() -> None:
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        panel.run_worker(held_turn(), group="ai_chat", name="held-test-turn")
        await wait_until(started.is_set)
        if close == "button":
            assert await pilot.click(panel.query_one("#btn-chat-close"))
        else:
            await pilot.press(close)
        await wait_until(lambda: not panel.is_attached and cancelled.is_set())
        assert not app.screen.query(ChatPanel)
        app.voice_input_service.cancel_recording.assert_called_once_with()
        app.voice_output_service.stop.assert_called_once_with()
        conversation = app.voice_conversation_service
        conversation.set_state_callback.assert_called_once_with(None)
        conversation.set_transcript_callback.assert_called_once_with(None)
        conversation.set_error_callback.assert_called_once_with(None)
        conversation.set_stopped_callback.assert_called_once_with(None)
        conversation.stop.assert_called_once_with(join=False)


@pytest.mark.asyncio
async def test_chat_stays_on_its_screen_when_another_screen_is_pushed() -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(160, 50)) as pilot:
        home = app.screen
        original = await _open_chat(app, pilot, "f2")
        await pilot.press(*"home draft")
        adjacent = _ContentScreen()
        await app.push_screen(adjacent)
        assert not adjacent.query(ChatPanel)
        assert home.query_one(ChatPanel) is original
        other = await _open_chat(app, pilot, "ctrl+g")
        assert other is not original
        app.pop_screen()
        await wait_until(lambda: app.screen is home and not other.is_attached)
        assert home.query_one(ChatPanel) is original
        assert original.query_one("#chat-input", TextArea).text == "home draft"


@pytest.mark.asyncio
@pytest.mark.parametrize("editor_id", ["detail", "chat-input"])
async def test_f6_and_f7_keep_their_textarea_selection_meaning(
    editor_id: str,
) -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        editor = app.screen.query_one(f"#{editor_id}", TextArea)
        editor.load_text("first café\nsecond Ω")
        editor.focus()
        await pilot.press("f6")
        assert editor.selected_text == "first café"
        await pilot.press("f7")
        assert editor.selected_text == "first café\nsecond Ω"
        assert app.focused is editor
        assert app.screen.query_one(ChatPanel) is panel


@pytest.mark.asyncio
async def test_log_picker_keeps_local_f2_manage_paths_before_global_chat() -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(160, 50)) as pilot:
        home = app.screen
        picker = LogPickerModal(
            available_logs=["/var/log/app.log"],
            discovered_logs=[],
            instance={"id": "server-1"},
            log_viewer_service=SimpleNamespace(
                get_custom_paths=lambda instance_id: ["/var/log/app.log"],
            ),
        )
        await app.push_screen(picker)
        assert isinstance(app.focused, Input)
        await pilot.press("f2")
        await wait_until(lambda: isinstance(app.screen, ManagePathsModal))
        assert not home.query(ChatPanel)
        assert not picker.query(ChatPanel)
        await pilot.press("escape")
        await wait_until(lambda: app.screen is picker)
        await pilot.press("escape")
        await wait_until(lambda: app.screen is home)
        await _open_chat(app, pilot, "ctrl+g")
