"""Collapse preserves a screen-owned text turn; End retains teardown."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual.app import ComposeResult
from textual.command import CommandList
from textual.geometry import Region
from textual.widgets import Button, Footer, Input, TextArea
from textual.widgets.text_area import Selection

from servonaut.config.schema import AppConfig, VoiceConfig
from servonaut.services.chat_service import ChatMessage, ChatSession
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.custom_servers import CustomServersScreen
from servonaut.screens.help import HelpScreen
from servonaut.screens.key_management import KeyManagementScreen
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen
from tests._async_bounds import wait_until
from tests.test_workspace_characterization import _ContentScreen, _WorkspaceApp, _open_chat
from tests.test_workspace_pilot import _Host, _click

pytestmark = pytest.mark.usefixtures("navigation_open")


class _UnmigratedScreen(_ContentScreen):
    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield from super().compose()
        yield Footer()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_unmigrated_compact_bar_keeps_mouse_restore_and_end_visible(size: tuple) -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=size) as pilot:
        await app.switch_screen(_UnmigratedScreen())
        panel = await _open_chat(app, pilot, "f2")
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep this draft")
        await pilot.press("f2")
        await pilot.pause()
        assert panel._collapsed and panel.region.height == 1
        header = app.screen.query_one(SafeHeader)
        footer = app.screen.query_one(Footer)
        assert panel.region.y >= header.region.bottom
        assert panel.region.bottom <= footer.region.y
        content_input = app.screen.query_one("#content-input", Input)
        native_top_border = content_input.render_lines(
            Region(0, 0, *content_input.region.size),
        )[0].text
        painted_top_border = app.screen._compositor.render_strips()[
            content_input.region.y
        ].crop(content_input.region.x, content_input.region.right).text
        assert painted_top_border == native_top_border
        assert content_input.region.y >= panel.region.bottom
        for button_id in ("btn-chat-restore", "btn-chat-end"):
            button = panel.query_one(f"#{button_id}", Button)
            assert button.region.height == 1 and button.region.width > 0
            assert app.get_widget_at(*button.region.center)[0] is button
        for _ in range(8):
            await pilot.press("tab")
            assert app.focused not in panel.query_one("#chat-inner").walk_children()
        await _click(pilot, "#btn-chat-restore")
        await wait_until(lambda: app.focused is editor)
        assert not panel._collapsed and editor.text == "Keep this draft"
        await pilot.press("f2")
        await _click(pilot, "#btn-chat-end")
        await wait_until(lambda: not panel.is_attached)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("screen_kind", ["help", "custom_servers", "keys"])
async def test_actual_workspace_collapse_restores_content_without_losing_the_turn(
    size: tuple, screen_kind: str,
) -> None:
    app = _WorkspaceApp()
    app.custom_server_service = SimpleNamespace(list_servers=lambda: [])
    app.ssh_service = SimpleNamespace(
        check_ssh_agent=lambda: True, list_available_keys=lambda: [],
    )
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def held_turn() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with app.run_test(size=size) as pilot:
        if screen_kind == "help":
            screen = HelpScreen()
        elif screen_kind == "custom_servers":
            screen = CustomServersScreen()
        else:
            screen = KeyManagementScreen()
        await app.switch_screen(screen)
        await pilot.pause()
        assert isinstance(screen, WorkspaceScreen)
        row = screen.query_one("#main-layout")
        content = screen.query_one(".workspace-content")
        original_region = content.region
        original_top_row = screen._compositor.render_strips()[content.region.y].crop(
            content.region.x, content.region.right,
        ).text
        panel = await _open_chat(app, pilot, "f2")
        session = panel._session = ChatSession()
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Unsent draft")
        editor.selection = Selection((0, 0), (0, 6))
        document, selection = editor.document, editor.selection
        panel.run_worker(held_turn(), group="ai_chat")
        await wait_until(started.is_set)
        await pilot.press("f2")
        await pilot.pause()
        # Compare actual compositor paint, not only the content widget's own rows.
        painted_top_row = screen._compositor.render_strips()[content.region.y].crop(
            content.region.x, content.region.right,
        ).text
        assert painted_top_row == original_top_row
        assert content.display and content.region == original_region
        assert panel.parent is row and panel._collapsed and not panel.display
        controls = screen.query_one(WorkspaceControls)
        assert controls.region.y >= screen.query_one(SafeHeader).region.bottom
        assert row.region.y >= controls.region.bottom
        assert content.region.bottom <= screen.query_one(Footer).region.y
        restore = screen.query_one("#workspace_chat", Button)
        end = screen.query_one("#workspace_chat_end", Button)
        assert restore.label.plain == "Restore chat"
        for button in (restore, end):
            assert button.visible and not button.disabled
            assert app.get_widget_at(*button.region.center)[0] is button
        assert panel.is_attached and panel._session is session and not cancelled.is_set()
        assert await _open_chat(app, pilot, "ctrl+g") is panel
        assert editor.document is document and editor.text == "Unsent draft"
        assert editor.selection == selection and not cancelled.is_set()
        app.action_end_chat()
        await wait_until(lambda: not panel.is_attached and cancelled.is_set())


@pytest.mark.asyncio
async def test_end_respects_live_modal_and_operation_holds() -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(100, 30)) as pilot:
        home = app.screen
        panel = await _open_chat(app, pilot, "f2")
        await pilot.press("f2")
        await app.push_screen(ConfirmActionScreen(
            title="Confirm", description="Approve this operation", consequences=[],
            confirm_text="web-1", action_label="Continue",
        ))
        modal = app.screen
        focus = app.focused
        await pilot.press("f3")
        app.action_end_chat()
        assert app.screen is modal and app.focused is focus and panel.is_attached
        assert "End chat" not in {command.title for command in app.get_system_commands(modal)}
        await pilot.press("escape")
        await wait_until(lambda: app.screen is home)
        home.navigation_hold_reason = lambda: "An operation is pending"
        await pilot.press("f3")
        app.action_end_chat()
        assert panel.is_attached
        assert "End chat" not in {command.title for command in app.get_system_commands(home)}
        home.navigation_hold_reason = lambda: None
        await pilot.press("f3")
        await wait_until(lambda: not panel.is_attached)


@pytest.mark.asyncio
async def test_hidden_panel_unmount_on_exit_still_cancels_owned_turn() -> None:
    app = _WorkspaceApp()
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def held_turn() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        panel.run_worker(held_turn(), group="ai_chat")
        await wait_until(started.is_set)
        await pilot.press("f2")
        assert panel._collapsed and panel.is_attached
    assert cancelled.is_set() and not panel.is_attached


@pytest.mark.asyncio
async def test_rapid_toggle_preserves_session_conversation_and_one_shot_flags() -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        session = panel._session = ChatSession()
        panel._remote_conversation_id = "conversation-1"
        panel._session_provider_override = "openai"
        panel._first_run_modal_shown = panel._empty_state_modal_shown = True
        panel._last_debit_micros = 15
        for _ in range(5):
            await pilot.press("f2", "ctrl+g")
        assert app.screen.query_one(ChatPanel) is panel
        assert panel._session is session and panel._remote_conversation_id == "conversation-1"
        assert panel._session_provider_override == "openai"
        assert panel._first_run_modal_shown and panel._empty_state_modal_shown
        assert panel._last_debit_micros == 15


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["f2", "ctrl+g"])
async def test_collapse_restores_same_editor_document_selection_and_scroll(key: str) -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot, key)
        app.notify = Mock()
        editor = panel.query_one("#chat-input", TextArea)
        draft = "\n".join(f"draft line {index}" for index in range(20))
        editor.load_text(draft)
        editor.selection = Selection((16, 2), (17, 6))
        await pilot.pause()
        editor.scroll_to(y=12, animate=False)
        await pilot.pause()
        document, selection, scroll = editor.document, editor.selection, editor.scroll_offset
        await pilot.press(key)
        await pilot.pause()
        assert panel.is_attached and panel._collapsed
        assert not panel.query_one("#chat-inner").display
        assert app.focused is None or app.focused not in panel.walk_children()
        restored = await _open_chat(app, pilot, key)
        assert restored is panel
        assert editor.document is document and editor.text == draft
        assert editor.selection == selection and editor.scroll_offset == scroll
        app.notify.assert_not_called()


@pytest.mark.asyncio
async def test_real_text_turn_finishes_once_while_collapsed(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _WorkspaceApp()
    started, release = asyncio.Event(), asyncio.Event()
    session = ChatSession()

    async def send_message(session: ChatSession, text: str, **kwargs: object) -> dict:
        session.messages.append(ChatMessage(role="user", content=text))
        started.set()
        await release.wait()
        session.messages.append(ChatMessage(role="assistant", content="Reply completed"))
        return {"tokens_used": 7, "estimated_cost": 0.02}

    service = SimpleNamespace(send_message=AsyncMock(side_effect=send_message))
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        panel._session = session
        monkeypatch.setattr(panel, "_get_chat_service", lambda: service)
        monkeypatch.setattr(panel, "_active_provider_name", lambda: "openai")
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Check the server")
        await pilot.press("enter")
        await wait_until(started.is_set)
        editor.load_text("Next unsent draft")
        await pilot.press("f2")
        assert panel.is_attached and panel._collapsed and panel._thinking
        release.set()
        await wait_until(lambda: not panel._thinking)
        assert [message.content for message in session.messages] == [
            "Check the server", "Reply completed",
        ]
        assert panel._total_tokens == 7 and panel._total_cost == 0.02
        assert editor.text == "Next unsent draft"
        service.send_message.assert_awaited_once()
        assert await _open_chat(app, pilot, "ctrl+g") is panel
        await pilot.pause()
        assert "Reply completed" in "".join(
            strip.text
            for widget in panel.query(".chat-message-assistant")
            for strip in widget.render_lines(Region(0, 0, *widget.region.size))
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("end_route", ["key", "palette", "button"])
async def test_end_remains_available_while_hidden_and_cancels_turn(
    monkeypatch: pytest.MonkeyPatch, end_route: str,
) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _Host()
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def held_turn() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        await pilot.press("f2")
        await pilot.pause()
        panel = screen.query_one(ChatPanel)
        panel.run_worker(held_turn(), group="ai_chat")
        await wait_until(started.is_set)
        await pilot.press("f2")
        await pilot.pause()
        assert not panel.display and not cancelled.is_set()
        restore = screen.query_one("#workspace_chat", Button)
        end = screen.query_one("#workspace_chat_end", Button)
        assert restore.label.plain == "Restore chat"
        assert end.visible and not end.disabled
        assert app.get_widget_at(*end.region.center)[0] is end
        if end_route == "key":
            await pilot.press("f3")
        elif end_route == "button":
            await _click(pilot, "#workspace_chat_end")
        else:
            await pilot.press("ctrl+p", *"End chat")
            commands = app.screen.query_one(CommandList)
            await wait_until(lambda: commands.option_count == 1)
            assert str(commands.get_option_at_index(0).hit.text) == "End chat"
            await pilot.press("enter")
            await wait_until(lambda: app.screen is screen)
        await wait_until(lambda: not panel.is_attached and cancelled.is_set())
        assert not screen.query(ChatPanel)
        await pilot.pause()
        assert restore.label.plain == "Open chat"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["openai", "servonaut"])
@pytest.mark.parametrize("target_source", ["selected", "prefix"])
async def test_send_captures_target_before_worker_dispatch(
    monkeypatch: pytest.MonkeyPatch, provider: str, target_source: str,
) -> None:
    app = _WorkspaceApp()
    selected = {"id": "server-1", "name": "web-1", "provider": "custom"}
    captured: list[dict] = []
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        panel._session = ChatSession()
        jobs: list[object] = []
        monkeypatch.setattr(panel, "run_worker", lambda job, **kwargs: jobs.append(job))
        monkeypatch.setattr(panel, "_active_provider_name", lambda: provider)
        app.screen._instance = selected
        app.resolve_instance = lambda token: selected

        async def send_message(session: object, text: str, **kwargs: object) -> dict:
            assert text == "Check disk"
            captured.append(kwargs)
            return {}

        async def consume(provider: object, body: dict):
            captured.append(body)
            yield {"event": "done", "data": {}}

        service = SimpleNamespace(send_message=send_message, save_session=lambda session: None)
        monkeypatch.setattr(panel, "_get_chat_service", lambda: service)
        monkeypatch.setattr(panel, "_servonaut_consume_stream", consume)
        monkeypatch.setattr(panel, "_build_memory_injection", lambda **kwargs: "")
        app.servonaut_provider = object()
        prompt = "@web-1 Check disk" if target_source == "prefix" else "Check disk"
        panel.query_one("#chat-input", TextArea).load_text(prompt)
        panel._send()
        # Reusing a mutable fleet record must not mutate the captured target.
        selected.update(id="server-2", name="db-1")
        await app.push_screen(_ContentScreen())
        await jobs.pop(0)
        assert len(captured) == 1
        if provider == "servonaut":
            assert captured[0]["context"] == {"instance_ids": ["server-1"]}
        else:
            assert captured[0]["instance_id"] == "server-1"
            assert captured[0]["instance_name"] == "web-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["listening", "speaking"])
async def test_collapse_stops_audio_and_late_callbacks_leave_draft_untouched(state: str) -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep this draft")
        app.voice_input_service = Mock(spec=["cancel_recording"])
        app.voice_output_service = Mock(spec=["stop"])
        app.voice_conversation_service = Mock(spec=[
            "set_state_callback", "set_transcript_callback", "set_error_callback",
            "set_stopped_callback", "stop", "reply_finished", "speaking_finished",
        ])
        app.config_manager = SimpleNamespace(
            get=lambda: AppConfig(voice=VoiceConfig(enabled=True, tts_enabled=True)),
        )
        panel._recording = panel._conversation_active = True
        panel._speaking = state == "speaking"
        panel._conversation_state = state
        old_callback = panel._voice_callback(panel._handle_convo_transcript, panel._voice_generation)
        await pilot.press("f2")
        app.voice_input_service.cancel_recording.assert_called_once_with()
        app.voice_output_service.stop.assert_called_once_with()
        app.voice_conversation_service.stop.assert_called_once_with(join=False)
        panel._apply_convo_state("listening")
        panel._handle_convo_transcript("Late transcript")
        panel._render_partial("Late partial")
        panel._notify_convo_reply_done(False)
        assert not panel._conversation_active and not panel._recording and not panel._speaking
        assert editor.text == "Keep this draft" and not panel._thinking
        app.voice_conversation_service.reply_finished.assert_not_called()
        app.voice_conversation_service.speaking_finished.assert_not_called()
        assert not panel._maybe_speak_reply("A late completed reply")
        await _open_chat(app, pilot, "f2")
        assert not panel._conversation_active and not panel._recording
        old_callback("A transcript queued before collapse")
        assert editor.text == "Keep this draft"
        assert not panel._maybe_speak_reply("This old reply finished after restore.")


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["capture", "transcription", "speech", "stream_speech", "conversation"])
async def test_delayed_audio_work_cannot_restart_after_collapse_and_restore(
    monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    app = _WorkspaceApp()
    entered, release = threading.Event(), threading.Event()
    calls: list[str] = []

    def delayed() -> bool:
        entered.set()
        if not release.wait(10):
            raise TimeoutError("test audio operation did not release")
        return True

    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        editor = panel.query_one("#chat-input", TextArea)
        draft = "Typed words visible partial" if operation == "transcription" else "Preserved draft"
        editor.load_text(draft)
        app.config_manager = SimpleNamespace(
            get=lambda: AppConfig(voice=VoiceConfig(enabled=True, tts_enabled=True)),
        )
        service = SimpleNamespace(
            is_available=delayed,
            start_recording=lambda: calls.append("start_capture"),
            cancel_recording=lambda: calls.append("cancel_capture"),
            stop=lambda **kwargs: calls.append("stop"),
            speak=lambda text, **kwargs: calls.append("speak"),
            unavailable_reason=lambda: "",
            set_state_callback=lambda callback: None,
            set_transcript_callback=lambda callback: None,
            set_error_callback=lambda callback: None,
            set_stopped_callback=lambda callback: None,
        )
        app.voice_input_service = app.voice_output_service = app.voice_conversation_service = service
        if operation == "capture":
            panel._starting = True
            job = panel._do_start_recording(service)
        elif operation == "transcription":
            def transcribe(hint: str) -> str:
                delayed()
                return "Late transcription"
            service.stop_and_transcribe = transcribe
            panel._transcribing = True
            job = panel._do_transcribe(service)
        elif operation == "conversation":
            monkeypatch.setattr(panel, "_model_missing_reason", AsyncMock(return_value=""))
            monkeypatch.setattr(panel, "_vad_model_ok", lambda: True)
            service.start = lambda: calls.append("start_conversation")
            job = panel._do_start_conversation(service)
        elif operation == "stream_speech":
            service.begin_utterance = lambda **kwargs: calls.append("begin_speech")
            job = panel._start_turn_speech_session()
        else:
            job = panel._do_speak(service, "Late reply")
        task = asyncio.create_task(job)
        try:
            await wait_until(entered.is_set)
            app.notify = Mock()
            await pilot.press("f2")
            assert panel.is_attached and panel._collapsed
            if operation == "transcription":
                app.notify.assert_called_once_with(
                    "Dictation stopped. Your draft was kept.",
                    severity="information", markup=False,
                )
            await _open_chat(app, pilot, "ctrl+g")
            release.set()
            await task
            assert editor.text == draft
            if operation == "transcription":
                assert app.notify.call_count == 1
            assert not {"start_capture", "start_conversation", "speak", "begin_speech"}.intersection(calls)
            assert not panel._recording and not panel._conversation_active and not panel._speaking
        finally:
            release.set()
            await task


@pytest.mark.asyncio
async def test_speech_queued_before_collapse_cannot_start_after_restore(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _WorkspaceApp()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        app.config_manager = SimpleNamespace(
            get=lambda: AppConfig(voice=VoiceConfig(enabled=True, tts_enabled=True)),
        )
        output = Mock(spec=["stop", "current_epoch", "is_available", "speak"])
        output.current_epoch.return_value = 1
        output.is_available.return_value = True
        app.voice_output_service = output
        jobs: list = []
        monkeypatch.setattr(panel, "run_worker", lambda job, **kwargs: jobs.append(job))
        assert panel._maybe_speak_reply("A reply queued for playback.")
        await pilot.press("f2", "ctrl+g")
        await jobs.pop(0)
        output.is_available.assert_not_called()
        output.speak.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["capture", "conversation"])
async def test_collapse_during_device_open_retires_late_start(
    monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    app = _WorkspaceApp()
    entered, release = threading.Event(), threading.Event()
    state = {"active": False}
    order: list[str] = []

    def start() -> None:
        entered.set()
        if not release.wait(10):
            raise TimeoutError("test device did not release")
        state["active"] = True
        order.append("start")

    def stop(**kwargs: object) -> None:
        state["active"] = False
        order.append("stop")

    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _open_chat(app, pilot, "f2")
        app.config_manager = SimpleNamespace(
            get=lambda: AppConfig(voice=VoiceConfig(enabled=True, tts_enabled=False)),
        )
        service = SimpleNamespace(
            is_available=lambda: True,
            start_recording=start, cancel_recording=stop, start=start, stop=stop,
            set_state_callback=lambda callback: None,
            set_transcript_callback=lambda callback: None,
            set_error_callback=lambda callback: None,
            set_stopped_callback=lambda callback: None,
        )
        app.voice_input_service = app.voice_conversation_service = service
        monkeypatch.setattr(panel, "_model_missing_reason", AsyncMock(return_value=""))
        monkeypatch.setattr(panel, "_vad_model_ok", lambda: True)
        if kind == "capture":
            panel._starting = True
            job = panel._do_start_recording(service)
        else:
            job = panel._do_start_conversation(service)
        task = asyncio.create_task(job)
        try:
            await wait_until(entered.is_set)
            await pilot.press("f2")
            await _open_chat(app, pilot, "ctrl+g")
            # Another audio request cannot take over a device still opening.
            if kind == "capture":
                panel._toggle_recording()
            else:
                panel._toggle_conversation()
            release.set()
            await task
            assert not state["active"] and order[-2:] == ["start", "stop"]
            assert not panel._recording and not panel._conversation_active
        finally:
            release.set()
            await task


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["end", "hidden_exit"])
async def test_unmount_during_device_open_cannot_leave_a_hot_microphone(route: str) -> None:
    app = _WorkspaceApp()
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()
    state = {"active": False}
    order: list[str] = []

    def start() -> None:
        entered.set()
        if not release.wait(10):
            raise TimeoutError("test device did not release")
        state["active"] = True
        order.append("late_start")
        returned.set()

    def cancel() -> None:
        state["active"] = False
        order.append("cancel")

    app.config_manager = SimpleNamespace(
        get=lambda: AppConfig(voice=VoiceConfig(enabled=True)),
    )
    app.voice_input_service = SimpleNamespace(
        is_available=lambda: True, start_recording=start, cancel_recording=cancel,
    )
    try:
        async with app.run_test(size=(160, 50)) as pilot:
            panel = await _open_chat(app, pilot, "f2")
            panel._toggle_recording()
            await wait_until(entered.is_set)
            if route == "end":
                # This existing Close route also exercises the unchanged baseline.
                assert await pilot.click(panel.query_one("#btn-chat-close"))
                await wait_until(lambda: not panel.is_attached)
            else:
                # Exercise native hidden-node shutdown independently of toggle code.
                panel.display = False
                assert not panel.display
        assert not panel.is_attached
        release.set()
        await wait_until(returned.is_set)
        assert not state["active"] and order[-2:] == ["late_start", "cancel"]
    finally:
        release.set()
        await wait_until(returned.is_set)


@pytest.mark.asyncio
async def test_collapsed_turn_retains_existing_push_pop_lifetime() -> None:
    app = _WorkspaceApp()
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def held_turn() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with app.run_test(size=(100, 30)) as pilot:
        home = app.screen
        panel = await _open_chat(app, pilot, "f2")
        panel.run_worker(held_turn(), group="ai_chat")
        await wait_until(started.is_set)
        await pilot.press("f2")
        adjacent = _ContentScreen()
        await app.push_screen(adjacent)
        assert not adjacent.query(ChatPanel)
        assert home.query_one(ChatPanel) is panel and not cancelled.is_set()
        app.pop_screen()
        await wait_until(lambda: app.screen is home)
        assert panel.is_attached and panel._collapsed and not cancelled.is_set()
        app.switch_screen(_ContentScreen())
        await wait_until(lambda: not panel.is_attached and cancelled.is_set())


@pytest.mark.asyncio
@pytest.mark.parametrize("route,button_id", [
    ("held", "btn-chat-close"), ("stale", "btn-chat-close"),
    ("stale", "btn-chat-end"),
])
async def test_end_buttons_respect_operation_hold_and_active_screen(
    route: str, button_id: str,
) -> None:
    app = _WorkspaceApp()
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def held_turn() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with app.run_test(size=(160, 50)) as pilot:
        if button_id == "btn-chat-end":
            await app.switch_screen(_UnmigratedScreen())
        home = app.screen
        panel = await _open_chat(app, pilot, "f2")
        session = panel._session = ChatSession()
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("Keep the original draft")
        editor.selection = Selection((0, 5), (0, 13))
        document, selection = editor.document, editor.selection
        panel.run_worker(held_turn(), group="ai_chat")
        await wait_until(started.is_set)
        if button_id == "btn-chat-end":
            await pilot.press("f2")
            await pilot.pause()
            assert panel._collapsed and panel.has_class("--compact-collapsed")
        collapsed = panel._collapsed
        end = panel.query_one(f"#{button_id}", Button)

        if route == "held":
            home.navigation_hold_reason = lambda: "An operation is pending"
            assert await pilot.click(end)
            await pilot.pause()
        else:
            adjacent = _ContentScreen()
            await app.push_screen(adjacent)
            other = await _open_chat(app, pilot, "f2")
            other_editor = other.query_one("#chat-input", TextArea)
            other_editor.load_text("Keep the adjacent draft")
            other_document = other_editor.document
            # Deliver the native button message after its owner lost the screen.
            # Calling the active App action without an ownership gate would end
            # the adjacent panel instead of rejecting this stale event.
            assert panel.post_message(Button.Pressed(end))
            await pilot.pause()
            assert other.is_attached and not other._collapsed
            assert adjacent.query_one(ChatPanel) is other
            assert other_editor.document is other_document
            assert other_editor.text == "Keep the adjacent draft"
            assert app.focused is other_editor and app.screen is adjacent
            app.pop_screen()
            await wait_until(lambda: app.screen is home and not other.is_attached)

        assert home.query_one(ChatPanel) is panel
        assert panel.is_attached and panel._collapsed is collapsed and not cancelled.is_set()
        assert panel._session is session
        assert editor.document is document and editor.selection == selection
        assert editor.text == "Keep the original draft"
        if route == "held":
            home.navigation_hold_reason = lambda: None
        await wait_until(lambda: not end.has_class("-active"))
        assert await pilot.click(end)
        await wait_until(lambda: not panel.is_attached and cancelled.is_set())
        assert not home.query(ChatPanel) and app._exception is None
