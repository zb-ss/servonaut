"""UI wiring tests for hands-free conversation mode.

Every decision the wiring makes lives in a pure function —
:func:`resolve_conversation_start`, :func:`resolve_transcript_action`,
:func:`is_modal_blocking`, the glyph/status mappers — precisely so this
file can pin the behaviour without mounting a Textual app, matching the
conventions of the neighbouring voice test files. The two safety
guarantees (a transcript is never delivered while a modal is up; the
typed-confirmation flows are untouched) get dedicated tests.
"""

from __future__ import annotations

import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.screen import ModalScreen

from servonaut.config.schema import (
    AppConfig,
    CONVERSATION_IDLE_SECONDS_MAX,
    CONVERSATION_IDLE_SECONDS_MIN,
    VAD_SILENCE_MS_MAX,
    VAD_SILENCE_MS_MIN,
    VoiceConfig,
)
from servonaut.screens.settings.base import ValidationError
from servonaut.screens.settings.panels.voice import (
    VoicePanel,
    parse_conversation_idle_seconds,
    parse_vad_silence_ms,
    vad_model_action,
)
from servonaut.widgets.chat_panel import (
    ChatPanel,
    _CONVO_IDLE,
    _CONVO_STATE_GLYPHS,
    _CONVO_TOGGLE_KEY,
    conversation_button_label,
    conversation_status_markup,
    is_modal_blocking,
    resolve_conversation_start,
    resolve_transcript_action,
)


# ---------------------------------------------------------------------------
# Helpers (chat panel without a mounted app — mirrors test_voice_tts_ui)
# ---------------------------------------------------------------------------


def _build_panel() -> ChatPanel:
    """Construct a :class:`ChatPanel` without Widget.__init__/app context."""
    panel = ChatPanel.__new__(ChatPanel)
    panel._stale_cache = {}
    panel._upstream_failures = []
    panel._session_provider_override = None
    panel._last_fallback_used = False
    panel._last_soft_capped = False
    panel._last_hard_capped = False
    panel._remote_conversation_id = None
    panel._thinking = False
    panel._total_tokens = 0
    panel._total_cost = 0.0
    panel._model = ""
    panel._session = None
    panel._turn_tool_calls = 0
    return panel


def _attach_app(panel: ChatPanel, *, voice: VoiceConfig) -> MagicMock:
    """Return a mocked ``app`` (installed via patch by each test)."""
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.config_manager.get.return_value = AppConfig(voice=voice)
    return app


def _app_property(app: MagicMock):
    """Context manager patching ``ChatPanel.app`` to *app*."""
    return patch.object(ChatPanel, "app", property(lambda _self: app))


def _modal_stub() -> MagicMock:
    """A stand-in that passes the ``isinstance(_, ModalScreen)`` check."""
    return MagicMock(spec=ModalScreen)


# ---------------------------------------------------------------------------
# Pure decisions — start readiness
# ---------------------------------------------------------------------------


class TestResolveConversationStart:

    def _ready(self, **overrides) -> str:
        kwargs = dict(
            voice_enabled=True,
            input_available=True,
            input_reason="",
            stt_model_ok=True,
            vad_model_ok=True,
            output_available=True,
            output_reason="",
        )
        kwargs.update(overrides)
        return resolve_conversation_start(**kwargs)

    def test_everything_ready_clears_the_start(self):
        assert self._ready() == ""

    def test_disabled_voice_points_at_settings(self):
        message = self._ready(voice_enabled=False)
        assert "switched off" in message
        assert "Settings" in message

    def test_unavailable_input_reports_the_service_reason(self):
        message = self._ready(
            input_available=False, input_reason="No microphone was found"
        )
        assert message.startswith("No microphone was found")
        assert "Settings" in message

    def test_unavailable_input_without_a_reason_still_explains(self):
        message = self._ready(input_available=False, input_reason="")
        assert "unavailable" in message
        assert "Settings" in message

    def test_missing_speech_model_is_named(self):
        assert "speech model" in self._ready(stt_model_ok=False)

    def test_missing_vad_model_is_named(self):
        assert "voice-detection model" in self._ready(vad_model_ok=False)

    def test_unavailable_output_reports_the_service_reason(self):
        message = self._ready(
            output_available=False, output_reason="No output device"
        )
        assert message.startswith("No output device")

    def test_tts_off_waives_the_output_requirement(self):
        """Spoken replies off means playback never runs: the loop is a
        hands-free dictation cycle and must not demand the synthesis
        stack it will never use."""
        assert self._ready(
            output_available=False,
            output_reason="No output device",
            tts_enabled=False,
        ) == ""

    def test_tts_on_still_requires_the_output_stack(self):
        message = self._ready(output_available=False, tts_enabled=True)
        assert "Speech output" in message

    def test_the_first_unmet_requirement_wins(self):
        """Capture before detection before playback — one message, the
        first fix, mirroring the Settings readiness card."""
        message = self._ready(
            input_available=False,
            input_reason="mic gone",
            vad_model_ok=False,
            output_available=False,
        )
        assert message.startswith("mic gone")


# ---------------------------------------------------------------------------
# Pure decisions — transcript delivery matrix
# ---------------------------------------------------------------------------


class TestResolveTranscriptAction:

    def test_clear_path_sends(self):
        assert resolve_transcript_action(
            "restart nginx", modal_blocking=False, thinking=False,
        ) == "send"

    @pytest.mark.parametrize("text", [None, "", "   ", "\n\t"])
    def test_empty_never_sends(self, text):
        assert resolve_transcript_action(
            text, modal_blocking=False, thinking=False,
        ) == "drop_empty"

    def test_a_modal_on_the_stack_drops_the_utterance(self):
        assert resolve_transcript_action(
            "yes do it", modal_blocking=True, thinking=False,
        ) == "drop_modal"

    def test_a_streaming_turn_drops_the_utterance(self):
        assert resolve_transcript_action(
            "and another thing", modal_blocking=False, thinking=True,
        ) == "drop_busy"

    def test_the_modal_rule_outranks_the_busy_rule(self):
        assert resolve_transcript_action(
            "yes", modal_blocking=True, thinking=True,
        ) == "drop_modal"


# ---------------------------------------------------------------------------
# Pure decisions — modal detection
# ---------------------------------------------------------------------------


class TestIsModalBlocking:

    def test_an_empty_stack_does_not_block(self):
        assert is_modal_blocking([]) is False

    def test_plain_screens_do_not_block(self):
        assert is_modal_blocking([object(), object()]) is False

    def test_any_modal_anywhere_in_the_stack_blocks(self):
        assert is_modal_blocking([object(), _modal_stub(), object()]) is True

    def test_a_modal_subclass_blocks_without_an_allowlist(self):
        """Future confirmation modals must be covered automatically."""

        class FutureConfirmModal(ModalScreen):
            pass

        modal = FutureConfirmModal.__new__(FutureConfirmModal)
        assert is_modal_blocking([object(), modal]) is True

    def test_an_unreadable_stack_fails_safe(self):
        """If the stack cannot be inspected, block — never send blind."""
        assert is_modal_blocking(None) is True

    def test_the_reusable_destructive_confirm_is_covered(self):
        """ConfirmActionScreen is the app-wide destructive-operation
        confirm (terminate instance, delete server, DNS record, bucket…).
        It MUST be a ModalScreen: the isinstance predicate is how the
        conversation loop learns a confirmation is up, and a plain-Screen
        confirm would let a spoken utterance auto-send mid-confirmation."""
        from servonaut.screens.confirm_action import ConfirmActionScreen

        assert issubclass(ConfirmActionScreen, ModalScreen)
        confirm = ConfirmActionScreen.__new__(ConfirmActionScreen)
        assert is_modal_blocking([object(), confirm]) is True


# ---------------------------------------------------------------------------
# Glyphs, bindings, status wording
# ---------------------------------------------------------------------------


class TestGlyphsAndBindings:

    def test_no_conversation_glyph_carries_a_vs16_selector(self):
        assert "\ufe0f" not in _CONVO_IDLE
        for glyph in _CONVO_STATE_GLYPHS.values():
            assert "\ufe0f" not in glyph

    def test_button_label_maps_every_state(self):
        assert conversation_button_label("idle") == _CONVO_IDLE
        for state, glyph in _CONVO_STATE_GLYPHS.items():
            assert conversation_button_label(state) == glyph

    def test_an_unknown_state_falls_back_to_the_idle_glyph(self):
        assert conversation_button_label("wat") == _CONVO_IDLE

    def test_idle_renders_no_status_slot(self):
        assert conversation_status_markup("idle") == ""

    def test_listening_names_the_stop_key(self):
        assert _CONVO_TOGGLE_KEY in conversation_status_markup("listening")

    def test_speaking_names_the_interrupt_key(self):
        assert _CONVO_TOGGLE_KEY in conversation_status_markup("speaking")

    def test_the_toggle_binding_is_priority_ctrl_n(self):
        binding = next(
            b for b in ChatPanel.BINDINGS if b.action == "toggle_conversation"
        )
        assert binding.key == _CONVO_TOGGLE_KEY == "ctrl+n"
        assert binding.priority is True

    def test_the_escape_binding_exists_for_the_interrupt(self):
        binding = next(
            b for b in ChatPanel.BINDINGS if b.action == "convo_interrupt"
        )
        assert binding.key == "escape"

    def test_escape_is_claimed_only_while_conversation_speaks(self):
        panel = _build_panel()
        assert panel.check_action("convo_interrupt", ()) is False
        panel._conversation_active = True
        panel._conversation_state = "listening"
        assert panel.check_action("convo_interrupt", ()) is False
        panel._conversation_state = "speaking"
        assert panel.check_action("convo_interrupt", ()) is True

    def test_other_actions_stay_unaffected_by_the_gate(self):
        panel = _build_panel()
        assert panel.check_action("stop_speaking", ()) is True
        assert panel.check_action("toggle_conversation", ()) is True


# ---------------------------------------------------------------------------
# Toggle flow
# ---------------------------------------------------------------------------


class TestToggleConversation:

    def _panel(self, *, voice=None, service="default"):
        panel = _build_panel()
        app = _attach_app(panel, voice=voice or VoiceConfig(enabled=True))
        if service == "default":
            service = MagicMock()
        app.voice_conversation_service = service
        panel.run_worker = MagicMock()
        panel._convo_call = MagicMock()
        panel._do_start_conversation = MagicMock(return_value="job")
        return panel, app

    def test_a_missing_controller_is_reported(self):
        panel, app = self._panel(service=None)
        with _app_property(app):
            panel._toggle_conversation()
        assert app.notify.call_args.kwargs["markup"] is False
        panel.run_worker.assert_not_called()

    def test_starting_dispatches_on_the_conversation_group(self):
        panel, app = self._panel()
        with _app_property(app):
            panel._toggle_conversation()
        panel.run_worker.assert_called_once()
        assert panel.run_worker.call_args.kwargs["group"] == "voice_convo"

    def test_disabled_voice_refuses_with_a_pointer_at_settings(self):
        panel, app = self._panel(voice=VoiceConfig(enabled=False))
        with _app_property(app):
            panel._toggle_conversation()
        panel.run_worker.assert_not_called()
        message = app.notify.call_args[0][0]
        assert "Settings" in message

    def test_a_dictation_in_flight_refuses_the_start(self):
        panel, app = self._panel()
        panel._recording = True
        with _app_property(app):
            panel._toggle_conversation()
        panel.run_worker.assert_not_called()
        app.notify.assert_called_once()

    def test_a_second_toggle_while_listening_stops_the_session(self):
        panel, app = self._panel()
        panel._conversation_active = True
        panel._conversation_state = "listening"
        with _app_property(app):
            panel._toggle_conversation()
        panel._convo_call.assert_called_once_with("stop")
        panel.run_worker.assert_not_called()

    def test_a_toggle_while_speaking_interrupts_instead(self):
        panel, app = self._panel()
        panel._conversation_active = True
        panel._conversation_state = "speaking"
        with _app_property(app):
            panel._toggle_conversation()
        panel._convo_call.assert_called_once_with("interrupt")

    def test_the_action_routes_to_the_toggle(self):
        panel = _build_panel()
        panel._toggle_conversation = MagicMock()
        panel.action_toggle_conversation()
        panel._toggle_conversation.assert_called_once()

    def test_the_escape_action_routes_to_interrupt(self):
        panel = _build_panel()
        panel._convo_call = MagicMock()
        panel.action_convo_interrupt()
        panel._convo_call.assert_called_once_with("interrupt")

    def test_push_to_talk_refuses_while_the_loop_owns_the_mic(self):
        panel = _build_panel()
        panel._conversation_active = True
        app = _attach_app(panel, voice=VoiceConfig(enabled=True))
        app.voice_input_service = MagicMock()
        panel.run_worker = MagicMock()
        with _app_property(app):
            panel._toggle_recording()
        panel.run_worker.assert_not_called()
        message = app.notify.call_args[0][0]
        assert "Conversation mode" in message
        assert app.notify.call_args.kwargs["markup"] is False


# ---------------------------------------------------------------------------
# Start worker
# ---------------------------------------------------------------------------


class TestDoStartConversation:

    def _panel(self, *, voice=None):
        panel = _build_panel()
        app = _attach_app(panel, voice=voice or VoiceConfig(enabled=True))
        input_service = MagicMock()
        input_service.is_available.return_value = True
        output_service = MagicMock()
        output_service.is_available.return_value = True
        app.voice_input_service = input_service
        app.voice_output_service = output_service
        panel._model_missing_reason = AsyncMock(return_value="")
        panel._vad_model_ok = MagicMock(return_value=True)
        panel._sync_convo_button = MagicMock()
        panel._update_stats = MagicMock()
        return panel, app

    @pytest.mark.asyncio
    async def test_a_ready_stack_starts_and_registers_callbacks(self):
        panel, app = self._panel()
        service = MagicMock()
        with _app_property(app):
            await panel._do_start_conversation(service)
        service.set_state_callback.assert_called_once()
        service.set_transcript_callback.assert_called_once()
        service.set_error_callback.assert_called_once()
        service.set_stopped_callback.assert_called_once()
        service.start.assert_called_once()
        assert panel._conversation_active is True
        assert panel._conversation_state == "listening"
        kwargs = app.notify.call_args.kwargs
        assert kwargs["markup"] is False

    @pytest.mark.asyncio
    async def test_a_missing_vad_model_blocks_the_start_with_the_reason(self):
        panel, app = self._panel()
        panel._vad_model_ok = MagicMock(return_value=False)
        service = MagicMock()
        with _app_property(app):
            await panel._do_start_conversation(service)
        service.start.assert_not_called()
        message = app.notify.call_args[0][0]
        assert "voice-detection model" in message
        assert app.notify.call_args.kwargs["markup"] is False
        assert panel._conversation_active is False

    @pytest.mark.asyncio
    async def test_an_unavailable_output_blocks_the_start_when_tts_is_on(self):
        panel, app = self._panel(
            voice=VoiceConfig(enabled=True, tts_enabled=True)
        )
        app.voice_output_service.is_available.return_value = False
        app.voice_output_service.unavailable_reason.return_value = (
            "No output device was found"
        )
        service = MagicMock()
        with _app_property(app):
            await panel._do_start_conversation(service)
        service.start.assert_not_called()
        assert "No output device" in app.notify.call_args[0][0]

    @pytest.mark.asyncio
    async def test_tts_off_skips_the_output_probe_and_starts(self):
        """With spoken replies off, the loop is a dictation cycle: the
        synthesis stack is never probed, never required."""
        panel, app = self._panel()  # tts_enabled defaults to False
        app.voice_output_service.is_available.return_value = False
        service = MagicMock()
        with _app_property(app):
            await panel._do_start_conversation(service)
        service.start.assert_called_once()
        app.voice_output_service.is_available.assert_not_called()
        assert panel._conversation_active is True

    @pytest.mark.asyncio
    async def test_a_cancelled_start_retires_the_orphaned_loop(self):
        """The panel can go away while start() is still running on its
        executor thread; the thread finishes the start and opens a mic
        nobody owns. The cancellation path must hand the orphan to the
        abort thread, which stops it."""
        import asyncio as _asyncio
        import time as _time

        panel, app = self._panel()
        service = MagicMock()
        service.start.side_effect = _asyncio.CancelledError()
        with _app_property(app):
            with pytest.raises(_asyncio.CancelledError):
                await panel._do_start_conversation(service)
        deadline = _time.monotonic() + 5.0
        while _time.monotonic() < deadline and not service.stop.called:
            _time.sleep(0.01)
        service.stop.assert_called_once()
        assert panel._conversation_active is False

    @pytest.mark.asyncio
    async def test_a_start_failure_is_an_error_toast(self):
        panel, app = self._panel()
        service = MagicMock()
        service.start.side_effect = RuntimeError("mic vanished mid-open")
        with _app_property(app):
            await panel._do_start_conversation(service)
        kwargs = app.notify.call_args.kwargs
        assert kwargs["severity"] == "error"
        assert kwargs["markup"] is False
        assert panel._conversation_active is False


# ---------------------------------------------------------------------------
# Transcript delivery — including the two safety guarantees
# ---------------------------------------------------------------------------


class TestTranscriptDelivery:

    def _panel(self, *, stack=None, thinking=False):
        panel = _build_panel()
        panel._thinking = thinking
        panel._conversation_active = True
        panel._conversation_state = "thinking"
        app = _attach_app(panel, voice=VoiceConfig(enabled=True))
        app.screen_stack = stack if stack is not None else []
        app.push_screen = MagicMock()
        # A successful _send flips _thinking — the delivery handler reads
        # it back to tell "turn dispatched" from "send bailed silently".
        panel._send = MagicMock(
            side_effect=lambda: setattr(panel, "_thinking", True)
        )
        panel._convo_call = MagicMock()
        inp = MagicMock()
        panel.query_one = MagicMock(return_value=inp)
        return panel, app, inp

    def test_a_clear_transcript_lands_in_the_box_and_sends(self):
        panel, app, inp = self._panel()
        with _app_property(app):
            panel._handle_convo_transcript("restart nginx on web-1")
        inp.load_text.assert_called_once_with("restart nginx on web-1")
        panel._send.assert_called_once()
        panel._convo_call.assert_not_called()

    def test_demo_mode_scrubs_the_transcript_before_rendering(self):
        panel, app, inp = self._panel()
        app.demo_mode = True
        app.redaction_service = MagicMock()
        app.redaction_service.scrub_stream = lambda text: "scrubbed"
        with _app_property(app):
            panel._handle_convo_transcript("something sensitive")
        inp.load_text.assert_called_once_with("scrubbed")

    # -- SAFETY (a): a modal on the stack means the transcript is dropped

    def test_a_modal_on_the_stack_drops_the_transcript_entirely(self):
        panel, app, inp = self._panel(stack=[object(), _modal_stub()])
        with _app_property(app):
            panel._handle_convo_transcript("yes run it")
        # Never delivered: not into the box, not into the send path.
        inp.load_text.assert_not_called()
        panel._send.assert_not_called()
        # One notice, no markup; listening resumes.
        app.notify.assert_called_once()
        assert app.notify.call_args.kwargs["markup"] is False
        panel._convo_call.assert_called_once_with("reply_finished")

    # -- SAFETY (b): the typed-confirmation flows are untouched

    def test_the_confirmation_modal_itself_is_never_touched(self):
        """The suppression must not interact with the modal in any way —
        no attribute access that calls it, no dismissal, no new screens
        pushed. The typed-RUN keyboard flow stays exactly as it was."""
        modal = _modal_stub()
        panel, app, inp = self._panel(stack=[object(), modal])
        with _app_property(app):
            panel._handle_convo_transcript("RUN")
        assert modal.mock_calls == []
        app.push_screen.assert_not_called()
        panel._send.assert_not_called()

    def test_a_streaming_turn_drops_and_leaves_the_machine_alone(self):
        """drop_busy must NOT resume listening: the in-flight turn owns
        the loop, and reopening the mic under its spoken reply would
        break half-duplex."""
        panel, app, inp = self._panel(thinking=True)
        with _app_property(app):
            panel._handle_convo_transcript("another thought")
        panel._send.assert_not_called()
        panel._convo_call.assert_not_called()
        app.notify.assert_called_once()
        assert app.notify.call_args.kwargs["markup"] is False

    def test_an_empty_transcript_resumes_listening_silently(self):
        panel, app, inp = self._panel()
        with _app_property(app):
            panel._handle_convo_transcript("   ")
        panel._send.assert_not_called()
        app.notify.assert_not_called()
        panel._convo_call.assert_called_once_with("reply_finished")

    def test_an_unreadable_screen_stack_fails_safe(self):
        panel, app, inp = self._panel()
        # A stack that cannot be iterated must read as blocked.
        app.screen_stack = None
        with _app_property(app):
            panel._handle_convo_transcript("send this")
        panel._send.assert_not_called()
        panel._convo_call.assert_called_once_with("reply_finished")

    def test_a_send_that_bails_silently_still_resumes_listening(self):
        """_send has silent early-outs (input box gone, demo-mode scrub
        emptied the text). No turn started means no completion hook will
        ever fire reply_finished — the handler must do it, or the loop is
        stranded in THINKING with the mic closed."""
        panel, app, inp = self._panel()
        panel._send = MagicMock()  # bails: never sets _thinking
        with _app_property(app):
            panel._handle_convo_transcript("send this")
        panel._send.assert_called_once()
        panel._convo_call.assert_called_once_with("reply_finished")

    def test_a_raising_transcript_render_still_resumes_listening(self):
        """A demo-mode scrub (or the input box) raising mid-render must
        not strand the loop: nothing was sent, so the handler owns the
        resume — and the raw transcript must never reach the box."""
        panel, app, inp = self._panel()
        app.demo_mode = True
        app.redaction_service = MagicMock()
        app.redaction_service.scrub_stream = MagicMock(
            side_effect=RuntimeError("redactor died"),
        )
        with _app_property(app):
            panel._handle_convo_transcript("something sensitive")
        inp.load_text.assert_not_called()  # fail-closed: no raw render
        panel._convo_call.assert_called_once_with("reply_finished")

    def test_a_raising_send_still_resumes_listening(self):
        panel, app, inp = self._panel()
        panel._send = MagicMock(side_effect=RuntimeError("dispatch died"))
        with _app_property(app):
            panel._handle_convo_transcript("send this")
        panel._send.assert_called_once()
        panel._convo_call.assert_called_once_with("reply_finished")


# ---------------------------------------------------------------------------
# Loop wiring — send, reply completion, speaking bridge
# ---------------------------------------------------------------------------


class TestLoopWiring:

    def test_send_closes_the_mic_via_reply_started(self):
        panel = _build_panel()
        panel._conversation_active = True
        panel._interrupt_speech = MagicMock()
        panel._show_thinking = MagicMock()
        panel._convo_call = MagicMock()
        panel.run_worker = MagicMock()
        panel._do_send = MagicMock(return_value="job")
        inp = MagicMock()
        inp.text = "typed while listening"
        panel.query_one = MagicMock(return_value=inp)
        panel._send()
        panel._convo_call.assert_called_once_with("reply_started")

    def test_a_plain_send_does_not_touch_the_loop(self):
        panel = _build_panel()
        panel._interrupt_speech = MagicMock()
        panel._show_thinking = MagicMock()
        panel._convo_call = MagicMock()
        panel.run_worker = MagicMock()
        panel._do_send = MagicMock(return_value="job")
        inp = MagicMock()
        inp.text = "hello"
        panel.query_one = MagicMock(return_value=inp)
        panel._send()
        panel._convo_call.assert_not_called()

    def test_reply_done_without_speech_resumes_listening(self):
        panel = _build_panel()
        panel._conversation_active = True
        panel._convo_call = MagicMock()
        panel._notify_convo_reply_done(False)
        panel._convo_call.assert_called_once_with("reply_finished")

    def test_reply_done_with_speech_defers_to_the_speak_worker(self):
        panel = _build_panel()
        panel._conversation_active = True
        panel._convo_call = MagicMock()
        panel._notify_convo_reply_done(True)
        panel._convo_call.assert_not_called()

    def test_reply_done_outside_a_conversation_is_a_noop(self):
        panel = _build_panel()
        panel._convo_call = MagicMock()
        panel._notify_convo_reply_done(False)
        panel._convo_call.assert_not_called()

    def test_finalise_bridges_an_unspoken_turn_back_to_listening(self):
        from servonaut.services.chat_service import ChatMessage, ChatSession

        panel = _build_panel()
        panel._conversation_active = True
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._maybe_speak_reply = MagicMock(return_value=False)
        panel._notify_convo_reply_done = MagicMock()
        panel._session = ChatSession(
            id="s1", title="already titled",
            messages=[ChatMessage(role="user", content="hi")],
        )
        panel._finalise_servonaut_turn(MagicMock(), "The disk is fine.")
        panel._notify_convo_reply_done.assert_called_once_with(False)

    def test_finalise_defers_to_playback_when_the_reply_is_spoken(self):
        from servonaut.services.chat_service import ChatMessage, ChatSession

        panel = _build_panel()
        panel._conversation_active = True
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._maybe_speak_reply = MagicMock(return_value=True)
        panel._notify_convo_reply_done = MagicMock()
        panel._session = ChatSession(
            id="s1", title="already titled",
            messages=[ChatMessage(role="user", content="hi")],
        )
        panel._finalise_servonaut_turn(MagicMock(), "The disk is fine.")
        panel._notify_convo_reply_done.assert_called_once_with(True)

    @pytest.mark.asyncio
    async def test_a_cancelled_servonaut_send_settles_the_turn(self):
        """CancelledError escapes the streaming body (it must — the
        worker is being cancelled), but the wrapper's finally still has
        to clear the typed-send guard, drop the spinner, and resume
        listening; otherwise the loop is stranded in THINKING with the
        mic closed. In-app trigger: loading a previous conversation
        dispatches an exclusive ai_chat worker that cancels the send."""
        panel = _build_panel()
        panel._thinking = True
        panel._conversation_active = True
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._notify_convo_reply_done = MagicMock()
        panel._run_servonaut_turn = AsyncMock(
            side_effect=asyncio.CancelledError()
        )
        with pytest.raises(asyncio.CancelledError):
            await panel._do_send_servonaut("hi")
        assert panel._thinking is False
        panel._hide_thinking.assert_called_once()
        panel._notify_convo_reply_done.assert_called_once_with(False)

    @pytest.mark.asyncio
    async def test_a_settled_servonaut_send_is_not_double_finalised(self):
        """When the turn settles normally (_thinking already cleared by
        the streaming body), the wrapper's finally must stay out of it —
        a second reply_finished could reopen the mic under playback."""
        panel = _build_panel()
        panel._thinking = True
        panel._conversation_active = True
        panel._hide_thinking = MagicMock()
        panel._notify_convo_reply_done = MagicMock()

        async def _settles(_text):
            panel._thinking = False

        panel._run_servonaut_turn = _settles
        await panel._do_send_servonaut("hi")
        panel._hide_thinking.assert_not_called()
        panel._notify_convo_reply_done.assert_not_called()

    @pytest.mark.asyncio
    async def test_generic_send_bridges_the_turn_end(self):
        from servonaut.services.chat_service import ChatSession

        panel = _build_panel()
        panel._conversation_active = True
        panel._active_provider_name = MagicMock(return_value="openai")
        panel._resolve_active_instance = MagicMock(return_value=(None, "hi"))
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._speak_last_reply = MagicMock(return_value=False)
        panel._notify_convo_reply_done = MagicMock()
        chat_service = MagicMock()
        chat_service.send_message = AsyncMock(return_value={})
        panel._get_chat_service = MagicMock(return_value=chat_service)
        panel._session = ChatSession(id="s1", title="t", messages=[])
        await panel._do_send("hi")
        panel._notify_convo_reply_done.assert_called_once_with(False)


class TestConvoMarshal:
    """Thread routing for service callbacks -> UI-thread handlers."""

    def test_a_service_thread_marshals_through_the_app(self):
        panel = _build_panel()
        app = MagicMock()
        app._thread_id = threading.get_ident() + 1  # not this thread
        handler = MagicMock()
        with _app_property(app):
            panel._convo_marshal(handler, "x")
        app.call_from_thread.assert_called_once_with(handler, "x")
        handler.assert_not_called()

    def test_the_ui_thread_runs_the_handler_directly(self):
        panel = _build_panel()
        app = MagicMock()
        app._thread_id = threading.get_ident()
        handler = MagicMock()
        with _app_property(app):
            panel._convo_marshal(handler, "x")
        handler.assert_called_once_with("x")
        app.call_from_thread.assert_not_called()

    def test_a_failing_marshalled_handler_is_not_retried(self):
        """call_from_thread re-raises exceptions the handler raised AFTER
        running (possibly partway, with side effects) on the UI thread; a
        blanket catch-and-retry would run it a second time — worst case
        the same transcript dispatched as two chat turns."""
        panel = _build_panel()
        app = MagicMock()
        app._thread_id = threading.get_ident() + 1
        app.call_from_thread.side_effect = RuntimeError("handler blew up")
        handler = MagicMock()
        with _app_property(app):
            panel._convo_marshal(handler, "x")
        handler.assert_not_called()

    def test_no_app_at_all_degrades_to_a_direct_guarded_call(self):
        panel = _build_panel()
        handler = MagicMock()

        def _no_app(_self):
            raise RuntimeError("no active app")

        # Deterministic no-app: another test's app context must not leak
        # into this one through Textual's ambient active-app lookup.
        with patch.object(ChatPanel, "app", property(_no_app)):
            panel._convo_marshal(handler, "x")
        handler.assert_called_once_with("x")

    def test_a_direct_handler_failure_is_swallowed(self):
        panel = _build_panel()
        handler = MagicMock(side_effect=RuntimeError("widget gone"))
        panel._convo_marshal(handler)  # must not raise


class TestDoSpeakBridge:

    def _panel(self, *, active=True):
        panel = _build_panel()
        panel._conversation_active = active
        panel._update_stats = MagicMock()
        panel._convo_call = MagicMock()
        return panel

    @pytest.mark.asyncio
    async def test_speaking_started_fires_before_the_first_audio(self):
        panel = self._panel()
        convo = MagicMock()
        panel._conversation_service = MagicMock(return_value=convo)
        order = []
        convo.speaking_started.side_effect = lambda: order.append("started")
        service = MagicMock()
        service.is_available.return_value = True
        service.speak.side_effect = lambda _t: order.append("speak")
        await panel._do_speak(service, "Hello")
        assert order == ["started", "speak"]
        panel._convo_call.assert_called_once_with("speaking_finished")

    @pytest.mark.asyncio
    async def test_no_conversation_means_no_bridge_calls(self):
        panel = self._panel(active=False)
        panel._conversation_service = MagicMock()
        service = MagicMock()
        service.is_available.return_value = True
        await panel._do_speak(service, "Hello")
        panel._conversation_service.assert_not_called()
        panel._convo_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_an_unavailable_speaker_resumes_listening(self):
        panel = self._panel()
        panel._notify_convo_reply_done = MagicMock()
        service = MagicMock()
        service.is_available.return_value = False
        service.unavailable_reason.return_value = "no model"
        await panel._do_speak(service, "Hello")
        panel._notify_convo_reply_done.assert_called_once_with(False)
        panel._convo_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_superseded_worker_does_not_fire_speaking_finished(self):
        panel = self._panel()
        convo = MagicMock()
        panel._conversation_service = MagicMock(return_value=convo)
        service = MagicMock()
        service.is_available.return_value = True

        def _speak_and_supersede(_text):
            panel._speak_seq += 1

        service.speak.side_effect = _speak_and_supersede
        await panel._do_speak(service, "Hello")
        panel._convo_call.assert_not_called()


# ---------------------------------------------------------------------------
# Callback handlers — state, stopped, error, teardown, autostart
# ---------------------------------------------------------------------------


class TestConversationHandlers:

    def _panel(self):
        panel = _build_panel()
        panel._sync_convo_button = MagicMock()
        panel._update_stats = MagicMock()
        return panel

    def test_a_state_change_repaints_and_marks_the_session_live(self):
        panel = self._panel()
        panel._apply_convo_state("listening")
        assert panel._conversation_state == "listening"
        assert panel._conversation_active is True
        panel._sync_convo_button.assert_called_once()
        panel._update_stats.assert_called_once()

    def test_an_idle_timeout_notice_names_the_window(self):
        panel = self._panel()
        panel._conversation_active = True
        panel._conversation_state = "listening"
        app = _attach_app(
            panel,
            voice=VoiceConfig(enabled=True, conversation_idle_seconds=90),
        )
        with _app_property(app):
            panel._handle_convo_stopped("idle_timeout")
        assert panel._conversation_active is False
        assert panel._conversation_state == "idle"
        message = app.notify.call_args[0][0]
        assert "Stopped listening" in message
        assert "90s" in message
        assert app.notify.call_args.kwargs["markup"] is False

    def test_a_user_stop_gets_its_own_wording(self):
        panel = self._panel()
        panel._conversation_active = True
        app = _attach_app(panel, voice=VoiceConfig(enabled=True))
        with _app_property(app):
            panel._handle_convo_stopped("user")
        assert "off" in app.notify.call_args[0][0]

    def test_an_error_stop_does_not_double_notify(self):
        """The error callback already explained itself."""
        panel = self._panel()
        panel._conversation_active = True
        app = _attach_app(panel, voice=VoiceConfig(enabled=True))
        with _app_property(app):
            panel._handle_convo_stopped("error")
        app.notify.assert_not_called()
        assert panel._conversation_active is False

    def test_a_loop_error_is_surfaced_without_markup(self):
        panel = self._panel()
        app = _attach_app(panel, voice=VoiceConfig(enabled=True))
        with _app_property(app):
            panel._handle_convo_error("Transcription failed: [boom]")
        kwargs = app.notify.call_args.kwargs
        assert kwargs["severity"] == "error"
        assert kwargs["markup"] is False

    def test_unmount_stops_the_loop_without_callbacks(self):
        panel = self._panel()
        panel._conversation_active = True
        panel._conversation_state = "listening"
        app = _attach_app(panel, voice=VoiceConfig(enabled=True))
        service = MagicMock()
        app.voice_conversation_service = service
        with _app_property(app):
            panel._teardown_conversation()
        service.set_state_callback.assert_called_once_with(None)
        service.set_transcript_callback.assert_called_once_with(None)
        service.set_error_callback.assert_called_once_with(None)
        service.set_stopped_callback.assert_called_once_with(None)
        # join=False: this runs on the UI thread, which must never wait
        # out a listener thread that is mid-transcription.
        service.stop.assert_called_once_with(join=False)
        assert panel._conversation_active is False

    def test_teardown_stops_even_when_the_panel_thinks_it_is_idle(self):
        """A start worker cancelled mid-start() never sets
        _conversation_active even though the loop may already be live, so
        the flag proves nothing at unmount: teardown must stop (and
        unregister callbacks) unconditionally. stop() is documented as a
        safe no-op when the loop really is idle."""
        panel = self._panel()
        app = _attach_app(panel, voice=VoiceConfig(enabled=True))
        service = MagicMock()
        app.voice_conversation_service = service
        with _app_property(app):
            panel._teardown_conversation()
        service.set_state_callback.assert_called_once_with(None)
        service.stop.assert_called_once_with(join=False)

    def test_on_unmount_runs_the_teardown(self):
        panel = self._panel()
        panel._recording = False
        panel._starting = False
        panel._stop_spinner = MagicMock()
        panel._interrupt_speech = MagicMock()
        panel._teardown_conversation = MagicMock()
        panel.on_unmount()
        panel._teardown_conversation.assert_called_once()

    def test_autostart_honours_the_config_switch(self):
        panel = self._panel()
        app = _attach_app(
            panel, voice=VoiceConfig(enabled=True, conversation_mode=True)
        )
        app.voice_conversation_service = MagicMock()
        panel.run_worker = MagicMock()
        panel._do_start_conversation = MagicMock(return_value="job")
        with _app_property(app):
            panel._maybe_autostart_conversation()
        panel.run_worker.assert_called_once()
        assert panel.run_worker.call_args.kwargs["group"] == "voice_convo"

    @pytest.mark.parametrize("voice", [
        VoiceConfig(enabled=True, conversation_mode=False),
        VoiceConfig(enabled=False, conversation_mode=True),
    ])
    def test_autostart_stays_quiet_when_not_opted_in(self, voice):
        panel = self._panel()
        app = _attach_app(panel, voice=voice)
        app.voice_conversation_service = MagicMock()
        panel.run_worker = MagicMock()
        with _app_property(app):
            panel._maybe_autostart_conversation()
        panel.run_worker.assert_not_called()
        app.notify.assert_not_called()


# ---------------------------------------------------------------------------
# Settings panel — pure helpers
# ---------------------------------------------------------------------------


class TestConversationSettingsHelpers:

    @pytest.mark.parametrize("raw,expected", [
        (str(VAD_SILENCE_MS_MIN), VAD_SILENCE_MS_MIN),
        ("800", 800),
        (str(VAD_SILENCE_MS_MAX), VAD_SILENCE_MS_MAX),
    ])
    def test_silence_accepts_the_supported_window(self, raw, expected):
        assert parse_vad_silence_ms(raw) == expected

    @pytest.mark.parametrize("raw", ["abc", "", "1.5", "199", "3001", "-5"])
    def test_silence_rejects_everything_else(self, raw):
        with pytest.raises(ValueError):
            parse_vad_silence_ms(raw)

    @pytest.mark.parametrize("raw,expected", [
        (str(CONVERSATION_IDLE_SECONDS_MIN), CONVERSATION_IDLE_SECONDS_MIN),
        ("60", 60),
        (str(CONVERSATION_IDLE_SECONDS_MAX), CONVERSATION_IDLE_SECONDS_MAX),
    ])
    def test_idle_accepts_the_supported_window(self, raw, expected):
        assert parse_conversation_idle_seconds(raw) == expected

    @pytest.mark.parametrize("raw", ["abc", "", "9", "601", "-1"])
    def test_idle_rejects_everything_else(self, raw):
        with pytest.raises(ValueError):
            parse_conversation_idle_seconds(raw)

    def test_download_action_states_the_size_up_front(self):
        label, widget_id, variant = vad_model_action(False, "~629 KB")
        assert widget_id == "voice_btn_vad_download"
        assert variant == "primary"
        assert "629 KB" in label

    def test_present_model_offers_removal_instead(self):
        label, widget_id, variant = vad_model_action(True)
        assert widget_id == "voice_btn_vad_remove"
        assert variant == "error"
        assert "Remove" in label


# ---------------------------------------------------------------------------
# Settings panel — round-trip for the conversation fields
# ---------------------------------------------------------------------------


class _StubWidgets:
    """Serves stub widgets from ``query_one`` keyed by selector."""

    def __init__(self, values: dict) -> None:
        self._widgets = {}
        for selector, value in values.items():
            widget = MagicMock()
            widget.value = value
            self._widgets[selector] = widget

    def query_one(self, selector, _type=None):
        if selector in self._widgets:
            return self._widgets[selector]
        raise KeyError(selector)


_FORM = {
    "#voice_enabled": True,
    "#voice_model_size": "small",
    "#voice_language": "en",
    "#voice_input_device": "",
    "#voice_max_recording_seconds": "60",
    "#voice_auto_submit": False,
    "#voice_engine": "whisper",
    "#voice_latency": 320,
    "#voice_tts_enabled": False,
    "#voice_tts_voice": "af_heart",
    "#voice_tts_speed": "1.0",
    "#voice_output_device": "",
    "#voice_conversation_mode": False,
    "#voice_vad_silence_ms": "800",
    "#voice_conversation_idle_seconds": "60",
    "#voice_barge_in": False,
}


def _panel_with(values: dict) -> VoicePanel:
    panel = VoicePanel()
    stub = _StubWidgets(values)
    panel.query_one = stub.query_one  # type: ignore[method-assign]
    return panel


def _form(**overrides) -> dict:
    values = dict(_FORM)
    values.update({f"#voice_{k}": v for k, v in overrides.items()})
    return values


class TestConversationRoundTrip:

    def test_conversation_fields_are_collected(self):
        fields = _panel_with(_form(
            conversation_mode=True,
            vad_silence_ms="1200",
            conversation_idle_seconds="120",
        )).collect()
        assert fields["conversation_mode"] is True
        assert fields["vad_silence_ms"] == 1200
        assert fields["conversation_idle_seconds"] == 120

    def test_blank_fields_fall_back_to_the_defaults(self):
        fields = _panel_with(_form(
            vad_silence_ms="", conversation_idle_seconds="",
        )).collect()
        assert fields["vad_silence_ms"] == 800
        assert fields["conversation_idle_seconds"] == 60

    @pytest.mark.parametrize("raw", ["abc", "199", "3001"])
    def test_bad_silence_is_a_validation_error_on_its_own_field(self, raw):
        with pytest.raises(ValidationError) as exc:
            _panel_with(_form(vad_silence_ms=raw)).collect()
        assert exc.value.field_id == "voice_vad_silence_ms"

    @pytest.mark.parametrize("raw", ["abc", "9", "601"])
    def test_bad_idle_window_is_a_validation_error_on_its_own_field(self, raw):
        with pytest.raises(ValidationError) as exc:
            _panel_with(_form(conversation_idle_seconds=raw)).collect()
        assert exc.value.field_id == "voice_conversation_idle_seconds"

    def test_conversation_fields_are_part_of_dirty_tracking(self):
        values = _panel_with(_form(
            conversation_mode=True, vad_silence_ms="1500",
        )).current_values()
        assert values["conversation_mode"] is True
        assert values["vad_silence_ms"] == "1500"
        assert values["conversation_idle_seconds"] == "60"

    def _persist(self, panel):
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig(voice=VoiceConfig())
        panel._finish_save = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        panel._offer_model_cleanup = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel.persist()
        return panel, app

    def test_persist_writes_the_conversation_fields(self):
        panel = _panel_with(_form(
            conversation_mode=True,
            vad_silence_ms="1000",
            conversation_idle_seconds="300",
        ))
        _panel, app = self._persist(panel)
        saved = app.config_manager.update.call_args.kwargs["voice"]
        assert saved.conversation_mode is True
        assert saved.vad_silence_ms == 1000
        assert saved.conversation_idle_seconds == 300

    def test_persist_rebuilds_the_conversation_service(self):
        from servonaut.services.voice_conversation_service import (
            VoiceConversationService,
        )

        panel = _panel_with(_form())
        old_loop = MagicMock()
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig(voice=VoiceConfig())
        app.voice_conversation_service = old_loop
        panel._finish_save = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        panel._offer_model_cleanup = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel.persist()
        # An active session must be stopped before the loop is replaced.
        old_loop.stop.assert_called_once()
        assert isinstance(
            app.voice_conversation_service, VoiceConversationService
        )
        saved = app.config_manager.update.call_args.kwargs["voice"]
        assert app.voice_conversation_service._config is saved

    def test_turning_conversation_off_offers_model_cleanup(self):
        panel = _panel_with(_form(conversation_mode=False))
        panel._loaded_conversation_mode = True
        _panel, _app = self._persist(panel)
        panel._offer_model_cleanup.assert_called_once()

    def test_an_unchanged_conversation_switch_offers_no_cleanup(self):
        panel = _panel_with(_form(conversation_mode=False))
        panel._loaded_conversation_mode = False
        _panel, _app = self._persist(panel)
        panel._offer_model_cleanup.assert_not_called()

    def test_barge_in_is_collected(self):
        assert _panel_with(_form(barge_in=True)).collect()["barge_in"] is True

    def test_barge_in_defaults_off(self):
        """Off unless the user opted in — on speakers the microphone hears
        the assistant's own voice, so this must never turn itself on."""
        assert _panel_with(_form()).collect()["barge_in"] is False

    def test_barge_in_is_part_of_dirty_tracking(self):
        values = _panel_with(_form(barge_in=True)).current_values()
        assert values["barge_in"] is True

    def test_persist_writes_barge_in(self):
        panel = _panel_with(_form(barge_in=True))
        _panel, app = self._persist(panel)
        saved = app.config_manager.update.call_args.kwargs["voice"]
        assert saved.barge_in is True

    def test_persist_hands_the_flag_to_the_rebuilt_conversation_service(self):
        """The loop reads ``barge_in`` from the config it was built with,
        so the save-time rebuild is what makes the switch take effect
        without a restart."""
        from servonaut.services.voice_conversation_service import (
            VoiceConversationService,
        )

        panel = _panel_with(_form(barge_in=True))
        _panel, app = self._persist(panel)
        service = app.voice_conversation_service
        assert isinstance(service, VoiceConversationService)
        assert service._config.barge_in is True

    def test_cleanup_inventory_tracks_the_conversation_switch(self):
        panel = _panel_with(_form(conversation_mode=True))
        setup = MagicMock()
        setup.stale_models.return_value = []
        panel._setup_service = lambda: setup  # type: ignore[method-assign]
        app = MagicMock()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._offer_model_cleanup()
        kwargs = setup.stale_models.call_args.kwargs
        assert kwargs["active_conversation_mode"] is True


# ---------------------------------------------------------------------------
# Settings panel — VAD model download / remove actions
# ---------------------------------------------------------------------------


class TestVadSetupActions:

    def _panel_and_service(self):
        panel = _panel_with(_form())
        service = MagicMock()
        service.vad_download_size_hint.return_value = "~629 KB"
        panel._setup_service = lambda: service  # type: ignore[method-assign]
        panel._show_download_progress = MagicMock()  # type: ignore[method-assign]
        panel.run_worker = MagicMock()  # type: ignore[method-assign]
        panel._set_actions_enabled = MagicMock()  # type: ignore[method-assign]
        panel._do_vad_download = MagicMock(return_value="job")  # type: ignore[method-assign]
        app = MagicMock()
        return panel, service, app

    def test_download_announces_the_size_before_fetching(self):
        panel, _service, app = self._panel_and_service()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._start_vad_download()
        announced = app.notify.call_args[0][0]
        assert "629 KB" in announced
        panel.run_worker.assert_called_once()
        assert panel.run_worker.call_args.kwargs["group"] == "voice_setup"

    def test_download_is_gated_while_another_action_runs(self):
        panel, _service, app = self._panel_and_service()
        panel._busy = True
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._start_vad_download()
        panel.run_worker.assert_not_called()

    @pytest.mark.asyncio
    async def test_download_worker_reports_and_repaints(self):
        panel = _panel_with(_form())
        panel._hide_download_progress = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        panel._set_actions_enabled = MagicMock()  # type: ignore[method-assign]
        panel._busy = True
        service = MagicMock()
        service.download_vad_model = AsyncMock(
            return_value=(True, "Downloaded the voice-detection model.")
        )
        app = MagicMock()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            await panel._do_vad_download(service)
        assert panel._busy is False
        kwargs = app.notify.call_args.kwargs
        assert kwargs["markup"] is False
        assert kwargs["severity"] == "information"
        panel._refresh_readiness.assert_called_once_with(force=True)

    @pytest.mark.asyncio
    async def test_download_worker_failure_is_an_error_toast(self):
        panel = _panel_with(_form())
        panel._hide_download_progress = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        panel._set_actions_enabled = MagicMock()  # type: ignore[method-assign]
        service = MagicMock()
        service.download_vad_model = AsyncMock(side_effect=OSError("disk full"))
        app = MagicMock()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            await panel._do_vad_download(service)
        assert panel._busy is False
        kwargs = app.notify.call_args.kwargs
        assert kwargs["severity"] == "error"
        assert kwargs["markup"] is False

    def test_remove_deletes_the_silero_entry(self):
        panel = _panel_with(_form())
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        service = MagicMock()
        model = MagicMock()
        model.engine = "silero-vad"
        service.installed_models.return_value = [
            MagicMock(engine="whisper"), model,
        ]
        service.remove_installed.return_value = (True, "removed")
        panel._setup_service = lambda: service  # type: ignore[method-assign]
        app = MagicMock()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._remove_vad_model()
        service.remove_installed.assert_called_once_with(model)
        panel._refresh_readiness.assert_called_once_with(force=True)

    def test_remove_with_no_model_on_disk_reports_honestly(self):
        panel = _panel_with(_form())
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        service = MagicMock()
        service.installed_models.return_value = []
        panel._setup_service = lambda: service  # type: ignore[method-assign]
        app = MagicMock()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._remove_vad_model()
        service.remove_installed.assert_not_called()
        assert "not on disk" in app.notify.call_args[0][0]


class TestPanelClosePath:
    """The panel must leave the render set before removal begins —
    a repaint reaching the input TextArea mid-removal crashes in the
    framework, and voice's cross-thread updates make that easy to hit."""

    def test_close_panel_hides_before_removing(self):
        from unittest.mock import patch as _patch
        from servonaut.widgets.chat_panel import ChatPanel

        panel = ChatPanel()
        seen = {}

        def _record_remove():
            seen["display_at_remove"] = panel.display

        with _patch.object(panel, "remove", side_effect=_record_remove):
            panel.close_panel()
        assert seen["display_at_remove"] is False

    def test_no_bare_remove_call_sites_remain(self):
        """Both close paths must go through close_panel()."""
        import pathlib
        root = pathlib.Path(__file__).parent.parent / "src" / "servonaut"
        chat_src = (root / "widgets" / "chat_panel.py").read_text()
        app_src = (root / "app.py").read_text()
        assert "self.close_panel()" in chat_src
        assert "panel.close_panel()" in app_src
        assert "panel.remove()" not in app_src
