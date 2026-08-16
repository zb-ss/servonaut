"""Chat-panel wiring tests for streaming speech on the Servonaut SSE path.

Mirrors the conventions of ``test_voice_tts_ui.py``: the text-level
decision is the pure :func:`resolve_spoken_sentence`, and the widget
methods are driven on an unmounted panel with stubbed collaborators —
no Textual app, no audio stack.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, VoiceConfig
from servonaut.services.voice_stream_chunker import VoiceStreamChunker
from servonaut.widgets.chat_panel import ChatPanel, resolve_spoken_sentence


# ---------------------------------------------------------------------------
# Helpers
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
    panel._update_stats = MagicMock()
    return panel


def _attach_app(panel: ChatPanel, *, voice: VoiceConfig) -> MagicMock:
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.config_manager.get.return_value = AppConfig(voice=voice)
    return app


def _app_property(app: MagicMock):
    return patch.object(ChatPanel, "app", property(lambda _self: app))


def _make_service(*, available: bool = True) -> MagicMock:
    """An output-service stand-in with the session API."""
    service = MagicMock()
    service.is_available.return_value = available
    service.current_epoch.return_value = 7
    return service


def _armed_panel(*, tts_enabled=True, service="default", conversation=False):
    panel = _build_panel()
    app = _attach_app(panel, voice=VoiceConfig(tts_enabled=tts_enabled))
    if service == "default":
        service = _make_service()
    app.voice_output_service = service
    panel._conversation_active = conversation
    return panel, app


# ---------------------------------------------------------------------------
# resolve_spoken_sentence — the per-sentence gate
# ---------------------------------------------------------------------------


class TestResolveSpokenSentence:

    def test_prose_passes_through(self):
        assert resolve_spoken_sentence("The disk is fine.") == "The disk is fine."

    @pytest.mark.parametrize("sentence", ["", "   ", "\n\t"])
    def test_empty_speaks_nothing(self, sentence):
        assert resolve_spoken_sentence(sentence) == ""

    def test_demo_mode_scrubs_before_speaking(self):
        spoken = resolve_spoken_sentence(
            "the ip is 10.0.0.5",
            demo_mode=True,
            scrub=lambda text: text.replace("10.0.0.5", "x.x.x.x"),
        )
        assert spoken == "the ip is x.x.x.x"

    def test_demo_mode_without_a_redactor_fails_closed(self):
        assert resolve_spoken_sentence("secret", demo_mode=True, scrub=None) == ""

    def test_demo_mode_scrub_failure_fails_closed(self):
        def _broken(_text):
            raise RuntimeError("redactor died")
        assert resolve_spoken_sentence("secret", demo_mode=True, scrub=_broken) == ""

    def test_demo_mode_scrub_returning_non_text_fails_closed(self):
        assert resolve_spoken_sentence(
            "secret", demo_mode=True, scrub=lambda _t: None,
        ) == ""

    def test_scrub_is_not_applied_outside_demo_mode(self):
        scrub = MagicMock()
        assert resolve_spoken_sentence("plain", scrub=scrub) == "plain"
        scrub.assert_not_called()


# ---------------------------------------------------------------------------
# _begin_turn_speech — arming per turn
# ---------------------------------------------------------------------------


class TestBeginTurnSpeech:

    def test_arms_a_chunker_when_tts_is_on(self):
        panel, app = _armed_panel()
        with _app_property(app):
            panel._begin_turn_speech()
        assert isinstance(panel._turn_chunker, VoiceStreamChunker)
        assert panel._turn_speech_session is None
        assert panel._turn_speech_suppressed is False

    def test_tts_off_streams_silently(self):
        panel, app = _armed_panel(tts_enabled=False)
        with _app_property(app):
            panel._begin_turn_speech()
        assert panel._turn_chunker is None

    def test_missing_service_streams_silently(self):
        panel, app = _armed_panel(service=None)
        with _app_property(app):
            panel._begin_turn_speech()
        assert panel._turn_chunker is None

    def test_rearming_clears_the_previous_turn_state(self):
        panel, app = _armed_panel()
        panel._turn_speech_session = MagicMock()
        panel._turn_speech_suppressed = True
        with _app_property(app):
            panel._begin_turn_speech()
        assert panel._turn_speech_session is None
        assert panel._turn_speech_suppressed is False


# ---------------------------------------------------------------------------
# _start_turn_speech_session — first sentence of the turn
# ---------------------------------------------------------------------------


class TestStartTurnSpeechSession:

    @pytest.mark.asyncio
    async def test_opens_the_session_with_the_pinned_epoch(self):
        panel, app = _armed_panel()
        service = app.voice_output_service
        order = []
        service.stop.side_effect = lambda: order.append("stop")
        service.current_epoch.side_effect = lambda: order.append("epoch") or 7
        with _app_property(app):
            started = await panel._start_turn_speech_session()
        assert started is True
        # Supersede-then-pin, in that order, exactly like _maybe_speak_reply.
        assert order == ["stop", "epoch"]
        assert service.begin_utterance.call_args.kwargs["epoch"] == 7
        assert panel._turn_speech_session is service.begin_utterance.return_value
        assert panel._speaking is True

    @pytest.mark.asyncio
    async def test_unavailable_service_suppresses_the_turn_quietly(self):
        panel, app = _armed_panel(service=_make_service(available=False))
        with _app_property(app):
            started = await panel._start_turn_speech_session()
        assert started is False
        assert panel._turn_speech_suppressed is True
        app.voice_output_service.begin_utterance.assert_not_called()
        app.notify.assert_not_called()
        assert panel._speaking is False

    @pytest.mark.asyncio
    async def test_conversation_mode_enters_speaking_before_audio(self):
        panel, app = _armed_panel(conversation=True)
        convo = MagicMock()
        app.voice_conversation_service = convo
        with _app_property(app):
            await panel._start_turn_speech_session()
        convo.speaking_started.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_conversation_no_speaking_started(self):
        panel, app = _armed_panel(conversation=False)
        convo = MagicMock()
        app.voice_conversation_service = convo
        with _app_property(app):
            await panel._start_turn_speech_session()
        convo.speaking_started.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_session_born_superseded_never_enters_speaking(self):
        """A cross-thread stop() between the epoch pin and
        begin_utterance retires the session on the spot: its completion
        already fired with the current seq, so entering SPEAKING (or
        setting the speaking flag) would wedge behind a session that can
        never complete again. The retired session is kept so it swallows
        the rest of the turn's sentences."""
        panel, app = _armed_panel(conversation=True)
        convo = MagicMock()
        app.voice_conversation_service = convo
        session = app.voice_output_service.begin_utterance.return_value
        session.is_settled = True
        with _app_property(app):
            started = await panel._start_turn_speech_session()
        assert started is False
        convo.speaking_started.assert_not_called()
        assert panel._speaking is False
        assert panel._turn_speech_session is session


# ---------------------------------------------------------------------------
# _stream_speech_feed — deltas to sentences to the session
# ---------------------------------------------------------------------------


class TestStreamSpeechFeed:

    @pytest.mark.asyncio
    async def test_sentences_flow_to_the_session_as_they_complete(self):
        panel, app = _armed_panel()
        service = app.voice_output_service
        session = service.begin_utterance.return_value
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("First one. Sec")
            await panel._stream_speech_feed("ond one. Tail")
        assert [c.args[0] for c in session.enqueue.call_args_list] == [
            "First one.", "Second one.",
        ]
        # One session per turn, opened by the first sentence.
        service.begin_utterance.assert_called_once()

    @pytest.mark.asyncio
    async def test_unarmed_panel_ignores_deltas(self):
        panel, app = _armed_panel(tts_enabled=False)
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("Complete sentence. ")
        app.voice_output_service.begin_utterance.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_suppressed_turn_probes_only_once(self):
        panel, app = _armed_panel(service=_make_service(available=False))
        service = app.voice_output_service
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("First one. ")
            await panel._stream_speech_feed("Second one. ")
        assert service.is_available.call_count == 1
        service.begin_utterance.assert_not_called()

    @pytest.mark.asyncio
    async def test_demo_mode_scrubs_every_sentence(self):
        panel, app = _armed_panel()
        app.demo_mode = True
        app.redaction_service = MagicMock()
        app.redaction_service.scrub_stream = (
            lambda text: text.replace("10.0.0.5", "x.x.x.x")
        )
        session = app.voice_output_service.begin_utterance.return_value
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("Host 10.0.0.5 is up. ")
        session.enqueue.assert_called_once_with("Host x.x.x.x is up.")

    @pytest.mark.asyncio
    async def test_demo_mode_without_a_redactor_speaks_nothing(self):
        panel, app = _armed_panel()
        app.demo_mode = True
        app.redaction_service = None
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("Sensitive sentence. ")
        app.voice_output_service.begin_utterance.assert_not_called()

    @pytest.mark.asyncio
    async def test_code_fences_hold_until_closed(self):
        panel, app = _armed_panel()
        session = app.voice_output_service.begin_utterance.return_value
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("```\nsecret = 1\n")
            assert session.enqueue.call_count == 0
            await panel._stream_speech_feed("```\n")
        session.enqueue.assert_called_once_with("Code block shown on screen.")


# ---------------------------------------------------------------------------
# _finish_turn_speech / finalise — end of the stream
# ---------------------------------------------------------------------------


class TestFinishTurnSpeech:

    @pytest.mark.asyncio
    async def test_flush_remainder_is_enqueued_and_the_session_ends(self):
        panel, app = _armed_panel()
        session = app.voice_output_service.begin_utterance.return_value
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("Done. Trailing words")
            streamed, owns_edge = panel._finish_turn_speech()
        assert streamed is True
        assert owns_edge is True
        assert [c.args[0] for c in session.enqueue.call_args_list] == [
            "Done.", "Trailing words",
        ]
        session.end.assert_called_once()
        assert panel._turn_speech_session is None
        assert panel._turn_chunker is None

    def test_without_a_session_finalise_falls_back_to_final_reply_speech(self):
        panel, app = _armed_panel()
        with _app_property(app):
            panel._begin_turn_speech()
            streamed, owns_edge = panel._finish_turn_speech()
        assert streamed is False
        assert owns_edge is False

    @pytest.mark.asyncio
    async def test_a_settled_session_does_not_own_the_edge(self):
        """An interrupt retired the session mid-stream: its exactly-once
        completion has already fired and can never fire again, so
        finalise must not defer the SPEAKING -> LISTENING edge to it —
        that is the strand-in-THINKING bug. The reply must still not be
        re-spoken (streamed=True suppresses the final-reply path)."""
        panel, app = _armed_panel()
        session = app.voice_output_service.begin_utterance.return_value
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("First sentence spoken. ")
            # The interrupt lands: the output service retires the session.
            session.is_settled = True
            session.enqueue.reset_mock()
            streamed, owns_edge = panel._finish_turn_speech()
        assert streamed is True
        assert owns_edge is False
        # The flush is skipped: a retired session drops every enqueue.
        session.enqueue.assert_not_called()
        assert panel._turn_speech_session is None
        assert panel._turn_chunker is None

    def test_finalise_prefers_the_streaming_session(self):
        """When streaming spoke the reply, the final-reply path must not
        run — it would read the whole reply out a second time."""
        panel, app = _armed_panel()
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._maybe_speak_reply = MagicMock()
        panel._notify_convo_reply_done = MagicMock()
        panel._finish_turn_speech = MagicMock(return_value=(True, True))
        from servonaut.services.chat_service import ChatMessage, ChatSession
        panel._session = ChatSession(
            id="s1", title="already titled",
            messages=[ChatMessage(role="user", content="hi")],
        )
        with _app_property(app):
            panel._finalise_servonaut_turn(MagicMock(), "The disk is fine.")
        panel._maybe_speak_reply.assert_not_called()
        panel._notify_convo_reply_done.assert_called_once_with(True)

    def test_finalise_falls_back_when_streaming_never_started(self):
        panel, app = _armed_panel()
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._maybe_speak_reply = MagicMock(return_value=True)
        panel._notify_convo_reply_done = MagicMock()
        panel._finish_turn_speech = MagicMock(return_value=(False, False))
        from servonaut.services.chat_service import ChatMessage, ChatSession
        panel._session = ChatSession(
            id="s1", title="already titled",
            messages=[ChatMessage(role="user", content="hi")],
        )
        with _app_property(app):
            panel._finalise_servonaut_turn(MagicMock(), "The disk is fine.")
        panel._maybe_speak_reply.assert_called_once_with("The disk is fine.")
        panel._notify_convo_reply_done.assert_called_once_with(True)

    def test_finalise_resumes_the_loop_when_the_session_was_interrupted(self):
        """Regression: mid-stream interrupt + a transcript dropped as
        drop_busy left the loop stranded in THINKING. A retired session
        does not own the SPEAKING -> LISTENING edge, so finalise must
        report the turn as unspoken to the conversation loop (which
        resumes listening via reply_finished) while STILL suppressing
        the final-reply re-speak."""
        panel, app = _armed_panel(conversation=True)
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._maybe_speak_reply = MagicMock()
        panel._notify_convo_reply_done = MagicMock()
        panel._finish_turn_speech = MagicMock(return_value=(True, False))
        from servonaut.services.chat_service import ChatMessage, ChatSession
        panel._session = ChatSession(
            id="s1", title="already titled",
            messages=[ChatMessage(role="user", content="hi")],
        )
        with _app_property(app):
            panel._finalise_servonaut_turn(MagicMock(), "The disk is fine.")
        panel._maybe_speak_reply.assert_not_called()
        panel._notify_convo_reply_done.assert_called_once_with(False)


# ---------------------------------------------------------------------------
# _abort_turn_speech — error and cancellation paths
# ---------------------------------------------------------------------------


class TestAbortTurnSpeech:

    @pytest.mark.asyncio
    async def test_abort_stops_playback_and_settles_the_session(self):
        panel, app = _armed_panel()
        service = app.voice_output_service
        session = service.begin_utterance.return_value
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("Streamed so far. ")
            service.stop.reset_mock()  # the session-open stop
            panel._abort_turn_speech()
        service.stop.assert_called_once()
        session.end.assert_called_once()
        assert panel._turn_speech_session is None
        assert panel._turn_chunker is None

    def test_abort_without_a_session_is_a_noop(self):
        panel, app = _armed_panel()
        with _app_property(app):
            panel._begin_turn_speech()
            panel._abort_turn_speech()
        app.voice_output_service.stop.assert_not_called()

    @pytest.mark.asyncio
    async def test_a_cancelled_send_aborts_streaming_speech(self):
        """The _do_send_servonaut finally must silence a cancelled turn's
        mid-reply speech, not just settle the thinking flag."""
        panel, app = _armed_panel()
        panel._thinking = True
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._notify_convo_reply_done = MagicMock()
        panel._abort_turn_speech = MagicMock()
        panel._run_servonaut_turn = AsyncMock(
            side_effect=asyncio.CancelledError()
        )
        with _app_property(app):
            with pytest.raises(asyncio.CancelledError):
                await panel._do_send_servonaut("hi")
        panel._abort_turn_speech.assert_called_once()


# ---------------------------------------------------------------------------
# Utterance completion — the SPEAKING -> LISTENING bridge
# ---------------------------------------------------------------------------


class TestStreamSpeechCompletion:

    def test_completion_clears_the_indicator(self):
        panel, app = _armed_panel()
        panel._speaking = True
        panel._speak_seq = 3
        panel._convo_call = MagicMock()
        with _app_property(app):
            panel._handle_stream_speech_complete(3, True)
        assert panel._speaking is False
        panel._convo_call.assert_not_called()  # conversation inactive

    def test_completion_resumes_listening_in_conversation_mode(self):
        panel, app = _armed_panel(conversation=True)
        panel._speaking = True
        panel._speak_seq = 3
        panel._convo_call = MagicMock()
        with _app_property(app):
            panel._handle_stream_speech_complete(3, True)
        panel._convo_call.assert_called_once_with("speaking_finished")

    def test_an_interrupted_session_still_resumes_listening(self):
        """played_to_end=False (stop/interrupt) must still close SPEAKING
        — speaking_finished is a no-op if interrupt already moved on."""
        panel, app = _armed_panel(conversation=True)
        panel._speaking = True
        panel._speak_seq = 3
        panel._convo_call = MagicMock()
        with _app_property(app):
            panel._handle_stream_speech_complete(3, False)
        panel._convo_call.assert_called_once_with("speaking_finished")

    def test_a_superseded_completion_is_ignored(self):
        """A newer speech owner exists: the old session's completion must
        not wipe the indicator or reopen the mic under it."""
        panel, app = _armed_panel(conversation=True)
        panel._speaking = True
        panel._speak_seq = 4  # newer owner
        panel._convo_call = MagicMock()
        with _app_property(app):
            panel._handle_stream_speech_complete(3, False)
        assert panel._speaking is True
        panel._convo_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_the_session_callback_routes_through_the_marshaller(self):
        panel, app = _armed_panel()
        service = app.voice_output_service
        panel._convo_marshal = MagicMock()
        with _app_property(app):
            panel._begin_turn_speech()
            await panel._stream_speech_feed("A sentence. ")
        on_complete = service.begin_utterance.call_args.kwargs["on_complete"]
        on_complete(True)
        panel._convo_marshal.assert_called_once()
        args = panel._convo_marshal.call_args.args
        assert args[0] == panel._handle_stream_speech_complete
