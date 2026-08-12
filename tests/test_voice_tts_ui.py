"""UI wiring tests for spoken replies (chat panel + Voice settings panel).

The speak-on-reply decision lives in the pure
:func:`~servonaut.widgets.chat_panel.resolve_spoken_reply`, and the
settings-panel decisions in pure helpers (`parse_tts_speed`,
`tts_model_action`, …), precisely so this file can pin the behaviour
without mounting a Textual app — unmounted containers cannot be queried,
so anything widget-shaped is driven through stubbed ``query_one`` /
mocked collaborators, matching the conventions of the neighbouring
voice test files.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, VoiceConfig
from servonaut.screens.settings.base import ValidationError
from servonaut.screens.settings.panels.voice import (
    VoicePanel,
    parse_tts_speed,
    tts_model_action,
    tts_model_note,
    tts_package_action,
    tts_package_note,
    tts_voice_label,
)
from servonaut.services.chat_service import ChatMessage, ChatSession
from servonaut.widgets.chat_panel import ChatPanel, resolve_spoken_reply


# ---------------------------------------------------------------------------
# Helpers (chat panel without a mounted app — mirrors test_chat_panel_security)
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


# ---------------------------------------------------------------------------
# resolve_spoken_reply — the speak-on-reply decision matrix
# ---------------------------------------------------------------------------


class TestResolveSpokenReply:

    def test_disabled_speaks_nothing(self):
        assert resolve_spoken_reply("Hello", tts_enabled=False) == ""

    def test_enabled_passes_prose_through(self):
        assert resolve_spoken_reply("Hello there", tts_enabled=True) == "Hello there"

    @pytest.mark.parametrize("text", [None, "", "   ", "\n\t"])
    def test_empty_text_speaks_nothing(self, text):
        assert resolve_spoken_reply(text, tts_enabled=True) == ""

    def test_error_placeholder_is_never_spoken(self):
        """The generic path appends 'Error: …' bubbles on failure."""
        assert resolve_spoken_reply("Error: boom", tts_enabled=True) == ""

    @pytest.mark.parametrize("text", [
        "(no response)",
        "(model ran 3 tools but didn't summarise — see tool output above)",
    ])
    def test_fallback_bubbles_are_never_spoken(self, text):
        assert resolve_spoken_reply(text, tts_enabled=True) == ""

    def test_demo_mode_scrubs_before_speaking(self):
        spoken = resolve_spoken_reply(
            "the ip is 10.0.0.5",
            tts_enabled=True,
            demo_mode=True,
            scrub=lambda text: text.replace("10.0.0.5", "x.x.x.x"),
        )
        assert spoken == "the ip is x.x.x.x"

    def test_demo_mode_without_a_redactor_fails_closed(self):
        """No scrubber means no speech — never unredacted audio."""
        assert resolve_spoken_reply(
            "secret", tts_enabled=True, demo_mode=True, scrub=None,
        ) == ""

    def test_demo_mode_scrub_failure_fails_closed(self):
        def _broken(_text):
            raise RuntimeError("redactor died")
        assert resolve_spoken_reply(
            "secret", tts_enabled=True, demo_mode=True, scrub=_broken,
        ) == ""

    def test_demo_mode_scrub_returning_non_text_fails_closed(self):
        assert resolve_spoken_reply(
            "secret", tts_enabled=True, demo_mode=True, scrub=lambda _t: None,
        ) == ""

    def test_scrub_is_not_applied_outside_demo_mode(self):
        scrub = MagicMock()
        assert resolve_spoken_reply(
            "plain", tts_enabled=True, demo_mode=False, scrub=scrub,
        ) == "plain"
        scrub.assert_not_called()


# ---------------------------------------------------------------------------
# ChatPanel._maybe_speak_reply — service wiring around the decision
# ---------------------------------------------------------------------------


class TestMaybeSpeakReply:

    def _speaking_panel(self, *, tts_enabled=True, service="default"):
        panel = _build_panel()
        app = _attach_app(panel, voice=VoiceConfig(tts_enabled=tts_enabled))
        if service == "default":
            service = MagicMock()
        app.voice_output_service = service
        panel.run_worker = MagicMock()
        panel._do_speak = MagicMock(return_value="job")
        return panel, app

    def test_speaks_when_enabled_and_service_present(self):
        panel, app = self._speaking_panel()
        with _app_property(app):
            panel._maybe_speak_reply("Hello")
        panel._do_speak.assert_called_once_with(
            app.voice_output_service, "Hello",
            epoch=app.voice_output_service.current_epoch.return_value,
        )
        kwargs = panel.run_worker.call_args.kwargs
        assert kwargs["group"] == "voice_speak"
        assert kwargs["exclusive"] is True

    def test_the_epoch_is_pinned_after_the_stop(self):
        """The cancellation token must be snapshotted AFTER service.stop()
        (which bumps it) and before the worker is scheduled, so a stop
        landing mid-hand-off retires the utterance."""
        panel, app = self._speaking_panel()
        order = []
        app.voice_output_service.stop.side_effect = lambda: order.append("stop")
        app.voice_output_service.current_epoch.side_effect = (
            lambda: order.append("epoch") or 7
        )
        with _app_property(app):
            panel._maybe_speak_reply("Hello")
        assert order == ["stop", "epoch"]
        panel._do_speak.assert_called_once_with(
            app.voice_output_service, "Hello", epoch=7,
        )

    def test_a_service_without_current_epoch_gets_none(self):
        """Loose coupling: a stand-in service lacking the epoch API must
        still be spoken through, just without pre-submit cancellation."""

        class _MinimalService:
            def stop(self):
                pass

        panel, app = self._speaking_panel(service=_MinimalService())
        with _app_property(app):
            panel._maybe_speak_reply("Hello")
        panel._do_speak.assert_called_once_with(
            app.voice_output_service, "Hello", epoch=None,
        )

    def test_new_reply_stops_the_previous_utterance_first(self):
        panel, app = self._speaking_panel()
        with _app_property(app):
            panel._maybe_speak_reply("Hello")
        app.voice_output_service.stop.assert_called_once()

    def test_disabled_config_dispatches_nothing(self):
        panel, app = self._speaking_panel(tts_enabled=False)
        with _app_property(app):
            panel._maybe_speak_reply("Hello")
        panel.run_worker.assert_not_called()

    def test_missing_service_dispatches_nothing(self):
        panel, app = self._speaking_panel(service=None)
        with _app_property(app):
            panel._maybe_speak_reply("Hello")
        panel.run_worker.assert_not_called()

    def test_error_reply_dispatches_nothing(self):
        panel, app = self._speaking_panel()
        with _app_property(app):
            panel._maybe_speak_reply("Error: upstream fell over")
        panel.run_worker.assert_not_called()

    def test_demo_mode_hands_the_scrubbed_text_to_the_worker(self):
        panel, app = self._speaking_panel()
        app.demo_mode = True
        app.redaction_service = MagicMock()
        app.redaction_service.scrub_stream = lambda text: "scrubbed"
        with _app_property(app):
            panel._maybe_speak_reply("raw with a hostname in it")
        panel._do_speak.assert_called_once_with(
            app.voice_output_service, "scrubbed",
            epoch=app.voice_output_service.current_epoch.return_value,
        )

    def test_a_failing_stop_does_not_block_the_new_utterance(self):
        panel, app = self._speaking_panel()
        app.voice_output_service.stop.side_effect = RuntimeError("audio gone")
        with _app_property(app):
            panel._maybe_speak_reply("Hello")
        panel.run_worker.assert_called_once()


# ---------------------------------------------------------------------------
# ChatPanel.refresh_voice_affordance — re-check resets BOTH probe caches
# ---------------------------------------------------------------------------


class TestRefreshVoiceAffordance:

    def test_recheck_resets_both_voice_services(self):
        """The output service caches its no-output-device verdict exactly
        like the input service caches its probe; a re-check that only
        revived the mic would leave spoken replies silently skipped."""
        panel = _build_panel()
        app = _attach_app(panel, voice=VoiceConfig())
        with _app_property(app):
            panel.refresh_voice_affordance()
        app.voice_input_service.reset_availability.assert_called_once()
        app.voice_output_service.reset_availability.assert_called_once()

    def test_recheck_survives_missing_services(self):
        panel = _build_panel()
        app = _attach_app(panel, voice=VoiceConfig())
        app.voice_input_service = None
        app.voice_output_service = None
        with _app_property(app):
            panel.refresh_voice_affordance()  # must not raise


# ---------------------------------------------------------------------------
# ChatPanel._do_speak — the playback worker
# ---------------------------------------------------------------------------


class TestDoSpeakWorker:

    def _panel(self):
        panel = _build_panel()
        panel._update_stats = MagicMock()
        return panel

    @pytest.mark.asyncio
    async def test_speaks_and_clears_the_indicator(self):
        panel = self._panel()
        service = MagicMock()
        service.is_available.return_value = True
        seen = []
        service.speak.side_effect = lambda text: seen.append(
            (text, panel._speaking)
        )
        await panel._do_speak(service, "Hello")
        assert seen == [("Hello", True)]
        assert panel._speaking is False

    @pytest.mark.asyncio
    async def test_unavailable_service_is_a_quiet_skip(self):
        panel = self._panel()
        app = MagicMock()
        service = MagicMock()
        service.is_available.return_value = False
        service.unavailable_reason.return_value = "no model"
        with _app_property(app):
            await panel._do_speak(service, "Hello")
        service.speak.assert_not_called()
        app.notify.assert_not_called()
        assert panel._speaking is False

    @pytest.mark.asyncio
    async def test_a_speak_failure_notifies_without_markup(self):
        panel = self._panel()
        app = MagicMock()
        service = MagicMock()
        service.is_available.return_value = True
        service.speak.side_effect = RuntimeError("[bold]synthesis died[/bold]")
        with _app_property(app):
            await panel._do_speak(service, "Hello")
        assert panel._speaking is False
        kwargs = app.notify.call_args.kwargs
        assert kwargs["markup"] is False

    @pytest.mark.asyncio
    async def test_a_superseded_worker_does_not_wipe_the_new_indicator(self):
        """The seq guard: an old utterance winding down must not clear the
        flag its replacement just set."""
        panel = self._panel()
        service = MagicMock()
        service.is_available.return_value = True

        def _speak_and_supersede(_text):
            # A newer worker started while this one was speaking.
            panel._speak_seq += 1
            panel._speaking = True

        service.speak.side_effect = _speak_and_supersede
        await panel._do_speak(service, "Hello")
        assert panel._speaking is True

    @pytest.mark.asyncio
    async def test_the_pinned_epoch_reaches_the_service(self):
        """The token captured in _maybe_speak_reply must ride through to
        speak(), where it is what actually cancels a stale utterance."""
        panel = self._panel()
        service = MagicMock()
        service.is_available.return_value = True
        await panel._do_speak(service, "Hello", epoch=7)
        service.speak.assert_called_once_with("Hello", epoch=7)

    @pytest.mark.asyncio
    async def test_no_epoch_speaks_without_the_keyword(self):
        """epoch=None keeps the pre-epoch call shape, so stand-in services
        with a plain speak(text) signature keep working."""
        panel = self._panel()
        service = MagicMock()
        service.is_available.return_value = True
        await panel._do_speak(service, "Hello")
        service.speak.assert_called_once_with("Hello")


# ---------------------------------------------------------------------------
# Interrupt paths — stop key, stop-before-send, unmount teardown
# ---------------------------------------------------------------------------


class TestInterruptSpeech:

    def test_interrupt_stops_the_service_and_clears_the_flag(self):
        panel = _build_panel()
        panel._update_stats = MagicMock()
        panel._speaking = True
        app = MagicMock()
        service = MagicMock()
        app.voice_output_service = service
        with _app_property(app):
            panel._interrupt_speech()
        service.stop.assert_called_once()
        assert panel._speaking is False

    def test_interrupt_survives_a_missing_service(self):
        panel = _build_panel()
        panel._update_stats = MagicMock()
        panel._speaking = True
        app = MagicMock()
        app.voice_output_service = None
        with _app_property(app):
            panel._interrupt_speech()
        assert panel._speaking is False

    def test_interrupt_survives_a_raising_stop(self):
        panel = _build_panel()
        panel._update_stats = MagicMock()
        panel._speaking = True
        app = MagicMock()
        app.voice_output_service.stop.side_effect = RuntimeError("boom")
        with _app_property(app):
            panel._interrupt_speech()
        assert panel._speaking is False

    def test_the_stop_action_routes_to_interrupt(self):
        panel = _build_panel()
        panel._interrupt_speech = MagicMock()
        panel.action_stop_speaking()
        panel._interrupt_speech.assert_called_once()

    def test_the_stop_binding_exists_without_a_vs16_glyph(self):
        binding = next(
            b for b in ChatPanel.BINDINGS if b.action == "stop_speaking"
        )
        assert binding.key == "ctrl+o"
        assert binding.priority is True
        # The stats-bar speaker glyph must not carry the VS16 variant
        # selector that corrupts row rendering in some terminals.
        from servonaut.widgets.chat_panel import _SPEAKER_ACTIVE
        assert "\ufe0f" not in _SPEAKER_ACTIVE

    def test_check_action_keeps_the_stop_binding_always_active(self):
        panel = _build_panel()
        assert panel.check_action("stop_speaking", ()) is True

    def test_send_interrupts_speech_before_dispatching(self):
        panel = _build_panel()
        order = MagicMock()
        panel._interrupt_speech = order.interrupt
        panel.run_worker = order.run_worker
        panel._show_thinking = MagicMock()
        panel._do_send = MagicMock(return_value="job")
        inp = MagicMock()
        inp.text = "hello"
        panel.query_one = MagicMock(return_value=inp)
        panel._send()
        names = [name for name, _args, _kwargs in order.mock_calls]
        assert names.index("interrupt") < names.index("run_worker")

    def test_an_empty_send_does_not_touch_playback(self):
        """Nothing dispatches, so nothing should be interrupted either."""
        panel = _build_panel()
        panel._interrupt_speech = MagicMock()
        inp = MagicMock()
        inp.text = "   "
        panel.query_one = MagicMock(return_value=inp)
        panel._send()
        panel._interrupt_speech.assert_not_called()

    def test_unmount_stops_playback_even_when_idle(self):
        panel = _build_panel()
        panel._recording = False
        panel._starting = False
        panel._stop_spinner = MagicMock()
        panel._interrupt_speech = MagicMock()
        panel.on_unmount()
        panel._interrupt_speech.assert_called_once()


# ---------------------------------------------------------------------------
# Reply-path hooks — generic provider path and the Servonaut SSE path
# ---------------------------------------------------------------------------


class TestSpeakLastReply:

    def test_last_assistant_message_is_offered_to_the_speaker(self):
        panel = _build_panel()
        panel._maybe_speak_reply = MagicMock()
        panel._session = ChatSession(
            id="s1", title="t",
            messages=[ChatMessage(role="assistant", content="All done.")],
        )
        panel._speak_last_reply()
        panel._maybe_speak_reply.assert_called_once_with("All done.")

    def test_a_trailing_user_message_stays_silent(self):
        panel = _build_panel()
        panel._maybe_speak_reply = MagicMock()
        panel._session = ChatSession(
            id="s1", title="t",
            messages=[ChatMessage(role="user", content="hello?")],
        )
        panel._speak_last_reply()
        panel._maybe_speak_reply.assert_not_called()

    def test_no_session_or_messages_stays_silent(self):
        panel = _build_panel()
        panel._maybe_speak_reply = MagicMock()
        panel._speak_last_reply()
        panel._session = ChatSession(id="s1", title="t", messages=[])
        panel._speak_last_reply()
        panel._maybe_speak_reply.assert_not_called()

    @pytest.mark.asyncio
    async def test_generic_send_path_speaks_after_the_turn_settles(self):
        panel = _build_panel()
        panel._active_provider_name = MagicMock(return_value="openai")
        panel._resolve_active_instance = MagicMock(return_value=(None, "hi"))
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._speak_last_reply = MagicMock()
        chat_service = MagicMock()
        chat_service.send_message = AsyncMock(return_value={})
        panel._get_chat_service = MagicMock(return_value=chat_service)
        panel._session = ChatSession(id="s1", title="t", messages=[])
        await panel._do_send("hi")
        panel._speak_last_reply.assert_called_once()

    @pytest.mark.asyncio
    async def test_generic_send_path_speaks_even_after_an_error(self):
        """The finally hook runs either way; the decision function is what
        keeps the Error placeholder silent."""
        panel = _build_panel()
        panel._active_provider_name = MagicMock(return_value="openai")
        panel._resolve_active_instance = MagicMock(return_value=(None, "hi"))
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._speak_last_reply = MagicMock()
        chat_service = MagicMock()
        chat_service.send_message = AsyncMock(side_effect=RuntimeError("down"))
        panel._get_chat_service = MagicMock(return_value=chat_service)
        panel._session = ChatSession(id="s1", title="t", messages=[])
        await panel._do_send("hi")
        panel._speak_last_reply.assert_called_once()
        # The error bubble the except-path appended would be filtered by
        # resolve_spoken_reply's Error: guard.
        assert panel._session.messages[-1].content.startswith("Error:")


class TestServonautFinaliseSpeaks:

    def _panel(self):
        panel = _build_panel()
        panel._hide_thinking = MagicMock()
        panel._refresh_messages = MagicMock()
        panel._maybe_speak_reply = MagicMock()
        panel._session = ChatSession(
            id="s1", title="already titled",
            messages=[ChatMessage(role="user", content="hi")],
        )
        return panel

    def test_streamed_prose_is_spoken(self):
        panel = self._panel()
        panel._finalise_servonaut_turn(MagicMock(), "The disk is fine.")
        panel._maybe_speak_reply.assert_called_once_with("The disk is fine.")

    def test_an_empty_stream_speaks_nothing(self):
        panel = self._panel()
        panel._finalise_servonaut_turn(MagicMock(), "")
        panel._maybe_speak_reply.assert_not_called()

    def test_a_tool_only_turn_speaks_nothing(self):
        panel = self._panel()
        panel._turn_tool_calls = 2
        panel._finalise_servonaut_turn(MagicMock(), "   ")
        panel._maybe_speak_reply.assert_not_called()


# ---------------------------------------------------------------------------
# Settings panel — pure helpers
# ---------------------------------------------------------------------------


class TestTtsHelpers:

    def test_voice_labels_decode_accent_and_gender(self):
        assert tts_voice_label("af_heart") == "af_heart (American female) — default"
        assert tts_voice_label("bm_george") == "bm_george (British male)"
        assert tts_voice_label("bf_emma") == "bf_emma (British female)"
        assert tts_voice_label("am_adam") == "am_adam (American male)"

    @pytest.mark.parametrize("raw,expected", [
        ("1", 1.0), ("1.25", 1.25), ("0.5", 0.5), ("2.0", 2.0),
    ])
    def test_speed_accepts_the_supported_window(self, raw, expected):
        assert parse_tts_speed(raw) == expected

    @pytest.mark.parametrize("raw", ["abc", "0.4", "2.1", "-1", "nan", "inf", ""])
    def test_speed_rejects_everything_else(self, raw):
        with pytest.raises(ValueError):
            parse_tts_speed(raw)

    def test_download_action_states_the_size_up_front(self):
        label, widget_id, variant = tts_model_action(False)
        assert widget_id == "voice_btn_tts_download"
        assert variant == "primary"
        assert "126 MB" in label

    def test_present_model_offers_removal_instead(self):
        label, widget_id, variant = tts_model_action(True)
        assert widget_id == "voice_btn_tts_remove"
        assert variant == "error"
        assert "Remove" in label

    def test_package_note_shows_the_install_extra_when_missing(self):
        assert tts_package_note(True) == "installed"
        assert "servonaut[voice-output]" in tts_package_note(False)

    def test_package_note_prefers_the_method_aware_command(self):
        """A pipx user must see a pipx line, not a wrong-interpreter pip one."""
        command = "pipx inject servonaut sherpa-onnx sounddevice numpy"
        assert tts_package_note(False, command) == command
        assert tts_package_note(True, command) == "installed"

    def test_missing_packages_offer_a_one_click_install(self):
        label, widget_id, variant = tts_package_action(False)
        assert widget_id == "voice_btn_tts_install"
        assert variant == "primary"
        assert "Install" in label

    def test_satisfied_packages_offer_no_install_button(self):
        assert tts_package_action(True) is None

    def test_model_note_reports_disk_use_or_download_cost(self):
        assert "on disk" in tts_model_note(
            True, on_disk=189_455_587, download_hint="unused"
        )
        assert tts_model_note(
            False, on_disk=0, download_hint="~126 MB download"
        ) == "~126 MB download"


# ---------------------------------------------------------------------------
# Settings panel — collect / persist round-trip for the new fields
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


class TestPanelRoundTrip:

    def test_tts_fields_are_collected(self):
        fields = _panel_with(_form(
            tts_enabled=True, tts_voice="bm_george", tts_speed="1.5",
            output_device="USB Speakers",
        )).collect()
        assert fields["tts_enabled"] is True
        assert fields["tts_voice"] == "bm_george"
        assert fields["tts_speed"] == 1.5
        assert fields["output_device"] == "USB Speakers"

    def test_blank_speed_falls_back_to_normal(self):
        assert _panel_with(_form(tts_speed="")).collect()["tts_speed"] == 1.0

    def test_blank_output_device_becomes_none(self):
        assert _panel_with(_form(output_device="")).collect()["output_device"] is None

    @pytest.mark.parametrize("raw", ["fast", "0.1", "9"])
    def test_bad_speed_is_a_validation_error_on_its_own_field(self, raw):
        with pytest.raises(ValidationError) as exc:
            _panel_with(_form(tts_speed=raw)).collect()
        assert exc.value.field_id == "voice_tts_speed"

    def test_tts_fields_are_part_of_dirty_tracking(self):
        values = _panel_with(_form(tts_enabled=True, tts_speed="1.5")).current_values()
        assert values["tts_enabled"] is True
        assert values["tts_speed"] == "1.5"
        assert values["tts_voice"] == "af_heart"
        assert values["output_device"] == ""

    def _persist(self, values, existing=None, *, output_service="mock"):
        panel = _panel_with(values)
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig(
            voice=existing or VoiceConfig()
        )
        if output_service == "mock":
            output_service = MagicMock()
        app.voice_output_service = output_service
        panel._finish_save = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        panel._offer_model_cleanup = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel.persist()
        return panel, app

    def test_persist_writes_the_tts_fields(self):
        _panel, app = self._persist(_form(
            tts_enabled=True, tts_voice="af_nova", tts_speed="0.8",
            output_device="HDMI",
        ))
        saved = app.config_manager.update.call_args.kwargs["voice"]
        assert saved.tts_enabled is True
        assert saved.tts_voice == "af_nova"
        assert saved.tts_speed == 0.8
        assert saved.output_device == "HDMI"

    def test_persist_rebuilds_the_output_service_via_the_factory(self):
        from servonaut.services.voice_output_service import VoiceOutputService
        old = MagicMock()
        _panel, app = self._persist(_form(), output_service=old)
        # close(), not stop(): the old worker thread and any loaded
        # engine must be released, not merely silenced.
        old.close.assert_called_once()
        assert isinstance(app.voice_output_service, VoiceOutputService)
        saved = app.config_manager.update.call_args.kwargs["voice"]
        assert app.voice_output_service._config is saved

    def test_turning_tts_off_offers_model_cleanup(self):
        panel = _panel_with(_form(tts_enabled=False))
        panel._loaded_tts_enabled = True
        _p, _app = self._persist_panel(panel)
        panel._offer_model_cleanup.assert_called_once()

    def test_an_unchanged_tts_switch_offers_no_cleanup(self):
        panel = _panel_with(_form(tts_enabled=False))
        panel._loaded_tts_enabled = False
        _p, _app = self._persist_panel(panel)
        panel._offer_model_cleanup.assert_not_called()

    def _persist_panel(self, panel):
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig(voice=VoiceConfig())
        panel._finish_save = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        panel._offer_model_cleanup = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel.persist()
        return panel, app

    def test_cleanup_inventory_tracks_the_tts_switch(self):
        panel = _panel_with(_form(tts_enabled=True))
        setup = MagicMock()
        setup.stale_models.return_value = []
        panel._setup_service = lambda: setup  # type: ignore[method-assign]
        app = MagicMock()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._offer_model_cleanup()
        assert setup.stale_models.call_args.kwargs["active_tts_enabled"] is True


# ---------------------------------------------------------------------------
# Settings panel — TTS download / remove actions
# ---------------------------------------------------------------------------


class TestTtsSetupActions:

    def _panel_and_service(self):
        panel = _panel_with(_form())
        service = MagicMock()
        service.tts_download_size_hint.return_value = (
            "~126 MB download (~181 MB on disk)"
        )
        panel._setup_service = lambda: service  # type: ignore[method-assign]
        panel._show_download_progress = MagicMock()  # type: ignore[method-assign]
        panel.run_worker = MagicMock()  # type: ignore[method-assign]
        panel._set_actions_enabled = MagicMock()  # type: ignore[method-assign]
        panel._do_tts_download = MagicMock(return_value="job")  # type: ignore[method-assign]
        app = MagicMock()
        return panel, service, app

    def test_download_announces_the_size_before_fetching(self):
        panel, _service, app = self._panel_and_service()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._start_tts_download()
        announced = app.notify.call_args[0][0]
        assert "126 MB" in announced
        panel.run_worker.assert_called_once()
        assert panel.run_worker.call_args.kwargs["group"] == "voice_setup"

    def test_download_is_gated_while_another_action_runs(self):
        panel, _service, app = self._panel_and_service()
        panel._busy = True
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._start_tts_download()
        panel.run_worker.assert_not_called()

    def test_download_without_a_setup_service_is_a_noop(self):
        panel, _service, app = self._panel_and_service()
        panel._setup_service = lambda: None  # type: ignore[method-assign]
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._start_tts_download()
        panel.run_worker.assert_not_called()

    @pytest.mark.asyncio
    async def test_download_worker_reports_and_repaints(self):
        panel = _panel_with(_form())
        panel._hide_download_progress = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        panel._set_actions_enabled = MagicMock()  # type: ignore[method-assign]
        panel._busy = True
        service = MagicMock()
        service.download_tts_model = AsyncMock(
            return_value=(True, "Downloaded the speech model.")
        )
        app = MagicMock()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            await panel._do_tts_download(service)
        assert panel._busy is False
        kwargs = app.notify.call_args.kwargs
        assert kwargs["markup"] is False
        assert kwargs["severity"] == "information"
        panel._refresh_readiness.assert_called_once_with(force=True)
        panel._set_actions_enabled.assert_called_once_with(True)

    @pytest.mark.asyncio
    async def test_download_worker_failure_is_an_error_toast(self):
        panel = _panel_with(_form())
        panel._hide_download_progress = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        panel._set_actions_enabled = MagicMock()  # type: ignore[method-assign]
        service = MagicMock()
        service.download_tts_model = AsyncMock(side_effect=OSError("disk full"))
        app = MagicMock()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            await panel._do_tts_download(service)
        assert panel._busy is False
        kwargs = app.notify.call_args.kwargs
        assert kwargs["severity"] == "error"
        assert kwargs["markup"] is False

    def _kokoro_model(self):
        model = MagicMock()
        model.engine = "kokoro"
        model.label = "Kokoro speech (spoken replies)"
        return model

    def test_remove_deletes_the_kokoro_entry(self):
        panel = _panel_with(_form())
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        service = MagicMock()
        model = self._kokoro_model()
        service.installed_models.return_value = [MagicMock(engine="whisper"), model]
        service.remove_installed.return_value = (True, "removed")
        panel._setup_service = lambda: service  # type: ignore[method-assign]
        app = MagicMock()
        with patch.object(type(panel), "app", property(lambda _self: app)):
            panel._remove_tts_model()
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
            panel._remove_tts_model()
        service.remove_installed.assert_not_called()
        assert "not on disk" in app.notify.call_args[0][0]
