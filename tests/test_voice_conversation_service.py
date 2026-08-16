"""Tests for the hands-free conversation loop's state machine.

Everything runs against stand-ins — a fake capture service, a fake
output service, and a scripted voice-activity monitor — so no audio
runtime is needed and CI exercises the same code paths a real
conversation does. The listening loop runs on a real thread, so the
assertions poll with a bounded wait rather than sleeping fixed amounts.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from servonaut.config.schema import VoiceConfig
from servonaut.services.voice_conversation_service import (
    STOP_REASON_ERROR,
    STOP_REASON_IDLE_TIMEOUT,
    STOP_REASON_USER,
    ConversationState,
    VoiceConversationError,
    VoiceConversationService,
)
from servonaut.services.voice_input_service import SAMPLE_RATE, VoiceInputError
from servonaut.services.voice_vad import SPEECH_STARTED, UTTERANCE_ENDED


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeInput:
    """Capture-service stand-in exposing the frame tap the loop needs."""

    def __init__(self, transcripts=("hello there",)) -> None:
        self.transcripts = list(transcripts)
        self.frame_callback = None
        self.recording = False
        self.start_calls = 0
        self.cancel_calls = 0
        self.transcribe_calls = 0
        self.budget_resets = 0
        self.available = True
        self.start_error = None
        self.transcribe_error = None

    def is_available(self) -> bool:
        return self.available

    def unavailable_reason(self) -> str:
        return "" if self.available else "No microphone detected"

    def set_frame_callback(self, callback) -> None:
        self.frame_callback = callback

    def start_recording(self) -> None:
        if self.start_error is not None:
            raise self.start_error
        self.start_calls += 1
        self.recording = True

    def stop_and_transcribe(self, initial_prompt: str = "") -> str:
        self.transcribe_calls += 1
        self.recording = False
        if self.transcribe_error is not None:
            raise self.transcribe_error
        return self.transcripts.pop(0) if self.transcripts else ""

    def cancel_recording(self) -> None:
        self.cancel_calls += 1
        self.recording = False

    def reset_recording_budget(self) -> None:
        self.budget_resets += 1

    @property
    def is_recording(self) -> bool:
        return self.recording


class _TaplessInput(_FakeInput):
    """An input service without the frame tap the loop requires."""

    set_frame_callback = property()  # attribute access raises AttributeError


class _FakeOutput:
    def __init__(self) -> None:
        self.stop_calls = 0

    def stop(self) -> None:
        self.stop_calls += 1


class _ScriptedMonitor:
    """Voice-activity stand-in emitting a scripted event list per feed."""

    def __init__(self, script=None) -> None:
        self.script = list(script or [])
        self.feeds = 0
        self.resets = 0
        self.flushes = 0
        self.utterance_in_progress = False

    def feed(self, block):
        self.feeds += 1
        events = self.script.pop(0) if self.script else []
        if SPEECH_STARTED in events:
            self.utterance_in_progress = True
        if UTTERANCE_ENDED in events:
            self.utterance_in_progress = False
        return events

    def flush(self):
        self.flushes += 1
        if self.utterance_in_progress:
            self.utterance_in_progress = False
            return [UTTERANCE_ENDED]
        return []

    def reset(self) -> None:
        self.resets += 1
        self.utterance_in_progress = False


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class _Events:
    """Recorder for the four UI callbacks."""

    def __init__(self, service) -> None:
        self.states = []
        self.transcripts = []
        self.errors = []
        self.stops = []
        service.set_state_callback(self.states.append)
        service.set_transcript_callback(self.transcripts.append)
        service.set_error_callback(self.errors.append)
        service.set_stopped_callback(self.stops.append)


def _wait_until(predicate, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached within the timeout")


def _make(
    *,
    transcripts=("hello there",),
    monitor=None,
    clock=None,
    input_service=None,
    **config_overrides,
):
    fake_input = input_service if input_service is not None else _FakeInput(transcripts)
    fake_output = _FakeOutput()
    monitor = monitor if monitor is not None else _ScriptedMonitor()
    service = VoiceConversationService(
        VoiceConfig(**config_overrides),
        input_service=lambda: fake_input,
        output_service=lambda: fake_output,
        vad_factory=lambda _config: monitor,
        clock=clock or time.monotonic,
    )
    return service, fake_input, fake_output, monitor


def _start_listening(service, fake_input):
    service.start()
    _wait_until(lambda: fake_input.start_calls >= 1
                and fake_input.frame_callback is not None)


def _feed_block(fake_input, samples: int = 1600) -> None:
    callback = fake_input.frame_callback
    assert callback is not None
    callback([0.0] * samples)


def _drive_to_thinking(service, fake_input):
    """Push one scripted utterance through: LISTENING -> THINKING."""
    _start_listening(service, fake_input)
    for _ in range(3):
        _feed_block(fake_input)
    _wait_until(lambda: service.state is ConversationState.THINKING)


_ONE_UTTERANCE = [[SPEECH_STARTED], [], [UTTERANCE_ENDED]]


# ---------------------------------------------------------------------------
# Starting
# ---------------------------------------------------------------------------

class TestStart:

    def test_start_enters_listening_and_opens_capture(self):
        service, fake_input, _out, _mon = _make()
        events = _Events(service)
        try:
            _start_listening(service, fake_input)
            assert service.state is ConversationState.LISTENING
            assert events.states == [ConversationState.LISTENING]
        finally:
            service.stop()

    def test_double_start_raises(self):
        service, fake_input, _out, _mon = _make()
        try:
            _start_listening(service, fake_input)
            with pytest.raises(VoiceConversationError):
                service.start()
        finally:
            service.stop()

    def test_start_without_an_input_service_raises(self):
        service = VoiceConversationService(
            VoiceConfig(),
            input_service=lambda: None,
            output_service=lambda: None,
            vad_factory=lambda _config: _ScriptedMonitor(),
        )
        with pytest.raises(VoiceConversationError):
            service.start()
        assert service.state is ConversationState.IDLE

    def test_start_with_unavailable_input_names_the_reason(self):
        fake_input = _FakeInput()
        fake_input.available = False
        service, _in, _out, _mon = _make(input_service=fake_input)
        with pytest.raises(VoiceConversationError) as excinfo:
            service.start()
        assert "microphone" in str(excinfo.value)

    def test_start_without_a_frame_tap_raises(self):
        service, _in, _out, _mon = _make(input_service=_TaplessInput())
        with pytest.raises(VoiceConversationError) as excinfo:
            service.start()
        assert "conversation mode" in str(excinfo.value)

    def test_default_vad_path_requires_the_model(self):
        fake_input = _FakeInput()
        service = VoiceConversationService(
            VoiceConfig(),
            input_service=lambda: fake_input,
            output_service=lambda: None,
        )
        with patch(
            "servonaut.services.voice_conversation_service."
            "is_silero_vad_model_present",
            return_value=False,
        ):
            with pytest.raises(VoiceConversationError) as excinfo:
                service.start()
        assert "not downloaded" in str(excinfo.value)

    def test_capture_failure_after_start_lands_in_idle_via_the_error_path(self):
        fake_input = _FakeInput()
        fake_input.start_error = VoiceInputError("Could not open the microphone")
        service, _in, _out, _mon = _make(input_service=fake_input)
        events = _Events(service)
        service.start()
        _wait_until(lambda: service.state is ConversationState.IDLE
                    and events.stops == [STOP_REASON_ERROR])
        assert any("microphone" in message for message in events.errors)


# ---------------------------------------------------------------------------
# The normal loop
# ---------------------------------------------------------------------------

class TestUtteranceFlow:

    def test_endpoint_transcribes_and_enters_thinking(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        events = _Events(service)
        _drive_to_thinking(service, fake_input)
        assert events.transcripts == ["hello there"]
        assert events.states == [
            ConversationState.LISTENING, ConversationState.THINKING,
        ]
        # Half-duplex: the mic is fully closed before THINKING is reported.
        assert fake_input.recording is False
        assert fake_input.frame_callback is None

    def test_empty_transcript_resumes_listening_without_firing(self):
        monitor = _ScriptedMonitor([[SPEECH_STARTED], [UTTERANCE_ENDED]])
        service, fake_input, _out, _mon = _make(
            transcripts=("",), monitor=monitor,
        )
        events = _Events(service)
        try:
            _start_listening(service, fake_input)
            _feed_block(fake_input)
            _feed_block(fake_input)
            _wait_until(lambda: fake_input.start_calls == 2)
            assert service.state is ConversationState.LISTENING
            assert events.transcripts == []
            assert monitor.resets >= 1
        finally:
            service.stop()

    def test_transcription_failure_reports_and_stops(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        fake_input = _FakeInput()
        fake_input.transcribe_error = VoiceInputError("Transcription failed: boom")
        service, _in, _out, _mon = _make(input_service=fake_input, monitor=monitor)
        events = _Events(service)
        _start_listening(service, fake_input)
        for _ in range(3):
            _feed_block(fake_input)
        _wait_until(lambda: service.state is ConversationState.IDLE)
        assert events.stops == [STOP_REASON_ERROR]
        assert any("Transcription failed" in message for message in events.errors)

    def test_runaway_speech_is_endpointed_at_the_recording_cap(self):
        """Continuous noise must not hold the turn (and mic) open forever."""
        monitor = _ScriptedMonitor([[SPEECH_STARTED]])
        service, fake_input, _out, _mon = _make(
            monitor=monitor, max_recording_seconds=1,
        )
        events = _Events(service)
        _start_listening(service, fake_input)
        # 2 blocks x 16000 samples cross the 1s cap without any endpoint.
        _feed_block(fake_input, samples=SAMPLE_RATE)
        _feed_block(fake_input, samples=SAMPLE_RATE)
        _wait_until(lambda: service.state is ConversationState.THINKING)
        assert monitor.flushes >= 1
        assert events.transcripts == ["hello there"]

    def test_speech_start_restarts_the_capture_budget(self):
        """The capture services budget max_recording_seconds from
        mic-open, pre-turn silence included; the loop must restart that
        budget when speech begins or an utterance late in the idle window
        is silently truncated at the wall-clock cap."""
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        _drive_to_thinking(service, fake_input)
        assert fake_input.budget_resets >= 1

    def test_an_input_without_the_budget_hook_still_works(self):
        """The reset is duck-typed: an input service without the hook
        (or with a non-callable in its place) must not break the loop."""

        class _BudgetlessInput(_FakeInput):
            reset_recording_budget = None  # not callable — must be skipped

        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(
            monitor=monitor, input_service=_BudgetlessInput(),
        )
        _drive_to_thinking(service, fake_input)

    def test_a_raising_ui_callback_does_not_kill_the_loop(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        service.set_state_callback(lambda _state: (_ for _ in ()).throw(RuntimeError))
        transcripts = []
        service.set_transcript_callback(transcripts.append)
        _drive_to_thinking(service, fake_input)
        assert transcripts == ["hello there"]


# ---------------------------------------------------------------------------
# Idle timeout
# ---------------------------------------------------------------------------

class TestIdleTimeout:

    def test_no_speech_for_the_idle_window_stops_with_the_distinct_reason(self):
        clock = _FakeClock()
        service, fake_input, _out, _mon = _make(clock=clock)
        events = _Events(service)
        _start_listening(service, fake_input)
        clock.now = 61.0
        _wait_until(lambda: service.state is ConversationState.IDLE)
        assert events.stops == [STOP_REASON_IDLE_TIMEOUT]
        assert events.errors == []
        assert fake_input.cancel_calls >= 1

    def test_an_open_turn_suspends_the_idle_timeout(self):
        clock = _FakeClock()
        monitor = _ScriptedMonitor([[SPEECH_STARTED]])
        service, fake_input, _out, _mon = _make(clock=clock, monitor=monitor)
        try:
            _start_listening(service, fake_input)
            _feed_block(fake_input)
            _wait_until(lambda: monitor.feeds >= 1)
            clock.now = 1000.0
            time.sleep(0.3)  # give the loop several poll cycles to misbehave
            assert service.state is ConversationState.LISTENING
        finally:
            service.stop()


# ---------------------------------------------------------------------------
# UI-driven transitions
# ---------------------------------------------------------------------------

class TestReplyAndSpeaking:

    def test_reply_started_closes_the_mic_and_enters_thinking(self):
        service, fake_input, _out, _mon = _make()
        events = _Events(service)
        _start_listening(service, fake_input)
        service.reply_started()
        assert service.state is ConversationState.THINKING
        assert fake_input.cancel_calls >= 1
        assert events.states[-1] is ConversationState.THINKING

    def test_reply_started_is_a_noop_when_idle(self):
        service, _in, _out, _mon = _make()
        events = _Events(service)
        service.reply_started()
        assert service.state is ConversationState.IDLE
        assert events.states == []

    def test_speaking_started_moves_thinking_to_speaking(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        try:
            _drive_to_thinking(service, fake_input)
            service.speaking_started()
            assert service.state is ConversationState.SPEAKING
        finally:
            service.stop()

    def test_speaking_started_is_a_noop_while_listening(self):
        service, fake_input, _out, _mon = _make()
        try:
            _start_listening(service, fake_input)
            service.speaking_started()
            assert service.state is ConversationState.LISTENING
        finally:
            service.stop()

    def test_speaking_finished_reopens_the_mic(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        try:
            _drive_to_thinking(service, fake_input)
            service.speaking_started()
            service.speaking_finished()
            _wait_until(lambda: fake_input.start_calls == 2)
            assert service.state is ConversationState.LISTENING
        finally:
            service.stop()

    def test_reply_finished_reopens_the_mic_when_nothing_was_spoken(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        try:
            _drive_to_thinking(service, fake_input)
            service.reply_finished()
            _wait_until(lambda: fake_input.start_calls == 2)
            assert service.state is ConversationState.LISTENING
        finally:
            service.stop()

    def test_reply_finished_is_a_noop_while_speaking(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        try:
            _drive_to_thinking(service, fake_input)
            service.speaking_started()
            service.reply_finished()
            assert service.state is ConversationState.SPEAKING
        finally:
            service.stop()

    def test_reply_started_while_speaking_cuts_playback_and_enters_thinking(self):
        """A typed send while the reply is being read aloud supersedes it:
        playback stops, the machine lands in THINKING, and the mic stays
        closed. Without this edge the superseded playback's
        speaking_finished would reopen the microphone under the new turn."""
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, fake_output, _mon = _make(monitor=monitor)
        events = _Events(service)
        try:
            _drive_to_thinking(service, fake_input)
            service.speaking_started()
            service.reply_started()
            assert service.state is ConversationState.THINKING
            assert fake_output.stop_calls >= 1
            # No new listening session was opened: half-duplex holds.
            assert fake_input.start_calls == 1
            assert events.states[-1] is ConversationState.THINKING
        finally:
            service.stop()

    def test_a_superseded_speaking_finished_cannot_reopen_the_mic(self):
        """The old speak worker's speaking_finished lands AFTER a typed
        send moved the loop to THINKING — it must be a no-op, or the mic
        would reopen while the new turn streams."""
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        try:
            _drive_to_thinking(service, fake_input)
            service.speaking_started()
            service.reply_started()      # typed send supersedes the reply
            service.speaking_finished()  # old playback winding down
            assert service.state is ConversationState.THINKING
            assert fake_input.start_calls == 1
        finally:
            service.stop()

    def test_a_full_two_turn_conversation(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE) + list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(
            transcripts=("first turn", "second turn"), monitor=monitor,
        )
        events = _Events(service)
        try:
            _drive_to_thinking(service, fake_input)
            service.speaking_started()
            service.speaking_finished()
            _wait_until(lambda: fake_input.start_calls == 2)
            for _ in range(3):
                _feed_block(fake_input)
            _wait_until(lambda: len(events.transcripts) == 2)
            assert events.transcripts == ["first turn", "second turn"]
            assert service.state is ConversationState.THINKING
        finally:
            service.stop()


# ---------------------------------------------------------------------------
# Interrupt
# ---------------------------------------------------------------------------

class TestInterrupt:

    def test_interrupt_while_speaking_stops_playback_and_listens(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, fake_output, _mon = _make(monitor=monitor)
        try:
            _drive_to_thinking(service, fake_input)
            service.speaking_started()
            service.interrupt()
            _wait_until(lambda: fake_input.start_calls == 2)
            assert service.state is ConversationState.LISTENING
            assert fake_output.stop_calls >= 1
        finally:
            service.stop()

    def test_interrupt_while_thinking_abandons_the_reply(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        try:
            _drive_to_thinking(service, fake_input)
            service.interrupt()
            _wait_until(lambda: fake_input.start_calls == 2)
            assert service.state is ConversationState.LISTENING
        finally:
            service.stop()

    def test_interrupt_is_a_noop_when_idle(self):
        service, _in, fake_output, _mon = _make()
        service.interrupt()
        assert service.state is ConversationState.IDLE
        assert fake_output.stop_calls == 0

    def test_interrupt_is_a_noop_while_listening(self):
        service, fake_input, fake_output, _mon = _make()
        try:
            _start_listening(service, fake_input)
            service.interrupt()
            assert service.state is ConversationState.LISTENING
            assert fake_output.stop_calls == 0
        finally:
            service.stop()


# ---------------------------------------------------------------------------
# Stopping
# ---------------------------------------------------------------------------

class TestStop:

    def test_stop_while_listening_cleans_up_and_reports_the_user_reason(self):
        service, fake_input, fake_output, _mon = _make()
        events = _Events(service)
        _start_listening(service, fake_input)
        service.stop()
        assert service.state is ConversationState.IDLE
        assert events.stops == [STOP_REASON_USER]
        assert fake_input.cancel_calls >= 1
        assert fake_output.stop_calls >= 1
        assert fake_input.frame_callback is None

    def test_stop_without_join_still_lands_idle_and_cancels_capture(self):
        """join=False is the UI-thread teardown path: the listener thread
        is signalled but not waited for, and everything else — capture
        cancelled, IDLE reported with the user reason — is unchanged. The
        session-generation checks make the thread's late completion
        harmless, so nothing further is owed."""
        service, fake_input, fake_output, _mon = _make()
        events = _Events(service)
        _start_listening(service, fake_input)
        service.stop(join=False)
        assert service.state is ConversationState.IDLE
        assert events.stops == [STOP_REASON_USER]
        assert fake_input.cancel_calls >= 1
        assert fake_output.stop_calls >= 1

    def test_stop_while_thinking(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        _drive_to_thinking(service, fake_input)
        service.stop()
        assert service.state is ConversationState.IDLE

    def test_stop_while_speaking(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, fake_output, _mon = _make(monitor=monitor)
        _drive_to_thinking(service, fake_input)
        service.speaking_started()
        service.stop()
        assert service.state is ConversationState.IDLE
        assert fake_output.stop_calls >= 1

    def test_stop_when_idle_fires_nothing(self):
        service, _in, _out, _mon = _make()
        events = _Events(service)
        service.stop()
        assert events.stops == []
        assert events.states == []

    def test_frames_after_stop_are_ignored(self):
        """A tap invocation racing the shutdown must go nowhere."""
        monitor = _ScriptedMonitor()
        service, fake_input, _out, _mon = _make(monitor=monitor)
        _start_listening(service, fake_input)
        callback = fake_input.frame_callback
        service.stop()
        feeds_before = monitor.feeds
        callback([0.0] * 1600)
        time.sleep(0.1)
        assert monitor.feeds == feeds_before

    def test_restart_after_stop_works(self):
        service, fake_input, _out, _mon = _make()
        try:
            _start_listening(service, fake_input)
            service.stop()
            service.start()
            _wait_until(lambda: fake_input.start_calls == 2)
            assert service.state is ConversationState.LISTENING
        finally:
            service.stop()


# ---------------------------------------------------------------------------
# Barge-in (opt-in, SPEAKING only)
# ---------------------------------------------------------------------------

class TestBargeIn:
    """The headphones-mode exception to strict half-duplex.

    With ``barge_in`` on, SPEAKING opens a detection-only capture whose
    sustained-speech event drives interrupt(); with it off (the default)
    the microphone must stay fully closed during SPEAKING — asserted
    here so the exception can never quietly become the rule.
    """

    def _drive_to_speaking(self, service, fake_input):
        _drive_to_thinking(service, fake_input)
        service.speaking_started()
        assert service.state is ConversationState.SPEAKING

    def test_default_off_keeps_the_mic_fully_closed_while_speaking(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor)
        try:
            self._drive_to_speaking(service, fake_input)
            time.sleep(0.2)
            # No new capture was opened and no tap registered: strict
            # half-duplex holds exactly as before barge-in existed.
            assert fake_input.start_calls == 1
            assert fake_input.frame_callback is None
            assert fake_input.recording is False
        finally:
            service.stop()

    def test_speech_during_speaking_interrupts_playback(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE) + [[SPEECH_STARTED]])
        service, fake_input, fake_output, _mon = _make(
            monitor=monitor, barge_in=True,
        )
        try:
            self._drive_to_speaking(service, fake_input)
            # The barge monitor opens its own capture session.
            _wait_until(lambda: fake_input.frame_callback is not None
                        and fake_input.start_calls == 2)
            _feed_block(fake_input)
            _wait_until(lambda: service.state is ConversationState.LISTENING)
            assert fake_output.stop_calls >= 1
            # The barge capture was cancelled (never transcribed) before
            # the fresh listening session opened.
            assert fake_input.transcribe_calls == 1  # only the original turn
            assert fake_input.cancel_calls >= 1
        finally:
            service.stop()

    def test_non_speech_noise_does_not_interrupt(self):
        """The min-speech gate is the anti-false-barge filter: frames
        that never amount to SPEECH_STARTED must leave SPEAKING alone."""
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE) + [[], [], []])
        service, fake_input, fake_output, _mon = _make(
            monitor=monitor, barge_in=True,
        )
        try:
            self._drive_to_speaking(service, fake_input)
            _wait_until(lambda: fake_input.frame_callback is not None)
            for _ in range(3):
                _feed_block(fake_input)
            time.sleep(0.2)
            assert service.state is ConversationState.SPEAKING
            assert fake_output.stop_calls == 0
        finally:
            service.stop()

    def test_speaking_finished_retires_the_barge_monitor(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor, barge_in=True)
        try:
            self._drive_to_speaking(service, fake_input)
            _wait_until(lambda: fake_input.frame_callback is not None
                        and fake_input.start_calls == 2)
            service.speaking_finished()
            _wait_until(lambda: service.state is ConversationState.LISTENING)
            # The fresh LISTENING session owns the stream alone: the barge
            # session is gone and only one capture is live.
            assert service._barge_session is None
            assert fake_input.start_calls == 3
        finally:
            service.stop()

    def test_reply_started_while_speaking_retires_the_barge_monitor(self):
        """A typed send superseding the spoken reply closes the barge
        capture along with the playback it was watching."""
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, fake_output, _mon = _make(
            monitor=monitor, barge_in=True,
        )
        try:
            self._drive_to_speaking(service, fake_input)
            _wait_until(lambda: fake_input.frame_callback is not None
                        and fake_input.start_calls == 2)
            service.reply_started()
            assert service.state is ConversationState.THINKING
            assert service._barge_session is None
            assert fake_output.stop_calls >= 1
            # Half-duplex restored: no capture is live in THINKING.
            assert fake_input.recording is False
        finally:
            service.stop()

    def test_stop_while_speaking_retires_the_barge_monitor(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor, barge_in=True)
        self._drive_to_speaking(service, fake_input)
        _wait_until(lambda: fake_input.frame_callback is not None
                    and fake_input.start_calls == 2)
        service.stop()
        assert service.state is ConversationState.IDLE
        assert service._barge_session is None
        assert fake_input.recording is False

    def test_a_failing_barge_capture_degrades_to_plain_speaking(self):
        """Barge-in is a convenience on top of a working reply: capture
        failure must not disturb SPEAKING or surface an error."""
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        service, fake_input, _out, _mon = _make(monitor=monitor, barge_in=True)
        events = _Events(service)
        try:
            _drive_to_thinking(service, fake_input)
            fake_input.start_error = VoiceInputError("mic vanished")
            service.speaking_started()
            time.sleep(0.2)
            assert service.state is ConversationState.SPEAKING
            assert events.errors == []
            assert service._barge_session is None
        finally:
            fake_input.start_error = None
            service.stop()

    def test_a_failing_monitor_build_degrades_to_plain_speaking(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE))
        fake_input = _FakeInput()
        calls = {"n": 0}

        def _factory(_config):
            calls["n"] += 1
            if calls["n"] >= 2:  # the barge monitor build
                raise RuntimeError("model unloadable")
            return monitor

        service = VoiceConversationService(
            VoiceConfig(barge_in=True),
            input_service=lambda: fake_input,
            output_service=lambda: _FakeOutput(),
            vad_factory=_factory,
        )
        events = _Events(service)
        try:
            _drive_to_thinking(service, fake_input)
            service.speaking_started()
            time.sleep(0.2)
            assert service.state is ConversationState.SPEAKING
            assert events.errors == []
        finally:
            service.stop()

    def test_a_detector_fault_mid_barge_degrades_without_killing_speaking(self):
        from servonaut.services.voice_vad import VoiceVadError

        class _FaultyMonitor(_ScriptedMonitor):
            def feed(self, block):
                raise VoiceVadError("detector died")

        monitors = [_ScriptedMonitor(list(_ONE_UTTERANCE)), _FaultyMonitor()]
        fake_input = _FakeInput()
        service = VoiceConversationService(
            VoiceConfig(barge_in=True),
            input_service=lambda: fake_input,
            output_service=lambda: _FakeOutput(),
            vad_factory=lambda _config: monitors.pop(0),
        )
        events = _Events(service)
        try:
            _drive_to_thinking(service, fake_input)
            service.speaking_started()
            _wait_until(lambda: fake_input.frame_callback is not None)
            _feed_block(fake_input)
            _wait_until(lambda: service._barge_session is None)
            assert service.state is ConversationState.SPEAKING
            assert events.errors == []
        finally:
            service.stop()

    def test_barge_speech_is_never_transcribed(self):
        monitor = _ScriptedMonitor(list(_ONE_UTTERANCE) + [[SPEECH_STARTED]])
        service, fake_input, _out, _mon = _make(monitor=monitor, barge_in=True)
        try:
            self._drive_to_speaking(service, fake_input)
            _wait_until(lambda: fake_input.frame_callback is not None
                        and fake_input.start_calls == 2)
            transcribes_before = fake_input.transcribe_calls
            _feed_block(fake_input)
            _wait_until(lambda: service.state is ConversationState.LISTENING)
            assert fake_input.transcribe_calls == transcribes_before
        finally:
            service.stop()
