"""Tests for the voice-activity monitor and the conversation-mode knobs.

The monitor's turn-taking logic — the min-speech gate, the trailing-
silence endpoint, the blip filter — lives entirely in the wrapper, so it
is exercised here with a scripted detector stand-in and synthetic
blocks. No audio runtime is installed in CI and none is needed: the real
detector is only asked "is this block speech", and that answer is what
the stand-in scripts.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import patch

import pytest

from servonaut.config.schema import (
    CONVERSATION_IDLE_SECONDS_MAX,
    CONVERSATION_IDLE_SECONDS_MIN,
    VAD_MIN_SPEECH_MS_MAX,
    VAD_MIN_SPEECH_MS_MIN,
    VAD_SILENCE_MS_MAX,
    VAD_SILENCE_MS_MIN,
    VoiceConfig,
)
from servonaut.services.voice_input_service import SAMPLE_RATE
from servonaut.services.voice_vad import (
    SPEECH_STARTED,
    UTTERANCE_ENDED,
    VoiceActivityMonitor,
    VoiceVadError,
    block_sample_count,
    build_voice_activity_monitor,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeDetector:
    """Detector stand-in: the test flips ``speaking`` between feeds."""

    def __init__(self) -> None:
        self.speaking = False
        self.fed = []
        self.reset_calls = 0
        self.flush_calls = 0
        self.queued_segments = 0
        self.fail_on_feed = False

    def accept_waveform(self, samples) -> None:
        if self.fail_on_feed:
            raise RuntimeError("detector fault")
        self.fed.append(samples)

    def is_speech_detected(self) -> bool:
        return self.speaking

    def empty(self) -> bool:
        return self.queued_segments == 0

    def pop(self) -> None:
        self.queued_segments -= 1

    def flush(self) -> None:
        self.flush_calls += 1

    def reset(self) -> None:
        self.reset_calls += 1


def _block(ms: int):
    """A synthetic capture block of *ms* milliseconds of samples."""
    return [0.0] * int(SAMPLE_RATE * ms / 1000)


def _monitor(detector: _FakeDetector, **config_overrides) -> VoiceActivityMonitor:
    config = VoiceConfig(**config_overrides)
    return VoiceActivityMonitor(config, detector_factory=lambda: detector)


def _feed_ms(monitor, detector, *, speaking: bool, ms: int, step_ms: int = 100):
    """Feed *ms* of audio in *step_ms* blocks, collecting all events."""
    detector.speaking = speaking
    events = []
    remaining = ms
    while remaining > 0:
        chunk = min(step_ms, remaining)
        events.extend(monitor.feed(_block(chunk)))
        remaining -= chunk
    return events


# ---------------------------------------------------------------------------
# Turn-taking logic
# ---------------------------------------------------------------------------

class TestMinSpeechGate:

    def test_speech_shorter_than_the_gate_opens_no_turn(self):
        detector = _FakeDetector()
        monitor = _monitor(detector, vad_min_speech_ms=250)
        events = _feed_ms(monitor, detector, speaking=True, ms=100)
        assert events == []
        assert monitor.utterance_in_progress is False

    def test_crossing_the_gate_emits_speech_started_once(self):
        detector = _FakeDetector()
        monitor = _monitor(detector, vad_min_speech_ms=250)
        events = _feed_ms(monitor, detector, speaking=True, ms=600)
        assert events.count(SPEECH_STARTED) == 1
        assert monitor.utterance_in_progress is True

    def test_blips_separated_by_silence_do_not_accumulate(self):
        """A cough now and a clack later must not add up to speech."""
        detector = _FakeDetector()
        monitor = _monitor(detector, vad_min_speech_ms=250)
        for _ in range(5):
            assert _feed_ms(monitor, detector, speaking=True, ms=100) == []
            assert _feed_ms(monitor, detector, speaking=False, ms=100) == []
        assert monitor.utterance_in_progress is False


class TestTrailingSilenceEndpoint:

    def _open_turn(self, monitor, detector):
        events = _feed_ms(monitor, detector, speaking=True, ms=400)
        assert SPEECH_STARTED in events

    def test_silence_shorter_than_the_knob_keeps_the_turn_open(self):
        detector = _FakeDetector()
        monitor = _monitor(detector, vad_min_speech_ms=250, vad_silence_ms=800)
        self._open_turn(monitor, detector)
        events = _feed_ms(monitor, detector, speaking=False, ms=700)
        assert UTTERANCE_ENDED not in events
        assert monitor.utterance_in_progress is True

    def test_enough_silence_ends_the_turn(self):
        detector = _FakeDetector()
        monitor = _monitor(detector, vad_min_speech_ms=250, vad_silence_ms=800)
        self._open_turn(monitor, detector)
        events = _feed_ms(monitor, detector, speaking=False, ms=800)
        assert events.count(UTTERANCE_ENDED) == 1
        assert monitor.utterance_in_progress is False

    def test_speech_inside_the_window_resets_the_silence_count(self):
        """A mid-sentence pause shorter than the knob must not endpoint."""
        detector = _FakeDetector()
        monitor = _monitor(detector, vad_min_speech_ms=250, vad_silence_ms=800)
        self._open_turn(monitor, detector)
        _feed_ms(monitor, detector, speaking=False, ms=700)
        _feed_ms(monitor, detector, speaking=True, ms=100)
        events = _feed_ms(monitor, detector, speaking=False, ms=700)
        assert UTTERANCE_ENDED not in events
        events = _feed_ms(monitor, detector, speaking=False, ms=100)
        assert UTTERANCE_ENDED in events

    def test_a_second_turn_works_after_the_first_ended(self):
        detector = _FakeDetector()
        monitor = _monitor(detector, vad_min_speech_ms=250, vad_silence_ms=800)
        self._open_turn(monitor, detector)
        _feed_ms(monitor, detector, speaking=False, ms=800)
        events = _feed_ms(monitor, detector, speaking=True, ms=400)
        assert SPEECH_STARTED in events
        events = _feed_ms(monitor, detector, speaking=False, ms=800)
        assert UTTERANCE_ENDED in events


class TestFlushAndReset:

    def test_flush_closes_an_open_turn(self):
        detector = _FakeDetector()
        monitor = _monitor(detector, vad_min_speech_ms=250)
        _feed_ms(monitor, detector, speaking=True, ms=400)
        assert monitor.flush() == [UTTERANCE_ENDED]
        assert monitor.utterance_in_progress is False
        assert detector.flush_calls == 1

    def test_flush_without_a_turn_is_silent(self):
        detector = _FakeDetector()
        monitor = _monitor(detector)
        _feed_ms(monitor, detector, speaking=True, ms=100)
        assert monitor.flush() == []

    def test_flush_before_any_feed_never_raises(self):
        assert _monitor(_FakeDetector()).flush() == []

    def test_reset_forgets_everything_and_resets_the_detector(self):
        detector = _FakeDetector()
        monitor = _monitor(detector, vad_min_speech_ms=250)
        _feed_ms(monitor, detector, speaking=True, ms=400)
        monitor.reset()
        assert monitor.utterance_in_progress is False
        assert detector.reset_calls == 1
        # The gate applies afresh after a reset.
        assert _feed_ms(monitor, detector, speaking=True, ms=100) == []

    def test_internal_segments_are_drained(self):
        """The unused detector queue must not grow for the session."""
        detector = _FakeDetector()
        monitor = _monitor(detector)
        detector.queued_segments = 3
        monitor.feed(_block(100))
        assert detector.queued_segments == 0


class TestFailureModes:

    def test_detector_fault_surfaces_as_the_documented_error(self):
        detector = _FakeDetector()
        detector.fail_on_feed = True
        monitor = _monitor(detector)
        with pytest.raises(VoiceVadError):
            monitor.feed(_block(100))

    def test_empty_block_is_a_no_op(self):
        detector = _FakeDetector()
        monitor = _monitor(detector)
        assert monitor.feed([]) == []

    def test_missing_runtime_reports_the_install_extra(self, monkeypatch):
        # sys.modules[name] = None makes ``import name`` raise ImportError.
        monkeypatch.setitem(sys.modules, "sherpa_onnx", None)
        monitor = build_voice_activity_monitor(VoiceConfig())
        with pytest.raises(VoiceVadError) as excinfo:
            monitor.feed(_block(100))
        assert "pip install" in str(excinfo.value)

    def test_missing_model_reports_the_download_step(self, monkeypatch):
        monkeypatch.setitem(
            sys.modules, "sherpa_onnx", types.ModuleType("sherpa_onnx")
        )
        with patch(
            "servonaut.services.voice_vad.is_silero_vad_model_present",
            return_value=False,
        ):
            monitor = build_voice_activity_monitor(VoiceConfig())
            with pytest.raises(VoiceVadError) as excinfo:
                monitor.feed(_block(100))
        assert "not downloaded" in str(excinfo.value)


class TestBlockSampleCount:

    def test_counts_plain_sequences(self):
        assert block_sample_count([0.0] * 5) == 5

    def test_counts_shaped_objects(self):
        class _Shaped:
            shape = (7, 1)
        assert block_sample_count(_Shaped()) == 7

    def test_uncountable_input_degrades_to_zero(self):
        assert block_sample_count(object()) == 0


# ---------------------------------------------------------------------------
# Config knobs
# ---------------------------------------------------------------------------

class TestConversationConfigKnobs:

    def test_defaults(self):
        config = VoiceConfig()
        assert config.conversation_mode is False
        assert config.vad_silence_ms == 800
        assert config.vad_min_speech_ms == 250
        assert config.conversation_idle_seconds == 60
        # Barge-in is the opt-in exception to strict half-duplex; it must
        # never quietly become the default.
        assert config.barge_in is False

    def test_in_range_values_are_preserved(self):
        config = VoiceConfig(
            vad_silence_ms=1200, vad_min_speech_ms=400,
            conversation_idle_seconds=120,
        )
        assert config.vad_silence_ms == 1200
        assert config.vad_min_speech_ms == 400
        assert config.conversation_idle_seconds == 120

    @pytest.mark.parametrize("field,low,high", [
        ("vad_silence_ms", VAD_SILENCE_MS_MIN, VAD_SILENCE_MS_MAX),
        ("vad_min_speech_ms", VAD_MIN_SPEECH_MS_MIN, VAD_MIN_SPEECH_MS_MAX),
        ("conversation_idle_seconds",
         CONVERSATION_IDLE_SECONDS_MIN, CONVERSATION_IDLE_SECONDS_MAX),
    ])
    def test_out_of_range_values_are_clamped(self, field, low, high):
        assert getattr(VoiceConfig(**{field: low - 1}), field) == low
        assert getattr(VoiceConfig(**{field: high + 1}), field) == high

    @pytest.mark.parametrize("field,default", [
        ("vad_silence_ms", 800),
        ("vad_min_speech_ms", 250),
        ("conversation_idle_seconds", 60),
    ])
    def test_non_numeric_values_fall_back_to_the_default(self, field, default):
        assert getattr(VoiceConfig(**{field: "soon"}), field) == default
        assert getattr(VoiceConfig(**{field: float("nan")}), field) == default

    def test_missing_keys_load_as_defaults(self):
        """A pre-conversation-mode config dict must load unchanged."""
        config = VoiceConfig(**{"enabled": True, "engine": "whisper"})
        assert config.conversation_mode is False
        assert config.vad_silence_ms == 800
        assert config.barge_in is False

    def test_barge_in_round_trips(self):
        import dataclasses
        config = VoiceConfig(barge_in=True)
        reloaded = VoiceConfig(**dataclasses.asdict(config))
        assert reloaded.barge_in is True
