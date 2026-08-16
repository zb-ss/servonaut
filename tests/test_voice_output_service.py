"""Tests for spoken replies: config knobs, model registry, output service.

CI has none of the optional audio libraries, so — exactly like the voice
input tests — every import-dependent path runs against stand-ins patched
into the service's module globals, and the synthesis engine is a hand
rolled fake rather than a MagicMock so unexpected API usage fails loudly.
"""

from __future__ import annotations

import dataclasses
import threading
import time
import types
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

import servonaut.services.voice_engines as voice_engines
import servonaut.services.voice_output_service as vos
from servonaut.config.schema import VoiceConfig
from servonaut.services.interfaces import VoiceOutputServiceInterface
from servonaut.services.voice_engines import (
    DEFAULT_TTS_VOICE,
    KOKORO_ARCHIVE_BYTES,
    KOKORO_ARCHIVE_URL,
    KOKORO_DISK_BYTES,
    KOKORO_MODEL_ID,
    KOKORO_REQUIRED_FILES,
    KOKORO_VOICES,
    build_voice_output_service,
    is_kokoro_model_present,
    kokoro_model_dir,
    kokoro_voice_sid,
)
from servonaut.services.voice_output_service import (
    VoiceOutputError,
    VoiceOutputService,
)


# ---------------------------------------------------------------------------
# Config knobs
# ---------------------------------------------------------------------------

class TestVoiceConfigTTS:

    def test_defaults(self):
        config = VoiceConfig()
        assert config.tts_enabled is False
        assert config.tts_voice == DEFAULT_TTS_VOICE
        assert config.tts_speed == 1.0
        assert config.output_device is None

    @pytest.mark.parametrize("given,expected", [
        (1.0, 1.0),
        (0.5, 0.5),
        (2.0, 2.0),
        (5.0, 2.0),
        (0.1, 0.5),
        (-3, 0.5),
        ("not a number", 1.0),
        (None, 1.0),
        # NaN defeats a plain min/max clamp (every comparison is False)
        # and json.load accepts the literal from a hand-edited config —
        # regression guard for the finite-number fallback.
        (float("nan"), 1.0),
        (float("inf"), 1.0),
        (float("-inf"), 1.0),
    ])
    def test_tts_speed_is_clamped(self, given, expected):
        assert VoiceConfig(tts_speed=given).tts_speed == expected

    def test_round_trip_preserves_the_new_fields(self):
        """Serialise → deserialise, the path every config save takes."""
        config = VoiceConfig(
            tts_enabled=True, tts_voice="am_adam",
            tts_speed=1.5, output_device="USB Speakers",
        )
        reloaded = VoiceConfig(**dataclasses.asdict(config))
        assert reloaded.tts_enabled is True
        assert reloaded.tts_voice == "am_adam"
        assert reloaded.tts_speed == 1.5
        assert reloaded.output_device == "USB Speakers"

    def test_old_configs_without_the_fields_load_with_defaults(self):
        """The manager passes stored dicts straight to the dataclass, so a
        pre-TTS config must construct cleanly — no migration needed."""
        old = {"enabled": True, "engine": "whisper", "model_size": "small"}
        config = VoiceConfig(**old)
        assert config.tts_enabled is False
        assert config.tts_speed == 1.0

    def test_unknown_voice_is_kept_as_given(self):
        """Fallback happens at playback time, not by rewriting the config."""
        assert VoiceConfig(tts_voice="af_new_in_v2").tts_voice == "af_new_in_v2"


# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------

class TestKokoroRegistry:

    def test_model_dir_lives_under_the_voice_model_root(self):
        assert kokoro_model_dir() == voice_engines.VOICE_MODEL_ROOT / KOKORO_MODEL_ID

    def test_archive_url_is_https_and_pinned_to_the_model_id(self):
        # Pinning the host and project path (not just "https") means a
        # download-source change has to be a deliberate, reviewed edit.
        assert KOKORO_ARCHIVE_URL.startswith(
            "https://github.com/k2-fsa/sherpa-onnx/releases/download/"
        )
        assert KOKORO_MODEL_ID in KOKORO_ARCHIVE_URL

    def test_size_constants_are_plausible(self):
        assert 0 < KOKORO_ARCHIVE_BYTES < KOKORO_DISK_BYTES

    def test_default_voice_is_in_the_roster(self):
        assert DEFAULT_TTS_VOICE in KOKORO_VOICES

    def test_voice_sids_are_unique(self):
        assert len(set(KOKORO_VOICES.values())) == len(KOKORO_VOICES)

    def test_known_voice_resolves_to_its_sid(self):
        assert kokoro_voice_sid("am_adam") == KOKORO_VOICES["am_adam"]

    def test_unknown_voice_falls_back_to_the_default(self):
        assert kokoro_voice_sid("no_such_voice") == KOKORO_VOICES[DEFAULT_TTS_VOICE]

    def test_absent_model_dir_is_not_present(self, tmp_path, monkeypatch):
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path)
        assert is_kokoro_model_present() is False

    def test_complete_file_set_is_present(self, tmp_path, monkeypatch):
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path)
        _make_kokoro_model(tmp_path)
        assert is_kokoro_model_present() is True

    def test_a_missing_file_reads_as_absent(self, tmp_path, monkeypatch):
        """An interrupted extraction must not read as an installed model."""
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path)
        _make_kokoro_model(tmp_path)
        (tmp_path / KOKORO_MODEL_ID / "voices.bin").unlink()
        assert is_kokoro_model_present() is False

    def test_factory_builds_an_interface_implementation(self):
        service = build_voice_output_service(VoiceConfig())
        assert isinstance(service, VoiceOutputService)
        assert isinstance(service, VoiceOutputServiceInterface)


def _make_kokoro_model(root):
    """Write the full required file set under *root*."""
    model_dir = root / KOKORO_MODEL_ID
    for name in KOKORO_REQUIRED_FILES:
        path = model_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
    return model_dir


# ---------------------------------------------------------------------------
# Output service fakes
# ---------------------------------------------------------------------------

class _FakeAudio:
    """What the fake engine's generate() returns."""

    def __init__(self, samples, sample_rate=24000):
        self.samples = samples
        self.sample_rate = sample_rate


class _FakeTts:
    """Hand-rolled synthesis engine: records calls, honours the callback."""

    def __init__(self, samples_per_call=8, fail_with: Optional[str] = None):
        self.calls: list = []
        self.samples_per_call = samples_per_call
        self.fail_with = fail_with
        self.sample_rate = 24000

    def generate(self, text, sid=0, speed=1.0, callback=None):
        self.calls.append({"text": text, "sid": sid, "speed": speed})
        if self.fail_with:
            raise RuntimeError(self.fail_with)
        if callback is not None and callback([0.0], 0.5) == 0:
            return _FakeAudio([])
        return _FakeAudio([0.1] * self.samples_per_call)


class _FakeStream:
    """Output stream stand-in that records every write."""

    def __init__(self):
        self.written: list = []
        self.aborted = False
        self.closed = False
        self.block_event: Optional[threading.Event] = None

    def start(self):
        pass

    def write(self, chunk):
        if self.block_event is not None:
            self.block_event.wait(timeout=5)
        self.written.append(list(chunk))

    def abort(self):
        self.aborted = True

    def stop(self):
        pass

    def close(self):
        self.closed = True


class _FakeNumpy:
    """Just enough numpy for the playback path."""

    class _Array(list):
        def reshape(self, *_args):
            return self

        def __getitem__(self, item):
            result = list.__getitem__(self, item)
            return _FakeNumpy._Array(result) if isinstance(item, slice) else result

    @staticmethod
    def asarray(values, dtype=None):
        return _FakeNumpy._Array(values)


def _make_sd(streams=None, devices=None):
    """A sounddevice stand-in whose OutputStream returns queued fakes."""
    if devices is None:
        devices = [{"max_output_channels": 2, "name": "Fake Speakers"}]
    sd = types.SimpleNamespace()
    sd.query_devices = MagicMock(return_value=devices)
    created = streams if streams is not None else []

    def _output_stream(**kwargs):
        stream = _FakeStream()
        stream.kwargs = kwargs
        created.append(stream)
        return stream

    sd.OutputStream = _output_stream
    sd.created_streams = created
    return sd


@pytest.fixture
def tts_env(monkeypatch, tmp_path):
    """Deps importable, model on disk, one fake output device."""
    monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path)
    _make_kokoro_model(tmp_path)
    sd = _make_sd()
    monkeypatch.setattr(vos, "HAS_TTS_DEPS", True)
    monkeypatch.setattr(vos, "sd", sd)
    monkeypatch.setattr(vos, "np", _FakeNumpy)
    monkeypatch.setattr(vos, "sherpa_onnx", MagicMock(name="sherpa_onnx"))
    return sd


def _service(config=None, engine=None) -> VoiceOutputService:
    service = VoiceOutputService(config or VoiceConfig())
    if engine is not None:
        service._tts = engine
    return service


def _wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------

class TestAvailability:

    def test_missing_deps_yield_the_install_hint(self, monkeypatch):
        monkeypatch.setattr(vos, "HAS_TTS_DEPS", False)
        monkeypatch.setattr(vos, "reload_tts_deps", lambda: False)
        service = _service()
        assert service.is_available() is False
        assert "pip install" in service.unavailable_reason()

    def test_missing_deps_verdict_is_not_cached(self, monkeypatch, tmp_path):
        """An install outside the app must flip the verdict without a reset."""
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path)
        _make_kokoro_model(tmp_path)
        monkeypatch.setattr(vos, "HAS_TTS_DEPS", False)
        monkeypatch.setattr(vos, "reload_tts_deps", lambda: False)
        service = _service()
        assert service.is_available() is False

        monkeypatch.setattr(vos, "HAS_TTS_DEPS", True)
        monkeypatch.setattr(vos, "sd", _make_sd())
        assert service.is_available() is True

    def test_missing_model_yields_the_model_hint(self, monkeypatch, tmp_path):
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path)
        monkeypatch.setattr(vos, "HAS_TTS_DEPS", True)
        service = _service()
        assert service.is_available() is False
        assert "model" in service.unavailable_reason().lower()

    def test_missing_model_verdict_is_not_cached(self, tts_env, monkeypatch, tmp_path):
        """The download button changes this mid-session."""
        service = _service()
        assert service.is_available() is True
        # Remove one required file: presence must flip without a reset.
        (tmp_path / KOKORO_MODEL_ID / "tokens.txt").unlink()
        assert service.is_available() is False

    def test_no_output_device_is_reported(self, monkeypatch, tmp_path):
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path)
        _make_kokoro_model(tmp_path)
        monkeypatch.setattr(vos, "HAS_TTS_DEPS", True)
        monkeypatch.setattr(
            vos, "sd",
            _make_sd(devices=[{"max_output_channels": 0, "name": "Mic"}]),
        )
        service = _service()
        assert service.is_available() is False
        assert "output device" in service.unavailable_reason()

    def test_device_verdict_is_cached_until_reset(self, tts_env):
        service = _service()
        service.is_available()
        service.is_available()
        assert tts_env.query_devices.call_count == 1
        service.reset_availability()
        service.is_available()
        assert tts_env.query_devices.call_count == 2

    def test_available_reason_is_empty(self, tts_env):
        service = _service()
        assert service.is_available() is True
        assert service.unavailable_reason() == ""


# ---------------------------------------------------------------------------
# Speaking
# ---------------------------------------------------------------------------

class TestSpeak:

    def test_speak_raises_when_unavailable(self, monkeypatch):
        monkeypatch.setattr(vos, "HAS_TTS_DEPS", False)
        monkeypatch.setattr(vos, "reload_tts_deps", lambda: False)
        with pytest.raises(VoiceOutputError):
            _service().speak("hello")

    def test_speak_synthesises_and_plays(self, tts_env):
        engine = _FakeTts(samples_per_call=10)
        service = _service(engine=engine)
        service.speak("Disk usage is fine.")
        assert engine.calls[0]["text"] == "Disk usage is fine."
        assert len(tts_env.created_streams) == 1
        played = [s for chunk in tts_env.created_streams[0].written for s in chunk]
        assert len(played) == 10
        # The stream persists between sentences (closing it per sentence
        # put an audible gap on every boundary); close() releases it.
        assert tts_env.created_streams[0].closed is False
        assert service.is_speaking() is False
        service.close()
        _wait_until(lambda: tts_env.created_streams[0].closed)
        assert tts_env.created_streams[0].closed is True

    def test_consecutive_sentences_share_one_stream(self, tts_env):
        """No per-sentence device open: the whole reply uses one stream."""
        engine = _FakeTts(samples_per_call=10)
        service = _service(engine=engine)
        service.speak("First sentence.")
        service.speak("Second sentence.")
        assert len(engine.calls) == 2
        assert len(tts_env.created_streams) == 1

    def test_next_sentence_synthesises_while_current_plays(self, tts_env):
        """The pipeline's whole point: the listener never waits out the
        NEXT sentence's synthesis as dead air between sentences."""
        engine = _FakeTts(samples_per_call=10)
        service = _service(engine=engine)
        playback_gate = threading.Event()

        # Every stream blocks its writes until the gate opens, so the
        # first sentence is guaranteed to still be "playing" when the
        # second is produced — no timing luck involved.
        original_output_stream = tts_env.OutputStream

        def _blocked_stream(**kwargs):
            stream = original_output_stream(**kwargs)
            stream.block_event = playback_gate
            return stream

        tts_env.OutputStream = _blocked_stream

        service.enqueue("First sentence.")
        service.enqueue("Second sentence.")
        # With playback stalled, the second sentence must still reach the
        # engine — synthesis running ahead is the pacing guarantee.
        assert _wait_until(lambda: len(engine.calls) == 2)
        playback_gate.set()
        assert _wait_until(lambda: not service.is_speaking())

    def test_speak_cleans_markdown_before_synthesis(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        service.speak("**Bold** claim.\n```\ncode\n```")
        spoken = engine.calls[0]["text"]
        assert "**" not in spoken
        assert "code\n" not in spoken

    def test_speak_with_nothing_speakable_is_a_silent_noop(self, monkeypatch):
        """No availability check either — nothing was going to be said."""
        monkeypatch.setattr(vos, "HAS_TTS_DEPS", False)
        monkeypatch.setattr(vos, "reload_tts_deps", lambda: False)
        service = _service()
        service.speak("   ")  # must not raise despite unavailability
        assert service.is_speaking() is False

    def test_speak_resolves_the_configured_voice(self, tts_env):
        engine = _FakeTts()
        service = _service(VoiceConfig(tts_voice="bm_george"), engine=engine)
        service.speak("hello")
        assert engine.calls[0]["sid"] == KOKORO_VOICES["bm_george"]

    def test_unknown_voice_falls_back_to_the_default_sid(self, tts_env):
        engine = _FakeTts()
        service = _service(VoiceConfig(tts_voice="af_added_later"), engine=engine)
        service.speak("hello")
        assert engine.calls[0]["sid"] == KOKORO_VOICES[DEFAULT_TTS_VOICE]

    def test_speed_reaches_the_engine(self, tts_env):
        engine = _FakeTts()
        service = _service(VoiceConfig(tts_speed=1.5), engine=engine)
        service.speak("hello")
        assert engine.calls[0]["speed"] == 1.5

    def test_out_of_range_speed_from_a_raw_config_is_clamped(self, tts_env):
        """The schema clamps on load; the service must not trust that a
        hot-swapped config object went through it."""
        engine = _FakeTts()
        raw = types.SimpleNamespace(
            tts_voice="af_heart", tts_speed=9.0, output_device=None,
        )
        service = _service(raw, engine=engine)
        service.speak("hello")
        assert engine.calls[0]["speed"] == 2.0

    def test_nan_speed_from_a_raw_config_falls_back_to_normal(self, tts_env):
        """NaN sails through min/max, so the service needs its own
        finite-number guard — the engine must never see speed=nan."""
        engine = _FakeTts()
        raw = types.SimpleNamespace(
            tts_voice="af_heart", tts_speed=float("nan"), output_device=None,
        )
        service = _service(raw, engine=engine)
        service.speak("hello")
        assert engine.calls[0]["speed"] == 1.0

    def test_output_device_is_honoured(self, tts_env):
        engine = _FakeTts()
        service = _service(VoiceConfig(output_device="USB Speakers"), engine=engine)
        service.speak("hello")
        assert tts_env.created_streams[0].kwargs["device"] == "USB Speakers"

    def test_default_output_device_is_none(self, tts_env):
        engine = _FakeTts()
        _service(engine=engine).speak("hello")
        assert tts_env.created_streams[0].kwargs["device"] is None

    def test_playback_uses_the_engines_sample_rate(self, tts_env):
        engine = _FakeTts()
        _service(engine=engine).speak("hello")
        assert tts_env.created_streams[0].kwargs["samplerate"] == 24000

    def test_synthesis_failure_surfaces_as_a_single_clean_error(self, tts_env):
        engine = _FakeTts(fail_with="onnx kernel exploded")
        service = _service(engine=engine)
        with pytest.raises(VoiceOutputError) as excinfo:
            service.speak("hello")
        message = str(excinfo.value)
        assert "onnx kernel exploded" in message
        assert "\n" not in message
        # The worker must survive the failure and serve the next utterance.
        engine.fail_with = None
        service.speak("try again")
        assert engine.calls[-1]["text"] == "try again"

    def test_empty_synthesis_output_plays_nothing(self, tts_env):
        engine = _FakeTts(samples_per_call=0)
        _service(engine=engine).speak("hello")
        assert tts_env.created_streams == []

    def test_a_stream_that_fails_to_start_is_closed(self, tts_env):
        """The constructor opens the device; a start() failure must close
        it rather than leak the handle (stop() never sees an unstarted
        stream)."""
        engine = _FakeTts()
        service = _service(engine=engine)

        def _output_stream(**kwargs):
            stream = _FakeStream()
            stream.kwargs = kwargs
            stream.start = MagicMock(side_effect=RuntimeError("device busy"))
            tts_env.created_streams.append(stream)
            return stream

        tts_env.OutputStream = _output_stream
        with pytest.raises(VoiceOutputError):
            service.speak("hello")
        assert tts_env.created_streams[0].closed is True


# ---------------------------------------------------------------------------
# Queue + stop semantics
# ---------------------------------------------------------------------------

class TestQueueAndStop:

    def test_enqueue_orders_utterances(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        service.enqueue("first sentence")
        service.enqueue("second sentence")
        assert _wait_until(lambda: len(engine.calls) == 2)
        assert [c["text"] for c in engine.calls] == \
            ["first sentence", "second sentence"]
        assert _wait_until(lambda: not service.is_speaking())

    def test_enqueue_never_raises_when_unavailable(self, monkeypatch):
        monkeypatch.setattr(vos, "HAS_TTS_DEPS", False)
        monkeypatch.setattr(vos, "reload_tts_deps", lambda: False)
        service = _service()
        service.enqueue("hello")  # must not raise
        assert service.is_speaking() is False

    def test_is_speaking_is_true_while_playing(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        gate = threading.Event()

        original_play = service._play

        def _blocking_play(samples, rate, epoch):
            gate.wait(timeout=5)
            original_play(samples, rate, epoch)

        with patch.object(service, "_play", side_effect=_blocking_play):
            service.enqueue("hello")
            assert _wait_until(service.is_speaking)
            gate.set()
            assert _wait_until(lambda: not service.is_speaking())

    def test_stop_discards_the_queue(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        gate = threading.Event()

        def _blocked_speak_job(job):
            gate.wait(timeout=5)

        with patch.object(service, "_synthesize_job", side_effect=_blocked_speak_job):
            service.enqueue("one")
            assert _wait_until(service.is_speaking)
            service.enqueue("two")
            service.enqueue("three")
            service.stop()
            gate.set()
        assert _wait_until(lambda: not service.is_speaking())
        # Nothing queued behind the in-flight job may reach the engine.
        assert engine.calls == []

    def test_stop_unblocks_a_waiting_speak_without_error(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        gate = threading.Event()
        outcome = {}

        def _blocked_speak_job(job):
            gate.wait(timeout=5)

        def _caller():
            try:
                service.speak("held utterance")
                outcome["error"] = None
            except Exception as e:  # noqa: BLE001 — recording for the assertion
                outcome["error"] = e

        with patch.object(service, "_synthesize_job", side_effect=_blocked_speak_job):
            first = threading.Thread(target=lambda: service.speak("in flight"))
            first.start()
            assert _wait_until(service.is_speaking)
            waiter = threading.Thread(target=_caller)
            waiter.start()
            service.stop()
            gate.set()
            waiter.join(timeout=5)
            first.join(timeout=5)
        assert not waiter.is_alive()
        assert outcome["error"] is None

    def test_stop_aborts_the_active_stream(self, tts_env):
        engine = _FakeTts(samples_per_call=100000)
        service = _service(engine=engine)
        stream_ready = threading.Event()
        release = threading.Event()

        def _output_stream(**kwargs):
            stream = _FakeStream()
            stream.kwargs = kwargs
            stream.block_event = release
            tts_env.created_streams.append(stream)
            stream_ready.set()
            return stream

        tts_env.OutputStream = _output_stream
        service.enqueue("a very long reply")
        assert stream_ready.wait(timeout=5)
        assert _wait_until(lambda: service._out_stream is not None)
        service.stop()
        release.set()
        assert _wait_until(lambda: not service.is_speaking())
        assert tts_env.created_streams[0].aborted is True
        # The epoch check stops the chunk loop: far fewer writes than the
        # full utterance.
        assert len(tts_env.created_streams[0].written) < 10

    def test_stop_cancels_synthesis_via_the_callback(self, tts_env):
        """The engine's progress callback must return 0 after stop()."""
        service = _service()
        seen = {}

        class _CallbackProbe:
            sample_rate = 24000

            def generate(self, text, sid=0, speed=1.0, callback=None):
                service.stop()
                seen["verdict"] = callback([0.0], 0.1)
                return _FakeAudio([])

        service._tts = _CallbackProbe()
        service.speak("hello")
        assert seen["verdict"] == 0

    def test_stop_when_idle_is_harmless(self, tts_env):
        service = _service()
        service.stop()
        assert service.is_speaking() is False

    def test_stop_keeps_jobs_pinned_to_the_new_epoch(self, tts_env):
        """stop() bumps the epoch and then drains the queue; a sentence
        another thread enqueued for the NEW utterance while the drain
        was still running (its epoch pinned post-bump, exactly as
        begin_utterance/_submit pin it) must survive the drain instead
        of being discarded with the stale jobs — dropping it would
        silently swallow the opening sentence of the superseding reply."""
        engine = _FakeTts()
        service = _service(engine=engine)
        with patch.object(service, "_ensure_worker"):
            stale = service._submit("stale sentence", check_available=False)
            # Emulate the racing producer: a job pinned to the epoch this
            # stop() is about to create, already in the queue when the
            # drain loop runs.
            fresh = vos._SpeechJob("fresh sentence", service.current_epoch() + 1)
            with service._lock:
                service._pending += 1
            service._queue.put_nowait(fresh)
            service.stop()
            assert stale is not None and stale.done.is_set()
            assert not fresh.done.is_set()
            assert service._queue.qsize() == 1
            assert service._queue.get_nowait() is fresh

    def test_stop_before_a_pinned_speak_drops_the_utterance(self, tts_env):
        """A caller snapshots current_epoch() before scheduling speak()
        on another thread; a stop() landing in that window must retire
        the utterance instead of letting it play after the stop."""
        engine = _FakeTts()
        service = _service(engine=engine)
        epoch = service.current_epoch()
        service.stop()
        service.speak("stale reply", epoch=epoch)  # normal return, no error
        assert engine.calls == []
        assert service.is_speaking() is False

    def test_a_current_epoch_speak_still_plays(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        service.speak("fresh reply", epoch=service.current_epoch())
        assert [c["text"] for c in engine.calls] == ["fresh reply"]

    def test_stop_during_the_cleaning_pass_drops_the_utterance(self, tts_env):
        """The epoch is pinned at _submit entry, before speakable_text():
        a stop() landing during the cleaning pass over a long reply must
        not race the utterance into the queue."""
        engine = _FakeTts()
        service = _service(engine=engine)

        def _stop_then_clean(text):
            service.stop()
            return text

        with patch.object(vos, "speakable_text", side_effect=_stop_then_clean):
            service.speak("held reply")
        assert engine.calls == []
        assert service.is_speaking() is False


# ---------------------------------------------------------------------------
# close() — service replacement lifecycle
# ---------------------------------------------------------------------------

class TestClose:

    def test_close_ends_the_worker_thread(self, tts_env):
        """Without close() the worker blocks on the queue forever, pinning
        the service — and its loaded engine — after every settings-save
        rebuild."""
        engine = _FakeTts()
        service = _service(engine=engine)
        service.speak("hello")  # starts the worker
        worker = service._worker
        assert worker is not None and worker.is_alive()
        service.close()
        worker.join(timeout=5)
        assert not worker.is_alive()

    def test_close_releases_the_cached_engine(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        service.speak("hello")
        service.close()
        assert service._tts is None

    def test_a_closed_service_drops_further_speaks(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        service.close()
        service.speak("into the void")  # silent no-op, no error
        assert engine.calls == []
        assert service.is_speaking() is False
        assert service._worker is None or not service._worker.is_alive()

    def test_close_is_idempotent_and_harmless_when_idle(self, tts_env):
        service = _service()
        service.close()
        service.close()
        assert service.is_speaking() is False

    def test_close_stops_active_playback(self, tts_env):
        """close() must be at least as prompt as stop() for whatever is
        already being spoken."""
        engine = _FakeTts(samples_per_call=100000)
        service = _service(engine=engine)
        stream_ready = threading.Event()
        release = threading.Event()

        def _output_stream(**kwargs):
            stream = _FakeStream()
            stream.kwargs = kwargs
            stream.block_event = release
            tts_env.created_streams.append(stream)
            stream_ready.set()
            return stream

        tts_env.OutputStream = _output_stream
        service.enqueue("a very long reply")
        assert stream_ready.wait(timeout=5)
        assert _wait_until(lambda: service._out_stream is not None)
        service.close()
        release.set()
        assert _wait_until(lambda: not service.is_speaking())
        assert tts_env.created_streams[0].aborted is True


# ---------------------------------------------------------------------------
# Streamed-utterance sessions
# ---------------------------------------------------------------------------

class TestUtteranceSessions:

    def _session(self, service):
        played = []
        session = service.begin_utterance(on_complete=played.append)
        return session, played

    def test_sentences_play_in_order_and_complete_once(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        session, played = self._session(service)
        session.enqueue("First sentence.")
        session.enqueue("Second sentence.")
        session.end()
        assert _wait_until(lambda: played == [True])
        assert [c["text"] for c in engine.calls] == \
            ["First sentence.", "Second sentence."]
        # Exactly once: nothing further may fire the callback.
        session.end()
        time.sleep(0.05)
        assert played == [True]

    def test_completion_waits_for_end(self, tts_env):
        """Playback finishing between sentences must NOT complete the
        session — a slow stream would otherwise reopen the mic mid-reply."""
        engine = _FakeTts()
        service = _service(engine=engine)
        session, played = self._session(service)
        session.enqueue("First sentence.")
        assert _wait_until(lambda: len(engine.calls) == 1)
        assert _wait_until(lambda: not service.is_speaking())
        time.sleep(0.05)
        assert played == []  # ended not called yet
        session.enqueue("Second sentence.")
        session.end()
        assert _wait_until(lambda: played == [True])

    def test_an_empty_session_completes_immediately(self, tts_env):
        service = _service(engine=_FakeTts())
        session, played = self._session(service)
        session.end()
        assert played == [True]

    def test_is_settled_flips_when_a_stop_retires_the_session(self, tts_env):
        """Consumers (the chat panel's finalise path) use ``is_settled``
        to tell a live session — whose completion still owns the
        conversation's speech edge — from one whose exactly-once
        completion has already fired and can never fire again."""
        service = _service(engine=_FakeTts())
        session, played = self._session(service)
        assert session.is_settled is False
        service.stop()
        assert session.is_settled is True
        assert played == [False]

    def test_is_settled_flips_on_natural_completion(self, tts_env):
        service = _service(engine=_FakeTts())
        session, played = self._session(service)
        assert session.is_settled is False
        session.end()
        assert played == [True]
        assert session.is_settled is True

    def test_stop_mid_session_fires_completion_with_false(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        gate = threading.Event()

        def _blocked_speak_job(job):
            gate.wait(timeout=5)

        with patch.object(service, "_synthesize_job", side_effect=_blocked_speak_job):
            session, played = self._session(service)
            session.enqueue("one sentence")
            assert _wait_until(service.is_speaking)
            session.enqueue("two sentences")
            service.stop()
            gate.set()
        assert _wait_until(lambda: played == [False])
        # The worker finishing the in-flight job must not fire again.
        assert _wait_until(lambda: not service.is_speaking())
        time.sleep(0.05)
        assert played == [False]

    def test_stop_fires_completion_even_without_end(self, tts_env):
        """An interrupted stream never reaches end(); the stop must still
        settle the session or the conversation loop hangs in SPEAKING."""
        service = _service(engine=_FakeTts())
        session, played = self._session(service)
        session.enqueue("held sentence")
        service.stop()
        assert played == [False]

    def test_enqueue_after_stop_is_dropped(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        session, played = self._session(service)
        service.stop()
        session.enqueue("stale sentence")
        session.end()
        time.sleep(0.05)
        assert engine.calls == []
        assert played == [False]

    def test_a_stale_epoch_session_is_born_superseded(self, tts_env):
        engine = _FakeTts()
        service = _service(engine=engine)
        played = []
        epoch = service.current_epoch()
        service.stop()
        session = service.begin_utterance(
            on_complete=played.append, epoch=epoch,
        )
        assert played == [False]
        session.enqueue("never plays")
        session.end()
        time.sleep(0.05)
        assert engine.calls == []
        assert played == [False]

    def test_a_second_session_supersedes_the_first(self, tts_env):
        """The panel stops before opening the next turn's session; the
        first session must settle with played_to_end=False."""
        engine = _FakeTts()
        service = _service(engine=engine)
        first_played = []
        first = service.begin_utterance(on_complete=first_played.append)
        # Hold the worker so the first sentence is still queued when the
        # stop lands. Without this the worker may dequeue it first, and a
        # job already in flight legitimately reaches the engine before
        # the epoch check cancels it mid-synthesis — the engine-call
        # assertion below would then be a race, not a contract.
        with patch.object(service, "_ensure_worker"):
            first.enqueue("first reply sentence")
            service.stop()
        second_played = []
        second = service.begin_utterance(on_complete=second_played.append)
        second.enqueue("second reply sentence.")
        second.end()
        assert first_played == [False]
        assert _wait_until(lambda: second_played == [True])
        assert [c["text"] for c in engine.calls] == ["second reply sentence."]

    def test_plain_speak_interleaves_with_sessions(self, tts_env):
        """speak() keeps working unchanged around session traffic."""
        engine = _FakeTts()
        service = _service(engine=engine)
        session, played = self._session(service)
        session.enqueue("session sentence.")
        session.end()
        assert _wait_until(lambda: played == [True])
        service.speak("plain speak sentence.")
        assert engine.calls[-1]["text"] == "plain speak sentence."

    def test_unspeakable_sentences_do_not_stall_completion(self, tts_env):
        service = _service(engine=_FakeTts())
        session, played = self._session(service)
        session.enqueue("   ")  # nothing speakable — no job queued
        session.end()
        assert played == [True]

    def test_unavailable_service_drops_sentences_but_still_completes(self, monkeypatch):
        monkeypatch.setattr(vos, "HAS_TTS_DEPS", False)
        monkeypatch.setattr(vos, "reload_tts_deps", lambda: False)
        service = _service()
        session, played = self._session(service)
        session.enqueue("cannot play")  # must not raise
        session.end()
        assert played == [True]

    def test_close_settles_live_sessions(self, tts_env):
        service = _service(engine=_FakeTts())
        session, played = self._session(service)
        session.enqueue("held")
        service.close()
        assert _wait_until(lambda: played == [False])

    def test_a_closed_service_yields_a_superseded_session(self, tts_env):
        service = _service(engine=_FakeTts())
        service.close()
        played = []
        session = service.begin_utterance(on_complete=played.append)
        assert played == [False]
        session.enqueue("into the void")
        session.end()
        assert played == [False]

    def test_completion_callback_failures_are_swallowed(self, tts_env):
        service = _service(engine=_FakeTts())

        def _explode(_played):
            raise RuntimeError("consumer bug")

        session = service.begin_utterance(on_complete=_explode)
        session.end()  # must not raise
        # And the service keeps working afterwards.
        session2, played2 = self._session(service)
        session2.end()
        assert played2 == [True]

    def test_completed_sessions_leave_the_roster(self, tts_env):
        service = _service(engine=_FakeTts())
        session, played = self._session(service)
        session.enqueue("one sentence.")
        session.end()
        assert _wait_until(lambda: played == [True])
        assert service._sessions == []
