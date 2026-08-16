"""Tests for the voice engine registry and the streaming service.

The streaming runtime (``sherpa-onnx``) is not installed in CI, so the
recognizer is stubbed. What is tested here is the wiring that decides
which engine runs, where its weights live, and that the decode loop
publishes partials and folds completed utterances together — the parts
that stay wrong silently if they are wrong.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import VoiceConfig
from servonaut.services.voice_engines import (
    DEFAULT_ENGINE,
    ENGINES,
    NEMOTRON_LATENCY_OPTIONS,
    SILERO_VAD_BYTES,
    SILERO_VAD_FILE,
    SILERO_VAD_MODEL_ID,
    SILERO_VAD_URL,
    VOICE_MODEL_ROOT,
    build_voice_input_service,
    directory_bytes,
    engine_spec,
    human_bytes,
    model_label,
    nemotron_model_dir,
    nemotron_repo,
    silero_vad_model_dir,
)


class TestSileroVadRegistry:
    """The voice-activity model's identity — a supply-chain input."""

    def test_download_url_is_https_and_pinned_to_the_release_host(self):
        # Pinning the host and project path (not just "https") means a
        # download-source change has to be a deliberate, reviewed edit —
        # the same guard the Kokoro archive URL carries.
        assert SILERO_VAD_URL.startswith(
            "https://github.com/k2-fsa/sherpa-onnx/releases/download/"
        )
        assert SILERO_VAD_URL.endswith(SILERO_VAD_FILE)

    def test_model_dir_lives_under_the_voice_model_root(self):
        assert silero_vad_model_dir() == VOICE_MODEL_ROOT / SILERO_VAD_MODEL_ID

    def test_size_constant_is_plausible(self):
        assert 0 < SILERO_VAD_BYTES < 10_000_000  # a small VAD, not an LLM


class TestEngineRegistry:

    def test_both_engines_are_registered(self):
        assert set(ENGINES) == {"whisper", "nemotron"}

    def test_only_nemotron_is_streaming(self):
        assert ENGINES["whisper"].streaming is False
        assert ENGINES["nemotron"].streaming is True

    def test_default_engine_is_the_lighter_download(self):
        """The default must not commit a new user to the bigger model."""
        assert DEFAULT_ENGINE == "whisper"

    def test_unknown_engine_falls_back_rather_than_raising(self):
        """A config from a newer release must not break the settings panel."""
        assert engine_spec("some-future-engine").id == DEFAULT_ENGINE
        assert engine_spec("").id == DEFAULT_ENGINE

    def test_each_engine_declares_the_modules_it_needs(self):
        assert "faster_whisper" in ENGINES["whisper"].import_names
        assert "sherpa_onnx" in ENGINES["nemotron"].import_names

    def test_each_engine_declares_numpy(self):
        """Both capture into numpy buffers, and neither runtime declares it."""
        for spec in ENGINES.values():
            assert any("numpy" in pkg for pkg in spec.packages)

    def test_engines_do_not_share_a_runtime_package(self):
        whisper = {p for p in ENGINES["whisper"].packages if "whisper" in p}
        nemotron = {p for p in ENGINES["nemotron"].packages if "sherpa" in p}
        assert whisper and nemotron
        assert not (whisper & nemotron)


class TestLatencyNormalisation:

    @pytest.mark.parametrize("latency", NEMOTRON_LATENCY_OPTIONS)
    def test_published_variants_are_kept(self, latency):
        assert f"{latency}ms" in nemotron_repo(latency)
        assert f"{latency}ms" in nemotron_model_dir(latency).name

    def test_unpublished_value_snaps_to_the_nearest(self):
        """An unpublished value would resolve to a repository that is 404."""
        assert "320ms" in nemotron_repo(300)
        assert "1120ms" in nemotron_repo(99999)
        assert "80ms" in nemotron_repo(1)

    def test_garbage_falls_back_to_the_default(self):
        assert "320ms" in nemotron_repo(None)  # type: ignore[arg-type]
        assert "320ms" in nemotron_repo("nonsense")  # type: ignore[arg-type]

    def test_model_dir_lives_under_the_managed_root(self):
        assert VOICE_MODEL_ROOT in nemotron_model_dir(320).parents

    def test_repo_targets_the_quantised_build(self):
        """The float build is ~2.6 GB against ~683 MB for no real gain."""
        assert "int8" in nemotron_repo(320)


class TestModelLabels:

    def test_whisper_label_names_the_size(self):
        assert model_label("whisper", model_size="tiny", latency_ms=320) == "Whisper tiny"

    def test_streaming_label_names_the_latency(self):
        label = model_label("nemotron", model_size="small", latency_ms=160)
        assert label == "Nemotron streaming 160ms"

    def test_streaming_label_ignores_the_whisper_size(self):
        """Size is meaningless for the streaming engine; it ships in one."""
        a = model_label("nemotron", model_size="tiny", latency_ms=320)
        b = model_label("nemotron", model_size="large-v3", latency_ms=320)
        assert a == b


class TestHumanBytes:

    @pytest.mark.parametrize("size,expected", [
        (0, "0 MB"),
        (None, "0 MB"),
        (2048, "2 KB"),
        (5 * 1024 ** 2, "5 MB"),
    ])
    def test_scales_to_a_readable_unit(self, size, expected):
        assert human_bytes(size) == expected

    def test_gigabytes_get_a_decimal(self):
        assert human_bytes(2 * 1024 ** 3) == "2.0 GB"


class TestDirectoryBytes:

    def test_absent_directory_is_zero(self, tmp_path):
        assert directory_bytes(tmp_path / "nope") == 0

    def test_sums_nested_files(self, tmp_path):
        (tmp_path / "a").write_bytes(b"x" * 100)
        nested = tmp_path / "sub"
        nested.mkdir()
        (nested / "b").write_bytes(b"y" * 50)
        assert directory_bytes(tmp_path) == 150

    def test_symlinks_are_not_double_counted(self, tmp_path):
        real = tmp_path / "real"
        real.write_bytes(b"z" * 200)
        (tmp_path / "link").symlink_to(real)
        assert directory_bytes(tmp_path) == 200


class TestServiceFactory:

    def test_whisper_config_builds_the_batch_service(self):
        service = build_voice_input_service(VoiceConfig(engine="whisper"))
        assert type(service).__name__ == "VoiceInputService"
        assert getattr(service, "supports_streaming", False) is False

    def test_nemotron_config_builds_the_streaming_service(self):
        service = build_voice_input_service(VoiceConfig(engine="nemotron"))
        assert type(service).__name__ == "StreamingVoiceInputService"
        assert service.supports_streaming is True

    def test_unknown_engine_builds_the_batch_service(self):
        service = build_voice_input_service(VoiceConfig(engine="nope"))
        assert type(service).__name__ == "VoiceInputService"

    def test_both_services_satisfy_the_interface(self):
        from servonaut.services.interfaces import VoiceInputServiceInterface
        for engine in ("whisper", "nemotron"):
            service = build_voice_input_service(VoiceConfig(engine=engine))
            assert isinstance(service, VoiceInputServiceInterface)


# ---------------------------------------------------------------------------
# Streaming service
# ---------------------------------------------------------------------------

def _fake_recognizer(results, *, endpoint_after=None):
    """Build a recognizer stub returning *results* in sequence."""
    rec = MagicMock()
    state = {"index": 0}

    def get_result(_stream):
        index = min(state["index"], len(results) - 1)
        return results[index]

    def is_ready(_stream):
        return False

    def is_endpoint(_stream):
        return endpoint_after is not None and state["index"] == endpoint_after

    rec.get_result.side_effect = get_result
    rec.is_ready.side_effect = is_ready
    rec.is_endpoint.side_effect = is_endpoint
    rec.create_stream.return_value = MagicMock()
    return rec, state


class TestStreamingService:

    def _service(self, **kwargs):
        import servonaut.services.voice_streaming_service as vss
        return vss.StreamingVoiceInputService(VoiceConfig(engine="nemotron", **kwargs))

    def test_declares_streaming_support(self):
        assert self._service().supports_streaming is True

    def test_missing_packages_report_the_streaming_extra(self):
        import servonaut.services.voice_streaming_service as vss
        with patch.object(vss, "_load_modules", return_value=(None, None)):
            service = self._service()
            assert service.is_available() is False
            assert "voice-streaming" in service.unavailable_reason()

    def test_missing_model_is_reported_separately_from_packages(self, tmp_path):
        """"Install the packages" is the wrong advice once they are installed."""
        import servonaut.services.voice_streaming_service as vss
        with patch.object(vss, "_load_modules", return_value=(MagicMock(), MagicMock())):
            with patch.object(vss, "nemotron_model_dir", return_value=tmp_path / "absent"):
                service = self._service()
                assert service.is_available() is False
                assert "not downloaded" in service.unavailable_reason()

    def test_incomplete_model_directory_refuses_to_load(self, tmp_path):
        """A half-finished download must not surface as a decode failure."""
        import servonaut.services.voice_streaming_service as vss
        from servonaut.services.voice_input_service import VoiceInputError
        model_dir = tmp_path / "nemotron"
        model_dir.mkdir()
        (model_dir / "tokens.txt").write_text("a\n")
        with patch.object(vss, "_load_modules", return_value=(MagicMock(), MagicMock())):
            with patch.object(vss, "nemotron_model_dir", return_value=model_dir):
                with pytest.raises(VoiceInputError):
                    self._service()._get_recognizer()

    def test_partials_are_published_to_the_callback(self):
        import servonaut.services.voice_streaming_service as vss
        service = self._service()
        seen = []
        service.set_partial_callback(seen.append)
        service._publish_partial("hello")
        service._publish_partial("hello world")
        assert seen == ["hello", "hello world"]

    def test_an_unchanged_partial_is_not_republished(self):
        """Repainting the input box on every identical frame is wasted work."""
        service = self._service()
        seen = []
        service.set_partial_callback(seen.append)
        service._publish_partial("same")
        service._publish_partial("same")
        assert seen == ["same"]

    def test_a_failing_callback_does_not_kill_the_decoder(self):
        service = self._service()
        service.set_partial_callback(MagicMock(side_effect=RuntimeError("ui gone")))
        service._publish_partial("text")
        assert service.partial_text == "text"

    def test_committed_utterances_accumulate(self):
        """Endpointing resets the decoder; earlier words must not be lost."""
        service = self._service()
        service._commit_utterance("first sentence")
        service._publish_partial("second")
        assert service.partial_text == "first sentence second"

    def test_endpoint_detection_follows_auto_submit(self, tmp_path):
        """Endpointing mid-pause would truncate unless something acts on it."""
        import servonaut.services.voice_streaming_service as vss
        model_dir = tmp_path / "m"
        model_dir.mkdir()
        for name in ("encoder.int8.onnx", "decoder.int8.onnx",
                     "joiner.int8.onnx", "tokens.txt"):
            (model_dir / name).write_bytes(b"x")

        for auto_submit, expected in ((True, True), (False, False)):
            sherpa = MagicMock()
            with patch.object(vss, "_load_modules", return_value=(MagicMock(), sherpa)):
                with patch.object(vss, "nemotron_model_dir", return_value=model_dir):
                    service = vss.StreamingVoiceInputService(
                        VoiceConfig(engine="nemotron", auto_submit=auto_submit)
                    )
                    service._get_recognizer()
            kwargs = sherpa.OnlineRecognizer.from_transducer.call_args.kwargs
            assert kwargs["enable_endpoint_detection"] is expected

    def test_second_start_raises_instead_of_sharing_state(self):
        from servonaut.services.voice_input_service import VoiceInputError
        service = self._service()
        service._recording = True
        with pytest.raises(VoiceInputError):
            service.start_recording()

    def test_cancel_clears_the_transcript(self):
        service = self._service()
        service._publish_partial("discard me")
        service.cancel_recording()
        assert service.partial_text == ""

    def test_cancel_without_a_recording_is_silent(self):
        self._service().cancel_recording()

    def test_too_short_audio_returns_empty(self):
        service = self._service()
        service._publish_partial("noise")
        service._frames_captured = 10
        assert service.stop_and_transcribe() == ""

    def test_decode_error_surfaces_on_stop(self):
        from servonaut.services.voice_input_service import VoiceInputError
        service = self._service()
        service._decode_error = "onnx blew up"
        service._frames_captured = 16000
        with pytest.raises(VoiceInputError) as exc:
            service.stop_and_transcribe()
        assert "onnx blew up" in str(exc.value)

    def test_initial_prompt_is_accepted_and_ignored(self):
        """Interface compatibility: a transducer has no prompt to condition on."""
        service = self._service()
        service._publish_partial("hello there")
        service._frames_captured = 16000 * 2
        assert service.stop_and_transcribe("server-1, server-2") == "hello there"

    def test_the_cap_is_reported(self):
        service = self._service(max_recording_seconds=1)
        service._publish_partial("cut off")
        service._frames_captured = 16000 * 2
        service._hit_cap = True
        service.stop_and_transcribe()
        assert service.hit_recording_cap is True


class _TapBlock:
    """Minimal capture-block stand-in: only ``copy`` is needed by the tap."""

    def __init__(self, samples):
        self.samples = list(samples)

    def copy(self):
        return _TapBlock(self.samples)


class TestStreamingFrameTap:
    """The raw-block observer, streaming-engine side."""

    def _service(self, **kwargs):
        import servonaut.services.voice_streaming_service as vss
        return vss.StreamingVoiceInputService(VoiceConfig(engine="nemotron", **kwargs))

    def test_tap_receives_a_copy_alongside_the_decoder_queue(self):
        service = self._service()
        seen = []
        service.set_frame_callback(seen.append)
        block = _TapBlock([0.1] * 1600)
        service._on_audio_block(block, 1600, None, None)
        assert len(seen) == 1
        assert seen[0] is not block  # a private copy, retainable
        assert service._queue.qsize() == 1

    def test_tap_fires_past_the_recording_cap(self):
        """Past the cap the decoder queue stops growing but the tap still
        sees the microphone — a silence detector needs those frames."""
        service = self._service(max_recording_seconds=1)
        seen = []
        service.set_frame_callback(seen.append)
        block = _TapBlock([0.0] * 16000)
        service._on_audio_block(block, 16000, None, None)
        service._on_audio_block(block, 16000, None, None)
        assert len(seen) == 2
        assert service._queue.qsize() == 1

    def test_a_raising_tap_does_not_starve_the_decoder(self):
        service = self._service()
        service.set_frame_callback(
            lambda block: (_ for _ in ()).throw(RuntimeError("consumer gone"))
        )
        service._on_audio_block(_TapBlock([0.1] * 1600), 1600, None, None)
        assert service._queue.qsize() == 1

    def test_tap_can_be_removed(self):
        service = self._service()
        seen = []
        service.set_frame_callback(seen.append)
        service.set_frame_callback(None)
        service._on_audio_block(_TapBlock([0.1] * 1600), 1600, None, None)
        assert seen == []


# ---------------------------------------------------------------------------
# Lifecycle concurrency — the calls arrive from different threads (chat
# workers, the conversation listener, unmount teardown on the UI thread).
# Two of them driving the recognizer's native objects at once crashed the
# process below Python (SIGILL), so the protocol is pinned with a fake
# recognizer that records any concurrent entry into "native" code.
# ---------------------------------------------------------------------------

import threading as _threading
import time as _time


class _RaceProbe:
    """Trips when two threads are inside 'native' code at once."""

    def __init__(self):
        self._busy = _threading.Lock()
        self.violations = 0

    def __enter__(self):
        if not self._busy.acquire(blocking=False):
            self.violations += 1
            return self
        # Widen the window so a real race cannot slip through unseen.
        _time.sleep(0.0005)
        return self

    def __exit__(self, *exc):
        if self._busy.locked():
            try:
                self._busy.release()
            except RuntimeError:
                pass
        return False


class _ProbedStream:
    def __init__(self, probe, gate=None):
        self._probe = probe
        self._gate = gate

    def accept_waveform(self, rate, samples):
        with self._probe:
            if self._gate is not None:
                self._gate.wait(timeout=5)


class _ProbedRecognizer:
    def __init__(self, probe, gate=None):
        self._probe = probe
        self._gate = gate

    def create_stream(self):
        with self._probe:
            return _ProbedStream(self._probe, self._gate)

    def is_ready(self, stream):
        with self._probe:
            return False

    def decode_stream(self, stream):
        with self._probe:
            pass

    def get_result(self, stream):
        with self._probe:
            return "words"

    def is_endpoint(self, stream):
        with self._probe:
            return False

    def reset(self, stream):
        with self._probe:
            pass


class _Block:
    def __init__(self, n=1600):
        self._n = n

    def copy(self):
        return self

    def reshape(self, *_a):
        return [0.0] * self._n


class _FakeInputStream:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def start(self):
        pass

    def stop(self):
        pass

    def close(self):
        pass


class TestStreamingLifecycleConcurrency:

    def _service(self, probe, gate=None):
        import servonaut.services.voice_streaming_service as vss
        sd = MagicMock()
        sd.InputStream = _FakeInputStream
        patcher = patch.object(vss, "_load_modules", return_value=(sd, MagicMock()))
        patcher.start()
        service = vss.StreamingVoiceInputService(VoiceConfig(engine="nemotron"))
        service._recognizer = _ProbedRecognizer(probe, gate)
        service._probe = lambda: (True, "")
        return service, patcher

    def test_concurrent_stop_and_cancel_never_share_the_recognizer(self):
        for _ in range(25):
            probe = _RaceProbe()
            service, patcher = self._service(probe)
            try:
                service.start_recording()
                for _i in range(3):
                    service._on_audio_block(_Block(), 1600, None, None)
                barrier = _threading.Barrier(2)

                def _stopper():
                    barrier.wait()
                    try:
                        service.stop_and_transcribe()
                    except Exception:  # noqa: BLE001 — outcome is not the point
                        pass

                def _canceller():
                    barrier.wait()
                    service.cancel_recording()

                threads = [
                    _threading.Thread(target=_stopper),
                    _threading.Thread(target=_canceller),
                ]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=10)
                assert probe.violations == 0
            finally:
                patcher.stop()

    def test_a_pending_cancel_aborts_the_next_start(self):
        from servonaut.services.voice_input_service import VoiceInputError
        probe = _RaceProbe()
        service, patcher = self._service(probe)
        try:
            service._cancelled.set()
            with pytest.raises(VoiceInputError):
                service.start_recording()
            assert not service._cancelled.is_set()
        finally:
            patcher.stop()

    def test_cancel_flees_without_blocking_and_the_transcript_is_discarded(self):
        """The UI-thread cancel must return promptly even while another
        thread is mid stop_and_transcribe, and that call must then honour
        the cancel by discarding what it transcribed."""
        probe = _RaceProbe()
        gate = _threading.Event()
        service, patcher = self._service(probe, gate)
        try:
            service.start_recording()
            service._frames_captured = 16000 * 2
            service._on_audio_block(_Block(), 1600, None, None)  # decoder blocks on the gate
            _time.sleep(0.05)

            results = {}

            def _stopper():
                results["text"] = service.stop_and_transcribe()

            stopper = _threading.Thread(target=_stopper)
            stopper.start()
            _time.sleep(0.1)  # stopper holds the lifecycle, joining the decoder

            started = _time.monotonic()
            service.cancel_recording()
            elapsed = _time.monotonic() - started
            assert elapsed < 0.5  # fled, did not wait for the transcription

            gate.set()
            stopper.join(timeout=10)
            assert results.get("text") == ""  # cancel honoured: transcript discarded
            assert not service._cancelled.is_set()
            assert probe.violations == 0
        finally:
            gate.set()
            patcher.stop()
