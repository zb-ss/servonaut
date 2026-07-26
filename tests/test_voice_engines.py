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
    VOICE_MODEL_ROOT,
    build_voice_input_service,
    directory_bytes,
    engine_spec,
    human_bytes,
    model_label,
    nemotron_model_dir,
    nemotron_repo,
)


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
