"""Tests for the local speech-to-text service and its config plumbing.

The audio dependencies (``sounddevice``, ``faster-whisper``, ``numpy``) are
optional and are NOT installed in CI, so every test here has to run without
them: the degradation cases exercise the real absent-dependency path, and the
recording/transcription cases inject stand-in modules the same way the AI
service tests inject a fake ``httpx``.

The config round-trip case is the highest-value one — a nested dataclass that
loads back as a plain dict does not raise at load time, it raises on the first
attribute access, and only for users who already have the key on disk.
"""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, VoiceConfig, CONFIG_VERSION
from servonaut.services.voice_input_service import (
    MAX_INITIAL_PROMPT_CHARS,
    MIN_AUDIO_SECONDS,
    SAMPLE_RATE,
    VoiceInputError,
    VoiceInputService,
)


# ---------------------------------------------------------------------------
# Test doubles for the optional audio stack
# ---------------------------------------------------------------------------

class _FakeAudio:
    """Stand-in for the numpy array the service captures and concatenates.

    Only the operations the service actually performs are implemented
    (``copy``/``reshape``/``astype``/``shape``), so a test failure points at
    the service using a new numpy feature rather than at a silent MagicMock.
    """

    def __init__(self, samples) -> None:
        self.samples = list(samples)

    @property
    def shape(self):
        return (len(self.samples),)

    def copy(self) -> '_FakeAudio':
        return _FakeAudio(self.samples)

    def reshape(self, *_args) -> '_FakeAudio':
        return self

    def astype(self, _dtype) -> '_FakeAudio':
        return self


def _fake_concatenate(blocks, axis=0):
    """Flatten the captured blocks the way ``np.concatenate`` would."""
    flattened = [sample for block in blocks for sample in block.samples]
    return _FakeAudio(flattened)


def _make_segment(text: str):
    """Build a faster-whisper-style segment carrying only ``.text``."""
    segment = MagicMock()
    segment.text = text
    return segment


@contextmanager
def _mock_voice_deps(devices=None, segments=None, transcribe_error=None):
    """Inject stand-in audio modules and set HAS_VOICE_DEPS=True.

    Yields a namespace of the injected doubles (``sd``, ``whisper_model``,
    ``model``, ``stream``) so tests can assert on the calls the service made.
    """
    import servonaut.services.voice_input_service as svc_module

    stream = MagicMock()

    sd_mock = MagicMock()
    sd_mock.query_devices.return_value = (
        devices if devices is not None else [{'max_input_channels': 2}]
    )
    sd_mock.InputStream.return_value = stream

    model = MagicMock()
    if transcribe_error is not None:
        model.transcribe.side_effect = transcribe_error
    else:
        seg_texts = segments if segments is not None else [" hello world"]
        model.transcribe.return_value = (
            [_make_segment(t) for t in seg_texts],
            MagicMock(),
        )

    whisper_model = MagicMock(return_value=model)

    np_mock = MagicMock()
    np_mock.concatenate.side_effect = _fake_concatenate

    numpy_module = np_mock
    sounddevice_module = sd_mock
    faster_whisper_module = MagicMock()
    faster_whisper_module.WhisperModel = whisper_model

    originals = {
        name: sys.modules.get(name)
        for name in ('numpy', 'sounddevice', 'faster_whisper')
    }
    original_flag = svc_module.HAS_VOICE_DEPS
    original_np = svc_module.np
    original_sd = svc_module.sd
    original_whisper = svc_module.WhisperModel

    sys.modules['numpy'] = numpy_module
    sys.modules['sounddevice'] = sounddevice_module
    sys.modules['faster_whisper'] = faster_whisper_module
    svc_module.np = np_mock
    svc_module.sd = sd_mock
    svc_module.WhisperModel = whisper_model
    svc_module.HAS_VOICE_DEPS = True

    # A plain namespace rather than a MagicMock, so a mistyped attribute in a
    # test raises instead of silently returning an always-passing mock.
    doubles = SimpleNamespace(
        sd=sd_mock,
        np=np_mock,
        whisper_model=whisper_model,
        model=model,
        stream=stream,
    )

    try:
        yield doubles
    finally:
        svc_module.HAS_VOICE_DEPS = original_flag
        svc_module.np = original_np
        svc_module.sd = original_sd
        svc_module.WhisperModel = original_whisper
        for name, original in originals.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


def _feed(doubles, sample_count: int) -> None:
    """Push one block of audio through the PortAudio callback."""
    callback = doubles.sd.InputStream.call_args.kwargs['callback']
    block = _FakeAudio([0.1] * sample_count)
    callback(block, sample_count, None, None)


def _make_service(**overrides) -> VoiceInputService:
    """Build a service over a VoiceConfig with the given field overrides."""
    return VoiceInputService(VoiceConfig(**overrides))


# Comfortably above MIN_AUDIO_SECONDS so the model is actually invoked.
_LONG_ENOUGH = int(MIN_AUDIO_SECONDS * SAMPLE_RATE) + SAMPLE_RATE


# ---------------------------------------------------------------------------
# Degradation — optional dependencies absent (the CI path)
# ---------------------------------------------------------------------------

class TestDegradesWithoutDeps:

    def test_is_available_is_false(self):
        with patch("servonaut.services.voice_input_service.HAS_VOICE_DEPS", False):
            assert _make_service().is_available() is False

    def test_unavailable_reason_names_the_install_extra(self):
        with patch("servonaut.services.voice_input_service.HAS_VOICE_DEPS", False):
            reason = _make_service().unavailable_reason()
        assert reason
        assert "servonaut[voice]" in reason
        assert "pip install" in reason

    def test_start_recording_raises_the_documented_error(self):
        """The install hint must arrive as VoiceInputError, not NameError."""
        with patch("servonaut.services.voice_input_service.HAS_VOICE_DEPS", False):
            service = _make_service()
            with pytest.raises(VoiceInputError) as excinfo:
                service.start_recording()
        assert "servonaut[voice]" in str(excinfo.value)
        assert service.is_recording is False

    def test_stop_and_transcribe_returns_empty_without_raising(self):
        with patch("servonaut.services.voice_input_service.HAS_VOICE_DEPS", False):
            assert _make_service().stop_and_transcribe() == ""

    def test_cancel_recording_is_silent(self):
        with patch("servonaut.services.voice_input_service.HAS_VOICE_DEPS", False):
            _make_service().cancel_recording()

    def test_no_input_device_reports_no_microphone(self):
        with _mock_voice_deps(devices=[{'max_input_channels': 0}]):
            service = _make_service()
            assert service.is_available() is False
            assert service.unavailable_reason() == "No microphone detected"

    def test_device_probe_failure_degrades_instead_of_raising(self):
        """A headless host raises OSError from PortAudio during enumeration."""
        with _mock_voice_deps() as doubles:
            doubles.sd.query_devices.side_effect = OSError("PortAudio not initialized")
            service = _make_service()
            assert service.is_available() is False
            assert service.unavailable_reason() == "No microphone detected"

    def test_availability_is_probed_once(self):
        with _mock_voice_deps() as doubles:
            service = _make_service()
            service.is_available()
            service.is_available()
            service.unavailable_reason()
            assert doubles.sd.query_devices.call_count == 1


# ---------------------------------------------------------------------------
# Config plumbing — VoiceConfig on AppConfig and through ConfigManager
# ---------------------------------------------------------------------------

class TestVoiceConfigPersistence:

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Config manager writing to a temp path."""
        manager = ConfigManager()
        manager._config_path = tmp_path / 'config.json'
        return manager

    def test_voice_is_off_until_opted_into(self):
        """The feature costs hundreds of MB, so it must never default to on."""
        assert AppConfig().voice.enabled is False

    def test_defaults_land_on_appconfig(self):
        config = AppConfig()
        assert isinstance(config.voice, VoiceConfig)
        assert config.voice.model_size == "small"
        assert config.voice.language == "en"
        assert config.voice.input_device is None
        assert config.voice.max_recording_seconds == 60

    def test_round_trip_preserves_every_field(self, config_manager):
        voice = VoiceConfig(
            enabled=False,
            model_size="distil-small.en",
            language="auto",
            input_device="USB Audio Device",
            max_recording_seconds=15,
        )
        config_manager.save(AppConfig(voice=voice))
        config_manager._config = None
        loaded = config_manager.load()

        assert isinstance(loaded.voice, VoiceConfig)
        assert loaded.voice.enabled is False
        assert loaded.voice.model_size == "distil-small.en"
        assert loaded.voice.language == "auto"
        assert loaded.voice.input_device == "USB Audio Device"
        assert loaded.voice.max_recording_seconds == 15

    def test_config_without_voice_key_still_loads(self, config_manager):
        """Regression guard for the nested-config registration in _deserialize.

        An on-disk config predating the feature must yield a real VoiceConfig,
        not a missing attribute — and a config carrying the key must not come
        back as a plain dict.
        """
        config_manager._config_path.write_text(json.dumps({
            'version': CONFIG_VERSION,
            'default_username': 'ubuntu',
        }))
        loaded = config_manager.load()

        assert isinstance(loaded.voice, VoiceConfig)
        assert loaded.voice.model_size == "small"

    def test_unknown_voice_key_on_disk_does_not_break_the_load(self, config_manager):
        """A field removed in a future release must not take the config down."""
        config_manager._config_path.write_text(json.dumps({
            'version': CONFIG_VERSION,
            'voice': {'language': 'de', 'some_removed_field': True},
        }))
        loaded = config_manager.load()

        assert isinstance(loaded.voice, VoiceConfig)
        assert loaded.voice.language == "de"

    def test_unfamiliar_model_size_survives_a_load_and_save(self, config_manager):
        """The backend accepts sizes this release does not list (and local
        model directories), while a save serialises the whole config — so
        coercing the value would silently delete the user's choice."""
        config_manager._config_path.write_text(json.dumps({
            'version': CONFIG_VERSION,
            'voice': {'model_size': '/opt/models/whisper-custom'},
        }))
        loaded = config_manager.load()
        assert loaded.voice.model_size == "/opt/models/whisper-custom"

        config_manager.save(loaded)
        on_disk = json.loads(config_manager._config_path.read_text())
        assert on_disk['voice']['model_size'] == "/opt/models/whisper-custom"

    def test_service_reads_the_config_it_was_given(self, config_manager):
        config_manager._config_path.write_text(json.dumps({
            'version': CONFIG_VERSION,
            'voice': {'input_device': 'Front Mic', 'language': 'fr'},
        }))
        config = config_manager.load()

        with _mock_voice_deps() as doubles:
            service = VoiceInputService(config.voice)
            service.start_recording()

        assert doubles.sd.InputStream.call_args.kwargs['device'] == 'Front Mic'


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

class TestRecording:

    def test_start_recording_opens_and_starts_the_stream(self):
        with _mock_voice_deps() as doubles:
            service = _make_service()
            service.start_recording()

            assert service.is_recording is True
            doubles.stream.start.assert_called_once()
            kwargs = doubles.sd.InputStream.call_args.kwargs
            assert kwargs['samplerate'] == SAMPLE_RATE
            assert kwargs['channels'] == 1
            assert kwargs['dtype'] == 'float32'
            # None means "system default"; an empty config value must not be
            # forwarded as a device name.
            assert kwargs['device'] is None

    def test_backend_failure_becomes_voice_input_error(self):
        with _mock_voice_deps() as doubles:
            doubles.sd.InputStream.side_effect = OSError("Device unavailable")
            service = _make_service()
            with pytest.raises(VoiceInputError):
                service.start_recording()
            assert service.is_recording is False

    def test_second_start_raises_instead_of_sharing_the_buffer(self):
        """One service backs every panel, so a silent no-op would let a
        second caller drain audio the first one is still recording."""
        with _mock_voice_deps() as doubles:
            service = _make_service()
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)

            with pytest.raises(VoiceInputError):
                service.start_recording()

            assert doubles.sd.InputStream.call_count == 1
            assert service.is_recording is True

            service.stop_and_transcribe()
            audio = doubles.model.transcribe.call_args.args[0]
            assert audio.shape[0] == _LONG_ENOUGH

    def test_recording_is_capped_at_max_recording_seconds(self):
        with _mock_voice_deps() as doubles:
            service = _make_service(max_recording_seconds=1)
            service.start_recording()
            block = SAMPLE_RATE // 2
            for _ in range(6):
                _feed(doubles, block)
            service.stop_and_transcribe()

            audio = doubles.model.transcribe.call_args.args[0]
            assert audio.shape[0] == SAMPLE_RATE

    def test_hitting_the_cap_is_reported_to_the_caller(self):
        """Truncation must be surfaceable, not just logged."""
        with _mock_voice_deps() as doubles:
            service = _make_service(max_recording_seconds=1)
            service.start_recording()
            for _ in range(6):
                _feed(doubles, SAMPLE_RATE // 2)
            service.stop_and_transcribe()

            assert service.hit_recording_cap is True

    def test_a_recording_within_the_cap_reports_no_truncation(self):
        with _mock_voice_deps() as doubles:
            service = _make_service()
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            service.stop_and_transcribe()

            assert service.hit_recording_cap is False

    def test_cancel_discards_the_buffer(self):
        with _mock_voice_deps() as doubles:
            service = _make_service()
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            service.cancel_recording()

            assert service.is_recording is False
            doubles.stream.stop.assert_called_once()
            doubles.stream.close.assert_called_once()
            assert service.stop_and_transcribe() == ""
            doubles.model.transcribe.assert_not_called()

    def test_cancel_without_a_recording_is_silent(self):
        with _mock_voice_deps():
            _make_service().cancel_recording()

    def test_cancel_survives_a_failing_teardown(self):
        with _mock_voice_deps() as doubles:
            doubles.stream.stop.side_effect = OSError("stream already dead")
            service = _make_service()
            service.start_recording()
            service.cancel_recording()
            assert service.is_recording is False


# ---------------------------------------------------------------------------
# Transcription
# ---------------------------------------------------------------------------

class TestTranscription:

    def test_transcribes_the_buffered_audio(self):
        with _mock_voice_deps(segments=[" restart ", "nginx on web-1"]) as doubles:
            service = _make_service()
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH // 2)
            _feed(doubles, _LONG_ENOUGH // 2)
            text = service.stop_and_transcribe()

            assert text == "restart nginx on web-1"
            assert service.is_recording is False
            doubles.stream.close.assert_called_once()
            audio = doubles.model.transcribe.call_args.args[0]
            assert audio.shape[0] == (_LONG_ENOUGH // 2) * 2

    def test_empty_buffer_returns_empty_without_loading_the_model(self):
        with _mock_voice_deps() as doubles:
            service = _make_service()
            service.start_recording()
            assert service.stop_and_transcribe() == ""
            doubles.whisper_model.assert_not_called()
            doubles.model.transcribe.assert_not_called()

    def test_too_short_buffer_returns_empty_without_transcribing(self):
        with _mock_voice_deps() as doubles:
            service = _make_service()
            service.start_recording()
            _feed(doubles, int(MIN_AUDIO_SECONDS * SAMPLE_RATE) - 1)
            assert service.stop_and_transcribe() == ""
            doubles.model.transcribe.assert_not_called()

    def test_initial_prompt_is_truncated(self):
        with _mock_voice_deps() as doubles:
            service = _make_service()
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            service.stop_and_transcribe("web-1 " * 200)

            prompt = doubles.model.transcribe.call_args.kwargs['initial_prompt']
            assert len(prompt) == MAX_INITIAL_PROMPT_CHARS

    def test_empty_initial_prompt_is_passed_as_none(self):
        with _mock_voice_deps() as doubles:
            service = _make_service()
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            service.stop_and_transcribe("   ")

            assert doubles.model.transcribe.call_args.kwargs['initial_prompt'] is None

    def test_language_auto_maps_to_none(self):
        with _mock_voice_deps() as doubles:
            service = _make_service(language="auto")
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            service.stop_and_transcribe()

            assert doubles.model.transcribe.call_args.kwargs['language'] is None

    def test_explicit_language_is_forwarded(self):
        with _mock_voice_deps() as doubles:
            service = _make_service(language="de")
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            service.stop_and_transcribe()

            assert doubles.model.transcribe.call_args.kwargs['language'] == "de"

    def test_model_is_loaded_lazily_and_reused(self):
        with _mock_voice_deps() as doubles:
            service = _make_service(model_size="tiny")
            doubles.whisper_model.assert_not_called()

            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            doubles.whisper_model.assert_not_called()

            service.stop_and_transcribe()
            doubles.whisper_model.assert_called_once_with(
                "tiny", device="cpu", compute_type="int8"
            )

            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            service.stop_and_transcribe()
            assert doubles.whisper_model.call_count == 1

    def test_model_load_failure_becomes_voice_input_error(self):
        with _mock_voice_deps() as doubles:
            doubles.whisper_model.side_effect = RuntimeError("no such model")
            service = _make_service()
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            with pytest.raises(VoiceInputError):
                service.stop_and_transcribe()

    def test_transcription_failure_becomes_voice_input_error(self):
        with _mock_voice_deps(transcribe_error=RuntimeError("backend failure")) as doubles:
            service = _make_service()
            service.start_recording()
            _feed(doubles, _LONG_ENOUGH)
            with pytest.raises(VoiceInputError):
                service.stop_and_transcribe()
