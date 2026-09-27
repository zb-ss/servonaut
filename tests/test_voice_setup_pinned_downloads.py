"""The terminal app's voice setup downloads every model from pinned sources.

Streaming speech recognition, speech synthesis and voice-activity models
are fetched through the pinned registry: exact revision or release URL,
exact size and SHA-256, staged and verified before anything reaches the
directory the engines load from. The network is replaced by a fake URL
opener; the download, verification and staging run for real.
"""

from __future__ import annotations

import asyncio
import re
import threading
import time
import urllib.error

import pytest

import servonaut.services.voice_engines as voice_engines
import servonaut.services.voice_setup_service as voice_setup_service
from servonaut.config.schema import VoiceConfig
from servonaut.services.voice_engines import (
    NEMOTRON_FILES,
    NEMOTRON_LATENCY_OPTIONS,
    human_bytes,
    is_nemotron_model_present,
    kokoro_model_dir,
    nemotron_model_dir,
    silero_vad_model_dir,
)
from servonaut.services.voice_models import (
    KOKORO_TTS_SPEC,
    SILERO_VAD_SPEC,
    VoiceModelSpec,
    nemotron_spec,
)
from servonaut.services.voice_setup_service import VoiceReadiness, VoiceSetupService

from .voice_download_fakes import (
    FakeOpener,
    FakeResponse,
    downloader,
    pinned_asset,
    serving,
    staging_leftovers,
    with_assets,
)

LATENCY = 320
FILES = {name: f"{name} weights".encode() * 3 for name in NEMOTRON_FILES.values()}
_HF_PINNED = re.compile(
    r"https://huggingface\.co/[\w.-]+/[\w.-]+/resolve/[0-9a-f]{40}/[\w.-]+"
)


def run_async(coro):
    """Run a coroutine synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def model_root(tmp_path, monkeypatch):
    """Point the managed-model root at a temp dir."""
    root = tmp_path / "voice_models"
    monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", root)
    return root


def _ready() -> VoiceReadiness:
    return VoiceReadiness(
        packages_ok=True, portaudio_ok=True, device_ok=True,
        model_ok=False, model_size="small", engine="nemotron",
    )


def _streaming_service(monkeypatch, opener, *, spec: VoiceModelSpec | None = None):
    """A streaming-engine service whose model comes from *opener*.

    *spec* replaces the pinned registry entry; the real registry is used
    when it is None.
    """
    if spec is not None:
        monkeypatch.setattr(voice_setup_service, "nemotron_spec", lambda latency: spec)
    service = VoiceSetupService(
        VoiceConfig(engine="nemotron", nemotron_latency_ms=LATENCY),
        downloader=downloader(opener),
    )
    monkeypatch.setattr(service, "probe", lambda force=False: _ready())
    return service


def _test_spec(**pins_for) -> VoiceModelSpec:
    """The configured streaming variant, pinned to :data:`FILES`.

    ``pins_for`` overrides one file's pins, keyed by file name with dots
    replaced by underscores.
    """
    assets = tuple(
        pinned_asset(name, data, **pins_for.get(name.replace(".", "_"), {}))
        for name, data in FILES.items()
    )
    return with_assets(nemotron_spec(LATENCY), *assets)


# ---------------------------------------------------------------------------
# Download outcomes
# ---------------------------------------------------------------------------


class TestStreamingDownload:

    def test_success_installs_every_verified_file(self, model_root, monkeypatch):
        opener = serving(FILES)
        service = _streaming_service(monkeypatch, opener, spec=_test_spec())

        success, message = run_async(service.download_model())

        assert (success, message) == (True, f"Downloaded the streaming model ({LATENCY}ms).")
        assert is_nemotron_model_present(LATENCY)
        for name, data in FILES.items():
            assert (nemotron_model_dir(LATENCY) / name).read_bytes() == data
        assert sorted(opener.requested) == sorted(
            f"https://models.example/{name}" for name in FILES
        )
        assert staging_leftovers(model_root) == []
        # Only the model directory: the inventory lists streaming models by
        # directory, so a visible staging directory would read as installed.
        assert [p.name for p in model_root.iterdir()] == [nemotron_model_dir(LATENCY).name]

    def test_progress_counts_every_file_against_the_pinned_total(self, model_root, monkeypatch):
        service = _streaming_service(monkeypatch, serving(FILES), spec=_test_spec())
        seen = []

        run_async(service.download_model(
            progress=lambda label, done, total: seen.append((label, done, total))
        ))

        total = sum(len(data) for data in FILES.values())
        assert seen[-1] == (f"streaming model ({LATENCY}ms)", total, total)

    def test_hash_mismatch_fails_loudly_and_installs_nothing(self, model_root, monkeypatch):
        spec = _test_spec(joiner_int8_onnx={"expected_sha256": "0" * 64})
        service = _streaming_service(monkeypatch, serving(FILES), spec=spec)

        success, message = run_async(service.download_model())

        assert success is False
        assert message.startswith(
            f"The streaming model ({LATENCY}ms) failed verification and was not installed"
        )
        assert "joiner.int8.onnx" in message
        assert "hash mismatch" in message
        assert not nemotron_model_dir(LATENCY).exists()
        assert list(model_root.iterdir()) == []

    def test_size_mismatch_is_aborted_mid_stream(self, model_root, monkeypatch):
        oversized = dict(FILES, **{"tokens.txt": FILES["tokens.txt"] + b"extra"})
        service = _streaming_service(monkeypatch, serving(oversized), spec=_test_spec())

        success, message = run_async(service.download_model())

        assert success is False
        assert "failed verification" in message
        assert "tokens.txt" in message
        assert "exceeded its expected" in message
        assert list(model_root.iterdir()) == []

    def test_advertised_wrong_length_is_refused_before_the_body(self, model_root, monkeypatch):
        opener = serving(FILES)
        encoder = FILES["encoder.int8.onnx"]
        opener._responses["https://models.example/encoder.int8.onnx"] = FakeResponse(
            encoder, content_length=len(encoder) + 1,
        )
        service = _streaming_service(monkeypatch, opener, spec=_test_spec())

        success, message = run_async(service.download_model())

        assert success is False
        assert "failed verification" in message
        assert "encoder.int8.onnx" in message
        assert list(model_root.iterdir()) == []

    def test_an_interrupted_transfer_resumes_where_it_stopped(self, model_root, monkeypatch):
        opener = serving(FILES)
        decoder = FILES["decoder.int8.onnx"]
        half = len(decoder) // 2
        opener._responses["https://models.example/decoder.int8.onnx"] = [
            FakeResponse(decoder[:half], fail_after=ConnectionResetError("reset")),
            FakeResponse(
                decoder[half:], status=206,
                content_range=f"bytes {half}-{len(decoder) - 1}/{len(decoder)}",
            ),
        ]
        service = _streaming_service(monkeypatch, opener, spec=_test_spec())

        success, _ = run_async(service.download_model())

        assert success is True
        assert (nemotron_model_dir(LATENCY) / "decoder.int8.onnx").read_bytes() == decoder
        decoder_ranges = [
            rng for url, rng in zip(opener.requested, opener.ranges) if url.endswith("decoder.int8.onnx")
        ]
        assert decoder_ranges == [None, f"bytes={half}-"]

    def test_an_interrupted_download_leaves_no_file_in_place(self, model_root, monkeypatch):
        opener = serving(FILES)
        opener._responses["https://models.example/tokens.txt"] = (
            lambda: FakeResponse(b"tok", fail_after=ConnectionResetError("reset"))
        )
        service = _streaming_service(monkeypatch, opener, spec=_test_spec())

        success, message = run_async(service.download_model())

        assert success is False
        assert f"streaming model ({LATENCY}ms)" in message
        assert "kept failing" in message
        assert not nemotron_model_dir(LATENCY).exists()
        assert list(model_root.iterdir()) == []

    def test_a_failed_download_keeps_the_installed_model(self, model_root, monkeypatch):
        installed = nemotron_model_dir(LATENCY)
        installed.mkdir(parents=True)
        for name in FILES:
            (installed / name).write_bytes(b"previous")
        spec = _test_spec(encoder_int8_onnx={"expected_sha256": "0" * 64})
        service = _streaming_service(monkeypatch, serving(FILES), spec=spec)

        success, _ = run_async(service.download_model())

        assert success is False
        assert {p.name: p.read_bytes() for p in installed.iterdir()} == {
            name: b"previous" for name in FILES
        }
        assert staging_leftovers(model_root) == []

    def test_http_failure_names_the_model(self, model_root, monkeypatch):
        not_found = urllib.error.HTTPError(
            "https://models.example/encoder.int8.onnx", 404, "Not Found", {}, None,
        )
        opener = FakeOpener({"https://models.example/encoder.int8.onnx": not_found})
        service = _streaming_service(monkeypatch, opener, spec=_test_spec())

        success, message = run_async(service.download_model())

        assert success is False
        assert message.startswith(f"Download failed for the streaming model ({LATENCY}ms)")
        assert "404" in message
        # A client error is not retried.
        assert opener.requested == ["https://models.example/encoder.int8.onnx"]

    def test_packages_still_come_first(self, model_root):
        service = VoiceSetupService(VoiceConfig(engine="nemotron"))
        service._cached = VoiceReadiness(
            packages_ok=False, portaudio_ok=False, device_ok=False,
            model_ok=False, model_size="small", engine="nemotron",
        )
        assert run_async(service.download_model()) == (False, "Install the voice packages first.")


# ---------------------------------------------------------------------------
# Sources are the pinned registry
# ---------------------------------------------------------------------------


class TestPinnedSources:

    @pytest.mark.parametrize("latency", NEMOTRON_LATENCY_OPTIONS)
    def test_streaming_files_come_from_a_pinned_revision(self, model_root, monkeypatch, latency):
        spec = nemotron_spec(latency)
        not_found = urllib.error.HTTPError(spec.assets[0].url, 404, "Not Found", {}, None)
        opener = FakeOpener({asset.url: not_found for asset in spec.assets})
        service = VoiceSetupService(
            VoiceConfig(engine="nemotron", nemotron_latency_ms=latency),
            downloader=downloader(opener),
        )
        monkeypatch.setattr(service, "probe", lambda force=False: _ready())

        run_async(service.download_model())

        [url] = opener.requested
        assert url == spec.assets[0].url
        assert _HF_PINNED.fullmatch(url), url
        assert "/resolve/main/" not in url
        assert f"-{latency}ms-" in url
        for asset in spec.assets:
            assert _HF_PINNED.fullmatch(asset.url), asset.url

    @pytest.mark.parametrize("download,spec", [
        ("download_tts_model", KOKORO_TTS_SPEC),
        ("download_vad_model", SILERO_VAD_SPEC),
    ])
    def test_release_assets_come_from_the_pinned_url(self, model_root, download, spec):
        not_found = urllib.error.HTTPError(spec.assets[0].url, 404, "Not Found", {}, None)
        opener = FakeOpener({spec.assets[0].url: not_found})
        service = VoiceSetupService(VoiceConfig(), downloader=downloader(opener))

        success, _ = run_async(getattr(service, download)())

        assert success is False
        assert opener.requested == [spec.assets[0].url]
        assert "/releases/download/" in opener.requested[0]

    def test_the_default_downloader_bounds_silence_not_the_whole_transfer(self, model_root):
        policy = VoiceSetupService(VoiceConfig())._downloader.policy
        assert policy.stall_timeout_seconds > 0
        assert policy.max_resume_attempts > 0

    def test_each_request_uses_the_stall_timeout(self, model_root, monkeypatch):
        opener = serving(FILES)
        service = _streaming_service(monkeypatch, opener, spec=_test_spec())
        run_async(service.download_model())
        stall = service._downloader.policy.stall_timeout_seconds
        assert opener.timeouts == [stall] * len(FILES)


# ---------------------------------------------------------------------------
# Size hints come from the pins
# ---------------------------------------------------------------------------


class TestSizeHints:

    @pytest.mark.parametrize("latency", [80, 320, 1120])
    def test_streaming_hint_is_the_pinned_total(self, latency):
        service = VoiceSetupService(VoiceConfig(engine="nemotron", nemotron_latency_ms=latency))
        expected = f"~{human_bytes(nemotron_spec(latency).total_download_bytes)}"
        assert service.download_size_hint() == expected
        assert service.download_size_hint_for("nemotron", model_size="small") == expected

    def test_speech_model_hint_is_the_pinned_download_and_disk_size(self):
        hint = VoiceSetupService(VoiceConfig()).tts_download_size_hint()
        assert hint == (
            f"~{human_bytes(KOKORO_TTS_SPEC.total_download_bytes)} download "
            f"(~{human_bytes(KOKORO_TTS_SPEC.total_disk_bytes)} on disk)"
        )

    def test_voice_detection_hint_is_the_pinned_size(self):
        hint = VoiceSetupService(VoiceConfig()).vad_download_size_hint()
        assert hint == f"~{human_bytes(SILERO_VAD_SPEC.total_download_bytes)}"


# ---------------------------------------------------------------------------
# Where the files land
# ---------------------------------------------------------------------------


class TestModelsRoot:

    def test_the_root_is_resolved_when_the_download_runs(self, tmp_path, monkeypatch):
        """A root set after the service was built is the one written to."""
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path / "before")
        service = _streaming_service(monkeypatch, serving(FILES), spec=_test_spec())
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path / "after")

        success, _ = run_async(service.download_model())

        assert success is True
        assert is_nemotron_model_present(LATENCY, tmp_path / "after")
        assert not (tmp_path / "before").exists()

    def test_leftovers_of_a_killed_download_are_removed(self, model_root, monkeypatch):
        spec = _test_spec()
        model_root.mkdir(parents=True)
        own = model_root / f".partial.{spec.model_id}.abc123"
        own.mkdir()
        (own / "encoder.int8.onnx").write_bytes(b"half")
        retired = model_root / f".partial.{spec.model_id}.retired.def456"
        retired.mkdir()
        other = model_root / f".partial.{KOKORO_TTS_SPEC.model_id}.xyz789"
        other.mkdir()
        desktop = model_root / ".staging.anything"
        desktop.mkdir()
        service = _streaming_service(monkeypatch, serving(FILES), spec=spec)

        success, _ = run_async(service.download_model())

        assert success is True
        assert not own.exists()
        assert not retired.exists()
        # Another model's download, and the desktop cache's staging, are
        # not this download's to remove.
        assert other.is_dir()
        assert desktop.is_dir()

    def test_speech_and_detection_models_land_where_the_engines_load_them(
        self, model_root, monkeypatch,
    ):
        vad = pinned_asset(SILERO_VAD_SPEC.assets[0].filename, b"vad-weights")
        monkeypatch.setattr(voice_setup_service, "SILERO_VAD_SPEC", with_assets(SILERO_VAD_SPEC, vad))
        opener = serving({vad.filename: b"vad-weights"})
        service = VoiceSetupService(VoiceConfig(), downloader=downloader(opener))

        assert run_async(service.download_vad_model())[0] is True

        assert (silero_vad_model_dir() / vad.filename).read_bytes() == b"vad-weights"
        assert silero_vad_model_dir().parent == model_root
        assert kokoro_model_dir().parent == model_root


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


class TestCancellation:

    def test_cancelling_stops_the_transfer_and_installs_nothing(self, model_root, monkeypatch):
        gate = threading.Event()
        opener = serving(FILES)
        encoder = FILES["encoder.int8.onnx"]
        opener._responses["https://models.example/encoder.int8.onnx"] = FakeResponse(
            encoder, chunk_limit=4, gate=gate,
        )
        service = _streaming_service(monkeypatch, opener, spec=_test_spec())

        async def scenario() -> None:
            task = asyncio.ensure_future(service.download_model())
            while not opener.requested:
                await asyncio.sleep(0.01)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        run_async(scenario())
        gate.set()

        # The worker thread notices the cancellation at its next chunk and
        # removes its staging directory.
        deadline = time.monotonic() + 5
        while staging_leftovers(model_root) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert staging_leftovers(model_root) == []
        assert not nemotron_model_dir(LATENCY).exists()
        assert opener.requested == ["https://models.example/encoder.int8.onnx"]
