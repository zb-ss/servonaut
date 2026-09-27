"""Tests for the setup service's voice-activity model surface.

The model is a single small file, so unlike the speech model there is no
archive machinery to exercise — the network is replaced by a fake URL
opener the same way, and the interesting properties are staging (an
interrupted or mismatched download can never read as installed),
inventory, and cleanup.
"""

from __future__ import annotations

import asyncio
import urllib.error

import pytest

import servonaut.services.voice_engines as voice_engines
import servonaut.services.voice_setup_service as voice_setup_service
from servonaut.config.schema import VoiceConfig
from servonaut.services.voice_engines import (
    SILERO_VAD_FILE,
    SILERO_VAD_MODEL_ID,
    is_silero_vad_model_present,
    silero_vad_model_dir,
    silero_vad_model_path,
)
from servonaut.services.voice_models import SILERO_VAD_SPEC
from servonaut.services.voice_setup_service import VoiceSetupService

from .voice_download_fakes import (
    FakeOpener,
    FakeResponse,
    downloader,
    pinned_asset,
    serving,
    staging_leftovers,
    with_assets,
)


def run_async(coro):
    """Run a coroutine synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _service(**config_kwargs) -> VoiceSetupService:
    return VoiceSetupService(VoiceConfig(**config_kwargs))


@pytest.fixture
def model_root(tmp_path, monkeypatch):
    """Point the managed-model root at a temp dir."""
    root = tmp_path / "voice_models"
    root.mkdir()
    monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", root)
    return root


def _write_vad_model(payload: bytes = b"weights") -> None:
    silero_vad_model_dir().mkdir(parents=True, exist_ok=True)
    silero_vad_model_path().write_bytes(payload)


VAD_URL = f"https://models.example/{SILERO_VAD_FILE}"


def _served_service(monkeypatch, payload: bytes, *, opener=None, **pin_overrides):
    """A service whose voice-activity model is *payload*, pinned to those bytes.

    Args:
        opener: Serves the requests instead of *payload*.

    Returns:
        (service, opener).
    """
    asset = pinned_asset(SILERO_VAD_FILE, payload, **pin_overrides)
    monkeypatch.setattr(voice_setup_service, "SILERO_VAD_SPEC", with_assets(SILERO_VAD_SPEC, asset))
    opener = opener or serving({SILERO_VAD_FILE: payload})
    return VoiceSetupService(VoiceConfig(), downloader=downloader(opener)), opener


def _unavailable() -> urllib.error.HTTPError:
    return urllib.error.HTTPError(VAD_URL, 503, "Service Unavailable", {}, None)


# ---------------------------------------------------------------------------
# Presence + readiness
# ---------------------------------------------------------------------------

class TestVadPresence:

    def test_absent_model_is_not_present(self, model_root):
        assert is_silero_vad_model_present() is False
        assert _service().is_vad_model_present() is False

    def test_written_model_is_present(self, model_root):
        _write_vad_model()
        assert _service().is_vad_model_present() is True

    def test_an_empty_file_is_not_present(self, model_root):
        """A download interrupted before the first byte must not read as
        installed."""
        _write_vad_model(payload=b"")
        assert _service().is_vad_model_present() is False

    def test_probe_reports_the_vad_dimension(self, model_root):
        assert _service().probe(force=True).vad_model_ok is False
        _write_vad_model()
        assert _service().probe(force=True).vad_model_ok is True

    def test_vad_dimension_does_not_gate_dictation_readiness(self):
        from servonaut.services.voice_setup_service import VoiceReadiness
        readiness = VoiceReadiness(
            packages_ok=True, portaudio_ok=True, device_ok=True,
            model_ok=True, model_size="small", vad_model_ok=False,
        )
        assert readiness.is_ready is True
        assert readiness.next_step == ""

    def test_model_bytes_track_the_directory(self, model_root):
        service = _service()
        assert service.vad_model_bytes() == 0
        _write_vad_model()
        assert service.vad_model_bytes() > 0

    def test_download_size_hint_is_a_single_figure(self):
        hint = _service().vad_download_size_hint()
        assert hint.startswith("~")
        assert "KB" in hint


# ---------------------------------------------------------------------------
# Inventory + cleanup
# ---------------------------------------------------------------------------

class TestVadInventory:

    def test_model_on_disk_is_listed(self, model_root):
        _write_vad_model()
        entries = [m for m in _service().installed_models()
                   if m.engine == "silero-vad"]
        assert len(entries) == 1
        assert entries[0].key == SILERO_VAD_MODEL_ID
        assert entries[0].size_bytes > 0

    def test_absent_model_is_not_listed(self, model_root):
        assert [m for m in _service().installed_models()
                if m.engine == "silero-vad"] == []

    def test_in_use_follows_conversation_mode(self, model_root):
        _write_vad_model()
        enabled = [m for m in _service(conversation_mode=True).installed_models()
                   if m.engine == "silero-vad"][0]
        disabled = [m for m in _service(conversation_mode=False).installed_models()
                    if m.engine == "silero-vad"][0]
        assert enabled.in_use is True
        assert disabled.in_use is False

    def test_active_override_beats_the_saved_config(self, model_root):
        """The panel describes what is ABOUT to be saved, not what is."""
        _write_vad_model()
        service = _service(conversation_mode=False)
        entry = [m for m in service.installed_models(active_conversation_mode=True)
                 if m.engine == "silero-vad"][0]
        assert entry.in_use is True

    def test_disabled_conversation_model_is_stale_and_reclaimable(self, model_root):
        _write_vad_model()
        service = _service(conversation_mode=False)
        stale = [m for m in service.stale_models() if m.engine == "silero-vad"]
        assert len(stale) == 1
        success, message = service.remove_installed(stale[0])
        assert success is True
        assert not silero_vad_model_dir().exists()
        assert "Silero" in message


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

class TestVadDownload:

    def test_successful_download_installs_the_model(self, model_root, monkeypatch):
        service, opener = _served_service(monkeypatch, b"model-bytes")
        success, message = run_async(service.download_vad_model())
        assert (success, message) == (True, "Downloaded the voice-detection model.")
        assert service.is_vad_model_present() is True
        assert opener.requested == [VAD_URL]
        # No staging leftovers next to the final file or in the root.
        assert sorted(p.name for p in silero_vad_model_dir().iterdir()) == [
            silero_vad_model_path().name,
        ]
        assert staging_leftovers(model_root) == []

    def test_download_reports_progress(self, model_root, monkeypatch):
        service, _ = _served_service(monkeypatch, b"model-bytes")
        seen = []
        run_async(service.download_vad_model(
            progress=lambda label, done, total: seen.append((label, done, total))
        ))
        assert seen[-1] == ("voice-detection model", 11, 11)

    def test_failed_download_leaves_nothing_behind(self, model_root, monkeypatch):
        opener = FakeOpener({VAD_URL: _unavailable()})
        service, _ = _served_service(monkeypatch, b"model-bytes", opener=opener)
        success, message = run_async(service.download_vad_model())
        assert success is False
        assert "503" in message
        assert "voice-detection model" in message
        assert not silero_vad_model_path().exists()
        # The directory too: the inventory lists this model by directory
        # presence, so an empty leftover would read as an installed model.
        assert not silero_vad_model_dir().exists()
        assert list(model_root.iterdir()) == []

    def test_a_failed_redownload_keeps_the_existing_model(self, model_root, monkeypatch):
        """The cleanup must never take a good model down with it."""
        _write_vad_model(payload=b"old-weights")
        opener = FakeOpener({VAD_URL: _unavailable()})
        service, _ = _served_service(monkeypatch, b"new-weights", opener=opener)
        success, _ = run_async(service.download_vad_model())
        assert success is False
        assert silero_vad_model_path().read_bytes() == b"old-weights"

    def test_a_truncated_file_is_rejected(self, model_root, monkeypatch):
        """A body that keeps ending early never installs, however often it is resumed."""
        opener = FakeOpener({VAD_URL: lambda: FakeResponse(b"model")})
        service, _ = _served_service(monkeypatch, b"model-bytes", opener=opener)
        success, message = run_async(service.download_vad_model())
        assert success is False
        assert "voice-detection model" in message
        assert "kept failing" in message
        assert service.is_vad_model_present() is False
        # The useless partial file (and any directory) are gone, so the
        # inventory cannot list a half-downloaded "installed" model.
        assert list(model_root.iterdir()) == []

    def test_a_file_of_the_wrong_size_is_rejected(self, model_root, monkeypatch):
        opener = serving({SILERO_VAD_FILE: b"model-bytes-and-more"})
        service, _ = _served_service(monkeypatch, b"model-bytes", opener=opener)
        success, message = run_async(service.download_vad_model())
        assert success is False
        assert "voice-detection model failed verification" in message
        assert service.is_vad_model_present() is False
        assert list(model_root.iterdir()) == []

    def test_download_replaces_an_existing_model(self, model_root, monkeypatch):
        _write_vad_model(payload=b"old-weights")
        service, _ = _served_service(monkeypatch, b"new-weights")
        success, _ = run_async(service.download_vad_model())
        assert success is True
        assert silero_vad_model_path().read_bytes() == b"new-weights"

    def test_download_invalidates_cached_readiness(self, model_root, monkeypatch):
        service, _ = _served_service(monkeypatch, b"model-bytes")
        service.probe()
        run_async(service.download_vad_model())
        assert service._cached is None
