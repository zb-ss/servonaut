"""Tests for the setup service's voice-activity model surface.

The model is a single small file, so unlike the speech model there is no
archive machinery to exercise — the download seam is mocked the same way
and the interesting properties are staging (an interrupted download can
never read as installed), inventory, and cleanup.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

import servonaut.services.voice_engines as voice_engines
from servonaut.config.schema import VoiceConfig
from servonaut.services.voice_engines import (
    SILERO_VAD_MODEL_ID,
    is_silero_vad_model_present,
    silero_vad_model_dir,
    silero_vad_model_path,
)
from servonaut.services.voice_setup_service import VoiceSetupService


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


def _patch_download_with(writer):
    """Patch the download seam to 'fetch' locally written bytes."""
    async def _fake_download(self, client, url, destination, label, progress):
        writer(destination)
        if progress is not None:
            size = destination.stat().st_size
            progress(label, size, size)
        return True, ""

    return patch.object(VoiceSetupService, "_download_file", _fake_download)


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

    def test_successful_download_installs_the_model(self, model_root):
        service = _service()
        with _patch_download_with(lambda dest: dest.write_bytes(b"model-bytes")):
            success, message = run_async(service.download_vad_model())
        assert success is True
        assert service.is_vad_model_present() is True
        # No staging leftovers next to the final file.
        assert sorted(p.name for p in silero_vad_model_dir().iterdir()) == [
            silero_vad_model_path().name,
        ]

    def test_download_reports_progress(self, model_root):
        service = _service()
        seen = []
        with _patch_download_with(lambda dest: dest.write_bytes(b"model-bytes")):
            run_async(service.download_vad_model(
                progress=lambda label, done, total: seen.append((label, done, total))
            ))
        assert seen

    def test_failed_download_leaves_nothing_behind(self, model_root):
        async def _failing_download(self, client, url, destination, label, progress):
            return False, "Download failed for voice-detection model: HTTP 503"

        service = _service()
        with patch.object(VoiceSetupService, "_download_file", _failing_download):
            success, message = run_async(service.download_vad_model())
        assert success is False
        assert "503" in message
        assert not silero_vad_model_path().exists()
        # The directory too: the inventory lists this model by directory
        # presence, so an empty leftover would read as an installed model.
        assert not silero_vad_model_dir().exists()

    def test_a_failed_redownload_keeps_the_existing_model(self, model_root):
        """The cleanup must never take a good model down with it."""
        _write_vad_model(payload=b"old-weights")

        async def _failing_download(self, client, url, destination, label, progress):
            return False, "Download failed for voice-detection model: HTTP 503"

        service = _service()
        with patch.object(VoiceSetupService, "_download_file", _failing_download):
            success, _ = run_async(service.download_vad_model())
        assert success is False
        assert silero_vad_model_path().read_bytes() == b"old-weights"

    def test_empty_served_file_is_rejected(self, model_root):
        service = _service()
        with _patch_download_with(lambda dest: dest.write_bytes(b"")):
            success, message = run_async(service.download_vad_model())
        assert success is False
        assert "expected model" in message
        assert service.is_vad_model_present() is False
        # The useless empty file (and the then-empty directory) are gone,
        # so the inventory cannot list a 0 B "installed" model.
        assert not silero_vad_model_dir().exists()

    def test_download_replaces_an_existing_model(self, model_root):
        _write_vad_model(payload=b"old-weights")
        service = _service()
        with _patch_download_with(lambda dest: dest.write_bytes(b"new-weights")):
            success, _ = run_async(service.download_vad_model())
        assert success is True
        assert silero_vad_model_path().read_bytes() == b"new-weights"

    def test_download_invalidates_cached_readiness(self, model_root):
        service = _service()
        service.probe()
        with _patch_download_with(lambda dest: dest.write_bytes(b"model-bytes")):
            run_async(service.download_vad_model())
        assert service._cached is None
