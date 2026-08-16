"""Tests for the setup service's speech-model (TTS) surface.

Network is mocked at the single-file download seam; extraction runs
against real tar.bz2 archives built in the test, because the safety
property under test — a hostile archive extracts to nothing — lives in
the real tarfile machinery, not in a mock of it.
"""

from __future__ import annotations

import asyncio
import io
import shutil
import sys
import tarfile
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import servonaut.services.voice_engines as voice_engines
from servonaut.config.schema import VoiceConfig
from servonaut.services.voice_engines import (
    KOKORO_MODEL_ID,
    KOKORO_REQUIRED_FILES,
    TTS_PACKAGES,
    kokoro_model_dir,
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


def _write_kokoro_files(base: Path):
    for name in KOKORO_REQUIRED_FILES:
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"weights")


def _make_archive(path: Path, *, nested: bool = True, complete: bool = True):
    """Build a tar.bz2 shaped like the published release asset."""
    content = path.parent / "archive-content"
    base = content / KOKORO_MODEL_ID if nested else content
    _write_kokoro_files(base)
    if not complete:
        (base / "voices.bin").unlink()
    with tarfile.open(path, "w:bz2") as archive:
        for entry in sorted(content.rglob("*")):
            archive.add(entry, arcname=str(entry.relative_to(content)))
    shutil.rmtree(content)
    return path


def _make_hostile_archive(path: Path, member_name: str, *, link: bool = False):
    """Build a tar.bz2 holding one malicious member."""
    with tarfile.open(path, "w:bz2") as archive:
        info = tarfile.TarInfo(member_name)
        if link:
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)
        else:
            payload = b"evil"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return path


def _patch_download_with(archive_builder):
    """Patch the download seam to 'fetch' a locally built archive."""
    async def _fake_download(self, client, url, destination, label, progress):
        archive_builder(destination)
        if progress is not None:
            progress(label, destination.stat().st_size, destination.stat().st_size)
        return True, ""

    return patch.object(VoiceSetupService, "_download_file", _fake_download)


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------

class TestTTSReadiness:

    def test_probe_reports_tts_dimensions(self, model_root):
        readiness = _service().probe(force=True)
        assert readiness.tts_model_ok is False
        assert isinstance(readiness.tts_packages_ok, bool)

    def test_tts_model_presence_flows_into_probe(self, model_root):
        _write_kokoro_files(kokoro_model_dir())
        readiness = _service().probe(force=True)
        assert readiness.tts_model_ok is True

    def test_tts_dimensions_do_not_gate_dictation_readiness(self):
        """is_ready / next_step describe voice input; spoken replies are a
        separate, independently optional feature."""
        from servonaut.services.voice_setup_service import VoiceReadiness
        readiness = VoiceReadiness(
            packages_ok=True, portaudio_ok=True, device_ok=True,
            model_ok=True, model_size="small",
            tts_packages_ok=False, tts_model_ok=False,
        )
        assert readiness.is_ready is True
        assert readiness.next_step == ""

    def test_incomplete_model_is_not_present(self, model_root):
        _write_kokoro_files(kokoro_model_dir())
        (kokoro_model_dir() / "tokens.txt").unlink()
        assert _service().is_tts_model_present() is False

    def test_tts_runtime_probe_true_with_importable_stack(self):
        service = _service()
        fakes = {
            "numpy": types.ModuleType("numpy"),
            "sherpa_onnx": types.ModuleType("sherpa_onnx"),
            "sounddevice": types.ModuleType("sounddevice"),
        }
        saved = {name: sys.modules.get(name) for name in fakes}
        sys.modules.update(fakes)
        try:
            assert service._probe_tts_runtime() is True
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module

    def test_tts_runtime_probe_false_without_the_stack(self, monkeypatch):
        monkeypatch.delitem(sys.modules, "sherpa_onnx", raising=False)
        assert _service()._probe_tts_runtime() is False

    def test_tts_packages_are_the_registry_list(self):
        assert _service().tts_packages() == TTS_PACKAGES

    def test_download_size_hint_names_both_footprints(self):
        hint = _service().tts_download_size_hint()
        assert "download" in hint
        assert "on disk" in hint

    def test_model_bytes_sums_the_directory(self, model_root):
        _write_kokoro_files(kokoro_model_dir())
        assert _service().tts_model_bytes() > 0

    def test_model_bytes_zero_when_absent(self, model_root):
        assert _service().tts_model_bytes() == 0


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

class TestTTSInventory:

    def test_model_on_disk_is_listed(self, model_root):
        _write_kokoro_files(kokoro_model_dir())
        models = _service().installed_models()
        kokoro = [m for m in models if m.engine == "kokoro"]
        assert len(kokoro) == 1
        assert kokoro[0].key == KOKORO_MODEL_ID
        assert kokoro[0].size_bytes > 0

    def test_absent_model_is_not_listed(self, model_root):
        assert [m for m in _service().installed_models()
                if m.engine == "kokoro"] == []

    def test_in_use_follows_tts_enabled(self, model_root):
        _write_kokoro_files(kokoro_model_dir())
        enabled = [m for m in _service(tts_enabled=True).installed_models()
                   if m.engine == "kokoro"][0]
        disabled = [m for m in _service(tts_enabled=False).installed_models()
                    if m.engine == "kokoro"][0]
        assert enabled.in_use is True
        assert disabled.in_use is False

    def test_active_override_beats_the_saved_config(self, model_root):
        """The panel describes what is ABOUT to be saved, not what is."""
        _write_kokoro_files(kokoro_model_dir())
        service = _service(tts_enabled=False)
        entry = [m for m in service.installed_models(active_tts_enabled=True)
                 if m.engine == "kokoro"][0]
        assert entry.in_use is True

    def test_disabled_tts_model_is_stale_and_reclaimable(self, model_root):
        _write_kokoro_files(kokoro_model_dir())
        service = _service(tts_enabled=False)
        stale = [m for m in service.stale_models() if m.engine == "kokoro"]
        assert len(stale) == 1
        success, message = service.remove_installed(stale[0])
        assert success is True
        assert not kokoro_model_dir().exists()
        assert "Kokoro" in message


# ---------------------------------------------------------------------------
# Download + extraction
# ---------------------------------------------------------------------------

class TestTTSDownload:

    def test_successful_download_installs_the_model(self, model_root):
        service = _service()
        with _patch_download_with(lambda dest: _make_archive(dest, nested=True)):
            success, message = run_async(service.download_tts_model())
        assert success is True
        assert service.is_tts_model_present() is True
        # No staging leftovers.
        assert [p for p in model_root.iterdir()] == [kokoro_model_dir()]

    def test_flat_archive_layout_is_tolerated(self, model_root):
        service = _service()
        with _patch_download_with(lambda dest: _make_archive(dest, nested=False)):
            success, _ = run_async(service.download_tts_model())
        assert success is True
        assert service.is_tts_model_present() is True

    def test_download_reports_progress(self, model_root):
        service = _service()
        seen = []
        with _patch_download_with(lambda dest: _make_archive(dest)):
            run_async(service.download_tts_model(
                progress=lambda label, done, total: seen.append((label, done, total))
            ))
        assert seen  # at least one report reached the callback

    def test_failed_download_leaves_nothing_behind(self, model_root):
        async def _failing_download(self, client, url, destination, label, progress):
            return False, "Download failed for speech model: HTTP 503"

        service = _service()
        with patch.object(VoiceSetupService, "_download_file", _failing_download):
            success, message = run_async(service.download_tts_model())
        assert success is False
        assert "503" in message
        assert list(model_root.iterdir()) == []

    def test_incomplete_archive_is_rejected_after_extraction(self, model_root):
        service = _service()
        with _patch_download_with(lambda dest: _make_archive(dest, complete=False)):
            success, message = run_async(service.download_tts_model())
        assert success is False
        assert "expected model files" in message
        assert service.is_tts_model_present() is False

    def test_download_replaces_an_existing_model(self, model_root):
        _write_kokoro_files(kokoro_model_dir())
        (kokoro_model_dir() / "stale-extra.bin").write_bytes(b"old")
        service = _service()
        with _patch_download_with(lambda dest: _make_archive(dest)):
            success, _ = run_async(service.download_tts_model())
        assert success is True
        assert not (kokoro_model_dir() / "stale-extra.bin").exists()

    def test_download_invalidates_cached_readiness(self, model_root):
        service = _service()
        service.probe()
        with _patch_download_with(lambda dest: _make_archive(dest)):
            run_async(service.download_tts_model())
        assert service._cached is None

    def test_corrupt_archive_is_an_error_not_a_crash(self, model_root):
        service = _service()
        with _patch_download_with(lambda dest: dest.write_bytes(b"not a tarball")):
            success, message = run_async(service.download_tts_model())
        assert success is False
        assert service.is_tts_model_present() is False


class TestTarSafety:

    @pytest.mark.parametrize("member,link", [
        ("/etc/cron.d/evil", False),
        ("../../outside.txt", False),
        ("nested/../../outside.txt", False),
        ("C:/windows/evil.txt", False),
        ("innocent-link", True),
    ])
    def test_hostile_members_fail_the_whole_archive(
        self, model_root, tmp_path, member, link
    ):
        archive = _make_hostile_archive(
            tmp_path / "hostile.tar.bz2", member, link=link
        )
        service = _service()
        destination = model_root / "staging"
        error = service._extract_tts_archive(archive, destination)
        assert error != ""
        assert "unsafe" in error
        # One bad member means NOTHING is extracted.
        assert list(destination.iterdir()) == []
        # And nothing escaped the destination either.
        assert not (tmp_path / "outside.txt").exists()

    def test_clean_archive_extracts_fully(self, model_root, tmp_path):
        archive = _make_archive(tmp_path / "clean.tar.bz2", nested=True)
        service = _service()
        destination = model_root / "staging"
        error = service._extract_tts_archive(archive, destination)
        assert error == ""
        assert (destination / KOKORO_MODEL_ID / "model.int8.onnx").is_file()

    def test_hostile_download_never_installs(self, model_root):
        service = _service()
        with _patch_download_with(
            lambda dest: _make_hostile_archive(dest, "../../escape.txt")
        ):
            success, message = run_async(service.download_tts_model())
        assert success is False
        assert service.is_tts_model_present() is False
        assert list(model_root.iterdir()) == []


# ---------------------------------------------------------------------------
# Package install (one-click, method-aware)
# ---------------------------------------------------------------------------

class _FakeProcess:
    def __init__(self, returncode=0, output=b""):
        self.returncode = returncode
        self._output = output

    async def communicate(self):
        return self._output, b""

    def kill(self):
        pass

    async def wait(self):
        return self.returncode


class TestTTSInstallCommand:

    def test_pipx_installs_inject_the_tts_packages(self):
        """The synthesis list drives the argv, not the input engine's."""
        service = _service()
        with patch.object(service, "install_method", return_value="pipx"):
            with patch("shutil.which", return_value="/usr/bin/pipx"):
                argv = service.install_command(service.tts_packages())
        assert argv[:3] == ["/usr/bin/pipx", "inject", "servonaut"]
        assert all(pkg in argv for pkg in TTS_PACKAGES)
        assert not any("faster-whisper" in part for part in argv)

    def test_pip_installs_target_the_running_interpreter(self):
        service = _service()
        with patch.object(service, "install_method", return_value="pip"):
            argv = service.install_command(service.tts_packages())
        assert argv[0] == sys.executable
        assert argv[1:3] == ["-m", "pip"]
        assert all(pkg in argv for pkg in TTS_PACKAGES)

    def test_default_install_command_still_uses_the_engine_packages(self):
        """The new parameter must not change the dictation install flow."""
        service = _service()
        with patch.object(service, "install_method", return_value="pip"):
            argv = service.install_command()
        assert any("faster-whisper" in part for part in argv)

    def test_manual_command_is_method_aware_for_pipx(self):
        """A pip line handed to a pipx user targets the wrong interpreter."""
        service = _service()
        with patch.object(service, "install_method", return_value="pipx"):
            with patch("shutil.which", return_value="/usr/bin/pipx"):
                command = service.tts_manual_install_command()
        assert command.startswith("/usr/bin/pipx inject servonaut")

    def test_manual_command_for_source_names_the_extra(self):
        service = _service()
        with patch.object(service, "install_method", return_value="source"):
            command = service.tts_manual_install_command()
        assert command == "pip install -e '.[voice-output]'"

    def test_manual_command_for_unknown_method_lists_the_packages(self):
        service = _service()
        with patch.object(service, "install_method", return_value="unknown"):
            command = service.tts_manual_install_command()
        assert command.startswith("pip install")
        assert "sherpa-onnx" in command


class TestInstallTTSPackages:

    def test_source_checkout_refuses_with_the_tts_extra(self):
        service = _service()
        with patch.object(service, "install_method", return_value="source"):
            success, message = run_async(service.install_tts_packages())
        assert success is False
        assert "source checkout" in message
        assert "voice-output" in message

    def test_successful_install_reports_by_the_tts_probe(self):
        service = _service()
        proc = _FakeProcess(returncode=0)
        readiness = MagicMock(portaudio_ok=True, tts_packages_ok=True)
        with patch.object(service, "install_command", return_value=["pip", "install"]):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                with patch.object(service, "probe", return_value=readiness):
                    success, message = run_async(service.install_tts_packages())
        assert success is True
        assert message == "Speech packages installed."

    def test_unimportable_install_asks_for_a_restart(self):
        """Packages on disk but not importable in this process is not a failure."""
        service = _service()
        proc = _FakeProcess(returncode=0)
        readiness = MagicMock(portaudio_ok=True, tts_packages_ok=False)
        with patch.object(service, "install_command", return_value=["pip", "install"]):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                with patch.object(service, "probe", return_value=readiness):
                    success, message = run_async(service.install_tts_packages())
        assert success is True
        assert "Restart" in message
        assert "spoken replies" in message

    def test_missing_portaudio_names_the_system_command(self):
        service = _service()
        proc = _FakeProcess(returncode=0)
        readiness = MagicMock(portaudio_ok=False, tts_packages_ok=False)
        with patch.object(service, "install_command", return_value=["pip", "install"]):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                with patch.object(service, "probe", return_value=readiness):
                    with patch.object(service, "portaudio_command",
                                      return_value="sudo apt install libportaudio2"):
                        success, message = run_async(service.install_tts_packages())
        assert success is True
        assert "libportaudio2" in message

    def test_failed_install_surfaces_the_output_tail(self):
        service = _service()
        proc = _FakeProcess(returncode=1, output=b"noise\nERROR: no matching dist\n")
        with patch.object(service, "install_command", return_value=["pip", "install"]):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                success, message = run_async(service.install_tts_packages())
        assert success is False
        assert "no matching dist" in message
