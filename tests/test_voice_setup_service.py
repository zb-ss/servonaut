"""Tests for the voice-input setup service: readiness, install, model cache.

The optional voice dependencies are absent in CI, so the import-dependent
paths are driven by injecting fake modules into ``sys.modules`` (the same
approach ``test_ai_analysis_service.py`` takes for httpx). The filesystem
paths are exercised against a real temp cache directory rather than mocks,
because the bug they guard against — treating an interrupted download as a
complete one — lives in the directory layout itself.
"""

from __future__ import annotations

import asyncio
import sys
import types
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import VoiceConfig
from servonaut.services.voice_setup_service import (
    VOICE_PACKAGES,
    VoiceReadiness,
    VoiceSetupService,
    build_voice_setup_service,
)


def run_async(coro):
    """Run a coroutine synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@contextmanager
def _fake_voice_modules(*, portaudio_ok: bool = True, devices=None):
    """Install importable stand-ins for numpy / faster_whisper / sounddevice.

    Args:
        portaudio_ok: When False, importing ``sounddevice`` raises OSError —
            the real failure mode when the system library is absent.
        devices: Device list ``query_devices`` returns.
    """
    if devices is None:
        devices = [{'max_input_channels': 2, 'name': 'Fake Mic'}]

    numpy_mod = types.ModuleType('numpy')
    fw_mod = types.ModuleType('faster_whisper')
    fw_mod.WhisperModel = MagicMock(name='WhisperModel')

    sd_mod = types.ModuleType('sounddevice')
    sd_mod.query_devices = MagicMock(return_value=devices)

    saved = {name: sys.modules.get(name) for name in
             ('numpy', 'faster_whisper', 'sounddevice')}
    sys.modules['numpy'] = numpy_mod
    sys.modules['faster_whisper'] = fw_mod
    if portaudio_ok:
        sys.modules['sounddevice'] = sd_mod
    else:
        # A module that raises on import: drop it and make the finder fail.
        sys.modules.pop('sounddevice', None)

    try:
        if portaudio_ok:
            yield fw_mod
        else:
            real_import = __builtins__['__import__'] if isinstance(__builtins__, dict) \
                else __builtins__.__import__

            def _raising_import(name, *args, **kwargs):
                if name == 'sounddevice':
                    raise OSError("PortAudio library not found")
                return real_import(name, *args, **kwargs)

            with patch('builtins.__import__', side_effect=_raising_import):
                yield fw_mod
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def _service(**config_kwargs) -> VoiceSetupService:
    return VoiceSetupService(VoiceConfig(**config_kwargs))


# ---------------------------------------------------------------------------
# VoiceReadiness — the state machine the panel renders
# ---------------------------------------------------------------------------

class TestReadinessStateMachine:

    def _readiness(self, **overrides) -> VoiceReadiness:
        base = dict(
            packages_ok=True, portaudio_ok=True, device_ok=True,
            model_ok=True, model_size="small",
        )
        base.update(overrides)
        return VoiceReadiness(**base)

    def test_everything_present_is_ready(self):
        readiness = self._readiness()
        assert readiness.is_ready is True
        assert readiness.next_step == ""

    @pytest.mark.parametrize("missing,expected", [
        ("packages_ok", "packages"),
        ("portaudio_ok", "portaudio"),
        ("device_ok", "device"),
        ("model_ok", "model"),
    ])
    def test_next_step_names_the_missing_requirement(self, missing, expected):
        readiness = self._readiness(**{missing: False})
        assert readiness.is_ready is False
        assert readiness.next_step == expected

    def test_next_step_reports_the_earliest_unmet_requirement(self):
        """Reporting a missing model to someone with no packages buries the lede."""
        readiness = self._readiness(packages_ok=False, model_ok=False)
        assert readiness.next_step == "packages"


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------

class TestProbe:

    def test_missing_packages_report_packages_as_the_next_step(self):
        readiness = _service().probe()
        assert readiness.packages_ok is False
        assert readiness.next_step == "packages"
        assert readiness.is_ready is False

    def test_probe_is_cached_until_forced(self):
        service = _service()
        with patch.object(service, '_probe_runtime',
                          return_value=(False, False, False, "")) as probe:
            service.probe()
            service.probe()
            assert probe.call_count == 1
            service.probe(force=True)
            assert probe.call_count == 2

    def test_model_is_not_reported_missing_before_the_packages_are_there(self):
        """model_ok stays False without a cache hit, but packages come first."""
        service = _service()
        with patch.object(service, 'is_model_cached') as cached:
            readiness = service.probe()
        cached.assert_not_called()
        assert readiness.model_ok is False
        assert readiness.next_step == "packages"

    def test_present_packages_and_device_are_ready_when_the_model_is_cached(self):
        service = _service()
        with _fake_voice_modules():
            with patch.object(service, 'is_model_cached', return_value=True):
                readiness = service.probe(force=True)
        assert readiness.packages_ok is True
        assert readiness.portaudio_ok is True
        assert readiness.device_ok is True
        assert readiness.is_ready is True

    def test_no_capture_device_is_reported_separately(self):
        service = _service()
        with _fake_voice_modules(devices=[{'max_input_channels': 0, 'name': 'Speakers'}]):
            with patch.object(service, 'is_model_cached', return_value=True):
                readiness = service.probe(force=True)
        assert readiness.packages_ok is True
        assert readiness.portaudio_ok is True
        assert readiness.device_ok is False
        assert readiness.next_step == "device"

    def test_missing_portaudio_is_distinguished_from_missing_packages(self):
        """The distinction matters: pip fixes one and cannot fix the other."""
        service = _service()
        with _fake_voice_modules(portaudio_ok=False):
            readiness = service.probe(force=True)
        assert readiness.packages_ok is True
        assert readiness.portaudio_ok is False
        assert readiness.next_step == "portaudio"


# ---------------------------------------------------------------------------
# Model cache inspection
# ---------------------------------------------------------------------------

class TestModelCache:

    @pytest.fixture
    def cache(self, tmp_path, monkeypatch):
        """Point the hub cache at a temp dir via the documented env var."""
        root = tmp_path / 'hub'
        root.mkdir()
        monkeypatch.setenv('HF_HUB_CACHE', str(root))
        return root

    def _make_model(self, root, size, *, with_weights=True, org="Systran"):
        repo = root / f"models--{org}--faster-whisper-{size}"
        snapshot = repo / 'snapshots' / 'abc123'
        snapshot.mkdir(parents=True)
        if with_weights:
            (snapshot / 'model.bin').write_bytes(b'x' * 2048)
        return repo

    def test_absent_model_is_not_cached(self, cache):
        assert _service().is_model_cached('small') is False

    def test_downloaded_model_is_cached(self, cache):
        self._make_model(cache, 'small')
        assert _service().is_model_cached('small') is True

    def test_interrupted_download_is_not_treated_as_cached(self, cache):
        """The directory survives a cancelled download; the weights do not."""
        self._make_model(cache, 'small', with_weights=False)
        assert _service().is_model_cached('small') is False

    def test_a_different_size_does_not_satisfy_the_check(self, cache):
        self._make_model(cache, 'tiny')
        assert _service().is_model_cached('small') is False

    def test_cache_hit_survives_a_change_of_publishing_org(self, cache):
        """Matched by glob so a repo rename does not read as a missing model."""
        self._make_model(cache, 'small', org='SomeNewOrg')
        assert _service().is_model_cached('small') is True

    def test_cache_bytes_sums_the_weights(self, cache):
        self._make_model(cache, 'small')
        assert _service().model_cache_bytes('small') == 2048

    def test_cache_bytes_is_zero_when_absent(self, cache):
        assert _service().model_cache_bytes('small') == 0

    def test_remove_model_deletes_the_cache_entry(self, cache):
        repo = self._make_model(cache, 'small')
        service = _service()
        success, message = service.remove_model('small')
        assert success is True
        assert not repo.exists()
        assert 'small' in message

    def test_removing_an_absent_model_succeeds(self, cache):
        """The requested end state already holds, so this is not a failure."""
        success, _ = _service().remove_model('small')
        assert success is True

    def test_hf_home_is_honoured(self, tmp_path, monkeypatch):
        monkeypatch.delenv('HF_HUB_CACHE', raising=False)
        monkeypatch.delenv('HUGGINGFACE_HUB_CACHE', raising=False)
        monkeypatch.setenv('HF_HOME', str(tmp_path))
        root = tmp_path / 'hub'
        root.mkdir()
        self._make_model(root, 'base')
        assert _service(model_size='base').is_model_cached('base') is True

    def test_download_size_hint_is_offered_for_every_dropdown_size(self):
        service = _service()
        for size in ('tiny', 'base', 'small', 'distil-small.en', 'medium'):
            assert 'MB' in service.download_size_hint(size) or \
                   'GB' in service.download_size_hint(size)

    def test_unknown_size_hint_does_not_invent_a_number(self):
        assert _service().download_size_hint('not-a-model') == 'size unknown'


# ---------------------------------------------------------------------------
# Install command construction
# ---------------------------------------------------------------------------

class TestInstallCommand:

    def test_pipx_installs_use_inject(self):
        """pip install into a pipx venv would land in the wrong environment."""
        service = _service()
        with patch.object(service, 'install_method', return_value='pipx'):
            with patch('shutil.which', return_value='/usr/bin/pipx'):
                argv = service.install_command()
        assert argv[:3] == ['/usr/bin/pipx', 'inject', 'servonaut']
        assert all(pkg in argv for pkg in VOICE_PACKAGES)

    def test_pip_installs_target_the_running_interpreter(self):
        service = _service()
        with patch.object(service, 'install_method', return_value='pip'):
            argv = service.install_command()
        assert argv[0] == sys.executable
        assert argv[1:3] == ['-m', 'pip']
        assert all(pkg in argv for pkg in VOICE_PACKAGES)

    def test_source_checkouts_are_not_auto_installed(self):
        """Someone else owns that environment's dependencies."""
        service = _service()
        with patch.object(service, 'install_method', return_value='source'):
            assert service.install_command() is None

    def test_source_checkouts_get_the_extra_as_a_manual_command(self):
        service = _service()
        with patch.object(service, 'install_method', return_value='source'):
            assert service.manual_install_command() == "pip install -e '.[voice]'"

    def test_unknown_install_method_is_not_auto_installed(self):
        service = _service()
        with patch.object(service, 'install_method', return_value='unknown'):
            assert service.install_command() is None
            assert 'faster-whisper' in service.manual_install_command()

    def test_pipx_without_a_pipx_binary_falls_back_to_manual(self):
        service = _service()
        with patch.object(service, 'install_method', return_value='pipx'):
            with patch('shutil.which', return_value=None):
                assert service.install_command() is None

    def test_manual_command_is_the_runnable_argv_when_there_is_one(self):
        service = _service()
        with patch.object(service, 'install_method', return_value='pip'):
            assert service.manual_install_command().startswith(sys.executable)


class TestPortAudioCommand:

    def test_macos_uses_brew(self):
        service = _service()
        with patch('servonaut.services.voice_setup_service.get_os', return_value='macos'):
            assert service.portaudio_command() == 'brew install portaudio'

    def test_debian_uses_apt(self):
        service = _service()
        with patch('servonaut.services.voice_setup_service.get_os', return_value='linux'):
            with patch('servonaut.services.voice_setup_service.command_exists',
                       side_effect=lambda c: c == 'apt-get'):
                assert service.portaudio_command() == 'sudo apt install libportaudio2'

    def test_fedora_uses_dnf(self):
        service = _service()
        with patch('servonaut.services.voice_setup_service.get_os', return_value='linux'):
            with patch('servonaut.services.voice_setup_service.command_exists',
                       side_effect=lambda c: c == 'dnf'):
                assert service.portaudio_command() == 'sudo dnf install portaudio'

    def test_unknown_distro_still_says_something_useful(self):
        service = _service()
        with patch('servonaut.services.voice_setup_service.get_os', return_value='linux'):
            with patch('servonaut.services.voice_setup_service.command_exists',
                       return_value=False):
                assert 'PortAudio' in service.portaudio_command()


# ---------------------------------------------------------------------------
# Install execution
# ---------------------------------------------------------------------------

class _FakeProcess:
    def __init__(self, returncode=0, output=b''):
        self.returncode = returncode
        self._output = output
        self.killed = False

    async def communicate(self):
        return self._output, b''

    def kill(self):
        self.killed = True

    async def wait(self):
        return self.returncode


class TestInstallPackages:

    def test_source_checkout_refuses_and_explains(self):
        service = _service()
        with patch.object(service, 'install_command', return_value=None):
            with patch.object(service, 'install_method', return_value='source'):
                success, message = run_async(service.install_packages())
        assert success is False
        assert 'source checkout' in message

    def test_successful_install_reloads_the_deps(self):
        service = _service()
        proc = _FakeProcess(returncode=0)
        with patch.object(service, 'install_command', return_value=['pip', 'install']):
            with patch('asyncio.create_subprocess_exec', return_value=proc):
                with patch('servonaut.services.voice_input_service.reload_voice_deps',
                           return_value=True) as reload:
                    success, message = run_async(service.install_packages())
        reload.assert_called_once()
        assert success is True
        assert 'installed' in message.lower()

    def test_install_that_needs_a_restart_says_so(self):
        """Packages on disk but not importable in this process is not a failure."""
        service = _service()
        proc = _FakeProcess(returncode=0)
        with patch.object(service, 'install_command', return_value=['pip', 'install']):
            with patch('asyncio.create_subprocess_exec', return_value=proc):
                with patch('servonaut.services.voice_input_service.reload_voice_deps',
                           return_value=False):
                    with patch.object(service, 'probe') as probe:
                        probe.return_value = VoiceReadiness(
                            packages_ok=True, portaudio_ok=True, device_ok=True,
                            model_ok=False, model_size='small',
                        )
                        success, message = run_async(service.install_packages())
        assert success is True
        assert 'Restart' in message

    def test_missing_portaudio_after_install_names_the_system_command(self):
        service = _service()
        proc = _FakeProcess(returncode=0)
        with patch.object(service, 'install_command', return_value=['pip', 'install']):
            with patch('asyncio.create_subprocess_exec', return_value=proc):
                with patch('servonaut.services.voice_input_service.reload_voice_deps',
                           return_value=False):
                    with patch.object(service, 'probe') as probe:
                        probe.return_value = VoiceReadiness(
                            packages_ok=True, portaudio_ok=False, device_ok=False,
                            model_ok=False, model_size='small',
                        )
                        with patch.object(service, 'portaudio_command',
                                          return_value='sudo apt install libportaudio2'):
                            success, message = run_async(service.install_packages())
        assert success is True
        assert 'libportaudio2' in message

    def test_failed_install_surfaces_the_tail_of_the_output(self):
        service = _service()
        proc = _FakeProcess(returncode=1, output=b'lots of noise\nERROR: no matching dist\n')
        with patch.object(service, 'install_command', return_value=['pip', 'install']):
            with patch('asyncio.create_subprocess_exec', return_value=proc):
                success, message = run_async(service.install_packages())
        assert success is False
        assert 'no matching dist' in message

    def test_unstartable_installer_is_reported_not_raised(self):
        service = _service()
        with patch.object(service, 'install_command', return_value=['nope']):
            with patch('asyncio.create_subprocess_exec', side_effect=OSError('no such file')):
                success, message = run_async(service.install_packages())
        assert success is False
        assert 'no such file' in message

    def test_install_output_is_truncated(self):
        service = _service()
        proc = _FakeProcess(returncode=1, output=b'x' * 5000)
        with patch.object(service, 'install_command', return_value=['pip', 'install']):
            with patch('asyncio.create_subprocess_exec', return_value=proc):
                _success, message = run_async(service.install_packages())
        assert len(message) < 300


# ---------------------------------------------------------------------------
# Model download
# ---------------------------------------------------------------------------

class TestDownloadModel:

    def test_download_requires_the_packages_first(self):
        service = _service()
        success, message = run_async(service.download_model('small'))
        assert success is False
        assert 'packages' in message.lower()

    def test_successful_download_reports_the_size(self):
        service = _service()
        with patch.object(service, 'probe') as probe:
            probe.return_value = VoiceReadiness(
                packages_ok=True, portaudio_ok=True, device_ok=True,
                model_ok=False, model_size='small',
            )
            with patch.object(service, '_download_model_blocking',
                              return_value=(True, 'Downloaded the small model.')):
                success, message = run_async(service.download_model('small'))
        assert success is True
        assert 'small' in message

    def test_download_defaults_to_the_configured_size(self):
        service = _service(model_size='tiny')
        with patch.object(service, 'probe') as probe:
            probe.return_value = VoiceReadiness(
                packages_ok=True, portaudio_ok=True, device_ok=True,
                model_ok=False, model_size='tiny',
            )
            with patch.object(service, '_download_model_blocking',
                              return_value=(True, 'ok')) as blocking:
                run_async(service.download_model())
        blocking.assert_called_once_with('tiny')

    def test_download_failure_is_reported_not_raised(self):
        service = _service()
        with patch.object(service, 'probe') as probe:
            probe.return_value = VoiceReadiness(
                packages_ok=True, portaudio_ok=True, device_ok=True,
                model_ok=False, model_size='small',
            )
            with patch.object(service, '_download_model_blocking',
                              return_value=(False, 'Download failed: disk full')):
                success, message = run_async(service.download_model('small'))
        assert success is False
        assert 'disk full' in message

    def test_download_invalidates_the_cached_readiness(self):
        """A stale verdict would keep showing 'not downloaded' afterwards."""
        service = _service()
        with patch.object(service, 'probe') as probe:
            probe.return_value = VoiceReadiness(
                packages_ok=True, portaudio_ok=True, device_ok=True,
                model_ok=False, model_size='small',
            )
            with patch.object(service, '_download_model_blocking',
                              return_value=(True, 'ok')):
                run_async(service.download_model('small'))
        assert service._cached is None

    def test_blocking_download_wraps_backend_errors(self):
        service = _service()
        fw = types.ModuleType('faster_whisper')
        fw.WhisperModel = MagicMock(side_effect=RuntimeError('hub unreachable'))
        saved = sys.modules.get('faster_whisper')
        sys.modules['faster_whisper'] = fw
        try:
            success, message = service._download_model_blocking('small')
        finally:
            if saved is None:
                sys.modules.pop('faster_whisper', None)
            else:
                sys.modules['faster_whisper'] = saved
        assert success is False
        assert 'hub unreachable' in message


class TestFactory:

    def test_factory_returns_a_configured_service(self):
        config = VoiceConfig(model_size='base')
        service = build_voice_setup_service(config)
        assert isinstance(service, VoiceSetupService)
        assert service._config is config
