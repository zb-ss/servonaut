"""Unit tests for desktop voice application integration and UI wiring.

Verifies:
- DesktopVoiceSetupService readiness probing, package installation, and model downloads
- Model inventory mapping and eviction via DesktopVoiceSetupService
- VoiceConnection lazy callable command resolution
- ServonautApp service initialization in PACKAGED_DESKTOP and standard distributions
- Interfacing with VoiceReadiness and InstalledModel data structures
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import VoiceConfig
from servonaut.desktop.voice.connection import VoiceConnection
from servonaut.desktop.voice.models import (
    KOKORO_TTS_SPEC,
    NEMOTRON_ASR_SPEC,
    SILERO_VAD_SPEC,
    VoiceModelCache,
    VoiceModelCacheState,
    VoiceModelStatus,
)
from servonaut.desktop.voice.runtime import (
    VoiceRuntimeManager,
    VoiceRuntimeManifest,
    VoiceRuntimeState,
    VoiceRuntimeStatus,
)
from servonaut.desktop.voice.service import (
    DesktopVoiceConversationService,
    DesktopVoiceInputService,
    DesktopVoiceOutputService,
)
from servonaut.desktop.voice.setup_service import DesktopVoiceSetupService
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.services.voice_setup_service import InstalledModel, VoiceReadiness


def _make_dummy_layout(kind: DistributionKind, tmp_path: Path) -> RuntimeLayout:
    return RuntimeLayout(
        kind=kind,
        product_version="2.26.3",
        build_revision=None,
        resource_root=tmp_path / "resources",
        executable_root=tmp_path / "bin",
        data_root=tmp_path / "data",
        executable=tmp_path / "bin" / "servonaut",
        python_executable=Path(sys.executable),
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=PackageManagementCapability(
            kind=PackageManagementKind.MANAGED_RUNTIME if kind == DistributionKind.PACKAGED_DESKTOP else PackageManagementKind.PIP,
            argv_prefix=(),
            allows_automatic_mutation=False,
        ),
        is_frozen=(kind in (DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP)),
    )


class TestDesktopVoiceSetupService:
    def test_attributes_and_defaults(self, tmp_path: Path) -> None:
        cfg = VoiceConfig(engine="whisper")
        layout = _make_dummy_layout(DistributionKind.PACKAGED_DESKTOP, tmp_path)
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path / "runtime")
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        service = DesktopVoiceSetupService(
            cfg,
            runtime_layout=layout,
            runtime_manager=mgr,
            model_cache=cache,
        )

        assert service.engine_id == "whisper"
        assert service.package_install_available is True
        assert service.install_command() == ["servonaut-desktop", "voice", "provision"]
        assert "isolated companion runtime" in service._package_install_guidance("any")
        assert len(service.packages()) > 0
        assert service.can_download_speech_model() is True
        assert service.current_model_label()

    def test_probe_not_installed(self, tmp_path: Path) -> None:
        cfg = VoiceConfig(engine="nemotron")
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path / "runtime")
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        service = DesktopVoiceSetupService(cfg, runtime_manager=mgr, model_cache=cache)
        readiness = service.probe()

        assert isinstance(readiness, VoiceReadiness)
        assert not readiness.packages_ok
        assert not readiness.portaudio_ok
        assert not readiness.model_ok
        assert not readiness.is_ready
        assert readiness.next_step == "packages"

    def test_probe_packages_ready_model_missing(self, tmp_path: Path) -> None:
        cfg = VoiceConfig(engine="nemotron")
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path / "runtime")
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        # Mock runtime as READY
        with patch.object(mgr, "status") as mock_st:
            mock_st.return_value = VoiceRuntimeStatus(
                state=VoiceRuntimeState.READY,
                runtime_dir=tmp_path / "runtime",
            )
            service = DesktopVoiceSetupService(cfg, runtime_manager=mgr, model_cache=cache)
            readiness = service.probe(force=True)

            assert readiness.packages_ok
            assert readiness.portaudio_ok
            assert not readiness.model_ok
            assert not readiness.is_ready
            assert readiness.next_step == "model"

    def test_probe_all_ready(self, tmp_path: Path) -> None:
        cfg = VoiceConfig(engine="whisper", tts_enabled=True, conversation_mode=True)
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path / "runtime")
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        with (
            patch.object(mgr, "status") as mock_mgr_st,
            patch.object(cache, "status") as mock_cache_st,
        ):
            mock_mgr_st.return_value = VoiceRuntimeStatus(
                state=VoiceRuntimeState.READY,
                runtime_dir=tmp_path / "runtime",
            )
            mock_cache_st.return_value = VoiceModelStatus(
                model_id="any",
                state=VoiceModelCacheState.VERIFIED,
                model_dir=tmp_path / "models",
                size_bytes=1000,
            )

            service = DesktopVoiceSetupService(cfg, runtime_manager=mgr, model_cache=cache)
            readiness = service.probe(force=True)

            assert readiness.packages_ok
            assert readiness.portaudio_ok
            assert readiness.device_ok
            assert readiness.model_ok
            assert readiness.tts_packages_ok
            assert readiness.tts_model_ok
            assert readiness.vad_model_ok
            assert readiness.is_ready
            assert readiness.next_step == ""

    def test_install_packages_success(self, tmp_path: Path) -> None:
        cfg = VoiceConfig()
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path / "runtime")
        cache = VoiceModelCache(root_dir=tmp_path / "models")
        conn = MagicMock(spec=VoiceConnection)
        conn.is_connected = False

        with patch.object(mgr, "provision") as mock_prov:
            mock_prov.return_value = VoiceRuntimeStatus(
                state=VoiceRuntimeState.READY,
                runtime_dir=tmp_path / "runtime",
            )
            service = DesktopVoiceSetupService(
                cfg, runtime_manager=mgr, model_cache=cache, connection=conn
            )
            ok, msg = service.install_packages()
            assert ok is True
            assert "successfully installed" in msg
            conn.connect.assert_called_once()

    def test_install_packages_failure(self, tmp_path: Path) -> None:
        cfg = VoiceConfig()
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path / "runtime")
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        with patch.object(mgr, "provision", side_effect=RuntimeError("pip failed")):
            service = DesktopVoiceSetupService(cfg, runtime_manager=mgr, model_cache=cache)
            ok, msg = service.install_packages()
            assert ok is False
            assert "Installation failed" in msg

    def test_download_models(self, tmp_path: Path) -> None:
        cfg = VoiceConfig(engine="nemotron")
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path / "runtime")
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        with patch.object(cache, "download") as mock_download:
            mock_download.return_value = VoiceModelStatus(
                model_id="any",
                state=VoiceModelCacheState.VERIFIED,
                model_dir=tmp_path / "models",
                size_bytes=5000,
            )
            service = DesktopVoiceSetupService(cfg, runtime_manager=mgr, model_cache=cache)

            # Test speech model download
            ok, msg = service.download_speech_model()
            assert ok is True
            mock_download.assert_called_with(NEMOTRON_ASR_SPEC.model_id, progress_callback=None)

            # Test TTS model download
            ok, msg = service.download_tts_model()
            assert ok is True
            mock_download.assert_called_with(KOKORO_TTS_SPEC.model_id, progress_callback=None)

            # Test VAD model download
            ok, msg = service.download_vad_model()
            assert ok is True
            mock_download.assert_called_with(SILERO_VAD_SPEC.model_id, progress_callback=None)

    def test_installed_models_and_remove(self, tmp_path: Path) -> None:
        cfg = VoiceConfig(engine="nemotron")
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path / "runtime")
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        inv_items = [
            VoiceModelStatus(
                model_id=KOKORO_TTS_SPEC.model_id,
                state=VoiceModelCacheState.VERIFIED,
                model_dir=tmp_path / "models" / "kokoro",
                size_bytes=150_000_000,
            ),
            VoiceModelStatus(
                model_id=SILERO_VAD_SPEC.model_id,
                state=VoiceModelCacheState.NOT_DOWNLOADED,
                model_dir=tmp_path / "models",
                size_bytes=0,
            ),
        ]

        with (
            patch.object(cache, "inventory", return_value=inv_items),
            patch.object(cache, "evict") as mock_evict,
        ):
            service = DesktopVoiceSetupService(cfg, runtime_manager=mgr, model_cache=cache)
            models = service.installed_models()

            assert len(models) == 1
            assert isinstance(models[0], InstalledModel)
            assert models[0].key == KOKORO_TTS_SPEC.model_id
            assert models[0].size_bytes == 150_000_000

            # Remove model
            ok, msg = service.remove_model(models[0])
            assert ok is True
            mock_evict.assert_called_once_with(KOKORO_TTS_SPEC.model_id)


class TestVoiceConnectionCallableWorkerCmd:
    def test_callable_worker_cmd_resolution(self) -> None:
        calls = []

        def resolver() -> list[str]:
            calls.append(1)
            return ["dummy_python", "-m", "servonaut.desktop.voice.worker"]

        conn = VoiceConnection(worker_cmd=resolver)
        assert len(calls) == 0

        # Simulate spawn
        with (
            patch("subprocess.Popen") as mock_popen,
            patch.object(conn, "_start_reader_threads"),
        ):
            mock_proc = MagicMock()
            mock_proc.stdin = io.BytesIO()
            mock_proc.stdout = io.BytesIO()
            mock_proc.stderr = io.BytesIO()
            mock_popen.return_value = mock_proc

            conn._spawn_if_needed()
            assert len(calls) == 1
            mock_popen.assert_called_once()
            args, kwargs = mock_popen.call_args
            assert args[0] == ["dummy_python", "-m", "servonaut.desktop.voice.worker"]


class TestServonautAppDesktopVoiceBootstrap:
    def test_app_init_services_desktop_mode(self, tmp_path: Path) -> None:
        from servonaut.app import ServonautApp

        layout = _make_dummy_layout(DistributionKind.PACKAGED_DESKTOP, tmp_path)
        app = ServonautApp(runtime_layout=layout)
        app._init_services()

        assert isinstance(app.voice_setup_service, DesktopVoiceSetupService)
        assert isinstance(app.voice_input_service, DesktopVoiceInputService)
        assert isinstance(app.voice_output_service, DesktopVoiceOutputService)
        assert isinstance(app.voice_conversation_service, DesktopVoiceConversationService)

    def test_app_init_services_env_var_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from servonaut.app import ServonautApp

        monkeypatch.setenv("SERVONAUT_DESKTOP_VOICE", "1")
        layout = _make_dummy_layout(DistributionKind.SOURCE, tmp_path)
        app = ServonautApp(runtime_layout=layout)
        app._init_services()

        assert isinstance(app.voice_setup_service, DesktopVoiceSetupService)
        assert isinstance(app.voice_input_service, DesktopVoiceInputService)
        assert isinstance(app.voice_output_service, DesktopVoiceOutputService)
        assert isinstance(app.voice_conversation_service, DesktopVoiceConversationService)

    def test_app_init_services_standard_source_mode(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from servonaut.app import ServonautApp
        from servonaut.services.voice_setup_service import VoiceSetupService

        monkeypatch.delenv("SERVONAUT_DESKTOP_VOICE", raising=False)
        layout = _make_dummy_layout(DistributionKind.SOURCE, tmp_path)
        app = ServonautApp(runtime_layout=layout)
        app._init_services()

        # In standard source mode without env var, it constructs the standard in-process VoiceSetupService
        assert isinstance(app.voice_setup_service, VoiceSetupService)
        assert not isinstance(app.voice_setup_service, DesktopVoiceSetupService)
