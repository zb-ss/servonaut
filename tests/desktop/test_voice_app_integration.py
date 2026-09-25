"""Unit tests for desktop voice application integration and UI wiring.

Verifies:
- DesktopVoiceSetupService readiness probing, package installation, and model downloads
- Model inventory mapping and eviction via DesktopVoiceSetupService
- VoiceConnection lazy callable command resolution
- ServonautApp service initialization in PACKAGED_DESKTOP and standard distributions
- Non-desktop distributions, the standalone CLI included, never import servonaut.desktop
- Interfacing with VoiceReadiness and InstalledModel data structures
"""

from __future__ import annotations

import importlib.abc
import io
import json
import logging
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
from servonaut.desktop.voice.packaged_manifest import (
    BundledFile,
    PackagedVoiceManifest,
    ProvisionTimeouts,
)
from servonaut.desktop.voice.runtime import (
    VoiceRuntimeManager,
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


_PACKAGED_MANIFEST = PackagedVoiceManifest(
    schema_version=1,
    target="test-target",
    python_version="3.12.7",
    uv=BundledFile("uv", "a" * 64),
    wheel=BundledFile("servonaut-2.26.3-py3-none-any.whl", "b" * 64),
    requirements=BundledFile("voice-requirements.txt", "c" * 64),
    timeouts=ProvisionTimeouts(uv_command_seconds=30, stall_seconds=10, provision_seconds=120),
)


def _runtime_manager(tmp_path: Path) -> VoiceRuntimeManager:
    return VoiceRuntimeManager(
        runtime_dir=tmp_path / "runtime",
        bundle_dir=tmp_path / "bundle",
        manifest=_PACKAGED_MANIFEST,
        models_root=tmp_path / "models",
        product_version="2.26.3",
    )


def _write_packaged_manifest(layout: RuntimeLayout) -> None:
    voice_dir = layout.resource_root / "voice"
    voice_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "target": "test-target",
        "python_version": "3.12.7",
        "uv": {"filename": "uv", "sha256": "a" * 64},
        "wheel": {"filename": "servonaut-2.26.3-py3-none-any.whl", "sha256": "b" * 64},
        "requirements": {"filename": "voice-requirements.txt", "sha256": "c" * 64},
        "timeouts": {"uv_command_seconds": 30, "stall_seconds": 10, "provision_seconds": 120},
    }
    (voice_dir / "voice-runtime.json").write_text(json.dumps(manifest), encoding="utf-8")


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
            kind=PackageManagementKind.UNSUPPORTED if kind == DistributionKind.PACKAGED_DESKTOP else PackageManagementKind.PIP,
            argv_prefix=(),
            allows_automatic_mutation=False,
        ),
        is_frozen=(kind in (DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP)),
    )


class TestDesktopVoiceSetupService:
    def test_attributes_and_defaults(self, tmp_path: Path) -> None:
        cfg = VoiceConfig(engine="whisper")
        layout = _make_dummy_layout(DistributionKind.PACKAGED_DESKTOP, tmp_path)
        mgr = _runtime_manager(tmp_path)
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
        mgr = _runtime_manager(tmp_path)
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
        mgr = _runtime_manager(tmp_path)
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        # Mock runtime as READY
        with patch.object(mgr, "status") as mock_st:
            mock_st.return_value = VoiceRuntimeStatus(
                state=VoiceRuntimeState.READY,
                message="",
                expected_runtime_id="test",
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
        mgr = _runtime_manager(tmp_path)
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        with (
            patch.object(mgr, "status") as mock_mgr_st,
            patch.object(cache, "status") as mock_cache_st,
        ):
            mock_mgr_st.return_value = VoiceRuntimeStatus(
                state=VoiceRuntimeState.READY,
                message="",
                expected_runtime_id="test",
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
        mgr = _runtime_manager(tmp_path)
        cache = VoiceModelCache(root_dir=tmp_path / "models")
        conn = MagicMock(spec=VoiceConnection)
        conn.is_connected = False

        with patch.object(mgr, "provision") as mock_prov:
            mock_prov.return_value = VoiceRuntimeStatus(
                state=VoiceRuntimeState.READY,
                message="",
                expected_runtime_id="test",
            )
            service = DesktopVoiceSetupService(
                cfg, runtime_manager=mgr, model_cache=cache, connection=conn
            )
            ok, msg = service.install_packages()
            assert ok is True
            assert "successfully installed" in msg
            conn.connect.assert_called_once()

    def test_install_packages_restarts_a_running_worker(self, tmp_path: Path) -> None:
        """A worker started before the install must move to the new release."""
        mgr = _runtime_manager(tmp_path)
        conn = MagicMock()
        conn.is_connected = True
        ready = VoiceRuntimeStatus(
            state=VoiceRuntimeState.READY, message="", expected_runtime_id="test"
        )

        with patch.object(mgr, "provision", return_value=ready):
            service = DesktopVoiceSetupService(
                VoiceConfig(),
                runtime_manager=mgr,
                model_cache=VoiceModelCache(root_dir=tmp_path / "models"),
                connection=conn,
            )
            ok, msg = service.install_packages()

        assert ok is True and "successfully installed" in msg
        conn.restart.assert_called_once_with()
        conn.connect.assert_not_called()

    def test_install_packages_reports_a_worker_that_cannot_start(self, tmp_path: Path) -> None:
        from servonaut.desktop.voice.connection import VoiceConnectionError

        mgr = _runtime_manager(tmp_path)
        conn = MagicMock(spec=VoiceConnection)
        conn.is_connected = False
        conn.connect.side_effect = VoiceConnectionError("worker exited")
        ready = VoiceRuntimeStatus(
            state=VoiceRuntimeState.READY, message="", expected_runtime_id="test"
        )

        with patch.object(mgr, "provision", return_value=ready):
            service = DesktopVoiceSetupService(
                VoiceConfig(),
                runtime_manager=mgr,
                model_cache=VoiceModelCache(root_dir=tmp_path / "models"),
                connection=conn,
            )
            ok, msg = service.install_packages()

        assert ok is True
        assert "could not start" in msg and "worker exited" in msg

    def test_install_packages_failure(self, tmp_path: Path) -> None:
        cfg = VoiceConfig()
        mgr = _runtime_manager(tmp_path)
        cache = VoiceModelCache(root_dir=tmp_path / "models")

        with patch.object(mgr, "provision", side_effect=RuntimeError("pip failed")):
            service = DesktopVoiceSetupService(cfg, runtime_manager=mgr, model_cache=cache)
            ok, msg = service.install_packages()
            assert ok is False
            assert "Installation failed" in msg

    def test_download_models(self, tmp_path: Path) -> None:
        cfg = VoiceConfig(engine="nemotron")
        mgr = _runtime_manager(tmp_path)
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
        mgr = _runtime_manager(tmp_path)
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


_DESKTOP_PACKAGE = "servonaut.desktop"


def _is_desktop_module(name: str) -> bool:
    return name == _DESKTOP_PACKAGE or name.startswith(f"{_DESKTOP_PACKAGE}.")


class _DesktopPackageBlocker(importlib.abc.MetaPathFinder):
    """Stand in for a distribution built without the desktop package."""

    def __init__(self) -> None:
        self.requests: list[str] = []

    def find_spec(self, fullname: str, path: object = None, target: object = None) -> None:
        if _is_desktop_module(fullname):
            self.requests.append(fullname)
            raise ModuleNotFoundError(f"No module named {fullname!r}", name=fullname)
        return None


@pytest.fixture
def desktop_package_absent(monkeypatch: pytest.MonkeyPatch) -> _DesktopPackageBlocker:
    """Unload the desktop package and refuse every later import of it."""
    import servonaut

    for name in [name for name in sys.modules if _is_desktop_module(name)]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.delattr(servonaut, "desktop", raising=False)
    blocker = _DesktopPackageBlocker()
    monkeypatch.setattr(sys, "meta_path", [blocker, *sys.meta_path])
    return blocker


class TestServonautAppDesktopVoiceBootstrap:
    def test_app_init_services_desktop_mode(self, tmp_path: Path) -> None:
        from servonaut.app import ServonautApp

        layout = _make_dummy_layout(DistributionKind.PACKAGED_DESKTOP, tmp_path)
        _write_packaged_manifest(layout)
        app = ServonautApp(runtime_layout=layout)
        app._init_services()

        assert isinstance(app.voice_setup_service, DesktopVoiceSetupService)
        assert isinstance(app.voice_input_service, DesktopVoiceInputService)
        assert isinstance(app.voice_output_service, DesktopVoiceOutputService)
        assert isinstance(app.voice_conversation_service, DesktopVoiceConversationService)

    def test_desktop_voice_runtime_lives_under_the_runtime_data_root(self, tmp_path: Path) -> None:
        from servonaut.app import ServonautApp

        layout = _make_dummy_layout(DistributionKind.PACKAGED_DESKTOP, tmp_path)
        _write_packaged_manifest(layout)
        app = ServonautApp(runtime_layout=layout)
        app._init_services()

        runtime_dir = app.voice_setup_service.runtime_manager.runtime_dir
        assert runtime_dir == layout.data_root / "runtimes" / "voice"
        assert app.voice_setup_service.model_cache.root_dir == (
            layout.data_root / "voice_models"
        ).resolve()

    @pytest.mark.parametrize("environment_value", [None, "1"])
    def test_app_init_services_standard_source_mode(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, environment_value: str | None
    ) -> None:
        """Only a packaged desktop layout selects the desktop voice services."""
        from servonaut.app import ServonautApp
        from servonaut.services.voice_setup_service import VoiceSetupService

        if environment_value is None:
            monkeypatch.delenv("SERVONAUT_DESKTOP_VOICE", raising=False)
        else:
            monkeypatch.setenv("SERVONAUT_DESKTOP_VOICE", environment_value)
        layout = _make_dummy_layout(DistributionKind.SOURCE, tmp_path)
        app = ServonautApp(runtime_layout=layout)
        app._init_services()

        assert isinstance(app.voice_setup_service, VoiceSetupService)
        assert not isinstance(app.voice_setup_service, DesktopVoiceSetupService)

    @pytest.mark.parametrize(
        "kind",
        [kind for kind in DistributionKind if kind is not DistributionKind.PACKAGED_DESKTOP],
        ids=lambda kind: kind.value,
    )
    def test_non_desktop_distributions_never_import_the_desktop_package(
        self,
        tmp_path: Path,
        desktop_package_absent: _DesktopPackageBlocker,
        kind: DistributionKind,
    ) -> None:
        """The standalone CLI ships without servonaut.desktop and never asks for it."""
        from servonaut.app import ServonautApp
        from servonaut.services.voice_setup_service import VoiceSetupService

        app = ServonautApp(runtime_layout=_make_dummy_layout(kind, tmp_path))
        app._init_services()

        assert desktop_package_absent.requests == []
        assert not [name for name in sys.modules if _is_desktop_module(name)]
        assert isinstance(app.voice_setup_service, VoiceSetupService)
        assert app.voice_conversation_service is not None

    def test_desktop_voice_degrades_gracefully_without_its_package(
        self,
        tmp_path: Path,
        desktop_package_absent: _DesktopPackageBlocker,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from servonaut.app import ServonautApp

        layout = _make_dummy_layout(DistributionKind.PACKAGED_DESKTOP, tmp_path)
        app = ServonautApp(runtime_layout=layout)
        with caplog.at_level(logging.WARNING, logger="servonaut.app"):
            app._init_services()

        assert desktop_package_absent.requests == ["servonaut.desktop"]
        assert app.voice_setup_service is None
        assert app.voice_input_service is None
        assert app.voice_output_service is None
        assert app.voice_conversation_service is None
        assert "Voice services unavailable" in caplog.text
