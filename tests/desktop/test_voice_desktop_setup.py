"""Tests for the packaged desktop's voice setup service and its wiring.

Covers the shared setup interface, provisioning off the event loop with
progress and cancellation, honest Whisper presence, registry-backed size
hints, model inventory, handing saved settings to the worker, and the
worker's environment and models root.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import sys
import threading
from pathlib import Path
from typing import Any, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import VoiceConfig
from servonaut.desktop.voice import connection as connection_module
from servonaut.desktop.voice.connection import VoiceConnection, VoiceConnectionError
from servonaut.desktop.voice.models import (
    KOKORO_TTS_SPEC,
    SILERO_VAD_SPEC,
    VoiceModelCache,
    VoiceModelCacheState,
    VoiceModelStatus,
    nemotron_spec,
)
from servonaut.desktop.voice.packaged_manifest import (
    BundledFile,
    PackagedVoiceManifest,
    ProvisionTimeouts,
)
from servonaut.desktop.voice.protocol import VOICE_PROTOCOL_VERSION, VoiceWorkerConfig
from servonaut.desktop.voice.runtime import (
    VoiceRuntimeError,
    VoiceRuntimeManager,
    VoiceRuntimeManifest,
    VoiceRuntimeState,
    VoiceRuntimeStatus,
)
from servonaut.desktop.voice.setup_service import (
    DesktopVoiceSetupService,
    _step_progress,
)
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.services.interfaces import VoiceSetupServiceInterface
from servonaut.services.voice_engines import human_bytes
from servonaut.services.voice_setup_service import VoiceSetupService

_MANIFEST = PackagedVoiceManifest(
    schema_version=1,
    target="test-target",
    python_version="3.12.7",
    uv=BundledFile("uv", "a" * 64),
    wheel=BundledFile("servonaut-1.0.0-py3-none-any.whl", "b" * 64),
    requirements=BundledFile("voice-requirements.txt", "c" * 64),
    timeouts=ProvisionTimeouts(uv_command_seconds=30, stall_seconds=10, provision_seconds=120),
)

_READY = VoiceRuntimeStatus(
    state=VoiceRuntimeState.READY, message="", expected_runtime_id="test"
)


def _manager(tmp_path: Path) -> VoiceRuntimeManager:
    return VoiceRuntimeManager(
        runtime_dir=tmp_path / "runtime",
        bundle_dir=tmp_path / "bundle",
        manifest=_MANIFEST,
        models_root=tmp_path / "models",
        product_version="1.0.0",
    )


def _service(
    tmp_path: Path, config: VoiceConfig | None = None, **kwargs: Any
) -> DesktopVoiceSetupService:
    manager = kwargs.pop("runtime_manager", None) or _manager(tmp_path)
    return DesktopVoiceSetupService(
        config or VoiceConfig(),
        runtime_manager=manager,
        model_cache=VoiceModelCache(root_dir=manager.models_root),
        **kwargs,
    )


def _cache_whisper(manager: VoiceRuntimeManager, size: str) -> Path:
    """Lay out cached Whisper weights the way the hub library does."""
    repo = manager.whisper_cache_root / f"models--Systran--faster-whisper-{size}"
    weights = repo / "snapshots" / "0123abcd" / "model.bin"
    weights.parent.mkdir(parents=True)
    weights.write_bytes(b"\0" * 64)
    return repo


def _verified(model_id: str, tmp_path: Path, size: int = 1000) -> VoiceModelStatus:
    return VoiceModelStatus(
        model_id=model_id,
        state=VoiceModelCacheState.VERIFIED,
        model_dir=tmp_path / model_id,
        size_bytes=size,
    )


def _desktop_layout(tmp_path: Path) -> RuntimeLayout:
    return RuntimeLayout(
        kind=DistributionKind.PACKAGED_DESKTOP,
        product_version="1.0.0",
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
            kind=PackageManagementKind.UNSUPPORTED, argv_prefix=(),
            allows_automatic_mutation=False,
        ),
        is_frozen=True,
    )


def _desktop_app(tmp_path: Path) -> Any:
    from servonaut.app import ServonautApp

    layout = _desktop_layout(tmp_path)
    voice_dir = layout.resource_root / "voice"
    voice_dir.mkdir(parents=True)
    (voice_dir / "voice-runtime.json").write_text(
        '{"schema_version": 1, "target": "test-target", "python_version": "3.12.7",'
        ' "uv": {"filename": "uv", "sha256": "' + "a" * 64 + '"},'
        ' "wheel": {"filename": "servonaut-1.0.0-py3-none-any.whl", "sha256": "' + "b" * 64 + '"},'
        ' "requirements": {"filename": "voice-requirements.txt", "sha256": "' + "c" * 64 + '"},'
        ' "timeouts": {"uv_command_seconds": 30, "stall_seconds": 10, "provision_seconds": 120}}',
        encoding="utf-8",
    )
    app = ServonautApp(runtime_layout=layout)
    app._init_services()
    return app


# ---------------------------------------------------------------------------
# One interface, two implementations
# ---------------------------------------------------------------------------


def _shape(member: Any) -> List[Tuple[str, Any, Any]]:
    return [
        (param.name, param.kind, param.default)
        for param in inspect.signature(member).parameters.values()
    ]


class TestSharedInterface:
    def test_both_services_implement_the_interface(self) -> None:
        assert issubclass(VoiceSetupService, VoiceSetupServiceInterface)
        assert issubclass(DesktopVoiceSetupService, VoiceSetupServiceInterface)

    @pytest.mark.parametrize("name", sorted(VoiceSetupServiceInterface.__abstractmethods__))
    def test_signatures_and_async_ness_match(self, name: str) -> None:
        declared = inspect.getattr_static(VoiceSetupServiceInterface, name)
        for cls in (VoiceSetupService, DesktopVoiceSetupService):
            member = inspect.getattr_static(cls, name)
            if isinstance(declared, property):
                assert isinstance(member, property), f"{cls.__name__}.{name}"
                continue
            assert inspect.iscoroutinefunction(member) == inspect.iscoroutinefunction(
                declared
            ), f"{cls.__name__}.{name} sync/async differs from the interface"
            assert _shape(member) == _shape(declared), f"{cls.__name__}.{name}"


# ---------------------------------------------------------------------------
# Provisioning: off the loop, progress on the loop, cancellation
# ---------------------------------------------------------------------------


class TestProvisioning:
    def test_install_runs_off_the_loop_and_reports_progress_on_it(
        self, tmp_path: Path
    ) -> None:
        manager = _manager(tmp_path)
        seen: dict = {}

        def provision(progress: Any, cancel: threading.Event) -> VoiceRuntimeStatus:
            seen["thread"] = threading.get_ident()
            seen["cancel"] = cancel
            progress("Checking", 0, 0)  # no total: must not divide by zero
            progress("Downloading voice packages", 3, 8)
            return _READY

        reports: List[Tuple[str, int, int, int]] = []

        async def run() -> Tuple[bool, str]:
            seen["loop_thread"] = threading.get_ident()
            service = _service(tmp_path, runtime_manager=manager)
            return await service.install_packages(
                progress=lambda *a: reports.append((*a, threading.get_ident()))
            )

        with patch.object(manager, "provision", side_effect=provision):
            ok, message = asyncio.run(run())

        assert ok is True, message
        assert seen["thread"] != seen["loop_thread"]
        assert isinstance(seen["cancel"], threading.Event)
        assert [r[:3] for r in reports] == [
            ("Checking", 0, 0), ("Downloading voice packages", 3, 8),
        ]
        assert {r[3] for r in reports} == {seen["loop_thread"]}

    def test_step_progress_treats_a_zero_total_as_indeterminate(self) -> None:
        calls: list = []
        report = _step_progress(lambda *a: calls.append(a))
        report("Preparing", 2, 0)
        report("Installing", 9, 8)
        assert calls == [("Preparing", 0, 0), ("Installing", 8, 8)]

    def test_cancelling_the_install_cancels_provisioning(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        started = threading.Event()
        observed: dict = {}

        def provision(progress: Any, cancel: threading.Event) -> VoiceRuntimeStatus:
            started.set()
            observed["cancelled"] = cancel.wait(5.0)
            return _READY

        async def run() -> None:
            task = asyncio.ensure_future(
                _service(tmp_path, runtime_manager=manager).install_packages()
            )
            await asyncio.to_thread(started.wait, 5.0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        with patch.object(manager, "provision", side_effect=provision):
            asyncio.run(run())

        assert observed["cancelled"] is True

    def test_install_reports_a_worker_that_cannot_start(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        conn = MagicMock(spec=VoiceConnection)
        conn.connect.side_effect = VoiceConnectionError("worker exited with status 1")

        with patch.object(manager, "provision", return_value=_READY):
            service = _service(tmp_path, runtime_manager=manager, connection=conn)
            ok, message = asyncio.run(service.install_packages())

        assert ok is False
        assert "could not start" in message and "status 1" in message

    def test_failures_do_not_leak_proxy_credentials(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        manager = _manager(tmp_path)
        error = VoiceRuntimeError(
            "Downloading voice packages failed: proxy http://someone:hunter2@example.com:3128"
        )
        caplog.set_level(logging.DEBUG)

        service = _service(tmp_path, runtime_manager=manager)
        with patch.object(manager, "provision", side_effect=error):
            ok, message = asyncio.run(service.install_packages())

        assert ok is False
        assert "hunter2" not in message and "example.com:3128" in message
        assert "hunter2" not in caplog.text

    def test_speech_packages_provision_the_same_runtime(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        with patch.object(manager, "provision", return_value=_READY) as provision:
            ok, _ = asyncio.run(_service(tmp_path, runtime_manager=manager).install_tts_packages())
        assert ok is True
        provision.assert_called_once()

    def test_repair_rebuilds_and_restarts_the_worker(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        conn = MagicMock(spec=VoiceConnection)
        with patch.object(manager, "repair", return_value=_READY) as repair:
            service = _service(tmp_path, runtime_manager=manager, connection=conn)
            ok, message = asyncio.run(service.repair_runtime())
        assert ok is True and "repaired" in message
        repair.assert_called_once()
        conn.restart.assert_called_once_with()
        conn.connect.assert_called_once_with()

    def test_remove_stops_the_worker_before_deleting(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        order: list = []
        conn = MagicMock(spec=VoiceConnection)
        conn.restart.side_effect = lambda: order.append("restart")
        with patch.object(manager, "remove", side_effect=lambda: order.append("remove")):
            service = _service(tmp_path, runtime_manager=manager, connection=conn)
            ok, message = asyncio.run(service.remove_runtime())
        assert ok is True and "models were kept" in message
        assert order == ["restart", "remove"]

    def test_remove_reports_a_blocked_removal(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path)
        blocked = VoiceRuntimeError("A voice worker is still running from this runtime.")
        with patch.object(manager, "remove", side_effect=blocked):
            ok, message = asyncio.run(_service(tmp_path, runtime_manager=manager).remove_runtime())
        assert ok is False and "still running" in message


# ---------------------------------------------------------------------------
# Models: honest presence, registry sizes, streaming latency, inventory
# ---------------------------------------------------------------------------


class TestModels:
    def test_whisper_presence_reads_the_hub_cache_under_the_models_root(
        self, tmp_path: Path
    ) -> None:
        service = _service(tmp_path, VoiceConfig(engine="whisper", model_size="small"))
        assert service.is_model_present() is False

        _cache_whisper(service.runtime_manager, "small")

        assert service.is_model_present() is True
        assert service.is_model_present_for("whisper", model_size="base", latency_ms=320) is False
        assert service.model_bytes_for("whisper", model_size="small", latency_ms=320) == 64

    def test_missing_whisper_weights_download_on_first_use_without_blocking(
        self, tmp_path: Path
    ) -> None:
        service = _service(tmp_path, VoiceConfig(engine="whisper"))
        with patch.object(service.runtime_manager, "status", return_value=_READY):
            readiness = service.probe(force=True)
        assert readiness.model_ok is False
        assert readiness.model_downloads_on_first_use is True
        assert readiness.is_ready is True and readiness.next_step == ""

    def test_whisper_download_does_not_pretend(self, tmp_path: Path) -> None:
        service = _service(tmp_path, VoiceConfig(engine="whisper"))
        with patch.object(service.model_cache, "download") as download:
            ok, message = asyncio.run(service.download_model("small"))
        assert ok is False and "first time" in message
        download.assert_not_called()

    def test_streaming_model_follows_the_configured_latency(self, tmp_path: Path) -> None:
        spec = nemotron_spec(80)
        service = _service(tmp_path, VoiceConfig(engine="nemotron", nemotron_latency_ms=80))
        cache = service.model_cache
        verified = _verified(spec.model_id, tmp_path)

        with patch.object(cache, "download", return_value=verified) as download:
            ok, _ = asyncio.run(service.download_model())
        assert ok is True
        assert download.call_args.args == (spec.model_id,)

        with patch.object(cache, "status", side_effect=lambda mid, **_: (
            verified if mid == spec.model_id
            else VoiceModelStatus(mid, VoiceModelCacheState.NOT_DOWNLOADED, tmp_path)
        )):
            assert service.is_model_present() is True
            assert service.is_model_present_for("nemotron", model_size="", latency_ms=320) is False

        assert service.download_size_hint_for("nemotron", model_size="") == human_bytes(
            spec.total_download_bytes
        )

    def test_download_progress_arrives_on_the_loop_in_bytes(self, tmp_path: Path) -> None:
        service = _service(tmp_path, VoiceConfig(engine="nemotron"))
        spec = nemotron_spec(320)
        total = spec.total_download_bytes

        def download(model_id: str, *, progress_callback: Any) -> VoiceModelStatus:
            progress_callback(0.1, 1024, total)       # below the repaint step
            progress_callback(0.5, 64 << 20, total)
            progress_callback(1.0, total, total)
            return _verified(model_id, tmp_path)

        reports: list = []

        async def run() -> None:
            loop_thread = threading.get_ident()
            await service.download_model(
                progress=lambda *a: reports.append((*a, threading.get_ident() == loop_thread))
            )

        with patch.object(service.model_cache, "download", side_effect=download):
            asyncio.run(run())

        assert [r[1:3] for r in reports] == [(64 << 20, total), (total, total)]
        assert all(r[0] == spec.display_name and r[3] for r in reports)

    def test_size_hints_come_from_the_pinned_registry(self, tmp_path: Path) -> None:
        service = _service(tmp_path)
        assert human_bytes(KOKORO_TTS_SPEC.total_download_bytes) in service.tts_download_size_hint()
        assert human_bytes(KOKORO_TTS_SPEC.total_disk_bytes) in service.tts_download_size_hint()
        assert service.vad_download_size_hint() == human_bytes(
            SILERO_VAD_SPEC.total_download_bytes
        )

    def test_inventory_names_engines_the_panel_matches_on(self, tmp_path: Path) -> None:
        service = _service(tmp_path, VoiceConfig(engine="nemotron", nemotron_latency_ms=160))
        inventory = [
            _verified(KOKORO_TTS_SPEC.model_id, tmp_path),
            _verified(SILERO_VAD_SPEC.model_id, tmp_path),
            _verified(nemotron_spec(160).model_id, tmp_path),
            _verified(nemotron_spec(320).model_id, tmp_path),
        ]
        with patch.object(service.model_cache, "inventory", return_value=inventory):
            models = service.installed_models(
                active_tts_enabled=True, active_conversation_mode=False
            )
            stale = service.stale_models(active_tts_enabled=True, active_conversation_mode=False)

        by_key = {model.key: model for model in models}
        assert by_key[KOKORO_TTS_SPEC.model_id].engine == "kokoro"
        assert by_key[SILERO_VAD_SPEC.model_id].engine == "silero-vad"
        assert by_key[nemotron_spec(160).model_id].in_use is True
        assert by_key[nemotron_spec(320).model_id].in_use is False
        assert {model.key for model in stale} == {
            SILERO_VAD_SPEC.model_id, nemotron_spec(320).model_id,
        }

    def test_whisper_weights_are_listed_and_removable(self, tmp_path: Path) -> None:
        service = _service(tmp_path, VoiceConfig(engine="whisper", model_size="small"))
        repo = _cache_whisper(service.runtime_manager, "base")
        with patch.object(service.model_cache, "inventory", return_value=[]):
            (model,) = service.installed_models()
        assert (model.engine, model.key, model.in_use) == ("whisper", "base", False)

        ok, _ = service.remove_installed(model)

        assert ok is True and not repo.exists()

    def test_remove_model_evicts_the_configured_streaming_variant(self, tmp_path: Path) -> None:
        service = _service(tmp_path, VoiceConfig(engine="nemotron", nemotron_latency_ms=560))
        with patch.object(service.model_cache, "evict") as evict:
            ok, _ = service.remove_model("small")
        assert ok is True
        evict.assert_called_once_with(nemotron_spec(560).model_id)


# ---------------------------------------------------------------------------
# Saved settings reach the worker
# ---------------------------------------------------------------------------


class TestApplyConfig:
    def test_saved_settings_are_sent_to_the_worker_off_the_loop(self, tmp_path: Path) -> None:
        conn = MagicMock(spec=VoiceConnection)
        threads: dict = {}
        conn.configure.side_effect = lambda *_: threads.setdefault("worker", threading.get_ident())
        service = _service(tmp_path, connection=conn)
        updated = VoiceConfig(engine="nemotron", tts_voice="bf_emma", barge_in=True)

        async def run() -> Tuple[bool, str]:
            threads["loop"] = threading.get_ident()
            return await service.apply_config(updated)

        assert asyncio.run(run()) == (True, "")
        conn.configure.assert_called_once_with(VoiceWorkerConfig.from_voice_config(updated))
        assert threads["worker"] != threads["loop"]
        assert service.engine_id == "nemotron"

    def test_a_rejected_configure_is_reported(self, tmp_path: Path) -> None:
        conn = MagicMock(spec=VoiceConnection)
        conn.configure.side_effect = VoiceConnectionError("request timed out")
        ok, message = asyncio.run(_service(tmp_path, connection=conn).apply_config(VoiceConfig()))
        assert ok is False and "timed out" in message


# ---------------------------------------------------------------------------
# The worker process: environment, window, models root
# ---------------------------------------------------------------------------


def _spawn_kwargs(conn: VoiceConnection) -> dict:
    with patch.object(connection_module.subprocess, "Popen") as popen:
        popen.return_value = MagicMock()
        conn._spawn_if_needed(["voice-worker"])
    return popen.call_args.kwargs


class TestWorkerProcess:
    def test_desktop_worker_env_carries_no_parent_credentials(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "not-a-real-secret")
        monkeypatch.setenv("SERVONAUT_API_TOKEN", "not-a-real-token")
        monkeypatch.setenv("HF_TOKEN", "not-a-real-hub-token")
        app = _desktop_app(tmp_path)
        manager = app.voice_setup_service.runtime_manager

        env = _spawn_kwargs(app.voice_setup_service.connection)["env"]

        for name in ("AWS_SECRET_ACCESS_KEY", "SERVONAUT_API_TOKEN", "HF_TOKEN"):
            assert name not in env
        assert env["HF_HUB_CACHE"] == str(manager.whisper_cache_root)
        assert env["PYTHONUNBUFFERED"] == "1"

    def test_env_callable_is_resolved_at_each_spawn(self) -> None:
        values = iter([{"A": "1"}, {"A": "2"}])
        conn = VoiceConnection(env=lambda: next(values), inherit_env=False)
        assert _spawn_kwargs(conn)["env"]["A"] == "1"
        assert _spawn_kwargs(conn)["env"]["A"] == "2"

    def test_inherited_env_is_still_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SERVONAUT_TEST_MARKER", "present")
        env = _spawn_kwargs(VoiceConnection(env={"EXTRA": "1"}))["env"]
        assert env["SERVONAUT_TEST_MARKER"] == "present" and env["EXTRA"] == "1"

    def test_windows_spawn_has_no_console_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(connection_module.sys, "platform", "win32")
        assert _spawn_kwargs(VoiceConnection())["creationflags"] == 0x08000000

    def test_posix_spawn_passes_no_creation_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(connection_module.sys, "platform", "linux")
        assert "creationflags" not in _spawn_kwargs(VoiceConnection())

    def test_every_model_path_resolves_under_one_root(self, tmp_path: Path) -> None:
        app = _desktop_app(tmp_path)
        service = app.voice_setup_service
        manager = service.runtime_manager
        root = tmp_path / "data" / "voice_models"
        installed = VoiceRuntimeManifest(
            runtime_id=manager.expected_runtime_id,
            release="release-1",
            python_version="3.12.7",
            lock_sha256="a" * 64,
            wheel_sha256="b" * 64,
            product_version="1.0.0",
            protocol_version=VOICE_PROTOCOL_VERSION,
            created_at="2026-01-01T00:00:00+00:00",
        )
        ready = VoiceRuntimeStatus(
            state=VoiceRuntimeState.READY, message="",
            expected_runtime_id=manager.expected_runtime_id, installed=installed,
        )

        with patch.object(manager, "status", return_value=ready):
            argv = manager.get_worker_cmd()

        assert manager.models_root == root
        assert service.model_cache.root_dir == root.resolve()
        assert argv[argv.index("--models-root") + 1] == str(root)
        assert Path(manager.worker_env()["HF_HUB_CACHE"]).is_relative_to(root)


# ---------------------------------------------------------------------------
# The mounted settings panel driving the desktop service
# ---------------------------------------------------------------------------


class _VoicePanelHost:
    """Builds a minimal Textual app that mounts the voice settings panel."""

    @staticmethod
    def build(tmp_path: Path, service: DesktopVoiceSetupService) -> Any:
        from textual.app import App

        from servonaut.config.manager import ConfigManager
        from servonaut.config.schema import AppConfig
        from servonaut.screens.settings.panels.voice import VoicePanel
        from servonaut.styles import CSS_FILES

        manager = ConfigManager()
        manager._config_path = tmp_path / "config.json"  # type: ignore[attr-defined]
        manager._config = AppConfig(voice=VoiceConfig(engine="whisper"))  # type: ignore[attr-defined]
        manager.save(manager._config)  # type: ignore[attr-defined]

        class Host(App):
            CSS_PATH = CSS_FILES

            def __init__(self) -> None:
                super().__init__()
                self.config_manager = manager
                self.runtime_layout = _desktop_layout(tmp_path)
                self.voice_setup_service = service
                self.voice_input_service = MagicMock()
                self.voice_output_service = MagicMock()
                self.voice_conversation_service = MagicMock()
                self.panel = VoicePanel()

            def on_mount(self) -> None:
                self.mount(self.panel)

        return Host()


def _button_ids(panel: Any) -> set:
    from textual.widgets import Button

    return {button.id for button in panel.query(Button) if button.id}


@pytest.mark.asyncio
async def test_panel_installs_the_runtime_and_offers_maintenance(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    conn = MagicMock(spec=VoiceConnection)
    service = _service(tmp_path, VoiceConfig(engine="whisper"),
                       runtime_manager=manager, connection=conn)
    status = {"now": VoiceRuntimeStatus(
        state=VoiceRuntimeState.NOT_INSTALLED, message="", expected_runtime_id="test",
    )}
    labels: list = []

    def provision(progress: Any, cancel: threading.Event) -> VoiceRuntimeStatus:
        progress("Downloading voice packages", 3, 8)
        status["now"] = _READY
        return _READY

    app = _VoicePanelHost.build(tmp_path, service)
    with (
        patch.object(manager, "status", side_effect=lambda: status["now"]),
        patch.object(manager, "provision", side_effect=provision),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.panel
            assert "voice_btn_install" in _button_ids(panel)
            assert "voice_btn_repair_runtime" not in _button_ids(panel)

            original = panel._on_install_progress
            panel._on_install_progress = lambda *a: (labels.append(a), original(*a))
            panel._start_install()
            await pilot.app.workers.wait_for_complete()
            await pilot.pause()

            ids = _button_ids(panel)
            assert {"voice_btn_repair_runtime", "voice_btn_remove_runtime"} <= ids
            assert "voice_btn_install" not in ids
            # Whisper weights arrive on first use: no download button.
            assert "voice_btn_download" not in ids

    assert labels == [("Downloading voice packages", 3, 8)]
    assert [call[0] for call in conn.method_calls] == ["restart", "connect"]


@pytest.mark.asyncio
async def test_panel_save_reconfigures_the_worker_and_keeps_the_proxies(
    tmp_path: Path,
) -> None:
    from textual.widgets import Select

    conn = MagicMock(spec=VoiceConnection)
    service = _service(tmp_path, VoiceConfig(engine="whisper"), connection=conn)
    app = _VoicePanelHost.build(tmp_path, service)
    async with app.run_test() as pilot:
        await pilot.pause()
        proxies = (app.voice_input_service, app.voice_output_service,
                   app.voice_conversation_service)
        app.panel.query_one("#voice_engine", Select).value = "nemotron"
        await pilot.pause()
        app.panel.persist()
        await pilot.app.workers.wait_for_complete()
        await pilot.pause()

        assert (app.voice_input_service, app.voice_output_service,
                app.voice_conversation_service) == proxies
        assert app.voice_input_service._config.engine == "nemotron"

    sent = conn.configure.call_args.args[0]
    assert isinstance(sent, VoiceWorkerConfig) and sent.engine == "nemotron"
