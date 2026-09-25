"""Voice readiness and guided setup for the packaged desktop build.

The desktop build carries no voice packages of its own. "Installing the
packages" provisions an isolated voice runtime (see
:class:`~servonaut.desktop.voice.runtime.VoiceRuntimeManager`), the voice
worker runs from it, and model weights live in one models root managed by
:class:`~servonaut.desktop.voice.models.VoiceModelCache`. This service puts
both behind the setup interface the settings and chat panels drive.

Every blocking step (provisioning, model downloads, starting the worker)
runs on a worker thread, never on the event loop, and progress is delivered
back on the event loop that awaited the operation.
"""

from __future__ import annotations

import asyncio
import http.client
import logging
import re
import shutil
import tarfile
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

from servonaut.desktop.voice.connection import VoiceConnection, VoiceConnectionError
from servonaut.desktop.voice.models import (
    KOKORO_TTS_SPEC,
    MODEL_REGISTRY,
    SILERO_VAD_SPEC,
    VoiceModelCache,
    VoiceModelCacheState,
    VoiceModelError,
    VoiceModelSpec,
    nemotron_spec,
)
from servonaut.desktop.voice.protocol import VoiceWorkerConfig
from servonaut.desktop.voice.runtime import (
    VoiceRuntimeError,
    VoiceRuntimeManager,
    VoiceRuntimeState,
    VoiceRuntimeStatus,
)
from servonaut.runtime import RuntimeLayout, detect_runtime
from servonaut.services.interfaces import VoiceSetupProgress, VoiceSetupServiceInterface
from servonaut.services.voice_engines import (
    directory_bytes,
    engine_spec,
    human_bytes,
    is_whisper_model_cached,
    model_label,
    whisper_model_cache_dirs,
)
from servonaut.services.voice_setup_service import (
    MODEL_DOWNLOAD_SIZES,
    InstalledModel,
    VoiceReadiness,
    portaudio_install_command,
)

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

logger = logging.getLogger(__name__)

# Engine names the settings panel's per-model actions match on, keyed by
# the model registry's engine kinds.
_PANEL_ENGINE: Dict[str, str] = {"stt": "nemotron", "tts": "kokoro", "vad": "silero-vad"}

# Download progress is forwarded at most every this many bytes. The model
# cache reports every mebibyte; repainting the bar that often is wasted work.
_PROGRESS_STEP_BYTES = 4 << 20

# The runtime's size depends on the platform's wheels and is pinned nowhere,
# so this stays an approximation.
_RUNTIME_SIZE_HINT = "~200 MB"

# user:password@ in a URL. Provisioning errors can quote a proxy URL, and
# proxy settings are the one credential the provisioning environment carries.
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@")

_ModelProgress = Callable[[float, int, int], None]

# What a model download can raise once the cache has retried what it could:
# network, disk, protocol, archive and lock failures.
_DOWNLOAD_ERRORS = (
    OSError,
    VoiceModelError,
    VoiceRuntimeError,
    tarfile.TarError,
    http.client.HTTPException,
)


class DesktopVoiceSetupService(VoiceSetupServiceInterface):
    """Readiness and setup backed by the managed runtime and voice worker."""

    def __init__(
        self,
        config: 'VoiceConfig',
        *,
        runtime_layout: Optional[RuntimeLayout] = None,
        runtime_manager: VoiceRuntimeManager,
        model_cache: Optional[VoiceModelCache] = None,
        connection: Optional[VoiceConnection] = None,
    ) -> None:
        self._config = config
        self._runtime = runtime_layout or detect_runtime()
        self._runtime_manager = runtime_manager
        self._model_cache = model_cache or VoiceModelCache(
            root_dir=runtime_manager.models_root
        )
        self._connection = connection
        self._cached: Optional[VoiceReadiness] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def runtime_manager(self) -> VoiceRuntimeManager:
        """The managed voice runtime."""
        return self._runtime_manager

    @property
    def model_cache(self) -> VoiceModelCache:
        """The voice model store under the models root."""
        return self._model_cache

    @property
    def connection(self) -> Optional[VoiceConnection]:
        """Supervised worker connection, if wired."""
        return self._connection

    @property
    def engine_id(self) -> str:
        """Configured engine id, normalised to one this release knows."""
        return self._engine().id

    @property
    def runtime(self) -> RuntimeLayout:
        """Runtime layout of the running application."""
        return self._runtime

    @property
    def package_install_available(self) -> bool:
        """Always True: the runtime is provisioned from the bundled files."""
        return True

    @property
    def runtime_maintenance_available(self) -> bool:
        """Always True: the runtime is this service's to repair or remove."""
        return True

    def _engine(self) -> Any:
        return engine_spec(getattr(self._config, "engine", "whisper"))

    def _latency_ms(self) -> int:
        return int(getattr(self._config, "nemotron_latency_ms", 320) or 320)

    def current_model_label(self) -> str:
        """Human-readable name of the model the configuration points at."""
        return model_label(
            self.engine_id,
            model_size=self._config.model_size,
            latency_ms=self._latency_ms(),
        )

    def reset_availability(self) -> None:
        """Drop the cached readiness verdict after the settings changed."""
        self._cached = None

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------

    def probe(self, *, force: bool = False) -> VoiceReadiness:
        """Resolve which requirements are met, from files alone.

        Never starts a process, so it is safe on the UI thread. The runtime
        smoke test imports the audio stack, so a usable runtime also stands
        in for the PortAudio and device checks.
        """
        if self._cached is not None and not force:
            return self._cached
        runtime_ok, detail = self._runtime_readiness()
        model_ok = self.is_model_present()
        self._cached = VoiceReadiness(
            packages_ok=runtime_ok,
            portaudio_ok=runtime_ok,
            device_ok=runtime_ok,
            model_ok=model_ok if runtime_ok else False,
            model_size=self._config.model_size,
            detail=detail,
            engine=self.engine_id,
            tts_packages_ok=runtime_ok,
            tts_model_ok=self.is_tts_model_present(),
            vad_model_ok=self.is_vad_model_present(),
            model_downloads_on_first_use=(
                runtime_ok
                and not model_ok
                and not self.can_download_model_for(self.engine_id)
            ),
        )
        return self._cached

    def _runtime_readiness(self) -> Tuple[bool, str]:
        """(usable, detail) for the managed runtime."""
        status = self._runtime_manager.status()
        if status.is_ready:
            return True, ""
        if status.state is VoiceRuntimeState.UPDATE_AVAILABLE:
            # The installed runtime still works; Repair moves it forward.
            return True, "A newer voice runtime is available."
        if status.state is VoiceRuntimeState.NOT_INSTALLED:
            return False, "The voice runtime is not installed."
        return False, status.message

    def is_model_present(self) -> bool:
        """Whether the configured speech-recognition weights are on disk."""
        return self.is_model_present_for(
            self.engine_id,
            model_size=self._config.model_size,
            latency_ms=self._latency_ms(),
        )

    def is_model_present_for(
        self, engine_id: str, *, model_size: str, latency_ms: int
    ) -> bool:
        """Whether the weights for an engine/model choice are on disk."""
        if engine_spec(engine_id).streaming:
            return self._is_verified(nemotron_spec(latency_ms))
        return is_whisper_model_cached(
            model_size, cache_root=self._runtime_manager.whisper_cache_root
        )

    def model_bytes_for(
        self, engine_id: str, *, model_size: str, latency_ms: int
    ) -> int:
        """On-disk size of the weights for an engine/model choice, or 0."""
        if engine_spec(engine_id).streaming:
            return self._model_cache.status(nemotron_spec(latency_ms).model_id).size_bytes
        return sum(directory_bytes(path) for path in self._whisper_dirs(model_size))

    def download_size_hint_for(self, engine_id: str, *, model_size: str) -> str:
        """Exact size for the pinned streaming model; approximate for Whisper."""
        if engine_spec(engine_id).streaming:
            return human_bytes(nemotron_spec(self._latency_ms()).total_download_bytes)
        return MODEL_DOWNLOAD_SIZES.get(model_size, "size unknown")

    def can_download_model_for(self, engine_id: str) -> bool:
        """Streaming weights are pinned and fetched here; Whisper's are not.

        The worker's batch engine fetches Whisper weights through the hub
        library the first time it loads them, and this process carries no
        library that could fetch them ahead of time.
        """
        return engine_spec(engine_id).streaming

    def packages_size_hint(self, engine_id: Optional[str] = None) -> str:
        """Approximate size of the voice runtime; one runtime serves every engine."""
        return _RUNTIME_SIZE_HINT

    def manual_install_command(self) -> str:
        """Guidance only: the runtime is provisioned from inside the app."""
        return "Use 'Install packages' to set up the voice runtime."

    def tts_manual_install_command(self) -> str:
        """Guidance only: speech synthesis ships in the voice runtime."""
        return "installed with the voice runtime"

    def portaudio_command(self) -> str:
        """The command that installs the PortAudio system library."""
        return portaudio_install_command()

    def is_tts_model_present(self) -> bool:
        """Whether the speech-synthesis model is verified on disk."""
        return self._is_verified(KOKORO_TTS_SPEC)

    def tts_model_bytes(self) -> int:
        """On-disk size of the speech-synthesis model, or 0 when absent."""
        return self._model_cache.status(KOKORO_TTS_SPEC.model_id).size_bytes

    def tts_download_size_hint(self) -> str:
        """Exact download and on-disk size of the speech-synthesis model."""
        return (
            f"{human_bytes(KOKORO_TTS_SPEC.total_download_bytes)} download "
            f"({human_bytes(KOKORO_TTS_SPEC.total_disk_bytes)} on disk)"
        )

    def is_vad_model_present(self) -> bool:
        """Whether the voice-activity model is verified on disk."""
        return self._is_verified(SILERO_VAD_SPEC)

    def vad_model_bytes(self) -> int:
        """On-disk size of the voice-activity model, or 0 when absent."""
        return self._model_cache.status(SILERO_VAD_SPEC.model_id).size_bytes

    def vad_download_size_hint(self) -> str:
        """Exact size of the voice-activity model."""
        return human_bytes(SILERO_VAD_SPEC.total_download_bytes)

    def _is_verified(self, spec: VoiceModelSpec) -> bool:
        return self._model_cache.status(spec.model_id).is_verified

    def _whisper_dirs(self, model_size: str) -> List[Path]:
        return whisper_model_cache_dirs(
            model_size, cache_root=self._runtime_manager.whisper_cache_root
        )

    # ------------------------------------------------------------------
    # Inventory
    # ------------------------------------------------------------------

    def installed_models(
        self,
        *,
        active_engine: Optional[str] = None,
        active_model_size: Optional[str] = None,
        active_latency_ms: Optional[int] = None,
        active_tts_enabled: Optional[bool] = None,
        active_conversation_mode: Optional[bool] = None,
    ) -> List[InstalledModel]:
        """Every set of weights under the models root; ``in_use`` follows the choice."""
        streaming = engine_spec(active_engine or self.engine_id).streaming
        latency = active_latency_ms or self._latency_ms()
        in_use = {
            "stt": nemotron_spec(latency).model_id if streaming else None,
            "tts": _flag(active_tts_enabled, self._config, "tts_enabled"),
            "vad": _flag(active_conversation_mode, self._config, "conversation_mode"),
        }
        whisper_size = None if streaming else (active_model_size or self._config.model_size)
        return self._whisper_models(whisper_size) + self._registry_models(in_use)

    def _registry_models(self, in_use: Dict[str, Any]) -> List[InstalledModel]:
        models: List[InstalledModel] = []
        for item in self._model_cache.inventory():
            spec = MODEL_REGISTRY.get(item.model_id)
            if spec is None or item.state is not VoiceModelCacheState.VERIFIED:
                continue
            active = in_use[spec.engine]
            models.append(InstalledModel(
                engine=_PANEL_ENGINE[spec.engine],
                label=spec.display_name,
                key=spec.model_id,
                path=item.model_dir,
                size_bytes=item.size_bytes,
                in_use=(active == spec.model_id) if spec.engine == "stt" else bool(active),
            ))
        return models

    def _whisper_models(self, active_size: Optional[str]) -> List[InstalledModel]:
        cache_root = self._runtime_manager.whisper_cache_root
        models: List[InstalledModel] = []
        for size in MODEL_DOWNLOAD_SIZES:
            if not is_whisper_model_cached(size, cache_root=cache_root):
                continue
            paths = self._whisper_dirs(size)
            models.append(InstalledModel(
                engine="whisper",
                label=f"Whisper {size}",
                key=size,
                path=paths[0],
                size_bytes=sum(directory_bytes(path) for path in paths),
                in_use=size == active_size,
            ))
        return models

    def stale_models(self, **active: Any) -> List[InstalledModel]:
        """Weights on disk the given (or current) choice does not use."""
        return [model for model in self.installed_models(**active) if not model.in_use]

    def remove_installed(self, model: InstalledModel) -> Tuple[bool, str]:
        """Delete the weights *model* describes."""
        if model.engine == "whisper":
            return self._remove_whisper(model.key)
        return self._evict(model.key, model.label)

    def remove_model(self, model_size: str) -> Tuple[bool, str]:
        """Delete the configured engine's speech-recognition weights.

        *model_size* names the Whisper weights; the streaming engine's
        weights are selected by the configured latency instead.
        """
        if self._engine().streaming:
            spec = nemotron_spec(self._latency_ms())
            return self._evict(spec.model_id, spec.display_name)
        return self._remove_whisper(model_size)

    def _evict(self, model_id: str, label: str) -> Tuple[bool, str]:
        try:
            self._model_cache.evict(model_id)
        except (OSError, VoiceRuntimeError) as error:
            logger.error("Could not remove the voice model %s: %s", model_id, error)
            return False, f"Could not remove {label}: {error}"
        self.reset_availability()
        return True, f"Removed {label}."

    def _remove_whisper(self, model_size: str) -> Tuple[bool, str]:
        try:
            for path in self._whisper_dirs(model_size):
                shutil.rmtree(path)
        except OSError as error:
            logger.error("Could not remove the cached Whisper %s weights: %s", model_size, error)
            return False, f"Could not remove Whisper {model_size}: {error}"
        self.reset_availability()
        return True, f"Removed Whisper {model_size}."

    # ------------------------------------------------------------------
    # Runtime: install, repair, remove
    # ------------------------------------------------------------------

    async def install_packages(
        self, *, progress: Optional[VoiceSetupProgress] = None
    ) -> Tuple[bool, str]:
        """Provision the voice runtime, then start the worker from it."""
        return await self._install(
            self._runtime_manager.provision, progress, "Voice runtime installed."
        )

    async def install_tts_packages(
        self, *, progress: Optional[VoiceSetupProgress] = None
    ) -> Tuple[bool, str]:
        """Speech synthesis ships in the same runtime, so this provisions it."""
        return await self._install(
            self._runtime_manager.provision,
            progress,
            "Voice runtime installed; spoken replies can use it.",
        )

    async def repair_runtime(
        self, *, progress: Optional[VoiceSetupProgress] = None
    ) -> Tuple[bool, str]:
        """Rebuild the runtime even when it looks healthy, then restart the worker."""
        return await self._install(
            self._runtime_manager.repair, progress, "Voice runtime repaired."
        )

    async def remove_runtime(self) -> Tuple[bool, str]:
        """Stop the worker, then delete the runtime. Model weights are kept."""
        if self._connection is not None:
            # A worker still running from a release blocks its removal.
            await asyncio.to_thread(self._connection.restart)
        try:
            await asyncio.to_thread(self._runtime_manager.remove)
        except (OSError, VoiceRuntimeError) as error:
            reason = _redact(str(error))
            logger.error("Could not remove the voice runtime: %s", reason)
            return False, f"Could not remove the voice runtime: {reason}"
        finally:
            self.reset_availability()
        return True, "Voice runtime removed. Downloaded models were kept."

    async def _install(
        self,
        operation: Callable[..., VoiceRuntimeStatus],
        progress: Optional[VoiceSetupProgress],
        success: str,
    ) -> Tuple[bool, str]:
        """Run a provisioning *operation* off the loop, then move the worker onto it."""
        status, failure = await self._run_transaction(operation, progress)
        self.reset_availability()
        if status is None:
            return False, f"Voice runtime setup failed: {failure}"
        if not status.is_usable:
            return False, f"Voice runtime setup failed: {_redact(status.message)}"
        problem = await asyncio.to_thread(self._restart_worker)
        if problem is not None:
            return False, f"{success} But voice could not start from it: {problem}"
        return True, success

    async def _run_transaction(
        self,
        operation: Callable[..., VoiceRuntimeStatus],
        progress: Optional[VoiceSetupProgress],
    ) -> Tuple[Optional[VoiceRuntimeStatus], str]:
        """Run *operation* on a thread; returns (status, failure reason).

        Cancelling the awaiting task (the panel closing, the app exiting)
        cancels the provisioning too, so no installer child outlives it.
        """
        cancel = threading.Event()
        report = _step_progress(_on_loop(progress)) if progress is not None else None
        try:
            return await asyncio.to_thread(operation, report, cancel), ""
        except asyncio.CancelledError:
            cancel.set()
            raise
        except (OSError, VoiceRuntimeError) as error:
            reason = _redact(str(error))
            logger.error("Voice runtime operation failed: %s", reason)
            return None, reason

    def _restart_worker(self) -> Optional[str]:
        """Blocking: move the worker onto the current runtime; the failure reason.

        A running worker is stopped so it leaves the release it started
        from, and the restart re-arms the restart budget a broken runtime
        may have used up. The worker is then started, so a runtime that
        cannot host it is reported now rather than at the first dictation.
        """
        connection = self._connection
        if connection is None:
            return None
        try:
            connection.restart()
            connection.connect()
        except VoiceConnectionError as error:
            return _redact(str(error))
        return None

    # ------------------------------------------------------------------
    # Model downloads
    # ------------------------------------------------------------------

    async def download_model(
        self,
        model_size: Optional[str] = None,
        *,
        progress: Optional[VoiceSetupProgress] = None,
    ) -> Tuple[bool, str]:
        """Fetch the streaming weights; Whisper's arrive on first use instead."""
        if not self._engine().streaming:
            return False, "Whisper weights download automatically the first time you dictate."
        spec = nemotron_spec(self._latency_ms())
        return await self._download(spec, progress, f"Downloaded {spec.display_name}.")

    async def download_tts_model(
        self, *, progress: Optional[VoiceSetupProgress] = None
    ) -> Tuple[bool, str]:
        """Fetch the speech-synthesis model."""
        return await self._download(KOKORO_TTS_SPEC, progress, "Downloaded the speech model.")

    async def download_vad_model(
        self, *, progress: Optional[VoiceSetupProgress] = None
    ) -> Tuple[bool, str]:
        """Fetch the voice-activity model."""
        return await self._download(
            SILERO_VAD_SPEC, progress, "Downloaded the voice-detection model."
        )

    async def _download(
        self,
        spec: VoiceModelSpec,
        progress: Optional[VoiceSetupProgress],
        success: str,
    ) -> Tuple[bool, str]:
        """Download and verify *spec* on a thread."""
        report = None
        if progress is not None:
            report = _byte_progress(_on_loop(progress), spec.display_name)
        try:
            status = await asyncio.to_thread(
                self._model_cache.download, spec.model_id, progress_callback=report
            )
        except _DOWNLOAD_ERRORS as error:
            logger.error("Voice model download failed for %s: %s", spec.model_id, error)
            return False, f"Download failed: {error}"
        finally:
            self.reset_availability()
        if not status.is_verified:
            return False, f"Model download incomplete: {status.message}"
        return True, success

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    async def apply_config(self, config: 'VoiceConfig') -> Tuple[bool, str]:
        """Adopt saved settings and hand them to the voice worker.

        A worker that is not running takes them at its next start; a
        running one reconfigures in place. Returns (success, message); the
        message is empty on success.
        """
        self._config = config
        self.reset_availability()
        if self._connection is None:
            return True, ""
        worker_config = VoiceWorkerConfig.from_voice_config(config)
        try:
            await asyncio.to_thread(self._connection.configure, worker_config)
        except VoiceConnectionError as error:
            logger.warning("The voice worker did not take the new settings: %s", error)
            return False, (
                f"Voice settings were saved, but the voice worker did not apply them: {error}"
            )
        return True, ""


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _flag(override: Optional[bool], config: Any, name: str) -> bool:
    return bool(getattr(config, name, False)) if override is None else override


def _redact(text: str) -> str:
    """Drop credentials embedded in URLs from text bound for logs or the UI."""
    return _URL_CREDENTIALS.sub(r"\1***@", text)


def _on_loop(callback: VoiceSetupProgress) -> VoiceSetupProgress:
    """Wrap *callback* so a worker thread's calls run on the current event loop.

    The setup panel's progress callbacks repaint widgets, which is only
    safe from the event loop.
    """
    loop = asyncio.get_running_loop()

    def deliver(label: str, done: int, total: int) -> None:
        try:
            loop.call_soon_threadsafe(callback, label, done, total)
        except RuntimeError:
            # The loop closed under a still-running operation: nobody is
            # left to show progress to.
            logger.debug("Dropped voice setup progress; the event loop is closed")

    return deliver


def _step_progress(callback: VoiceSetupProgress) -> VoiceSetupProgress:
    """Adapt the runtime's ``(label, done_steps, total_steps)`` reports.

    A report without a positive total is passed on as indeterminate
    (``0, 0``) rather than divided by.
    """
    def report(label: str, done: int, total: int) -> None:
        if total <= 0:
            callback(label, 0, 0)
            return
        callback(label, min(max(done, 0), total), total)

    return report


def _byte_progress(callback: VoiceSetupProgress, label: str) -> _ModelProgress:
    """Adapt the cache's ``(fraction, done_bytes, total_bytes)`` reports.

    Forwarded every few megabytes and on completion, labelled with the
    model being fetched.
    """
    last_sent = [0]

    def report(fraction: float, done: int, total: int) -> None:
        finished = 0 < total <= done
        if not finished and done - last_sent[0] < _PROGRESS_STEP_BYTES:
            return
        last_sent[0] = done
        callback(label, done, max(total, 0))

    return report
