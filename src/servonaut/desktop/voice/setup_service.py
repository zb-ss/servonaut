"""Desktop companion voice setup and readiness service.

Bridges the managed VoiceRuntimeManager and VoiceModelCache into the
VoiceSetupService interface consumed by the Textual VoicePanel and ChatPanel.
Enables companion runtime provisioning, model downloads, readiness probing,
and model inventory management without native voice dependencies in the host.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence, Tuple, TYPE_CHECKING

from servonaut.desktop.voice.connection import VoiceConnection
from servonaut.desktop.voice.models import (
    KOKORO_TTS_SPEC,
    MODEL_REGISTRY,
    NEMOTRON_ASR_SPEC,
    SILERO_VAD_SPEC,
    VoiceModelCache,
    VoiceModelCacheState,
)
from servonaut.desktop.voice.requirements import (
    CORE_VOICE_REQUIREMENTS,
    get_default_requirements,
)
from servonaut.desktop.voice.runtime import VoiceRuntimeManager, VoiceRuntimeState
from servonaut.runtime import DistributionKind, RuntimeLayout, detect_runtime
from servonaut.services.voice_engines import engine_spec, model_label
from servonaut.services.voice_setup_service import InstalledModel, VoiceReadiness

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

logger = logging.getLogger(__name__)


class DesktopVoiceSetupService:
    """Desktop companion readiness detection and managed environment installer."""

    def __init__(
        self,
        config: 'VoiceConfig',
        *,
        runtime_layout: Optional[RuntimeLayout] = None,
        runtime_manager: Optional[VoiceRuntimeManager] = None,
        model_cache: Optional[VoiceModelCache] = None,
        connection: Optional[VoiceConnection] = None,
    ) -> None:
        self._config = config
        self._runtime = runtime_layout or detect_runtime()
        self._runtime_manager = runtime_manager or VoiceRuntimeManager()
        self._model_cache = model_cache or VoiceModelCache(
            root_dir=self._runtime_manager.models_dir
        )
        self._connection = connection
        self._cached: Optional[VoiceReadiness] = None

    @property
    def runtime_manager(self) -> VoiceRuntimeManager:
        """The managed companion environment manager."""
        return self._runtime_manager

    @property
    def model_cache(self) -> VoiceModelCache:
        """The local voice model cache store."""
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
        """Runtime layout of the parent application."""
        return self._runtime

    @property
    def package_install_available(self) -> bool:
        """Whether companion packages can be installed on demand."""
        return True

    def install_command(self) -> Optional[List[str]]:
        """Descriptive command representation for package provisioning."""
        return ["servonaut-desktop", "voice", "provision"]

    def _package_install_guidance(self, manual_command: str) -> str:
        """User-facing copy explaining the companion environment."""
        return (
            "Voice runs in an isolated companion runtime under "
            f"'{self._runtime_manager.runtime_dir}'. "
            "Click 'Install Packages' to automatically create and provision it."
        )

    def _engine(self):
        """Spec for the currently configured engine."""
        return engine_spec(getattr(self._config, "engine", "whisper"))

    def _latency_ms(self) -> int:
        """Configured streaming chunk size."""
        return int(getattr(self._config, "nemotron_latency_ms", 320) or 320)

    def packages(self) -> Tuple[str, ...]:
        """pip requirements needed by the companion environment."""
        return CORE_VOICE_REQUIREMENTS

    def packages_size_hint(self, engine: str) -> str:
        """Footprint estimate for the companion environment."""
        return "~200 MB"

    def current_model_label(self) -> str:
        """Human-readable name of the model the configuration points at."""
        return model_label(
            self.engine_id,
            model_size=self._config.model_size,
            latency_ms=self._latency_ms(),
        )

    def reset_availability(self) -> None:
        """Invalidate the cached readiness probe."""
        self._cached = None

    # ------------------------------------------------------------------
    # Readiness Probing
    # ------------------------------------------------------------------

    def probe(self, *, force: bool = False) -> VoiceReadiness:
        """Resolve which voice requirements are met in the companion environment."""
        if self._cached is not None and not force:
            return self._cached

        rt_status = self._runtime_manager.status()
        packages_ok = rt_status.is_ready
        portaudio_ok = packages_ok
        device_ok = packages_ok  # When companion is ready, sounddevice is available

        detail = ""
        if not packages_ok:
            if rt_status.state is VoiceRuntimeState.NOT_INSTALLED:
                detail = "Companion voice runtime is not installed"
            elif rt_status.state is VoiceRuntimeState.CORRUPTED:
                detail = f"Companion runtime corrupted: {rt_status.message}"
            elif rt_status.state is VoiceRuntimeState.UPDATE_AVAILABLE:
                packages_ok = True  # Can still run with existing packages
                portaudio_ok = True
                device_ok = True
                detail = "Companion runtime update available"
            else:
                detail = rt_status.message

        model_ok = self.is_model_present() if packages_ok else False
        tts_packages_ok = packages_ok
        tts_model_ok = self.is_tts_model_present()
        vad_model_ok = self.is_vad_model_present()

        self._cached = VoiceReadiness(
            packages_ok=packages_ok,
            portaudio_ok=portaudio_ok,
            device_ok=device_ok,
            model_ok=model_ok,
            model_size=self._config.model_size,
            detail=detail,
            engine=self.engine_id,
            tts_packages_ok=tts_packages_ok,
            tts_model_ok=tts_model_ok,
            vad_model_ok=vad_model_ok,
        )
        return self._cached

    def is_model_present(self) -> bool:
        """Whether the configured speech-to-text model is verified on disk."""
        if self.engine_id == "whisper":
            # Whisper weights are downloaded on first demand into HF cache
            return True
        st = self._model_cache.status(NEMOTRON_ASR_SPEC.model_id)
        return st.is_verified

    def is_tts_model_present(self) -> bool:
        """Whether the Kokoro speech-synthesis model is verified on disk."""
        st = self._model_cache.status(KOKORO_TTS_SPEC.model_id)
        return st.is_verified

    def is_vad_model_present(self) -> bool:
        """Whether the Silero voice-activity model is verified on disk."""
        st = self._model_cache.status(SILERO_VAD_SPEC.model_id)
        return st.is_verified

    # ------------------------------------------------------------------
    # Actions: Package Installation & Model Downloads
    # ------------------------------------------------------------------

    def install_packages(
        self,
        progress_callback: Optional[Callable[[str, float, str], None]] = None,
    ) -> Tuple[bool, str]:
        """Provision the companion virtualenv and verify baseline dependencies."""
        try:
            st = self._runtime_manager.provision(progress_callback=progress_callback)
            if not st.is_ready:
                return False, f"Companion runtime provisioning failed: {st.message}"

            self.reset_availability()
            # Try to connect companion daemon if wired
            if self._connection is not None and not self._connection.is_connected:
                with contextlib.suppress(Exception):
                    self._connection.connect()

            return True, "Companion voice runtime successfully installed."
        except Exception as e:
            logger.error("Failed to provision voice runtime: %s", e)
            return False, f"Installation failed: {e}"

    def can_download_speech_model(self) -> bool:
        """Whether the configured speech model can be downloaded."""
        return True

    def download_speech_model(
        self,
        progress: Optional[Callable[[float, int, int], None]] = None,
    ) -> Tuple[bool, str]:
        """Download weights for the configured speech-to-text engine."""
        if self.engine_id == "whisper":
            return True, "Whisper downloads weights automatically on first transcription."

        try:
            st = self._model_cache.download(
                NEMOTRON_ASR_SPEC.model_id,
                progress_callback=progress,
            )
            self.reset_availability()
            if st.is_verified:
                return True, "Downloaded the streaming speech model."
            return False, f"Model download incomplete: {st.message}"
        except Exception as e:
            logger.error("Failed to download speech model: %s", e)
            return False, f"Download failed: {e}"

    def download_tts_model(
        self,
        progress: Optional[Callable[[float, int, int], None]] = None,
    ) -> Tuple[bool, str]:
        """Download weights for Kokoro text-to-speech."""
        try:
            st = self._model_cache.download(
                KOKORO_TTS_SPEC.model_id,
                progress_callback=progress,
            )
            self.reset_availability()
            if st.is_verified:
                return True, "Downloaded the speech synthesis model."
            return False, f"Model download incomplete: {st.message}"
        except Exception as e:
            logger.error("Failed to download TTS model: %s", e)
            return False, f"Download failed: {e}"

    def download_vad_model(
        self,
        progress: Optional[Callable[[float, int, int], None]] = None,
    ) -> Tuple[bool, str]:
        """Download weights for Silero voice activity detection."""
        try:
            st = self._model_cache.download(
                SILERO_VAD_SPEC.model_id,
                progress_callback=progress,
            )
            self.reset_availability()
            if st.is_verified:
                return True, "Downloaded the voice-detection model."
            return False, f"Model download incomplete: {st.message}"
        except Exception as e:
            logger.error("Failed to download VAD model: %s", e)
            return False, f"Download failed: {e}"

    # ------------------------------------------------------------------
    # Model Inventory & Eviction
    # ------------------------------------------------------------------

    def installed_models(self) -> List[InstalledModel]:
        """Enumerate all verified voice models on disk."""
        models: List[InstalledModel] = []
        for item in self._model_cache.inventory():
            if item.state is not VoiceModelCacheState.VERIFIED:
                continue

            spec = MODEL_REGISTRY.get(item.model_id)
            if spec is None:
                continue

            in_use = False
            if spec.engine == "vad":
                in_use = bool(getattr(self._config, "conversation_mode", False))
            elif spec.engine == "tts":
                in_use = bool(getattr(self._config, "tts_enabled", False))
            elif spec.engine == "stt":
                in_use = (self.engine_id == "nemotron")

            models.append(
                InstalledModel(
                    engine=spec.engine,
                    label=spec.display_name,
                    key=spec.model_id,
                    path=item.model_dir,
                    size_bytes=item.size_bytes,
                    in_use=in_use,
                )
            )
        return models

    def remove_model(self, installed_model: InstalledModel) -> Tuple[bool, str]:
        """Evict a model from the cache."""
        try:
            self._model_cache.evict(installed_model.key)
            self.reset_availability()
            return True, f"Removed {installed_model.label}."
        except Exception as e:
            logger.error("Failed to remove model '%s': %s", installed_model.key, e)
            return False, f"Failed to remove model: {e}"

    def tts_model_bytes(self) -> int:
        """Disk space consumed by the Kokoro speech model."""
        return self._model_cache.status(KOKORO_TTS_SPEC.model_id).size_bytes

    def tts_download_size_hint(self) -> str:
        """Download size estimate for Kokoro TTS."""
        return "~130 MB"

    def tts_manual_install_command(self) -> str:
        """Manual command string (empty for managed companion runtime)."""
        return ""
