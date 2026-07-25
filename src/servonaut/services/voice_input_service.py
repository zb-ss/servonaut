"""Microphone capture and local speech-to-text for the chat panel.

Transcription runs entirely on the local machine via ``faster-whisper``
so dictated text never leaves the operator's workstation — the same
privacy stance the rest of the AI surface takes.

Both dependencies are optional (``pip install 'servonaut[voice]'``) and
the whole module degrades to a disabled feature when they are missing:
importing this module never raises, and :meth:`VoiceInputService.is_available`
reports the truth so callers can hide the mic affordance instead of
failing at click time.
"""

from __future__ import annotations

import importlib
import logging
import threading
from typing import Any, List, Optional, Tuple, TYPE_CHECKING

from .interfaces import VoiceInputServiceInterface

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

logger = logging.getLogger(__name__)

try:
    import numpy as np
    import sounddevice as sd
    from faster_whisper import WhisperModel
    HAS_VOICE_DEPS = True
except Exception:  # noqa: BLE001 — a broken PortAudio/ctranslate2 build raises OSError, not ImportError
    np = None  # type: ignore[assignment]
    sd = None  # type: ignore[assignment]
    WhisperModel = None  # type: ignore[assignment]
    HAS_VOICE_DEPS = False


def reload_voice_deps() -> bool:
    """Re-attempt the optional imports and rebind the module globals.

    The flag above is resolved once at import time, so a successful
    in-app install would otherwise keep reporting the feature as missing
    until the user restarted. Calling this after an install promotes the
    new packages without a restart; when the imports still fail the
    module is left exactly as it was.

    Returns:
        True when the dependencies are importable afterwards.
    """
    global np, sd, WhisperModel, HAS_VOICE_DEPS  # noqa: PLW0603 — rebinding the cached import state is the point

    importlib.invalidate_caches()
    try:
        import numpy as _np
        import sounddevice as _sd
        from faster_whisper import WhisperModel as _WhisperModel
    except Exception as e:  # noqa: BLE001 — same failure surface as the initial import
        logger.debug("Voice dependencies still unavailable after reload: %s", e)
        return False

    np = _np
    sd = _sd
    WhisperModel = _WhisperModel
    HAS_VOICE_DEPS = True
    logger.info("Voice dependencies loaded without a restart")
    return True

# Whisper models are trained on 16 kHz mono audio; feeding anything else
# means resampling somewhere, so capture at the target rate directly.
SAMPLE_RATE = 16000
CHANNELS = 1

# Below this, the buffer is a stray click or a mis-fired toggle — running
# the model on it wastes seconds and reliably returns hallucinated text.
MIN_AUDIO_SECONDS = 0.3

# Whisper only conditions on a short window of prior text; a long prompt
# crowds out the audio and degrades accuracy instead of biasing it.
MAX_INITIAL_PROMPT_CHARS = 200

_INSTALL_HINT = "Voice input needs: pip install 'servonaut[voice]'"
_NO_DEVICE_HINT = "No microphone detected"


class VoiceInputError(Exception):
    """Raised when recording or transcription fails.

    Wraps every backend failure (PortAudio, ctranslate2, model download)
    so callers never have to catch library-specific exception types.
    """


class VoiceInputService(VoiceInputServiceInterface):
    """Records microphone audio and transcribes it locally."""

    def __init__(self, config: 'VoiceConfig') -> None:
        self._config = config
        # Guards ``_blocks`` against the PortAudio callback thread, which
        # appends concurrently with the UI thread stopping the stream.
        self._lock = threading.Lock()
        self._blocks: List[Any] = []
        self._stream: Optional[Any] = None
        self._recording = False
        self._frames_captured = 0
        self._hit_cap = False
        self._last_hit_cap = False
        self._model: Optional[Any] = None
        # Device enumeration costs a PortAudio init, so probe once and
        # reuse the verdict for the lifetime of the service.
        self._availability: Optional[Tuple[bool, str]] = None

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Check if voice input can be used right now.

        Returns:
            True only when the optional libraries imported cleanly AND at
            least one input device is present.
        """
        available, _ = self._probe()
        return available

    def unavailable_reason(self) -> str:
        """Explain why voice input cannot be used.

        Returns:
            Short, actionable message, or an empty string when available.
            Never contains a traceback or a library-internal message.
        """
        _, reason = self._probe()
        return reason

    def reset_availability(self) -> None:
        """Drop the cached availability verdict so the next check re-probes.

        Call this after installing the dependencies or plugging in a
        microphone: without it the service would keep serving the
        "unavailable" answer it cached at startup for its whole lifetime.
        """
        self._availability = None

    def _probe(self) -> Tuple[bool, str]:
        """Resolve and cache the (available, reason) verdict."""
        if self._availability is not None:
            return self._availability

        if not HAS_VOICE_DEPS:
            self._availability = (False, _INSTALL_HINT)
            return self._availability

        try:
            devices = sd.query_devices()
            has_input = any(
                int(device.get('max_input_channels', 0)) > 0 for device in devices
            )
        except Exception as e:  # noqa: BLE001 — headless hosts raise OSError from PortAudio
            logger.debug("Audio device probe failed: %s", e)
            self._availability = (False, _NO_DEVICE_HINT)
            return self._availability

        if not has_input:
            self._availability = (False, _NO_DEVICE_HINT)
        else:
            self._availability = (True, "")
        return self._availability

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    @property
    def is_recording(self) -> bool:
        """Whether a recording is currently in progress."""
        return self._recording

    @property
    def hit_recording_cap(self) -> bool:
        """Whether the last transcription's audio was cut off by the cap.

        Set by :meth:`stop_and_transcribe` so callers can tell the user
        that the tail of what they said was dropped instead of leaving
        the truncation to a log line.
        """
        return self._last_hit_cap

    def start_recording(self) -> None:
        """Begin capturing microphone audio into an in-memory buffer.

        Raises:
            VoiceInputError: If a recording is already in progress, voice
                input is unavailable, or the audio device cannot be opened.
        """
        if self._recording:
            # One service instance backs every chat panel. Returning
            # quietly here would hand the second caller the first one's
            # buffer, which it would then drain as if it were its own.
            raise VoiceInputError("A recording is already in progress")

        available, reason = self._probe()
        if not available:
            raise VoiceInputError(reason)

        with self._lock:
            self._blocks = []
            self._frames_captured = 0
            self._hit_cap = False
            self._last_hit_cap = False

        try:
            self._stream = sd.InputStream(
                samplerate=SAMPLE_RATE,
                channels=CHANNELS,
                dtype='float32',
                device=self._config.input_device or None,
                callback=self._on_audio_block,
            )
            self._stream.start()
        except Exception as e:  # noqa: BLE001 — PortAudio raises its own error hierarchy
            self._stream = None
            logger.error("Failed to open audio input stream: %s", e)
            raise VoiceInputError(f"Could not open the microphone: {e}") from e

        self._recording = True
        logger.debug("Voice recording started (device=%s)", self._config.input_device or 'default')

    def _on_audio_block(self, indata: Any, frames: int, time_info: Any, status: Any) -> None:
        """PortAudio callback — runs on the audio thread, must not block."""
        if status:
            logger.debug("Audio input status: %s", status)

        max_frames = max(1, int(self._config.max_recording_seconds)) * SAMPLE_RATE
        with self._lock:
            if self._frames_captured >= max_frames:
                # Hard cap: keep the stream alive (stopping it from the
                # callback thread is fragile) but stop growing the buffer.
                self._hit_cap = True
                return
            self._blocks.append(indata.copy())
            self._frames_captured += frames

    def cancel_recording(self) -> None:
        """Stop capturing and discard the buffer without transcribing.

        Never raises — it is the cleanup path for every failure route.
        """
        self._close_stream()
        with self._lock:
            self._blocks = []
            self._frames_captured = 0
            self._hit_cap = False

    def _close_stream(self) -> None:
        """Stop and close the input stream, tolerating any backend error."""
        self._recording = False
        stream = self._stream
        self._stream = None
        if stream is None:
            return
        try:
            stream.stop()
            stream.close()
        except Exception as e:  # noqa: BLE001 — teardown must never mask the caller's outcome
            logger.debug("Error while closing audio stream: %s", e)

    # ------------------------------------------------------------------
    # Transcription
    # ------------------------------------------------------------------

    def stop_and_transcribe(self, initial_prompt: str = "") -> str:
        """Stop capturing and transcribe the buffered audio.

        This BLOCKS for the duration of the transcription (and, on the
        very first call, for the model load). Call it from a worker
        thread — never from the Textual event loop.

        Args:
            initial_prompt: Optional vocabulary hint (e.g. the names of
                the servers on screen) used to bias proper nouns.
                Truncated before it reaches the model.

        Returns:
            Transcribed text, or an empty string when the recording was
            shorter than :data:`MIN_AUDIO_SECONDS`.

        Raises:
            VoiceInputError: If transcription fails.
        """
        self._close_stream()

        with self._lock:
            blocks = self._blocks
            self._blocks = []
            self._frames_captured = 0
            hit_cap = self._hit_cap
            self._hit_cap = False

        self._last_hit_cap = hit_cap
        if hit_cap:
            logger.info(
                "Recording reached the %ss cap; transcribing the captured portion",
                self._config.max_recording_seconds,
            )

        if not blocks:
            return ""

        try:
            audio = np.concatenate(blocks, axis=0).reshape(-1).astype('float32')
        except Exception as e:  # noqa: BLE001 — a partial/ragged buffer must not crash the panel
            logger.error("Failed to assemble the audio buffer: %s", e)
            raise VoiceInputError("Recorded audio could not be read") from e

        if audio.shape[0] < int(MIN_AUDIO_SECONDS * SAMPLE_RATE):
            logger.debug("Discarding %d frames of audio (below the minimum)", audio.shape[0])
            return ""

        model = self._get_model()
        prompt = (initial_prompt or "").strip()[:MAX_INITIAL_PROMPT_CHARS] or None
        language = self._config.language
        language = None if not language or language == "auto" else language

        try:
            segments, _info = model.transcribe(
                audio,
                language=language,
                initial_prompt=prompt,
            )
            text = "".join(segment.text for segment in segments).strip()
        except Exception as e:  # noqa: BLE001 — ctranslate2 raises its own error types
            logger.error("Transcription failed: %s", e)
            raise VoiceInputError(f"Transcription failed: {e}") from e

        logger.debug("Transcribed %.1fs of audio into %d characters",
                     audio.shape[0] / SAMPLE_RATE, len(text))
        return text

    def _get_model(self) -> Any:
        """Load the transcription model, caching it on the instance.

        Deferred until the first transcription: constructing the model
        reads several hundred megabytes from disk (or downloads it), and
        app startup must stay instant for users who never dictate.

        Raises:
            VoiceInputError: If the model cannot be loaded.
        """
        if self._model is not None:
            return self._model

        if not HAS_VOICE_DEPS:
            raise VoiceInputError(_INSTALL_HINT)

        model_size = self._config.model_size
        try:
            # int8 on CPU keeps a small model real-time on a laptop while
            # leaving the GPU (if any) free for whatever else is running.
            self._model = WhisperModel(model_size, device="cpu", compute_type="int8")
        except Exception as e:  # noqa: BLE001 — model download/load failures vary by backend
            logger.error("Failed to load the '%s' speech model: %s", model_size, e)
            raise VoiceInputError(
                f"Could not load the '{model_size}' speech model: {e}"
            ) from e

        logger.info("Loaded speech model '%s' (cpu/int8)", model_size)
        return self._model
