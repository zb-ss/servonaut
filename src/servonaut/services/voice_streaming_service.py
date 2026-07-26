"""Streaming speech-to-text: text appears while the user is still talking.

Wraps a cache-aware transducer running under ``sherpa-onnx``. Unlike the
batch engine, decoding happens concurrently with capture, so partial text
can be shown as it is recognised — and because the model decodes
frame-synchronously rather than re-reading a widening buffer, the partial
text only ever grows. Nothing already shown to the user gets rewritten,
which is what makes it usable as live feedback in an input box.

Threading, since three threads are involved:

* The audio callback thread (owned by PortAudio) only enqueues blocks. It
  must never decode — overrunning that callback drops audio.
* A decoder thread drains the queue, advances the recognizer and reports
  partial text through a callback.
* The UI thread starts and stops the whole thing and receives partials via
  that callback, which it is responsible for marshalling onto its own loop.
"""

from __future__ import annotations

import importlib
import logging
import queue
import threading
from typing import Any, Callable, List, Optional, Tuple, TYPE_CHECKING

from .interfaces import VoiceInputServiceInterface
from .voice_engines import nemotron_model_dir
from .voice_input_service import (
    MIN_AUDIO_SECONDS,
    SAMPLE_RATE,
    VoiceInputError,
)

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

logger = logging.getLogger(__name__)

CHANNELS = 1

# Audio handed to the decoder in 100 ms blocks: long enough that the
# decode loop is not woken thousands of times a second, short enough that
# partial text keeps up with speech.
_BLOCK_SECONDS = 0.1

# Trailing silence (seconds) before the recognizer calls an utterance
# finished. Only consulted when endpoint detection is enabled; a shorter
# value clips people who pause mid-sentence.
_ENDPOINT_SILENCE_SECONDS = 2.0

# Sentinel pushed onto the queue to retire the decoder thread.
_STOP = object()

_INSTALL_HINT = "Streaming voice input needs: pip install 'servonaut[voice-streaming]'"
_NO_DEVICE_HINT = "No microphone detected"
_NO_MODEL_HINT = "The streaming model is not downloaded yet — see Settings > Voice Input"


def _load_modules() -> Tuple[Optional[Any], Optional[Any]]:
    """Import the streaming stack, returning ``(sounddevice, sherpa_onnx)``.

    Imported on demand rather than at module scope so this module is safe
    to import on an install that never enables streaming, and so an
    install performed while the app is running is picked up without a
    restart.
    """
    importlib.invalidate_caches()
    try:
        import numpy  # noqa: F401 — required by the capture buffer
        import sounddevice
        import sherpa_onnx
    except Exception as e:  # noqa: BLE001 — a broken onnxruntime build raises OSError
        logger.debug("Streaming voice dependencies unavailable: %s", e)
        return None, None
    return sounddevice, sherpa_onnx


class StreamingVoiceInputService(VoiceInputServiceInterface):
    """Records and transcribes concurrently, emitting partial text."""

    #: Marks this implementation as able to report text mid-utterance, so
    #: callers can register a partial-text callback without type-checking.
    supports_streaming = True

    def __init__(self, config: 'VoiceConfig') -> None:
        self._config = config
        self._lock = threading.Lock()
        self._queue: 'queue.Queue[Any]' = queue.Queue()
        self._stream: Optional[Any] = None
        self._decoder_thread: Optional[threading.Thread] = None
        self._recognizer: Optional[Any] = None
        self._online_stream: Optional[Any] = None
        self._recording = False
        self._frames_captured = 0
        self._hit_cap = False
        self._last_hit_cap = False
        self._partial_text = ""
        self._final_text = ""
        self._decode_error: Optional[str] = None
        self._on_partial: Optional[Callable[[str], None]] = None
        self._on_endpoint: Optional[Callable[[], None]] = None
        self._availability: Optional[Tuple[bool, str]] = None

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def set_partial_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callback for partial transcripts.

        The callback is invoked from the decoder thread, so a UI caller
        must marshal onto its own event loop (``App.call_from_thread``).
        """
        self._on_partial = callback

    def set_endpoint_callback(self, callback: Optional[Callable[[], None]]) -> None:
        """Register a callback fired when the speaker stops talking.

        Also invoked from the decoder thread. Only fires when endpoint
        detection is switched on, which this service ties to auto-submit:
        detecting the end of an utterance is only actionable if something
        is going to act on it.
        """
        self._on_endpoint = callback

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Whether a streaming dictation could start right now."""
        return self._probe()[0]

    def unavailable_reason(self) -> str:
        """Short actionable reason, or "" when the engine is usable."""
        return self._probe()[1]

    def reset_availability(self) -> None:
        """Drop the cached verdict so the next check re-probes."""
        self._availability = None

    def _probe(self) -> Tuple[bool, str]:
        """Resolve (available, reason), caching only stable outcomes."""
        sd, _sherpa = _load_modules()
        if sd is None:
            # Not cached: an install outside the app flips this at any time.
            return False, _INSTALL_HINT

        if not self._model_dir().is_dir():
            # Also not cached — the download button changes this.
            return False, _NO_MODEL_HINT

        if self._availability is not None:
            return self._availability

        try:
            devices = sd.query_devices()
            has_input = any(
                int(device.get('max_input_channels', 0)) > 0 for device in devices
            )
        except Exception as e:  # noqa: BLE001 — headless hosts raise from PortAudio
            logger.debug("Audio device probe failed: %s", e)
            self._availability = (False, _NO_DEVICE_HINT)
            return self._availability

        self._availability = (True, "") if has_input else (False, _NO_DEVICE_HINT)
        return self._availability

    def _model_dir(self):
        """Directory holding the weights for the configured latency."""
        return nemotron_model_dir(
            getattr(self._config, "nemotron_latency_ms", 320)
        )

    # ------------------------------------------------------------------
    # Recognizer
    # ------------------------------------------------------------------

    def _get_recognizer(self) -> Any:
        """Build the recognizer once and reuse it.

        Construction reads ~660 MB of quantised weights, so it is deferred
        to the first dictation and then cached for the process lifetime.
        """
        if self._recognizer is not None:
            return self._recognizer

        _sd, sherpa = _load_modules()
        if sherpa is None:
            raise VoiceInputError(_INSTALL_HINT)

        model_dir = self._model_dir()
        paths = {
            name: model_dir / name
            for name in ("encoder.int8.onnx", "decoder.int8.onnx",
                         "joiner.int8.onnx", "tokens.txt")
        }
        missing = [name for name, path in paths.items() if not path.is_file()]
        if missing:
            raise VoiceInputError(_NO_MODEL_HINT)

        # Endpoint detection is only switched on when something will act on
        # it; otherwise a mid-sentence pause would reset the decoder and
        # silently drop the first half of what was said.
        detect_endpoint = bool(getattr(self._config, "auto_submit", False))
        try:
            self._recognizer = sherpa.OnlineRecognizer.from_transducer(
                tokens=str(paths["tokens.txt"]),
                encoder=str(paths["encoder.int8.onnx"]),
                decoder=str(paths["decoder.int8.onnx"]),
                joiner=str(paths["joiner.int8.onnx"]),
                num_threads=2,
                sample_rate=SAMPLE_RATE,
                enable_endpoint_detection=detect_endpoint,
                rule1_min_trailing_silence=_ENDPOINT_SILENCE_SECONDS,
                rule2_min_trailing_silence=_ENDPOINT_SILENCE_SECONDS,
            )
        except Exception as e:  # noqa: BLE001 — onnxruntime raises its own types
            logger.error("Failed to load the streaming model: %s", e)
            raise VoiceInputError(f"Could not load the streaming model: {e}") from e

        logger.info("Loaded streaming model from %s", model_dir)
        return self._recognizer

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    @property
    def is_recording(self) -> bool:
        """Whether a capture is currently running."""
        return self._recording

    @property
    def hit_recording_cap(self) -> bool:
        """Whether the last dictation was cut short by the length cap."""
        return self._last_hit_cap

    @property
    def partial_text(self) -> str:
        """The most recent partial transcript."""
        with self._lock:
            return self._partial_text

    def start_recording(self) -> None:
        """Open the microphone and begin decoding concurrently.

        Blocks long enough to load the model on the first call, so callers
        must run it off the UI thread.

        Raises:
            VoiceInputError: If a capture is already running, the engine is
                unavailable, or the device cannot be opened.
        """
        if self._recording:
            raise VoiceInputError("A recording is already in progress")

        available, reason = self._probe()
        if not available:
            raise VoiceInputError(reason)

        recognizer = self._get_recognizer()
        sd, _sherpa = _load_modules()
        if sd is None:
            raise VoiceInputError(_INSTALL_HINT)

        with self._lock:
            self._partial_text = ""
            self._final_text = ""
            self._frames_captured = 0
            self._hit_cap = False
            self._last_hit_cap = False
            self._decode_error = None
        self._queue = queue.Queue()
        self._online_stream = recognizer.create_stream()

        # Started before the device opens: if the first blocks arrive
        # before the consumer exists they would sit in the queue unread,
        # and the first words of the dictation would surface late.
        self._decoder_thread = threading.Thread(
            target=self._decode_loop,
            args=(recognizer, self._online_stream),
            name="voice-stream-decoder",
            daemon=True,
        )
        self._decoder_thread.start()

        try:
            self._stream = sd.InputStream(
                samplerate=SAMPLE_RATE,
                channels=CHANNELS,
                dtype='float32',
                blocksize=int(SAMPLE_RATE * _BLOCK_SECONDS),
                device=self._config.input_device or None,
                callback=self._on_audio_block,
            )
            self._stream.start()
        except Exception as e:  # noqa: BLE001 — PortAudio has its own hierarchy
            self._stream = None
            self._queue.put(_STOP)
            self._join_decoder()
            logger.error("Failed to open audio input stream: %s", e)
            raise VoiceInputError(f"Could not open the microphone: {e}") from e

        self._recording = True
        logger.debug("Streaming capture started (device=%s)",
                     self._config.input_device or 'default')

    def _on_audio_block(self, indata: Any, frames: int, time_info: Any, status: Any) -> None:
        """PortAudio callback — enqueue only, never decode.

        Runs on the audio thread. Anything slow here overruns the callback
        and drops samples, so the work is handed to the decoder thread.
        """
        if status:
            logger.debug("Audio input status: %s", status)

        max_frames = max(1, int(self._config.max_recording_seconds)) * SAMPLE_RATE
        with self._lock:
            if self._frames_captured >= max_frames:
                self._hit_cap = True
                return
            self._frames_captured += frames
        self._queue.put(indata.copy())

    def _decode_loop(self, recognizer: Any, online_stream: Any) -> None:
        """Decoder thread: drain audio, advance the model, report partials."""
        try:
            while True:
                block = self._queue.get()
                if block is _STOP:
                    break
                online_stream.accept_waveform(SAMPLE_RATE, block.reshape(-1))
                while recognizer.is_ready(online_stream):
                    recognizer.decode_stream(online_stream)

                text = (recognizer.get_result(online_stream) or "").strip()
                if text:
                    self._publish_partial(text)

                if recognizer.is_endpoint(online_stream):
                    # Commit what was said and start a fresh utterance, so a
                    # long dictation is not capped by the model's context.
                    if text:
                        self._commit_utterance(text)
                    recognizer.reset(online_stream)
                    if self._on_endpoint is not None:
                        self._safe_endpoint_callback()
        except Exception as e:  # noqa: BLE001 — surfaced on stop, not swallowed
            logger.error("Streaming decode failed: %s", e)
            with self._lock:
                self._decode_error = str(e)

    def _publish_partial(self, text: str) -> None:
        """Store a partial transcript and notify the listener."""
        with self._lock:
            combined = f"{self._final_text} {text}".strip() if self._final_text else text
            if combined == self._partial_text:
                return
            self._partial_text = combined
        callback = self._on_partial
        if callback is None:
            return
        try:
            callback(combined)
        except Exception:  # noqa: BLE001 — a UI failure must not kill the decoder
            logger.debug("Partial-text callback failed", exc_info=True)

    def _commit_utterance(self, text: str) -> None:
        """Fold a completed utterance into the running final transcript."""
        with self._lock:
            self._final_text = f"{self._final_text} {text}".strip() if self._final_text else text
            self._partial_text = self._final_text

    def _safe_endpoint_callback(self) -> None:
        """Invoke the endpoint callback without letting it kill the decoder."""
        try:
            self._on_endpoint()  # type: ignore[misc]
        except Exception:  # noqa: BLE001
            logger.debug("Endpoint callback failed", exc_info=True)

    # ------------------------------------------------------------------
    # Stopping
    # ------------------------------------------------------------------

    def stop_and_transcribe(self, initial_prompt: str = "") -> str:
        """Stop capturing and return the full transcript.

        Most of the work already happened during capture, so this only
        drains what is still queued. ``initial_prompt`` is accepted for
        interface compatibility and ignored: a transducer has no prompt to
        condition on.

        Returns:
            The transcript, or "" when nothing intelligible was captured.

        Raises:
            VoiceInputError: If decoding failed.
        """
        self._close_stream()
        self._queue.put(_STOP)
        self._join_decoder()

        with self._lock:
            hit_cap = self._hit_cap
            self._last_hit_cap = hit_cap
            self._hit_cap = False
            error = self._decode_error
            frames = self._frames_captured
            text = self._partial_text.strip()

        if error:
            raise VoiceInputError(f"Transcription failed: {error}")

        if frames < int(MIN_AUDIO_SECONDS * SAMPLE_RATE):
            return ""

        if hit_cap:
            logger.info(
                "Recording reached the %ss cap; returning the captured portion",
                self._config.max_recording_seconds,
            )
        return text

    def cancel_recording(self) -> None:
        """Stop capturing and discard everything. Never raises."""
        self._close_stream()
        self._queue.put(_STOP)
        self._join_decoder()
        with self._lock:
            self._partial_text = ""
            self._final_text = ""
            self._frames_captured = 0
            self._hit_cap = False

    def _close_stream(self) -> None:
        """Stop and close the input stream, tolerating backend errors."""
        self._recording = False
        stream, self._stream = self._stream, None
        if stream is None:
            return
        try:
            stream.stop()
            stream.close()
        except Exception as e:  # noqa: BLE001 — teardown must not mask the outcome
            logger.debug("Error while closing audio stream: %s", e)

    def _join_decoder(self) -> None:
        """Wait for the decoder thread to retire.

        Bounded: a wedged decoder must not hang the UI thread that is
        waiting to repaint the microphone button.
        """
        thread, self._decoder_thread = self._decoder_thread, None
        if thread is None:
            return
        thread.join(timeout=10)
        if thread.is_alive():
            logger.warning("Streaming decoder did not stop within 10s")


def build_streaming_voice_service(config: 'VoiceConfig') -> StreamingVoiceInputService:
    """Construct the streaming service."""
    return StreamingVoiceInputService(config)
