"""Voice-activity events for the hands-free conversation loop.

Wraps the small on-disk Silero VAD model (run under the same runtime the
streaming speech-to-text engine and spoken replies already use) behind a
sans-I/O surface: raw capture blocks go in through :meth:`feed`,
turn-taking events come out. The wrapper — not the detector — owns the
two knobs that make a conversation feel right: how much speech counts as
"the user is talking" (``vad_min_speech_ms``) and how much trailing
silence ends their turn (``vad_silence_ms``). Keeping that logic here
means both capture engines share one turn-taking authority with
identical semantics, and the thresholds are unit-testable without any
audio stack.

The underlying detector is only ever asked one question per block — "is
this speech?" — so its own smoothing windows are pinned small instead of
mirroring the user knobs; mirroring would apply each threshold twice.

Import safety: importing this module never raises. The optional runtime
is imported lazily when the first block is fed, and a missing dependency
or model surfaces as :class:`VoiceVadError` with an actionable message.

Threading: a monitor instance is single-threaded by design. Feed it from
ONE consumer thread — never from the PortAudio callback itself, because
detector inference is not audio-callback-safe. The conversation service
owns that thread.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, List, Optional, TYPE_CHECKING

from .voice_engines import is_silero_vad_model_present, silero_vad_model_path
from .voice_input_service import SAMPLE_RATE

if TYPE_CHECKING:
    from servonaut.config.schema import VoiceConfig

logger = logging.getLogger(__name__)

# Event identifiers returned by VoiceActivityMonitor.feed()/flush().
#: The user has been speaking for at least ``vad_min_speech_ms`` — a real
#: turn has opened, not a blip.
SPEECH_STARTED = "speech_started"
#: At least ``vad_silence_ms`` of silence followed an open turn — the
#: user has finished talking.
UTTERANCE_ENDED = "utterance_ended"

# The detector's own smoothing windows, deliberately small: the wrapper
# owns turn-taking, and per-block "is this speech" answers must not lag
# behind the audio by the user-facing thresholds too.
_DETECTOR_MIN_SILENCE_SECONDS = 0.1
_DETECTOR_MIN_SPEECH_SECONDS = 0.05

# Internal detector buffer. Small on purpose — the wrapper drains the
# detector's segment queue without reading it (events are derived from
# the per-block speech verdicts), so the buffer only needs to hold the
# in-flight window.
_DETECTOR_BUFFER_SECONDS = 2.0

_INSTALL_HINT = "Conversation mode needs: pip install 'servonaut[voice-output]'"
NO_VAD_MODEL_HINT = (
    "The voice-detection model is not downloaded yet — see Settings > Voice Input"
)


class VoiceVadError(Exception):
    """Raised when the voice-activity detector cannot run.

    Wraps every backend failure (missing runtime, missing model, a
    detector fault mid-stream) so callers never have to catch
    library-specific exception types.
    """


def block_sample_count(block: Any) -> int:
    """Number of samples in a capture block, tolerating simple stand-ins.

    Works on anything with a ``shape`` (numpy) or a length (plain
    sequences in tests); returns 0 for anything else rather than raising,
    since a miscounted block must degrade to "no progress", not a crash.
    """
    shape = getattr(block, "shape", None)
    if shape:
        return int(shape[0])
    try:
        return len(block)
    except TypeError:
        return 0


class VoiceActivityMonitor:
    """Turns raw capture blocks into speech-start / utterance-end events.

    State machine over per-block speech verdicts:

    * Consecutive speech totalling ``vad_min_speech_ms`` opens a turn and
      emits :data:`SPEECH_STARTED`. Shorter bursts separated by silence
      never open one — the accumulator resets on any pre-turn silence, so
      a cough now and a clack later cannot add up to "speech".
    * Once a turn is open, ``vad_silence_ms`` of accumulated trailing
      silence closes it and emits :data:`UTTERANCE_ENDED`. Speech inside
      the window resets the silence count — pauses shorter than the knob
      do not end the turn.
    """

    def __init__(
        self,
        config: 'VoiceConfig',
        *,
        detector_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        """Build a monitor over *config*'s turn-taking knobs.

        Args:
            config: Source of ``vad_min_speech_ms`` / ``vad_silence_ms``.
                The thresholds are snapshotted here — a monitor lives for
                one listening session, and mid-session knob changes apply
                from the next session.
            detector_factory: Zero-argument callable returning a detector
                exposing ``accept_waveform(samples)``,
                ``is_speech_detected() -> bool``, ``empty()``, ``pop()``,
                ``flush()`` and ``reset()``. Defaults to the real
                Silero detector; tests inject a scripted stand-in so no
                audio runtime is needed.
        """
        self._detector_factory = detector_factory or self._build_detector
        self._detector: Optional[Any] = None
        self._min_speech_samples = max(
            1, int(SAMPLE_RATE * int(getattr(config, "vad_min_speech_ms", 250)) / 1000)
        )
        self._silence_samples_needed = max(
            1, int(SAMPLE_RATE * int(getattr(config, "vad_silence_ms", 800)) / 1000)
        )
        self._in_speech = False
        self._turn_open = False
        self._speech_samples = 0
        self._silence_samples = 0

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def utterance_in_progress(self) -> bool:
        """Whether a turn is open (enough speech heard, no endpoint yet)."""
        return self._turn_open

    # ------------------------------------------------------------------
    # Feeding
    # ------------------------------------------------------------------

    def feed(self, block: Any) -> List[str]:
        """Advance the detector with one raw capture block.

        Args:
            block: 16 kHz mono float32 samples, as delivered by the input
                services' frame tap (a 2-D ``(frames, 1)`` capture block
                is flattened here).

        Returns:
            The events this block produced, in order — usually empty,
            occasionally ``[SPEECH_STARTED]`` or ``[UTTERANCE_ENDED]``.

        Raises:
            VoiceVadError: If the detector cannot be built or fails
                mid-stream.
        """
        detector = self._ensure_detector()
        samples = block.reshape(-1) if hasattr(block, "reshape") else block
        count = block_sample_count(samples)
        if count <= 0:
            return []

        try:
            detector.accept_waveform(samples)
            speaking = bool(detector.is_speech_detected())
        except Exception as e:  # noqa: BLE001 — the runtime raises its own types
            raise VoiceVadError(f"Voice detection failed: {e}") from e
        self._drain_segments(detector)

        events: List[str] = []
        if speaking:
            self._in_speech = True
            self._silence_samples = 0
            self._speech_samples += count
            if not self._turn_open and self._speech_samples >= self._min_speech_samples:
                self._turn_open = True
                events.append(SPEECH_STARTED)
        else:
            self._in_speech = False
            if self._turn_open:
                self._silence_samples += count
                if self._silence_samples >= self._silence_samples_needed:
                    events.append(UTTERANCE_ENDED)
                    self._reset_turn()
            else:
                # Pre-turn silence discards accumulated speech: separate
                # blips must not add up to a turn.
                self._speech_samples = 0
        return events

    def flush(self) -> List[str]:
        """Close out an in-progress turn when capture is stopping.

        Called when something other than silence ends the session (the
        recording cap, a manual stop): a turn that was open counts as
        ended, so the captured speech is not silently discarded.

        Returns:
            ``[UTTERANCE_ENDED]`` when a turn was open, else ``[]``.
            Never raises.
        """
        if self._detector is not None:
            try:
                self._detector.flush()
            except Exception:  # noqa: BLE001 — a flush failure must not lose the turn
                logger.debug("VAD detector flush failed", exc_info=True)
            self._drain_segments(self._detector)
        self._in_speech = False
        if self._turn_open:
            self._reset_turn()
            return [UTTERANCE_ENDED]
        self._speech_samples = 0
        return []

    def reset(self) -> None:
        """Forget all speech/silence state between listening sessions.

        Never raises; the loaded detector is kept so the next session
        does not re-read the model.
        """
        self._reset_turn()
        self._in_speech = False
        if self._detector is not None:
            try:
                self._detector.reset()
            except Exception:  # noqa: BLE001 — reset must always leave a clean monitor
                logger.debug("VAD detector reset failed", exc_info=True)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _reset_turn(self) -> None:
        """Return the turn-taking accumulators to their idle values."""
        self._turn_open = False
        self._speech_samples = 0
        self._silence_samples = 0

    def _ensure_detector(self) -> Any:
        """Build the detector on first use and cache it."""
        if self._detector is None:
            self._detector = self._detector_factory()
        return self._detector

    @staticmethod
    def _drain_segments(detector: Any) -> None:
        """Discard the detector's internal segment queue.

        Events are derived from the per-block speech verdicts, not from
        the detector's own segments — but leaving them queued would grow
        memory for the length of the session.
        """
        try:
            while not detector.empty():
                detector.pop()
        except Exception:  # noqa: BLE001 — housekeeping must never kill the feed
            logger.debug("VAD segment drain failed", exc_info=True)

    @staticmethod
    def _build_detector() -> Any:
        """Construct the real Silero detector from the on-disk model.

        Raises:
            VoiceVadError: If the runtime is not installed, the model is
                not downloaded, or construction fails.
        """
        try:
            import sherpa_onnx
        except Exception as e:  # noqa: BLE001 — a broken onnxruntime build raises OSError
            raise VoiceVadError(_INSTALL_HINT) from e

        if not is_silero_vad_model_present():
            raise VoiceVadError(NO_VAD_MODEL_HINT)

        try:
            vad_config = sherpa_onnx.VadModelConfig()
            vad_config.silero_vad.model = str(silero_vad_model_path())
            vad_config.silero_vad.min_silence_duration = _DETECTOR_MIN_SILENCE_SECONDS
            vad_config.silero_vad.min_speech_duration = _DETECTOR_MIN_SPEECH_SECONDS
            vad_config.sample_rate = SAMPLE_RATE
            return sherpa_onnx.VoiceActivityDetector(
                vad_config, buffer_size_in_seconds=_DETECTOR_BUFFER_SECONDS
            )
        except Exception as e:  # noqa: BLE001 — the C++ loader raises opaque types
            logger.error("Failed to load the voice-activity model: %s", e)
            raise VoiceVadError(
                f"Could not load the voice-activity model: {e}"
            ) from e


def build_voice_activity_monitor(config: 'VoiceConfig') -> VoiceActivityMonitor:
    """Construct the monitor over the real detector.

    A factory for symmetry with the other voice builders, and so call
    sites do not import the class directly.
    """
    return VoiceActivityMonitor(config)
