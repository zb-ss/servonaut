"""Client-facing desktop voice service proxies implementing canonical interfaces.

These services run in the parent Servonaut application process and proxy all
audio capture, speech recognition, speech synthesis, and conversation loop
commands across a supervised VoiceConnection to the companion VoiceWorker daemon.
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Callable, Dict, Final, List, Optional, Sequence, Tuple
import uuid

from servonaut.config.schema import VoiceConfig
from servonaut.desktop.voice.connection import (
    VoiceConnection,
    VoiceConnectionError,
    VoiceConnectionTimeoutError,
    VoiceRemoteError,
)
from servonaut.desktop.voice.protocol import (
    MAX_FRAME_BYTES,
    ConversationErrorEvent,
    ConversationInterruptRequest,
    ConversationSignalRequest,
    ConversationStartRequest,
    ConversationStateEvent,
    ConversationStopRequest,
    ConversationStoppedEvent,
    ConversationTranscriptEvent,
    InputCancelRequest,
    InputEndpointEvent,
    InputPartialEvent,
    InputResetBudgetRequest,
    InputStartRequest,
    InputStopRequest,
    InputStopResponsePayload,
    OutputCloseRequest,
    OutputEnqueueRequest,
    OutputSpeakRequest,
    OutputStateEvent,
    OutputStopRequest,
    OutputUtteranceBeginRequest,
    OutputUtteranceEndRequest,
    OutputUtteranceEnqueueRequest,
    UtteranceCompletedEvent,
    VoiceProtocolError,
    VoiceRequest,
    VoiceWorkerConfig,
)
from servonaut.desktop.voice.runtime import base_worker_env
from servonaut.services.interfaces import (
    VoiceConversationServiceInterface,
    VoiceInputServiceInterface,
    VoiceOutputServiceInterface,
)
from servonaut.services.voice_conversation_service import (
    ConversationState,
    VoiceConversationError,
)
from servonaut.services.voice_engines import engine_spec
from servonaut.services.voice_input_service import VoiceInputError
from servonaut.services.voice_output_service import VoiceOutputError

logger = logging.getLogger(__name__)


# Room left in a frame for the envelope around a text field (ids, names).
_FRAME_ENVELOPE_RESERVE: Final[int] = 1024
# Worst case, one character costs six bytes in a frame (a JSON \uXXXX escape).
_MAX_TEXT_CHARS_PER_FRAME: Final[int] = (MAX_FRAME_BYTES - _FRAME_ENVELOPE_RESERVE) // 6


def _new_id() -> str:
    return str(uuid.uuid4())


def _frame_sized_chunks(text: str, limit: int = _MAX_TEXT_CHARS_PER_FRAME) -> List[str]:
    """Split *text* into pieces that each fit one frame, preferring whitespace.

    Long replies (a big code block read aloud, say) would otherwise exceed
    the frame limit and never reach the worker at all.
    """
    chunks: List[str] = []
    while len(text) > limit:
        cut = max(text.rfind("\n", limit // 2, limit), text.rfind(" ", limit // 2, limit))
        cut = limit if cut < 0 else cut + 1
        chunks.append(text[:cut])
        text = text[cut:]
    chunks.append(text)
    return chunks


def _ensure_connected(connection: VoiceConnection) -> bool:
    """Connect (spawning or respawning the worker) unless already connected."""
    if connection.is_connected:
        return True
    try:
        connection.connect()
        return True
    except VoiceConnectionError as e:
        logger.debug("Desktop voice worker not connected: %s", e)
        return False


def _slow_request_timeout(connection: VoiceConnection) -> float:
    """Budget for a request that may load a speech model first."""
    policy = connection.policy
    return policy.request_timeout_seconds + policy.model_load_timeout_seconds


# ---------------------------------------------------------------------------
# Input Service (Speech-to-Text)
# ---------------------------------------------------------------------------


class DesktopVoiceInputService(VoiceInputServiceInterface):
    """Proxy service for microphone audio capture and local transcription.

    Dispatches STT requests across a VoiceConnection to the worker process.
    Supports both batch Whisper and streaming Nemotron/Sherpa-ONNX engines.
    """

    supports_streaming = True

    def __init__(
        self,
        connection: VoiceConnection,
        config: VoiceConfig,
    ) -> None:
        self._connection = connection
        self._config = config
        self._lock = threading.Lock()

        self._is_recording = False
        self._start_in_flight = False
        self._hit_cap = False
        # Bumped by every cancel, so a start still in flight when the user
        # cancelled never marks the recording active once it lands.
        self._generation = 0

        self._on_partial: Optional[Callable[[str], None]] = None
        self._on_endpoint: Optional[Callable[[], None]] = None
        self._on_frame: Optional[Callable[[Any], None]] = None

        self._connection.subscribe(InputPartialEvent, self._handle_partial_event)
        self._connection.subscribe(InputEndpointEvent, self._handle_endpoint_event)
        self._connection.on_close(self._handle_connection_close)

    def is_available(self) -> bool:
        """Check if voice input can be used right now."""
        if not _ensure_connected(self._connection):
            return False
        try:
            return bool(self._connection.probe().input_available)
        except VoiceConnectionError:
            return False

    def unavailable_reason(self) -> str:
        """Explain why voice input cannot be used."""
        if not _ensure_connected(self._connection):
            return "Voice runtime companion is not connected"
        try:
            probe = self._connection.probe()
        except VoiceConnectionError as e:
            return f"Error probing voice worker: {e}"
        if probe.input_available:
            return ""
        return probe.input_unavailable_reason or "Microphone or speech model unavailable"

    def start_recording(self) -> None:
        """Begin capturing audio in the worker process.

        The first start may load the speech model, so it gets the policy's
        model-load budget. If it still times out, a cancel follows it: the
        worker runs input requests in order, so the microphone it may open
        late is closed again rather than left live behind the user's back.
        """
        with self._lock:
            if self._is_recording or self._start_in_flight:
                raise VoiceInputError("A recording is already in progress")
            self._start_in_flight = True
            generation = self._generation
        try:
            self._request_start()
        except VoiceInputError:
            with self._lock:
                self._start_in_flight = False
            raise
        with self._lock:
            self._start_in_flight = False
            cancelled = self._generation != generation
            if not cancelled:
                self._is_recording = True
        if cancelled:
            # Cancelled while the start was in flight: close the mic it opened.
            self._connection.notify(InputCancelRequest(id=_new_id()))

    def _request_start(self) -> None:
        if not _ensure_connected(self._connection):
            raise VoiceInputError("Voice runtime companion is not connected")
        with self._lock:
            self._hit_cap = False
        request = InputStartRequest(
            id=_new_id(),
            streaming=engine_spec(self._config.engine).streaming,
            max_seconds=float(self._config.max_recording_seconds),
        )
        try:
            self._connection.send_request(request, timeout=_slow_request_timeout(self._connection))
        except VoiceConnectionTimeoutError as e:
            self._connection.notify(InputCancelRequest(id=_new_id()))
            raise VoiceInputError(f"Failed to start recording: {e}") from e
        except VoiceRemoteError as e:
            raise VoiceInputError(e.message) from e
        except VoiceConnectionError as e:
            raise VoiceInputError(f"Failed to start recording: {e}") from e

    def stop_and_transcribe(self, initial_prompt: str = "") -> str:
        """Stop capturing and transcribe buffered audio.

        Waits for up to the configured recording cap plus the model-load
        budget: transcription time grows with the length of the recording.
        """
        with self._lock:
            self._is_recording = False

        if not self._connection.is_connected:
            raise VoiceInputError("Voice runtime companion is not connected")

        policy = self._connection.policy
        timeout = float(self._config.max_recording_seconds) + policy.model_load_timeout_seconds
        request = InputStopRequest(id=_new_id(), initial_prompt=initial_prompt)
        try:
            response = self._connection.send_request(request, timeout=timeout)
            payload = InputStopResponsePayload.from_dict(response.payload)
        except VoiceRemoteError as e:
            raise VoiceInputError(e.message) from e
        except (VoiceConnectionError, VoiceProtocolError) as e:
            raise VoiceInputError(f"Transcription failed: {e}") from e
        # From the reply itself: the cap event travels through the event
        # dispatcher and could land after the caller already asked.
        with self._lock:
            self._hit_cap = payload.hit_cap
        return payload.text

    def cancel_recording(self) -> None:
        """Cancel capture and discard buffered audio without transcribing.

        A start still in flight is cancelled too: it closes the microphone
        itself once the worker answers.
        """
        with self._lock:
            self._generation += 1
            was_recording, self._is_recording = self._is_recording, False
        if was_recording and self._connection.is_connected:
            self._connection.notify(InputCancelRequest(id=_new_id()))

    def reset_recording_budget(self) -> None:
        """Re-arm recording duration budget for a multi-turn conversation."""
        if not self._connection.is_connected:
            return
        self._connection.notify(InputResetBudgetRequest(id=_new_id()))

    @property
    def is_recording(self) -> bool:
        """Whether a recording is currently active."""
        with self._lock:
            return self._is_recording

    @property
    def hit_recording_cap(self) -> bool:
        """Whether the last recording hit the maximum duration cap."""
        with self._lock:
            return self._hit_cap

    def set_partial_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callback for streaming partial transcripts."""
        self._on_partial = callback

    def set_endpoint_callback(self, callback: Optional[Callable[[], None]]) -> None:
        """Register a callback fired when the user stops speaking."""
        self._on_endpoint = callback

    def set_frame_callback(self, callback: Optional[Callable[[Any], None]]) -> None:
        """Register an observer for audio blocks (internal to worker in desktop)."""
        self._on_frame = callback

    def _handle_partial_event(self, event: InputPartialEvent) -> None:
        if self._on_partial is not None:
            self._on_partial(event.text)

    def _handle_endpoint_event(self, event: InputEndpointEvent) -> None:
        if self._on_endpoint is not None:
            self._on_endpoint()

    def _handle_connection_close(self) -> None:
        with self._lock:
            self._is_recording = False


# ---------------------------------------------------------------------------
# Output Service (Text-to-Speech)
# ---------------------------------------------------------------------------


class _OrderedSender:
    """Sends requests one at a time, strictly in the order they were posted.

    Streamed-reply frames (begin, each sentence, end) must reach the worker
    in order; one sender thread per service guarantees it without blocking
    the producer.
    """

    def __init__(self, connection: VoiceConnection) -> None:
        self._connection = connection
        self._queue: "queue.Queue[Optional[Tuple[VoiceRequest, Optional[Callable[[], None]]]]]" = (
            queue.Queue()
        )
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._closed = False

    def post(self, request: VoiceRequest, on_failure: Optional[Callable[[], None]] = None) -> None:
        """Queue *request*; *on_failure* runs on the sender thread if it fails."""
        with self._lock:
            if self._closed:
                return
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name="DesktopVoiceOutputSender", daemon=True,
                )
                self._thread.start()
        self._queue.put((request, on_failure))

    def close(self) -> None:
        with self._lock:
            self._closed = True
            started = self._thread is not None
        if started:
            self._queue.put(None)

    def _run(self) -> None:
        while (item := self._queue.get()) is not None:
            request, on_failure = item
            try:
                self._connection.send_request(request)
            except Exception as e:  # noqa: BLE001 — the sender must outlive any one request
                logger.debug("Output request '%s' failed: %s", request.name, e)
                if on_failure is not None:
                    self._run_failure_callback(on_failure)

    @staticmethod
    def _run_failure_callback(on_failure: Callable[[], None]) -> None:
        try:
            on_failure()
        except Exception:  # noqa: BLE001 — a failing callback must not stop the sender
            logger.debug("Output failure callback raised", exc_info=True)


class DesktopUtteranceSession:
    """One streamed reply's sentences, tracked as a unit across the IPC boundary.

    Created by :meth:`DesktopVoiceOutputService.begin_utterance`. The producer
    enqueues sentences as they are generated, then calls :meth:`end`.
    ``on_complete`` fires EXACTLY ONCE per session.
    """

    def __init__(
        self,
        service: DesktopVoiceOutputService,
        session_id: str,
        epoch: int,
        on_complete: Optional[Callable[[bool], None]],
    ) -> None:
        self._service = service
        self._session_id = session_id
        self._epoch = epoch
        self._on_complete = on_complete

        self._lock = threading.Lock()
        self._ended = False
        self._settled = False

    @property
    def session_id(self) -> str:
        """Unique ID of this utterance session."""
        return self._session_id

    @property
    def epoch(self) -> int:
        """The cancellation epoch pinned to this utterance."""
        return self._epoch

    @property
    def is_settled(self) -> bool:
        """Whether the exactly-once completion has already fired."""
        with self._lock:
            return self._settled

    def enqueue(self, sentence: str) -> None:
        """Queue one sentence of this utterance for playback."""
        with self._lock:
            if self._settled or self._ended:
                return
        for chunk in _frame_sized_chunks(sentence):
            self._service._post(
                OutputUtteranceEnqueueRequest(id=_new_id(), session_id=self._session_id, text=chunk)
            )

    def end(self) -> None:
        """Mark the utterance stream complete."""
        with self._lock:
            if self._settled or self._ended:
                return
            self._ended = True
        self._service._post(
            OutputUtteranceEndRequest(id=_new_id(), session_id=self._session_id),
            on_failure=lambda: self._service._settle_session(self._session_id, False),
        )

    def _settle(self, played_to_end: bool) -> None:
        """Invoke on_complete exactly once."""
        with self._lock:
            if self._settled:
                return
            self._settled = True
            callback = self._on_complete
        if callback is not None:
            try:
                callback(played_to_end)
            except Exception:  # noqa: BLE001 — a consumer failure must not break playback
                logger.debug("Error in utterance on_complete callback", exc_info=True)


class DesktopVoiceOutputService(VoiceOutputServiceInterface):
    """Proxy service for local speech synthesis and playback of reply text.

    Dispatches TTS requests across a VoiceConnection to Kokoro/Sherpa-ONNX
    running inside the isolated companion worker. This service owns the
    playback epoch; every worker session learns it in the handshake.
    """

    def __init__(
        self,
        connection: VoiceConnection,
        config: VoiceConfig,
    ) -> None:
        self._connection = connection
        self._config = config
        self._lock = threading.Lock()

        self._epoch = 0
        self._is_speaking = False
        self._closed = False
        self._active_sessions: Dict[str, DesktopUtteranceSession] = {}
        self._sender = _OrderedSender(connection)

        self._connection.set_epoch_provider(self.current_epoch)
        self._connection.add_session_end_hook(self._advance_epoch)
        self._connection.subscribe(OutputStateEvent, self._handle_output_state)
        self._connection.subscribe(UtteranceCompletedEvent, self._handle_utterance_completed)
        self._connection.on_close(self._handle_connection_close)

    def is_available(self) -> bool:
        """Check if spoken replies can be produced right now."""
        if not _ensure_connected(self._connection):
            return False
        try:
            return bool(self._connection.probe().output_available)
        except VoiceConnectionError:
            return False

    def unavailable_reason(self) -> str:
        """Explain why spoken replies cannot be produced."""
        if not _ensure_connected(self._connection):
            return "Voice runtime companion is not connected"
        try:
            probe = self._connection.probe()
        except VoiceConnectionError as e:
            return f"Error probing voice worker: {e}"
        if probe.output_available:
            return ""
        return probe.output_unavailable_reason or "Speakers or speech model unavailable"

    def current_epoch(self) -> int:
        """Cancellation token for speak/enqueue scheduled across threads."""
        with self._lock:
            return self._epoch

    def _live_epoch(self, epoch: Optional[int]) -> Optional[int]:
        """The epoch to pin a new utterance to, or None when it is superseded."""
        with self._lock:
            if self._closed or (epoch is not None and epoch != self._epoch):
                return None
            return self._epoch

    def speak(self, text: str, *, epoch: Optional[int] = None) -> None:
        """Synthesise text and play it, blocking until playback finishes.

        No time cap: a long reply legitimately plays for minutes. A
        :meth:`stop` (or the worker going away) ends the wait instead.
        """
        target_epoch = self._live_epoch(epoch)
        if target_epoch is None:
            return
        if not _ensure_connected(self._connection):
            raise VoiceOutputError("Voice runtime companion is not connected")

        chunks = _frame_sized_chunks(text)
        if len(chunks) > 1:
            self._speak_as_utterance(chunks, target_epoch)
            return
        request = OutputSpeakRequest(id=_new_id(), text=text, epoch=target_epoch)
        try:
            self._connection.send_request(request, timeout=None)
        except VoiceRemoteError as e:
            raise VoiceOutputError(e.message) from e
        except VoiceConnectionError as e:
            raise VoiceOutputError(f"Speech synthesis failed: {e}") from e

    def _speak_as_utterance(self, chunks: List[str], epoch: int) -> None:
        """Speak text too long for one frame, still blocking until it played."""
        finished = threading.Event()
        session = self.begin_utterance(on_complete=lambda _played: finished.set(), epoch=epoch)
        for chunk in chunks:
            session.enqueue(chunk)
        session.end()
        finished.wait()

    def enqueue(self, sentence: str, *, epoch: Optional[int] = None) -> None:
        """Queue sentence for playback without waiting for it."""
        target_epoch = self._live_epoch(epoch)
        if target_epoch is None or not _ensure_connected(self._connection):
            return
        for chunk in _frame_sized_chunks(sentence):
            self._post(OutputEnqueueRequest(id=_new_id(), text=chunk, epoch=target_epoch))

    def begin_utterance(
        self,
        *,
        on_complete: Optional[Callable[[bool], None]] = None,
        epoch: Optional[int] = None,
    ) -> DesktopUtteranceSession:
        """Open a streamed-utterance session for one reply's sentences."""
        session_id = uuid.uuid4().hex
        target_epoch = self._live_epoch(epoch)
        if target_epoch is None:
            # Born superseded: completes at once and is never tracked.
            session = DesktopUtteranceSession(
                self, session_id, self.current_epoch() if epoch is None else epoch, on_complete,
            )
            session._settle(False)
            return session

        session = DesktopUtteranceSession(self, session_id, target_epoch, on_complete)
        with self._lock:
            self._active_sessions[session_id] = session
        if not _ensure_connected(self._connection):
            self._settle_session(session_id, False)
            return session

        self._post(
            OutputUtteranceBeginRequest(id=_new_id(), session_id=session_id, epoch=target_epoch),
            on_failure=lambda: self._settle_session(session_id, False),
        )
        return session

    def _post(self, request: VoiceRequest, on_failure: Optional[Callable[[], None]] = None) -> None:
        self._sender.post(request, on_failure)

    def _settle_session(self, session_id: str, played_to_end: bool) -> None:
        with self._lock:
            session = self._active_sessions.pop(session_id, None)
        if session is not None:
            session._settle(played_to_end)

    def _retire_sessions(self) -> None:
        with self._lock:
            sessions = list(self._active_sessions.values())
            self._active_sessions.clear()
            self._is_speaking = False
        for session in sessions:
            session._settle(False)

    def stop(self) -> None:
        """Discard everything queued and stop playback promptly.

        Never waits on the worker: the stop is posted, and its epoch alone
        retires anything older that is still in flight.
        """
        with self._lock:
            self._epoch += 1
            current = self._epoch
        self._retire_sessions()
        self._connection.notify(OutputStopRequest(id=_new_id(), epoch=current))

    def close(self) -> None:
        """Shut down the service and release audio resources."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._epoch += 1
            current = self._epoch
        self._retire_sessions()
        self._sender.close()
        # The stop carries the new epoch, so frames still queued behind the
        # close are rejected as stale instead of playing after it.
        self._connection.notify(OutputStopRequest(id=_new_id(), epoch=current))
        self._connection.notify(OutputCloseRequest(id=_new_id()))

    def is_speaking(self) -> bool:
        """Whether anything is currently being synthesized or played."""
        with self._lock:
            return self._is_speaking

    def _handle_output_state(self, event: OutputStateEvent) -> None:
        with self._lock:
            self._is_speaking = bool(event.is_speaking)

    def _handle_utterance_completed(self, event: UtteranceCompletedEvent) -> None:
        self._settle_session(event.session_id, bool(event.played_to_end))

    def _advance_epoch(self) -> None:
        """Session-end hook: everything in flight for the old worker is void.

        Runs synchronously as the session ends, so a respawned worker —
        which learns the epoch in its handshake — already rejects frames
        still queued for the old one.
        """
        with self._lock:
            self._epoch += 1

    def _handle_connection_close(self) -> None:
        self._retire_sessions()


# ---------------------------------------------------------------------------
# Conversation Service (Hands-free Loop Controller)
# ---------------------------------------------------------------------------


class DesktopVoiceConversationService(VoiceConversationServiceInterface):
    """Proxy service for the hands-free conversation loop.

    In desktop companion mode, the VAD monitor, audio capture, and state
    machine run inside the companion worker daemon. This service provides the
    parent-side controller and synchronizes state, transcripts, and errors.
    """

    def __init__(
        self,
        connection: VoiceConnection,
        config: VoiceConfig,
    ) -> None:
        self._connection = connection
        self._config = config
        self._lock = threading.Lock()

        self._state: ConversationState = ConversationState.IDLE
        self._state_callback: Optional[Callable[[Any], None]] = None
        self._transcript_callback: Optional[Callable[[str], None]] = None
        self._error_callback: Optional[Callable[[str], None]] = None
        self._stopped_callback: Optional[Callable[[str], None]] = None

        self._connection.subscribe(ConversationStateEvent, self._handle_state_event)
        self._connection.subscribe(ConversationTranscriptEvent, self._handle_transcript_event)
        self._connection.subscribe(ConversationErrorEvent, self._handle_error_event)
        self._connection.subscribe(ConversationStoppedEvent, self._handle_stopped_event)
        self._connection.on_close(self._handle_connection_close)

    @property
    def state(self) -> ConversationState:
        """The loop's current state."""
        with self._lock:
            return self._state

    def start(self) -> None:
        """Begin hands-free loop: IDLE -> LISTENING.

        A start that times out (a first-use model load beyond the budget)
        is followed by a stop, so the loop cannot come up unobserved.
        """
        if not _ensure_connected(self._connection):
            raise VoiceConversationError("Voice runtime companion is not connected")

        request = ConversationStartRequest(id=_new_id(), barge_in=bool(self._config.barge_in))
        try:
            self._connection.send_request(request, timeout=_slow_request_timeout(self._connection))
        except VoiceConnectionTimeoutError as e:
            self._connection.notify(ConversationStopRequest(id=_new_id(), reason="start_timeout"))
            raise VoiceConversationError(f"Failed to start conversation loop: {e}") from e
        except VoiceRemoteError as e:
            raise VoiceConversationError(e.message) from e
        except VoiceConnectionError as e:
            raise VoiceConversationError(f"Failed to start conversation loop: {e}") from e

    def stop(self, *, join: bool = True) -> None:
        """End the loop from any state: -> IDLE. Never raises."""
        if not self._connection.is_connected:
            with self._lock:
                self._state = ConversationState.IDLE
            return
        request = ConversationStopRequest(id=_new_id(), reason="user")
        if not join:
            self._connection.notify(request)
            return
        try:
            self._connection.send_request(request, timeout=_slow_request_timeout(self._connection))
        except VoiceConnectionError as e:
            logger.debug("Failed to send conversation stop request: %s", e)
            with self._lock:
                self._state = ConversationState.IDLE

    def interrupt(self) -> None:
        """Cut assistant reply short and resume listening. Never raises."""
        if self._connection.is_connected:
            self._connection.notify(ConversationInterruptRequest(id=_new_id()))

    def reply_started(self) -> None:
        """UI signal: assistant turn is in flight (LISTENING/SPEAKING -> THINKING)."""
        self._send_signal("reply_started")

    def reply_finished(self) -> None:
        """UI signal: reply completed with nothing to speak (THINKING -> LISTENING)."""
        self._send_signal("reply_finished")

    def speaking_started(self) -> None:
        """UI signal: reply playback began (THINKING -> SPEAKING)."""
        self._send_signal("speaking_started")

    def speaking_finished(self) -> None:
        """UI signal: reply playback fully drained (SPEAKING -> LISTENING)."""
        self._send_signal("speaking_finished")

    def _send_signal(self, signal_name: str) -> None:
        """Send a turn signal to the remote conversation state machine."""
        if self._connection.is_connected:
            self._connection.notify(ConversationSignalRequest(id=_new_id(), signal=signal_name))

    def set_state_callback(self, callback: Optional[Callable[[Any], None]]) -> None:
        """Register a callback fired on every state transition."""
        self._state_callback = callback

    def set_transcript_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callback fired with each non-empty utterance transcript."""
        self._transcript_callback = callback

    def set_error_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callback fired when a running loop fails."""
        self._error_callback = callback

    def set_stopped_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callback fired whenever the loop lands in IDLE."""
        self._stopped_callback = callback

    def _handle_state_event(self, event: ConversationStateEvent) -> None:
        """Track the worker's state; states travel as their enum values."""
        try:
            new_state = ConversationState(event.new_state)
        except ValueError:
            logger.warning("Unknown conversation state received: %s", event.new_state)
            return
        with self._lock:
            self._state = new_state
        if self._state_callback is not None:
            self._state_callback(new_state)

    def _handle_transcript_event(self, event: ConversationTranscriptEvent) -> None:
        if self._transcript_callback is not None:
            self._transcript_callback(event.text)

    def _handle_error_event(self, event: ConversationErrorEvent) -> None:
        if self._error_callback is not None:
            self._error_callback(event.message)

    def _handle_stopped_event(self, event: ConversationStoppedEvent) -> None:
        with self._lock:
            self._state = ConversationState.IDLE
        if self._stopped_callback is not None:
            self._stopped_callback(event.reason)

    def _handle_connection_close(self) -> None:
        """Reset state if the worker session ends while the loop runs."""
        with self._lock:
            had_loop = self._state is not ConversationState.IDLE
            self._state = ConversationState.IDLE
        if had_loop and self._stopped_callback is not None:
            self._stopped_callback("worker_disconnected")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_desktop_voice_services(
    config: VoiceConfig,
    *,
    connection: Optional[VoiceConnection] = None,
    worker_cmd: Optional[Sequence[str]] = None,
    auto_connect: bool = False,
) -> Tuple[DesktopVoiceInputService, DesktopVoiceOutputService, DesktopVoiceConversationService]:
    """Construct client-facing desktop voice services backed by a companion daemon.

    Args:
        config: The voice configuration; its worker-relevant settings are
            handed to the connection for every worker handshake.
        connection: Pre-configured or pre-connected VoiceConnection instance.
            If None, a new VoiceConnection is created with worker_cmd and
            an isolated environment (see ``base_worker_env``).
        worker_cmd: Command args used to launch the worker if connection is None.
        auto_connect: If True, connects and handshakes immediately during construction.

    Returns:
        A tuple of (input_service, output_service, conversation_service).
    """
    worker_config = VoiceWorkerConfig.from_voice_config(config)
    conn = connection
    if conn is None:
        # Never inherit this process's environment: it holds credentials
        # and tokens the speech engines have no business seeing.
        conn = VoiceConnection(worker_cmd=worker_cmd, env=base_worker_env, inherit_env=False)
    input_service = DesktopVoiceInputService(conn, config)
    output_service = DesktopVoiceOutputService(conn, config)
    conv_service = DesktopVoiceConversationService(conn, config)

    try:
        conn.configure(worker_config)
    except VoiceConnectionError as e:
        logger.debug("Could not apply voice settings to the worker: %s", e)
    if auto_connect:
        _ensure_connected(conn)
    return input_service, output_service, conv_service
