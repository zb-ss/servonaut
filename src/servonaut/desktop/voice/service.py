"""Client-facing desktop voice service proxies implementing canonical interfaces.

These services run in the parent Servonaut application process and proxy all
audio capture, speech recognition, speech synthesis, and conversation loop
commands across a supervised VoiceConnection to the companion VoiceWorker daemon.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from typing import Any, Callable, Dict, Final, Optional, Sequence, Tuple, Union
import uuid

from servonaut.config.schema import VoiceConfig
from servonaut.desktop.voice.connection import (
    VoiceConnection,
    VoiceConnectionClosedError,
    VoiceConnectionError,
    VoiceRemoteError,
)
from servonaut.desktop.voice.protocol import (
    ConversationErrorEvent,
    ConversationInterruptRequest,
    ConversationSignalRequest,
    ConversationStartRequest,
    ConversationStateEvent,
    ConversationStopRequest,
    ConversationStoppedEvent,
    ConversationTranscriptEvent,
    InputCapHitEvent,
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
    ProbeResponsePayload,
    UtteranceCompletedEvent,
    VoiceErrorCode,
)
from servonaut.services.interfaces import (
    VoiceConversationServiceInterface,
    VoiceInputServiceInterface,
    VoiceOutputServiceInterface,
)
from servonaut.services.voice_conversation_service import (
    ConversationState,
    VoiceConversationError,
)
from servonaut.services.voice_input_service import VoiceInputError
from servonaut.services.voice_output_service import VoiceOutputError

logger = logging.getLogger(__name__)


def _new_id() -> str:
    return str(uuid.uuid4())


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
        self._hit_cap = False
        self._streaming = bool(getattr(config, "engine", "whisper") == "nemotron")
        self._max_recording_seconds = float(getattr(config, "max_recording_seconds", 30.0))

        self._on_partial: Optional[Callable[[str], None]] = None
        self._on_endpoint: Optional[Callable[[], None]] = None
        self._on_frame: Optional[Callable[[Any], None]] = None

        # Subscribe to worker events
        self._connection.subscribe(InputPartialEvent, self._handle_partial_event)
        self._connection.subscribe(InputEndpointEvent, self._handle_endpoint_event)
        self._connection.subscribe(InputCapHitEvent, self._handle_cap_hit_event)
        self._connection.on_close(self._handle_connection_close)

    def _ensure_connected(self) -> bool:
        """Attempt connection if not already handshaken."""
        if self._connection.is_connected:
            return True
        try:
            self._connection.connect()
            return True
        except Exception as e:
            logger.debug("Desktop voice worker not connected: %s", e)
            return False

    def is_available(self) -> bool:
        """Check if voice input can be used right now."""
        if not self._ensure_connected():
            return False
        try:
            probe = self._connection.probe()
            return bool(probe.input_available)
        except Exception:
            return False

    def unavailable_reason(self) -> str:
        """Explain why voice input cannot be used."""
        if not self._ensure_connected():
            return "Voice runtime companion is not connected"
        try:
            probe = self._connection.probe()
            if probe.input_available:
                return ""
            return probe.input_unavailable_reason or "Microphone or speech model unavailable"
        except Exception as e:
            return f"Error probing voice worker: {e}"

    def start_recording(self) -> None:
        """Begin capturing audio in the worker process."""
        with self._lock:
            if self._is_recording:
                raise VoiceInputError("A recording is already in progress")

        if not self._ensure_connected():
            raise VoiceInputError("Voice runtime companion is not connected")

        self._hit_cap = False
        request = InputStartRequest(
            id=_new_id(),
            streaming=self._streaming,
            max_seconds=self._max_recording_seconds,
        )

        try:
            self._connection.send_request(request)
            with self._lock:
                self._is_recording = True
        except VoiceRemoteError as e:
            raise VoiceInputError(e.message) from e
        except Exception as e:
            raise VoiceInputError(f"Failed to start recording: {e}") from e

    def stop_and_transcribe(self, initial_prompt: str = "") -> str:
        """Stop capturing and transcribe buffered audio."""
        with self._lock:
            self._is_recording = False

        if not self._connection.is_connected:
            raise VoiceInputError("Voice runtime companion is not connected")

        request = InputStopRequest(id=_new_id(), initial_prompt=initial_prompt)
        try:
            response = self._connection.send_request(request, timeout=30.0)
            payload = response.payload
            if isinstance(payload, dict):
                try:
                    payload = InputStopResponsePayload.from_dict(payload)
                except Exception:
                    return str(payload.get("text", ""))
            if isinstance(payload, InputStopResponsePayload):
                return payload.text
            return ""
        except VoiceRemoteError as e:
            raise VoiceInputError(e.message) from e
        except Exception as e:
            raise VoiceInputError(f"Transcription failed: {e}") from e

    def cancel_recording(self) -> None:
        """Cancel capture and discard buffered audio without transcribing."""
        with self._lock:
            if not self._is_recording:
                return
            self._is_recording = False

        if not self._connection.is_connected:
            return

        try:
            self._connection.send_request(InputCancelRequest(id=_new_id()))
        except Exception as e:
            logger.debug("Failed to send cancel recording request: %s", e)

    def reset_recording_budget(self) -> None:
        """Re-arm recording duration budget for a multi-turn conversation."""
        if not self._connection.is_connected:
            return
        try:
            self._connection.send_request(InputResetBudgetRequest(id=_new_id()))
        except Exception as e:
            logger.debug("Failed to send reset budget request: %s", e)

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

    def _handle_partial_event(self, event: Any) -> None:
        """Forward partial transcript event to registered callback."""
        if isinstance(event, InputPartialEvent) and self._on_partial:
            try:
                self._on_partial(event.text)
            except Exception:
                logger.debug("Error in partial transcript callback", exc_info=True)

    def _handle_endpoint_event(self, event: Any) -> None:
        """Forward endpoint event to registered callback."""
        if isinstance(event, InputEndpointEvent) and self._on_endpoint:
            try:
                self._on_endpoint()
            except Exception:
                logger.debug("Error in endpoint callback", exc_info=True)

    def _handle_cap_hit_event(self, event: Any) -> None:
        """Track cap hit event."""
        if isinstance(event, InputCapHitEvent):
            with self._lock:
                self._hit_cap = True

    def _handle_connection_close(self) -> None:
        """Reset state when worker disconnects."""
        with self._lock:
            self._is_recording = False


# ---------------------------------------------------------------------------
# Output Service (Text-to-Speech)
# ---------------------------------------------------------------------------


class DesktopUtteranceSession:
    """One streamed reply's sentences, tracked as a unit across the IPC boundary.

    Created by :meth:`DesktopVoiceOutputService.begin_utterance`. The producer
    enqueues sentences as they are generated, then calls :meth:`end`.
    ``on_complete`` fires EXACTLY ONCE per session.
    """

    def __init__(
        self,
        service: DesktopVoiceOutputService,
        connection: VoiceConnection,
        session_id: str,
        epoch: int,
        on_complete: Optional[Callable[[bool], None]],
    ) -> None:
        self._service = service
        self._connection = connection
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

        if not self._connection.is_connected:
            return

        request = OutputUtteranceEnqueueRequest(
            id=_new_id(),
            session_id=self._session_id,
            text=sentence,
        )
        try:
            # Fire-and-forget; run in background thread or send without blocking caller
            threading.Thread(
                target=self._safe_send,
                args=(request,),
                name=f"UtteranceEnqueue-{self._session_id[:8]}",
                daemon=True,
            ).start()
        except Exception as e:
            logger.debug("Failed to spawn utterance enqueue thread: %s", e)

    def end(self) -> None:
        """Mark the utterance stream complete."""
        with self._lock:
            if self._settled or self._ended:
                return
            self._ended = True

        if not self._connection.is_connected:
            self._settle(False)
            return

        request = OutputUtteranceEndRequest(id=_new_id(), session_id=self._session_id)
        try:
            threading.Thread(
                target=self._safe_send,
                args=(request,),
                name=f"UtteranceEnd-{self._session_id[:8]}",
                daemon=True,
            ).start()
        except Exception as e:
            logger.debug("Failed to spawn utterance end thread: %s", e)

    def _safe_send(self, request: Any) -> None:
        """Safely send an utterance request."""
        try:
            self._connection.send_request(request)
        except Exception as e:
            logger.debug("Utterance request '%s' failed: %s", getattr(request, "name", "unknown"), e)

    def _settle(self, played_to_end: bool) -> None:
        """Invoke on_complete exactly once."""
        callback: Optional[Callable[[bool], None]] = None
        with self._lock:
            if self._settled:
                return
            self._settled = True
            callback = self._on_complete

        if callback is not None:
            try:
                callback(played_to_end)
            except Exception:
                logger.debug("Error in utterance on_complete callback", exc_info=True)


class DesktopVoiceOutputService(VoiceOutputServiceInterface):
    """Proxy service for local speech synthesis and playback of reply text.

    Dispatches TTS requests across a VoiceConnection to Kokoro/Sherpa-ONNX
    running inside the isolated companion worker.
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

        self._connection.subscribe(OutputStateEvent, self._handle_output_state)
        self._connection.subscribe(UtteranceCompletedEvent, self._handle_utterance_completed)
        self._connection.on_close(self._handle_connection_close)

    def _ensure_connected(self) -> bool:
        """Attempt connection if not already handshaken."""
        if self._connection.is_connected:
            return True
        try:
            self._connection.connect()
            return True
        except Exception as e:
            logger.debug("Desktop voice worker not connected: %s", e)
            return False

    def is_available(self) -> bool:
        """Check if spoken replies can be produced right now."""
        if not self._ensure_connected():
            return False
        try:
            probe = self._connection.probe()
            return bool(probe.output_available)
        except Exception:
            return False

    def unavailable_reason(self) -> str:
        """Explain why spoken replies cannot be produced."""
        if not self._ensure_connected():
            return "Voice runtime companion is not connected"
        try:
            probe = self._connection.probe()
            if probe.output_available:
                return ""
            return probe.output_unavailable_reason or "Speakers or speech model unavailable"
        except Exception as e:
            return f"Error probing voice worker: {e}"

    def current_epoch(self) -> int:
        """Cancellation token for speak/enqueue scheduled across threads."""
        with self._lock:
            return self._epoch

    def speak(self, text: str, *, epoch: Optional[int] = None) -> None:
        """Synthesise text and play it, blocking until playback finishes."""
        with self._lock:
            if self._closed:
                return
            if epoch is not None and epoch != self._epoch:
                return
            target_epoch = self._epoch if epoch is None else epoch

        if not self._ensure_connected():
            raise VoiceOutputError("Voice runtime companion is not connected")

        request = OutputSpeakRequest(id=_new_id(), text=text, epoch=target_epoch)
        try:
            self._connection.send_request(request, timeout=60.0)
        except VoiceRemoteError as e:
            raise VoiceOutputError(e.message) from e
        except Exception as e:
            raise VoiceOutputError(f"Speech synthesis failed: {e}") from e

    def enqueue(self, sentence: str, *, epoch: Optional[int] = None) -> None:
        """Queue sentence for playback without waiting for it."""
        with self._lock:
            if self._closed:
                return
            if epoch is not None and epoch != self._epoch:
                return
            target_epoch = self._epoch if epoch is None else epoch

        if not self._ensure_connected():
            return

        request = OutputEnqueueRequest(id=_new_id(), text=sentence, epoch=target_epoch)
        try:
            threading.Thread(
                target=self._safe_send,
                args=(request,),
                name="DesktopVoiceEnqueue",
                daemon=True,
            ).start()
        except Exception as e:
            logger.debug("Failed to spawn enqueue thread: %s", e)

    def begin_utterance(
        self,
        *,
        on_complete: Optional[Callable[[bool], None]] = None,
        epoch: Optional[int] = None,
    ) -> DesktopUtteranceSession:
        """Open a streamed-utterance session for one reply's sentences."""
        session_id = uuid.uuid4().hex

        with self._lock:
            if self._closed or (epoch is not None and epoch != self._epoch):
                # Born superseded: fire on_complete(False) immediately
                session = DesktopUtteranceSession(
                    self, self._connection, session_id, epoch or self._epoch, on_complete
                )
                session._settle(False)
                return session

            target_epoch = self._epoch if epoch is None else epoch
            session = DesktopUtteranceSession(
                self, self._connection, session_id, target_epoch, on_complete
            )
            self._active_sessions[session_id] = session

        if not self._ensure_connected():
            session._settle(False)
            return session

        request = OutputUtteranceBeginRequest(id=_new_id(), session_id=session_id, epoch=target_epoch)
        try:
            threading.Thread(
                target=self._safe_send,
                args=(request,),
                name=f"UtteranceBegin-{session_id[:8]}",
                daemon=True,
            ).start()
        except Exception as e:
            logger.debug("Failed to spawn utterance begin thread: %s", e)

        return session

    def stop(self) -> None:
        """Discard everything queued and stop playback promptly."""
        with self._lock:
            self._epoch += 1
            curr_epoch = self._epoch
            sessions = list(self._active_sessions.values())
            self._active_sessions.clear()
            self._is_speaking = False

        for session in sessions:
            session._settle(False)

        if not self._connection.is_connected:
            return

        try:
            self._connection.send_request(OutputStopRequest(id=_new_id(), epoch=curr_epoch))
        except Exception as e:
            logger.debug("Failed to send output stop request: %s", e)

    def close(self) -> None:
        """Shut down the service and release audio resources."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._epoch += 1
            sessions = list(self._active_sessions.values())
            self._active_sessions.clear()
            self._is_speaking = False

        for session in sessions:
            session._settle(False)

        if not self._connection.is_connected:
            return

        try:
            self._connection.send_request(OutputCloseRequest(id=_new_id()))
        except Exception as e:
            logger.debug("Failed to send output close request: %s", e)

    def is_speaking(self) -> bool:
        """Whether anything is currently being synthesized or played."""
        with self._lock:
            return self._is_speaking

    def _safe_send(self, request: Any) -> None:
        """Safely send an asynchronous request."""
        try:
            self._connection.send_request(request)
        except Exception as e:
            logger.debug("Output request '%s' failed: %s", getattr(request, "name", "unknown"), e)

    def _handle_output_state(self, event: Any) -> None:
        """Track output playback state changes."""
        if isinstance(event, OutputStateEvent):
            with self._lock:
                self._is_speaking = bool(event.is_speaking)

    def _handle_utterance_completed(self, event: Any) -> None:
        """Handle utterance session completion event."""
        if isinstance(event, UtteranceCompletedEvent):
            session: Optional[DesktopUtteranceSession] = None
            with self._lock:
                session = self._active_sessions.pop(event.session_id, None)

            if session is not None:
                session._settle(bool(event.played_to_end))

    def _handle_connection_close(self) -> None:
        """Settle all active sessions when worker disconnects."""
        sessions: list[DesktopUtteranceSession] = []
        with self._lock:
            self._is_speaking = False
            sessions = list(self._active_sessions.values())
            self._active_sessions.clear()

        for session in sessions:
            session._settle(False)


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

    def _ensure_connected(self) -> bool:
        """Attempt connection if not already handshaken."""
        if self._connection.is_connected:
            return True
        try:
            self._connection.connect()
            return True
        except Exception as e:
            logger.debug("Desktop voice worker not connected: %s", e)
            return False

    @property
    def state(self) -> ConversationState:
        """The loop's current state."""
        with self._lock:
            return self._state

    def start(self) -> None:
        """Begin hands-free loop: IDLE -> LISTENING."""
        if not self._ensure_connected():
            raise VoiceConversationError("Voice runtime companion is not connected")

        barge_in = bool(getattr(self._config, "barge_in", False))
        request = ConversationStartRequest(id=_new_id(), barge_in=barge_in)
        try:
            self._connection.send_request(request)
        except VoiceRemoteError as e:
            raise VoiceConversationError(e.message) from e
        except Exception as e:
            raise VoiceConversationError(f"Failed to start conversation loop: {e}") from e

    def stop(self, *, join: bool = True) -> None:
        """End the loop from any state: -> IDLE. Never raises."""
        if not self._connection.is_connected:
            with self._lock:
                self._state = ConversationState.IDLE
            return

        try:
            self._connection.send_request(ConversationStopRequest(id=_new_id(), reason="user"))
        except Exception as e:
            logger.debug("Failed to send conversation stop request: %s", e)
            with self._lock:
                self._state = ConversationState.IDLE

    def interrupt(self) -> None:
        """Cut assistant reply short and resume listening. Never raises."""
        if not self._connection.is_connected:
            return
        try:
            self._connection.send_request(ConversationInterruptRequest(id=_new_id()))
        except Exception as e:
            logger.debug("Failed to send conversation interrupt request: %s", e)

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
        if not self._connection.is_connected:
            return
        try:
            self._connection.send_request(
                ConversationSignalRequest(id=_new_id(), signal=signal_name)
            )
        except Exception as e:
            logger.debug("Failed to send conversation signal '%s': %s", signal_name, e)

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

    def _handle_state_event(self, event: Any) -> None:
        """Handle state change event from worker."""
        if not isinstance(event, ConversationStateEvent):
            return

        try:
            new_state = ConversationState[event.new_state]
        except KeyError:
            logger.warning("Unknown conversation state received: %s", event.new_state)
            return

        with self._lock:
            self._state = new_state

        if self._state_callback is not None:
            try:
                self._state_callback(new_state)
            except Exception:
                logger.debug("Error in conversation state callback", exc_info=True)

    def _handle_transcript_event(self, event: Any) -> None:
        """Handle transcript event from worker."""
        if isinstance(event, ConversationTranscriptEvent) and self._transcript_callback:
            try:
                self._transcript_callback(event.text)
            except Exception:
                logger.debug("Error in conversation transcript callback", exc_info=True)

    def _handle_error_event(self, event: Any) -> None:
        """Handle error event from worker."""
        if isinstance(event, ConversationErrorEvent) and self._error_callback:
            try:
                self._error_callback(event.message)
            except Exception:
                logger.debug("Error in conversation error callback", exc_info=True)

    def _handle_stopped_event(self, event: Any) -> None:
        """Handle loop stopped event from worker."""
        if not isinstance(event, ConversationStoppedEvent):
            return

        with self._lock:
            self._state = ConversationState.IDLE

        if self._stopped_callback is not None:
            try:
                self._stopped_callback(event.reason)
            except Exception:
                logger.debug("Error in conversation stopped callback", exc_info=True)

    def _handle_connection_close(self) -> None:
        """Reset state if worker disconnects unexpectedly."""
        had_loop = False
        with self._lock:
            if self._state != ConversationState.IDLE:
                had_loop = True
                self._state = ConversationState.IDLE

        if had_loop and self._stopped_callback is not None:
            try:
                self._stopped_callback("worker_disconnected")
            except Exception:
                logger.debug("Error in conversation stopped callback", exc_info=True)


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
        config: The voice configuration.
        connection: Pre-configured or pre-connected VoiceConnection instance.
            If None, a new VoiceConnection is created with worker_cmd.
        worker_cmd: Command args used to launch the worker if connection is None.
        auto_connect: If True, connects and handshakes immediately during construction.

    Returns:
        A tuple of (input_service, output_service, conversation_service).
    """
    conn = connection if connection is not None else VoiceConnection(worker_cmd=worker_cmd)
    if auto_connect:
        with contextlib.suppress(Exception):
            conn.connect()

    input_service = DesktopVoiceInputService(conn, config)
    output_service = DesktopVoiceOutputService(conn, config)
    conv_service = DesktopVoiceConversationService(conn, config)

    return input_service, output_service, conv_service
