"""Standalone companion voice worker process for Servonaut Desktop.

Executes local microphone capture, streaming speech-to-text (STT),
voice-activity detection (VAD), hands-free conversation loop, and speech
synthesis/playback (TTS) in an isolated process over standard I/O JSON Lines.
Raw PCM audio buffers never traverse the IPC boundary.

The worker builds its services from the settings the parent sends in the
handshake (and later ``configure`` requests). Requests that can block —
model loads, transcription, the conversation loop's start/stop — run on
ordered per-domain lanes, so the main loop keeps reading and a later
``output_stop`` or ``ping`` is never stuck behind them, while requests of
one domain (start, then cancel) still execute in the order they were sent.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import argparse
import logging
import math
import os
from pathlib import Path
import platform
import queue
import signal
import sys
import threading
from typing import Any, BinaryIO, Callable, Dict, Final, List, Optional, Tuple, Type
import uuid

from servonaut import __version__
from servonaut.config.schema import VoiceConfig
from servonaut.desktop.voice.protocol import (
    VOICE_PROTOCOL_VERSION,
    ConfigureRequest,
    ConversationErrorEvent,
    ConversationInterruptRequest,
    ConversationSignalRequest,
    ConversationStartRequest,
    ConversationStateEvent,
    ConversationStopRequest,
    ConversationStoppedEvent,
    ConversationTranscriptEvent,
    HandshakeRequest,
    HandshakeResponsePayload,
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
    OutputSpeakResponsePayload,
    OutputStateEvent,
    OutputStopRequest,
    OutputUtteranceBeginRequest,
    OutputUtteranceEndRequest,
    OutputUtteranceEnqueueRequest,
    PingRequest,
    ProbeRequest,
    ProbeResponsePayload,
    ShutdownRequest,
    UtteranceCompletedEvent,
    VoiceErrorCode,
    VoiceErrorPayload,
    VoiceFrameReader,
    VoiceMessage,
    VoiceProtocolEofError,
    VoiceProtocolError,
    VoiceProtocolVersionError,
    VoiceRequest,
    VoiceResponse,
    VoiceWorkerConfig,
    WorkerErrorEvent,
    write_voice_frame,
)
from servonaut.services import voice_engines
from servonaut.services.interfaces import (
    VoiceConversationServiceInterface,
    VoiceInputServiceInterface,
    VoiceOutputServiceInterface,
)

logger = logging.getLogger("servonaut.voice.worker")

DEFAULT_CAPABILITIES: Final[Tuple[str, ...]] = (
    "stt_batch",
    "stt_streaming",
    "tts",
    "vad",
    "conversation",
)
DEFAULT_MANIFEST_ID: Final[str] = "managed-runtime-v1"
# How long the teardown waits for a frame write already in progress.
_OUTPUT_CLOSE_WAIT_SECONDS: Final[float] = 2.0

# Settings baked into a service when it loads its model: changing one
# means building that service again. Everything else is read live from
# the shared settings object on each use.
_REBUILD_TRIGGERS: Final[Dict[str, Tuple[str, ...]]] = {
    "batch_input": ("model_size",),
    "streaming_input": ("nemotron_latency_ms", "auto_submit"),
    "output": ("output_device",),
}

# Error code reported when a handler fails unexpectedly, per request type.
_FAILURE_CODES: Final[Dict[Type[Any], VoiceErrorCode]] = {
    InputStartRequest: VoiceErrorCode.AUDIO_DEVICE_ERROR,
    InputStopRequest: VoiceErrorCode.TRANSCRIPTION_ERROR,
    OutputSpeakRequest: VoiceErrorCode.SYNTHESIS_ERROR,
    ConversationStartRequest: VoiceErrorCode.CONVERSATION_ERROR,
}


def _new_id() -> str:
    return str(uuid.uuid4())


class WorkerTerminated(BaseException):
    """Raised in the main thread by SIGTERM/SIGINT so a blocked read ends.

    A ``BaseException`` on purpose: it must pass through every
    ``except Exception`` guard on its way out to the teardown.
    """

    def __init__(self, signum: int) -> None:
        super().__init__(f"signal {signum}")
        self.signum = signum


# ---------------------------------------------------------------------------
# Service construction
# ---------------------------------------------------------------------------


class VoiceServiceFactory(ABC):
    """Builds the worker's voice services from its current settings."""

    @abstractmethod
    def build_input(self, config: VoiceConfig, *, streaming: bool) -> VoiceInputServiceInterface:
        """Capture + recognition service (batch or streaming)."""

    @abstractmethod
    def build_output(self, config: VoiceConfig) -> VoiceOutputServiceInterface:
        """Speech synthesis + playback service."""

    @abstractmethod
    def build_conversation(
        self,
        config: VoiceConfig,
        *,
        input_service: Callable[[], Optional[VoiceInputServiceInterface]],
        output_service: Callable[[], Optional[VoiceOutputServiceInterface]],
    ) -> VoiceConversationServiceInterface:
        """Hands-free loop over the providers of the current services."""


class EngineServiceFactory(VoiceServiceFactory):
    """Builds the real speech engines (the worker's default)."""

    def build_input(self, config: VoiceConfig, *, streaming: bool) -> VoiceInputServiceInterface:
        if streaming:
            from servonaut.services.voice_streaming_service import StreamingVoiceInputService

            return StreamingVoiceInputService(config)
        from servonaut.services.voice_input_service import VoiceInputService

        return VoiceInputService(config)

    def build_output(self, config: VoiceConfig) -> VoiceOutputServiceInterface:
        return voice_engines.build_voice_output_service(config)

    def build_conversation(
        self,
        config: VoiceConfig,
        *,
        input_service: Callable[[], Optional[VoiceInputServiceInterface]],
        output_service: Callable[[], Optional[VoiceOutputServiceInterface]],
    ) -> VoiceConversationServiceInterface:
        return voice_engines.build_voice_conversation_service(
            config, input_service=input_service, output_service=output_service,
        )


class _Lane:
    """One ordered background executor; its thread starts on first use."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._queue: "queue.Queue[Optional[Callable[[], None]]]" = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def submit(self, task: Callable[[], None]) -> None:
        with self._lock:
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name=f"voice-worker-{self._name}", daemon=True,
                )
                self._thread.start()
        self._queue.put(task)

    def close(self) -> None:
        self._queue.put(None)

    def _run(self) -> None:
        while (task := self._queue.get()) is not None:
            try:
                task()
            except Exception:  # noqa: BLE001 — a dead lane would stall every later request
                logger.exception("Voice worker lane '%s' task failed", self._name)


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


class VoiceWorker:
    """Manages voice capture, synthesis, and conversation in a companion process."""

    def __init__(
        self,
        stdin: BinaryIO,
        stdout: BinaryIO,
        *,
        manifest_id: str = DEFAULT_MANIFEST_ID,
        service_factory: Optional[VoiceServiceFactory] = None,
    ) -> None:
        self._stdin = stdin
        self._stdout = stdout
        self._manifest_id = manifest_id
        self._factory = service_factory or EngineServiceFactory()

        # Live settings shared by every service; replaced field-by-field by
        # the handshake and configure requests.
        self._config = VoiceConfig()
        self._services_lock = threading.RLock()
        self._batch_input: Optional[VoiceInputServiceInterface] = None
        self._streaming_input: Optional[VoiceInputServiceInterface] = None
        self._output: Optional[VoiceOutputServiceInterface] = None
        self._conversation: Optional[VoiceConversationServiceInterface] = None
        self._recording_streaming = False
        self._last_conv_state = "idle"

        # Parent-side playback epoch last seen; worker-side epochs belong
        # to the output service and are translated at this boundary.
        self._epoch_lock = threading.Lock()
        self._parent_epoch = 0

        self._sessions_lock = threading.Lock()
        self._active_utterance_sessions: Dict[str, Any] = {}

        self._handshaken = False
        self._shutdown = False
        self._torn_down = False
        self._write_lock = threading.Lock()
        self._output_closed = False
        self._lanes: Dict[str, _Lane] = {}
        self._routes: Dict[Type[Any], Tuple[Callable[[Any], None], Optional[str]]] = {
            HandshakeRequest: (self._handle_handshake, None),
            ConfigureRequest: (self._handle_configure, None),
            PingRequest: (self._handle_ping, None),
            ShutdownRequest: (self._handle_shutdown, None),
            OutputStopRequest: (self._handle_output_stop, None),
            ProbeRequest: (self._handle_probe, "probe"),
            InputStartRequest: (self._handle_input_start, "input"),
            InputStopRequest: (self._handle_input_stop, "input"),
            InputCancelRequest: (self._handle_input_cancel, "input"),
            InputResetBudgetRequest: (self._handle_input_reset_budget, "input"),
            OutputSpeakRequest: (self._handle_output_speak, "speak"),
            OutputEnqueueRequest: (self._handle_output_enqueue, "output"),
            OutputUtteranceBeginRequest: (self._handle_output_utterance_begin, "output"),
            OutputUtteranceEnqueueRequest: (self._handle_output_utterance_enqueue, "output"),
            OutputUtteranceEndRequest: (self._handle_output_utterance_end, "output"),
            OutputCloseRequest: (self._handle_output_close, "output"),
            ConversationStartRequest: (self._handle_conversation_start, "conversation"),
            ConversationStopRequest: (self._handle_conversation_stop, "conversation"),
            ConversationInterruptRequest: (self._handle_conversation_interrupt, "conversation"),
            ConversationSignalRequest: (self._handle_conversation_signal, "conversation"),
        }

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> int:
        """Serve requests from stdin until EOF or shutdown, then tear down."""
        logger.info("VoiceWorker starting main dispatch loop")
        try:
            self._serve()
        finally:
            self.teardown()
        return 0

    def _serve(self) -> None:
        reader = VoiceFrameReader(self._stdin)
        while not self._shutdown:
            try:
                msg = reader.read_frame()
            except VoiceProtocolEofError:
                logger.info("VoiceWorker received mid-frame EOF, terminating")
                return
            except (OSError, ValueError) as e:
                # stdin was closed or became unreadable: same as EOF.
                logger.info("VoiceWorker input unreadable (%s), terminating", e)
                return
            except VoiceProtocolVersionError as e:
                self._reject_foreign_version(e)
                continue
            except VoiceProtocolError as e:
                logger.warning("Voice protocol error: %s", e)
                self._send(WorkerErrorEvent(id=_new_id(), code=e.code, message=e.message))
                continue
            if msg is None:
                logger.info("VoiceWorker received EOF on stdin, terminating")
                return
            self._dispatch(msg)

    def _reject_foreign_version(self, error: VoiceProtocolVersionError) -> None:
        """Answer a request from another protocol version straight away.

        The reply is still written in this worker's version; the peer
        cannot decode it either, but it fails fast on the version instead
        of waiting out its request timeout.
        """
        logger.warning("Voice protocol version skew: %s", error.message)
        if error.msg_type == "request" and error.msg_id:
            self._send(self._error_response(
                error.msg_id, VoiceErrorCode.UNSUPPORTED_VERSION, error.message,
            ))
            return
        self._send(WorkerErrorEvent(id=_new_id(), code=error.code, message=error.message))

    def _dispatch(self, msg: VoiceMessage) -> None:
        """Route one decoded request inline or onto its lane."""
        route = self._routes.get(type(msg))
        if route is None:
            logger.warning("Worker received unexpected message type: %s", type(msg).__name__)
            return
        req: VoiceRequest = msg  # type: ignore[assignment]
        if not self._handshaken and req.name not in ("handshake", "ping", "shutdown"):
            self._reply_error(req, VoiceErrorCode.NOT_HANDSHAKEN, "Handshake required before operation")
            return

        handler, lane = route
        if lane is None:
            self._run_guarded(handler, req)
        else:
            self._lane(lane).submit(lambda: self._run_guarded(handler, req))

    def _lane(self, name: str) -> _Lane:
        lane = self._lanes.get(name)
        if lane is None:
            lane = self._lanes[name] = _Lane(name)
        return lane

    def _run_guarded(self, handler: Callable[[Any], None], req: VoiceRequest) -> None:
        if self._torn_down:
            # Queued behind the teardown: never reopen a device on the way out.
            return
        try:
            handler(req)
        except Exception as e:
            logger.exception("Error handling request %s", req.name)
            code = _FAILURE_CODES.get(type(req), VoiceErrorCode.INVALID_STATE)
            self._reply_error(req, code, f"{type(e).__name__}: {e}")

    # ------------------------------------------------------------------
    # Session and settings
    # ------------------------------------------------------------------

    def _handle_handshake(self, req: HandshakeRequest) -> None:
        if req.protocol_version != VOICE_PROTOCOL_VERSION:
            self._reply_error(
                req,
                VoiceErrorCode.UNSUPPORTED_VERSION,
                f"Protocol version mismatch: client requested {req.protocol_version}, "
                f"worker supports {VOICE_PROTOCOL_VERSION}",
            )
            return

        self._apply_config(req.config)
        with self._epoch_lock:
            self._parent_epoch = req.epoch
        self._handshaken = True

        payload = HandshakeResponsePayload(
            worker_version=__version__,
            protocol_version=VOICE_PROTOCOL_VERSION,
            manifest_id=self._manifest_id,
            python_version=platform.python_version(),
            platform=sys.platform,
            architecture=platform.machine(),
            capabilities=DEFAULT_CAPABILITIES,
            models_status=self._models_status(),
            audio_devices=self._inspect_audio_devices(),
        )
        self._reply(req, payload.to_dict())

    def _handle_configure(self, req: ConfigureRequest) -> None:
        self._apply_config(req.config)
        self._reply(req)

    def _apply_config(self, worker_config: VoiceWorkerConfig) -> None:
        """Adopt *worker_config*; rebuild only services whose model changed."""
        # Built through VoiceConfig so its clamping rules apply here too.
        incoming = VoiceConfig(**worker_config.to_dict())
        changed = {
            key for key in worker_config.to_dict()
            if getattr(incoming, key) != getattr(self._config, key)
        }
        with self._services_lock:
            for key in worker_config.to_dict():
                setattr(self._config, key, getattr(incoming, key))
            retired = self._detach_services_for(changed)
        for service in retired:
            self._retire_service(service)

    def _detach_services_for(self, changed: set[str]) -> List[Any]:
        retired: List[Any] = []
        for slot, triggers in _REBUILD_TRIGGERS.items():
            attr = f"_{slot}"
            service = getattr(self, attr)
            if service is not None and changed.intersection(triggers):
                retired.append(service)
                setattr(self, attr, None)
        return retired

    @staticmethod
    def _retire_service(service: Any) -> None:
        for method in ("cancel_recording", "stop", "close"):
            call = getattr(service, method, None)
            if call is None:
                continue
            try:
                call()
            except Exception:  # noqa: BLE001 — retiring must never fail a configure
                logger.debug("Error retiring %s.%s", type(service).__name__, method, exc_info=True)

    def _handle_ping(self, req: PingRequest) -> None:
        self._reply(req, {"pong": True, "status": "ready" if self._handshaken else "pending"})

    def _handle_shutdown(self, req: ShutdownRequest) -> None:
        logger.info("VoiceWorker shutdown requested (%s)", req.reason)
        self._shutdown = True
        self._reply(req, {"ack": True})

    def _handle_probe(self, req: ProbeRequest) -> None:
        in_svc = self._input_service(streaming=self._engine_is_streaming())
        out_svc = self._output_service()
        payload = ProbeResponsePayload(
            input_available=in_svc.is_available(),
            input_unavailable_reason=in_svc.unavailable_reason(),
            output_available=out_svc.is_available(),
            output_unavailable_reason=out_svc.unavailable_reason(),
            devices=self._inspect_audio_devices(),
        )
        self._reply(req, payload.to_dict())

    # ------------------------------------------------------------------
    # Input
    # ------------------------------------------------------------------

    def _handle_input_start(self, req: InputStartRequest) -> None:
        svc = self._input_service(streaming=req.streaming)
        if not svc.is_available():
            self._reply_error(
                req,
                VoiceErrorCode.AUDIO_DEVICE_ERROR,
                svc.unavailable_reason() or "Voice input device unavailable",
            )
            return
        if svc.is_recording:
            self._reply_error(req, VoiceErrorCode.INVALID_STATE, "Voice input recording already in progress")
            return

        # The request's cap is authoritative for the recording it starts.
        self._config.max_recording_seconds = max(1, math.ceil(req.max_seconds))
        if req.streaming:
            self._wire_streaming_callbacks(svc)
        svc.start_recording()
        self._recording_streaming = req.streaming
        self._reply(req)

    def _wire_streaming_callbacks(self, svc: VoiceInputServiceInterface) -> None:
        set_partial = getattr(svc, "set_partial_callback", None)
        if set_partial is not None:
            set_partial(lambda text: self._send(InputPartialEvent(id=_new_id(), text=text)))
        set_endpoint = getattr(svc, "set_endpoint_callback", None)
        if set_endpoint is not None:
            set_endpoint(lambda: self._send(InputEndpointEvent(id=_new_id())))

    def _handle_input_stop(self, req: InputStopRequest) -> None:
        svc = self._input_service(streaming=self._recording_streaming)
        text = svc.stop_and_transcribe(initial_prompt=req.initial_prompt)
        hit_cap = bool(getattr(svc, "hit_recording_cap", False))
        if hit_cap:
            self._send(InputCapHitEvent(id=_new_id()))
        self._reply(req, InputStopResponsePayload(text=text, hit_cap=hit_cap).to_dict())

    def _handle_input_cancel(self, req: InputCancelRequest) -> None:
        for svc in self._built_input_services():
            svc.cancel_recording()
        self._reply(req)

    def _handle_input_reset_budget(self, req: InputResetBudgetRequest) -> None:
        svc = self._input_service(streaming=self._recording_streaming)
        reset = getattr(svc, "reset_recording_budget", None)
        if reset is not None:
            reset()
        self._reply(req)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def _translate_epoch(self, parent_epoch: Optional[int]) -> Optional[int]:
        """Output-service epoch for a request pinned to *parent_epoch*.

        Returns None when the request is stale (the parent has stopped
        playback since pinning it). A parent epoch ahead of the last one
        seen means the parent stopped playback without this worker being
        told — for instance before the worker was running — so the worker
        catches up by stopping too.
        """
        output = self._output_service()
        with self._epoch_lock:
            if parent_epoch is None:
                return output.current_epoch()
            if parent_epoch < self._parent_epoch:
                return None
            if parent_epoch > self._parent_epoch:
                self._parent_epoch = parent_epoch
                output.stop()
            return output.current_epoch()

    def _current_parent_epoch(self) -> int:
        with self._epoch_lock:
            return self._parent_epoch

    def _handle_output_speak(self, req: OutputSpeakRequest) -> None:
        output = self._output_service()
        worker_epoch = self._translate_epoch(req.epoch)
        completed = False
        if worker_epoch is not None:
            self._send_output_state(True)
            try:
                output.speak(req.text, epoch=worker_epoch)
                completed = output.current_epoch() == worker_epoch
            finally:
                self._send_output_state(False)
        payload = OutputSpeakResponsePayload(completed=completed, epoch=self._current_parent_epoch())
        self._reply(req, payload.to_dict())

    def _send_output_state(self, is_speaking: bool) -> None:
        self._send(OutputStateEvent(
            id=_new_id(), is_speaking=is_speaking, current_epoch=self._current_parent_epoch(),
        ))

    def _handle_output_enqueue(self, req: OutputEnqueueRequest) -> None:
        worker_epoch = self._translate_epoch(req.epoch)
        if worker_epoch is not None:
            self._output_service().enqueue(req.text, epoch=worker_epoch)
        self._reply(req)

    def _handle_output_utterance_begin(self, req: OutputUtteranceBeginRequest) -> None:
        session_id = req.session_id
        worker_epoch = self._translate_epoch(req.epoch)
        if worker_epoch is None:
            self._send_utterance_completed(session_id, False)
            self._reply(req)
            return

        settled = threading.Event()

        def _on_complete(played_to_end: bool) -> None:
            settled.set()
            with self._sessions_lock:
                self._active_utterance_sessions.pop(session_id, None)
            self._send_utterance_completed(session_id, played_to_end)

        session = self._output_service().begin_utterance(on_complete=_on_complete, epoch=worker_epoch)
        with self._sessions_lock:
            # A session born superseded settles inside begin_utterance;
            # tracking it then would leak it for the life of the worker.
            if not settled.is_set():
                self._active_utterance_sessions[session_id] = session
        self._reply(req)

    def _send_utterance_completed(self, session_id: str, played_to_end: bool) -> None:
        self._send(UtteranceCompletedEvent(
            id=_new_id(), session_id=session_id, played_to_end=played_to_end,
        ))

    def _handle_output_utterance_enqueue(self, req: OutputUtteranceEnqueueRequest) -> None:
        session = self._session(req.session_id)
        if session is None:
            self._reply_unknown_session(req, req.session_id)
            return
        session.enqueue(req.text)
        self._reply(req)

    def _handle_output_utterance_end(self, req: OutputUtteranceEndRequest) -> None:
        session = self._session(req.session_id)
        if session is None:
            self._reply_unknown_session(req, req.session_id)
            return
        session.end()
        self._reply(req)

    def _session(self, session_id: str) -> Optional[Any]:
        with self._sessions_lock:
            return self._active_utterance_sessions.get(session_id)

    def _reply_unknown_session(self, req: VoiceRequest, session_id: str) -> None:
        self._reply_error(
            req, VoiceErrorCode.INVALID_STATE, f"No active utterance session with id {session_id}",
        )

    def _handle_output_stop(self, req: OutputStopRequest) -> None:
        """Stop playback unless the stop is already accounted for.

        A stop pinned to an epoch this worker has already reached — it
        caught up from a newer request, or learned the epoch in its
        handshake — is stale: acting on it would cut off audio that is
        current.
        """
        output = self._output_service()
        with self._epoch_lock:
            if req.epoch is None or req.epoch > self._parent_epoch:
                if req.epoch is not None:
                    self._parent_epoch = req.epoch
                output.stop()
        self._reply(req)

    def _handle_output_close(self, req: OutputCloseRequest) -> None:
        with self._services_lock:
            output, self._output = self._output, None
        if output is not None:
            output.close()
        self._reply(req)

    # ------------------------------------------------------------------
    # Conversation
    # ------------------------------------------------------------------

    def _handle_conversation_start(self, req: ConversationStartRequest) -> None:
        conv = self._conversation_service()
        self._config.barge_in = req.barge_in
        conv.start()
        self._reply(req)

    def _handle_conversation_stop(self, req: ConversationStopRequest) -> None:
        self._conversation_service().stop()
        self._reply(req)

    def _handle_conversation_interrupt(self, req: ConversationInterruptRequest) -> None:
        self._conversation_service().interrupt()
        self._reply(req)

    def _handle_conversation_signal(self, req: ConversationSignalRequest) -> None:
        conv = self._conversation_service()
        if req.signal in ("reply_started", "reply_finished", "speaking_started", "speaking_finished"):
            getattr(conv, req.signal)()
        else:
            logger.debug("Unknown conversation signal: %s", req.signal)
        self._reply(req)

    def _on_conversation_state(self, new_state: Any) -> None:
        new_state_str = str(getattr(new_state, "value", new_state)).lower()
        old_state_str, self._last_conv_state = self._last_conv_state, new_state_str
        self._send(ConversationStateEvent(id=_new_id(), old_state=old_state_str, new_state=new_state_str))

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def _engine_is_streaming(self) -> bool:
        return voice_engines.engine_spec(self._config.engine).streaming

    def _input_service(self, *, streaming: bool) -> VoiceInputServiceInterface:
        with self._services_lock:
            if streaming:
                if self._streaming_input is None:
                    self._streaming_input = self._factory.build_input(self._config, streaming=True)
                return self._streaming_input
            if self._batch_input is None:
                self._batch_input = self._factory.build_input(self._config, streaming=False)
            return self._batch_input

    def _built_input_services(self) -> List[VoiceInputServiceInterface]:
        with self._services_lock:
            return [svc for svc in (self._batch_input, self._streaming_input) if svc is not None]

    def _conversation_input(self) -> VoiceInputServiceInterface:
        """The capture service the configured engine selects."""
        return self._input_service(streaming=self._engine_is_streaming())

    def _output_service(self) -> VoiceOutputServiceInterface:
        with self._services_lock:
            if self._output is None:
                self._output = self._factory.build_output(self._config)
            return self._output

    def _conversation_service(self) -> VoiceConversationServiceInterface:
        with self._services_lock:
            if self._conversation is None:
                conv = self._factory.build_conversation(
                    self._config,
                    input_service=self._conversation_input,
                    output_service=self._output_service,
                )
                conv.set_state_callback(self._on_conversation_state)
                conv.set_transcript_callback(
                    lambda text: self._send(ConversationTranscriptEvent(id=_new_id(), text=text))
                )
                conv.set_error_callback(
                    lambda message: self._send(ConversationErrorEvent(id=_new_id(), message=message))
                )
                conv.set_stopped_callback(
                    lambda reason: self._send(ConversationStoppedEvent(id=_new_id(), reason=reason))
                )
                self._conversation = conv
            return self._conversation

    # ------------------------------------------------------------------
    # Engine / Hardware Queries
    # ------------------------------------------------------------------

    def _models_status(self) -> Dict[str, bool]:
        """Model presence, from the same path helpers the services load from."""
        config = self._config
        return {
            "whisper": voice_engines.is_whisper_model_cached(config.model_size),
            "nemotron": voice_engines.is_nemotron_model_present(config.nemotron_latency_ms),
            "kokoro": voice_engines.is_kokoro_model_present(),
            "silero": voice_engines.is_silero_vad_model_present(),
        }

    def _inspect_audio_devices(self) -> Dict[str, Any]:
        """Sanitized enumeration of audio input/output devices without machine secrets."""
        info: Dict[str, Any] = {
            "has_sounddevice": False,
            "input_count": 0,
            "output_count": 0,
            "default_input": None,
            "default_output": None,
        }
        try:
            import sounddevice as sd  # type: ignore[import-untyped]
            info["has_sounddevice"] = True
            devices = sd.query_devices()
            if isinstance(devices, list):
                info["input_count"] = sum(
                    1 for d in devices if d.get("max_input_channels", 0) > 0
                )
                info["output_count"] = sum(
                    1 for d in devices if d.get("max_output_channels", 0) > 0
                )
            default = sd.default.device
            if isinstance(default, (list, tuple)) and len(default) >= 2:
                info["default_input"] = default[0]
                info["default_output"] = default[1]
        except Exception as e:  # noqa: BLE001 — PortAudio/import failures vary
            logger.debug("Audio device probe failed: %s", e)
        return info

    # ------------------------------------------------------------------
    # Frame sending
    # ------------------------------------------------------------------

    def _reply(self, req: VoiceRequest, payload: Optional[Dict[str, Any]] = None) -> None:
        self._send(VoiceResponse(id=_new_id(), ref_id=req.id, ok=True, payload=payload or {}))

    def _reply_error(self, req: VoiceRequest, code: VoiceErrorCode, message: str) -> None:
        self._send(self._error_response(req.id, code, message))

    @staticmethod
    def _error_response(ref_id: str, code: VoiceErrorCode, message: str) -> VoiceResponse:
        return VoiceResponse(
            id=_new_id(), ref_id=ref_id, ok=False,
            error=VoiceErrorPayload(code=code, message=message),
        )

    def _send(self, message: VoiceMessage) -> None:
        with self._write_lock:
            if self._output_closed:
                return
            try:
                write_voice_frame(self._stdout, message)
            except (OSError, ValueError) as e:
                # The parent is gone (broken pipe / closed stream); stdin EOF
                # follows and ends the main loop.
                logger.debug("Dropped a frame to the parent: %s", e)

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def teardown(self) -> None:
        """Release audio devices and stop background work on worker exit."""
        logger.info("VoiceWorker tearing down active services")
        self._torn_down = True
        with self._services_lock:
            conversation, self._conversation = self._conversation, None
            inputs = [svc for svc in (self._batch_input, self._streaming_input) if svc is not None]
            self._batch_input = self._streaming_input = None
            output, self._output = self._output, None
        if conversation is not None:
            try:
                conversation.stop(join=False)
            except Exception:  # noqa: BLE001 — teardown must reach every service
                logger.debug("Error stopping the conversation loop", exc_info=True)
        for service in (*inputs, output):
            if service is not None:
                self._retire_service(service)
        for lane in self._lanes.values():
            lane.close()
        with self._sessions_lock:
            self._active_utterance_sessions.clear()
        self._close_output()

    def _close_output(self) -> None:
        """Stop writing to stdout before the interpreter starts finalizing.

        Background threads may still finish work after the teardown; a
        thread caught mid-write in stdout's buffered writer at interpreter
        shutdown aborts the process. Taking the write lock waits out any
        write in progress; later writes are dropped.
        """
        acquired = self._write_lock.acquire(timeout=_OUTPUT_CLOSE_WAIT_SECONDS)
        try:
            self._output_closed = True
        finally:
            if acquired:
                self._write_lock.release()


# ---------------------------------------------------------------------------
# Process entry points
# ---------------------------------------------------------------------------


def _raise_terminated(signum: int, frame: Any) -> None:
    # Ignore repeats so a second signal cannot interrupt the teardown.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    raise WorkerTerminated(signum)


def _install_signal_handlers() -> None:
    """Make SIGTERM/SIGINT end a read blocked on stdin.

    A handler that only sets a flag is not enough: PEP 475 retries the
    interrupted read, so the loop would never see the flag.
    """
    try:
        signal.signal(signal.SIGINT, _raise_terminated)
        signal.signal(signal.SIGTERM, _raise_terminated)
    except (ValueError, OSError, AttributeError):
        logger.debug("Signal handlers unavailable here; relying on stdin EOF")


def run_worker(
    stdin: Optional[BinaryIO] = None,
    stdout: Optional[BinaryIO] = None,
    *,
    manifest_id: str = DEFAULT_MANIFEST_ID,
) -> int:
    """Run the voice worker daemon on stdio."""
    worker = VoiceWorker(
        stdin=stdin or sys.stdin.buffer,
        stdout=stdout or sys.stdout.buffer,
        manifest_id=manifest_id,
    )
    _install_signal_handlers()
    try:
        return worker.run()
    except WorkerTerminated as e:
        logger.info("VoiceWorker stopped by signal %s", e.signum)
        return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for launching the companion voice worker process."""
    parser = argparse.ArgumentParser(description="Servonaut Managed Voice Companion Worker")
    parser.add_argument(
        "--manifest-id",
        default=os.environ.get("SERVONAUT_VOICE_MANIFEST_ID", DEFAULT_MANIFEST_ID),
        help="Managed runtime release identifier",
    )
    parser.add_argument(
        "--models-root",
        default=None,
        help=(
            "Directory containing voice model weights "
            f"(default: ${voice_engines.VOICE_MODELS_DIR_ENV}, then ~/.servonaut/voice_models)"
        ),
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] [voice-worker] %(message)s",
    )

    if args.models_root:
        # Before any service exists: services and the handshake's model
        # status must read the same directory.
        voice_engines.set_voice_models_root(Path(args.models_root).expanduser())
    return run_worker(manifest_id=args.manifest_id)


if __name__ == "__main__":
    sys.exit(main())
