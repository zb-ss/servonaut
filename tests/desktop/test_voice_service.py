"""Unit tests for parent-side Desktop Voice Service proxies."""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from typing import Any, Callable, Optional
import uuid

import pytest

from servonaut.config.schema import VoiceConfig
from servonaut.desktop.voice.connection import (
    VoiceConnection,
)
from servonaut.desktop.voice.protocol import (
    VOICE_PROTOCOL_VERSION,
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
    OutputStateEvent,
    OutputStopRequest,
    OutputUtteranceBeginRequest,
    OutputUtteranceEndRequest,
    OutputUtteranceEnqueueRequest,
    ProbeRequest,
    ProbeResponsePayload,
    UtteranceCompletedEvent,
    VoiceErrorCode,
    VoiceErrorPayload,
    VoiceRequest,
    VoiceResponse,
    read_voice_frame,
    write_voice_frame,
)
from servonaut.desktop.voice.service import (
    DesktopVoiceConversationService,
    DesktopVoiceInputService,
    DesktopVoiceOutputService,
    build_desktop_voice_services,
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


class PipeTransport:
    """Creates a pair of bidirectional OS pipes for testing."""

    def __init__(self) -> None:
        p2w_r, p2w_w = os.pipe()
        w2p_r, w2p_w = os.pipe()

        self.parent_in = os.fdopen(w2p_r, "rb", buffering=0)
        self.parent_out = os.fdopen(p2w_w, "wb", buffering=0)

        self.worker_in = os.fdopen(p2w_r, "rb", buffering=0)
        self.worker_out = os.fdopen(w2p_w, "wb", buffering=0)

    def close(self) -> None:
        for f in (self.parent_in, self.parent_out, self.worker_in, self.worker_out):
            try:
                f.close()
            except Exception:
                pass


@pytest.fixture
def pipes():
    transport = PipeTransport()
    yield transport
    transport.close()


def _default_handshake_payload() -> HandshakeResponsePayload:
    return HandshakeResponsePayload(
        worker_version="1.0.0",
        protocol_version=VOICE_PROTOCOL_VERSION,
        manifest_id="test-manifest",
        python_version="3.12.0",
        platform="linux",
        architecture="x86_64",
        capabilities=("stt_batch", "stt_streaming", "tts", "vad", "conversation"),
        models_status={"whisper": True, "kokoro": True},
        audio_devices={"input": True, "output": True},
    )


def _start_responder(
    pipes: PipeTransport,
    custom_handler: Optional[Callable[[VoiceRequest, PipeTransport], Optional[VoiceResponse]]] = None,
):
    """Run a worker responder loop handling handshake and custom requests."""
    def worker():
        while True:
            try:
                req = read_voice_frame(pipes.worker_in)
                if req is None:
                    break
                if isinstance(req, HandshakeRequest):
                    write_voice_frame(
                        pipes.worker_out,
                        VoiceResponse(
                            id=f"resp-{req.id}",
                            ref_id=req.id,
                            ok=True,
                            payload=_default_handshake_payload(),
                        ),
                    )
                    continue

                if custom_handler:
                    resp = custom_handler(req, pipes)
                    if resp is not None:
                        write_voice_frame(pipes.worker_out, resp)
                else:
                    write_voice_frame(
                        pipes.worker_out,
                        VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={}),
                    )
            except Exception as e:
                logger.debug("Worker loop encountered exception: %s", e)
                break

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# DesktopVoiceInputService Tests
# ---------------------------------------------------------------------------


def test_input_service_availability(pipes):
    """DesktopVoiceInputService queries worker probe for availability."""
    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, ProbeRequest):
            return VoiceResponse(
                id=f"resp-{req.id}",
                ref_id=req.id,
                ok=True,
                payload=ProbeResponsePayload(
                    input_available=True,
                    input_unavailable_reason="",
                    output_available=False,
                    output_unavailable_reason="No audio device",
                    devices={"default": True},
                ),
            )
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceInputService(conn, config)

    assert service.is_available() is True
    assert service.unavailable_reason() == ""
    conn.close()


def test_input_service_unavailable_when_probe_fails(pipes):
    """DesktopVoiceInputService reports reason when probe reports input unavailable."""
    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, ProbeRequest):
            return VoiceResponse(
                id=f"resp-{req.id}",
                ref_id=req.id,
                ok=True,
                payload=ProbeResponsePayload(
                    input_available=False,
                    input_unavailable_reason="No microphone found",
                    output_available=True,
                    output_unavailable_reason="",
                    devices={},
                ),
            )
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceInputService(conn, config)

    assert service.is_available() is False
    assert "No microphone found" in service.unavailable_reason()
    conn.close()


def test_input_service_recording_lifecycle(pipes):
    """Start recording, receive events, stop and transcribe."""
    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, InputStartRequest):
            def emit_events():
                time.sleep(0.05)
                write_voice_frame(
                    p.worker_out,
                    InputPartialEvent(id=_new_id(), text="hello wor"),
                )
                time.sleep(0.05)
                write_voice_frame(p.worker_out, InputEndpointEvent(id=_new_id()))

            threading.Thread(target=emit_events, daemon=True).start()
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

        if isinstance(req, InputStopRequest):
            return VoiceResponse(
                id=f"resp-{req.id}",
                ref_id=req.id,
                ok=True,
                payload=InputStopResponsePayload(
                    text="hello world",
                    hit_cap=False,
                ),
            )
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig(max_recording_seconds=15.0)
    service = DesktopVoiceInputService(conn, config)

    partials = []
    endpoints = []
    service.set_partial_callback(lambda txt: partials.append(txt))
    service.set_endpoint_callback(lambda: endpoints.append(True))

    service.start_recording()
    assert service.is_recording is True

    # Double start raises VoiceInputError
    with pytest.raises(VoiceInputError, match="already in progress"):
        service.start_recording()

    # Wait for events
    deadline = time.time() + 2.0
    while (not partials or not endpoints) and time.time() < deadline:
        time.sleep(0.05)

    assert partials == ["hello wor"]
    assert endpoints == [True]

    text = service.stop_and_transcribe()
    assert text == "hello world"
    assert service.is_recording is False
    conn.close()


def test_input_service_cancel(pipes):
    """Cancel recording resets state and tells the worker."""
    cancelled = []

    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, InputCancelRequest):
            cancelled.append(True)
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    service = DesktopVoiceInputService(conn, VoiceConfig())

    service.start_recording()
    service.cancel_recording()
    assert service.is_recording is False
    deadline = time.time() + 2.0
    while not cancelled and time.time() < deadline:
        time.sleep(0.01)
    assert cancelled == [True]
    conn.close()


def test_hit_cap_comes_from_the_stop_reply(pipes):
    """The cap is known the moment the transcript is, even with a busy dispatcher."""
    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, InputStopRequest):
            # The worker's order: partial and cap events first, then the reply.
            write_voice_frame(p.worker_out, InputPartialEvent(id=_new_id(), text="last words"))
            write_voice_frame(p.worker_out, InputCapHitEvent(id=_new_id()))
            return VoiceResponse(
                id=f"resp-{req.id}", ref_id=req.id, ok=True,
                payload=InputStopResponsePayload(text="long dictation", hit_cap=True).to_dict(),
            )
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    service = DesktopVoiceInputService(conn, VoiceConfig())
    service.set_partial_callback(lambda text: time.sleep(0.3))  # a UI thread that is busy

    service.start_recording()
    assert service.stop_and_transcribe() == "long dictation"
    assert service.hit_recording_cap is True

    service.start_recording()
    assert service.hit_recording_cap is False
    conn.close()


def test_input_service_remote_error_mapped(pipes):
    """Worker error response in start_recording maps to VoiceInputError."""
    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, InputStartRequest):
            return VoiceResponse(
                id=f"resp-{req.id}",
                ref_id=req.id,
                ok=False,
                error=VoiceErrorPayload(
                    code=VoiceErrorCode.AUDIO_DEVICE_ERROR,
                    message="Microphone device failed to initialize",
                ),
            )
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceInputService(conn, config)

    with pytest.raises(VoiceInputError, match="Microphone device failed to initialize"):
        service.start_recording()

    assert service.is_recording is False
    conn.close()


# ---------------------------------------------------------------------------
# DesktopVoiceOutputService Tests
# ---------------------------------------------------------------------------


def test_output_service_speak_blocking(pipes):
    """Speak sends request and blocks until worker responds."""
    spoken = []

    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, OutputSpeakRequest):
            spoken.append(req.text)
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceOutputService(conn, config)

    service.speak("Hello from unit test")
    assert spoken == ["Hello from unit test"]

    # Superseded epoch should be silently dropped without sending
    spoken.clear()
    service.speak("Superseded text", epoch=service.current_epoch() - 1)
    assert spoken == []

    conn.close()


def test_output_service_utterance_session_lifecycle(pipes):
    """Utterance session lifecycle with exactly-once completion."""
    enqueued = []
    begun = []
    ended = []

    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, OutputUtteranceBeginRequest):
            begun.append(req.session_id)
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})
        if isinstance(req, OutputUtteranceEnqueueRequest):
            enqueued.append((req.session_id, req.text))
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})
        if isinstance(req, OutputUtteranceEndRequest):
            ended.append(req.session_id)
            def emit_completed():
                time.sleep(0.05)
                write_voice_frame(
                    p.worker_out,
                    UtteranceCompletedEvent(
                        id=_new_id(),
                        session_id=req.session_id,
                        played_to_end=True,
                    ),
                )

            threading.Thread(target=emit_completed, daemon=True).start()
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceOutputService(conn, config)

    completed_results = []
    session = service.begin_utterance(
        on_complete=lambda played_to_end: completed_results.append(played_to_end)
    )

    session.enqueue("First sentence.")
    session.enqueue("Second sentence.")
    session.end()

    deadline = time.time() + 2.0
    while not completed_results and time.time() < deadline:
        time.sleep(0.05)

    assert session.is_settled is True
    assert completed_results == [True]
    assert begun == [session.session_id]
    assert enqueued == [
        (session.session_id, "First sentence."),
        (session.session_id, "Second sentence."),
    ]
    assert ended == [session.session_id]

    conn.close()


def test_output_service_stop_interrupts_and_bumps_epoch(pipes):
    """Stop bumps epoch, cancels active utterance sessions with False, sends stop request."""
    stop_requests = []

    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, OutputStopRequest):
            stop_requests.append(req.epoch)
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceOutputService(conn, config)

    old_epoch = service.current_epoch()
    completed_results = []
    session = service.begin_utterance(
        on_complete=lambda played_to_end: completed_results.append(played_to_end)
    )

    service.stop()

    assert service.current_epoch() == old_epoch + 1
    assert session.is_settled is True
    assert completed_results == [False]
    deadline = time.time() + 2.0
    while not stop_requests and time.time() < deadline:
        time.sleep(0.01)
    assert stop_requests == [service.current_epoch()]

    conn.close()


def test_output_service_state_event(pipes):
    """OutputStateEvent updates is_speaking property."""
    _start_responder(pipes)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceOutputService(conn, config)

    conn.connect()
    assert service.is_speaking() is False

    write_voice_frame(
        pipes.worker_out,
        OutputStateEvent(id=_new_id(), is_speaking=True, current_epoch=0),
    )

    deadline = time.time() + 1.0
    while not service.is_speaking() and time.time() < deadline:
        time.sleep(0.05)

    assert service.is_speaking() is True

    write_voice_frame(
        pipes.worker_out,
        OutputStateEvent(id=_new_id(), is_speaking=False, current_epoch=0),
    )

    deadline = time.time() + 1.0
    while service.is_speaking() and time.time() < deadline:
        time.sleep(0.05)

    assert service.is_speaking() is False
    conn.close()


# ---------------------------------------------------------------------------
# DesktopVoiceConversationService Tests
# ---------------------------------------------------------------------------


def test_conversation_service_state_and_signals(pipes):
    """Conversation state transitions and UI signals."""
    signals_received = []

    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, ConversationStartRequest):
            def emit_state():
                time.sleep(0.05)
                write_voice_frame(
                    p.worker_out,
                    ConversationStateEvent(
                        id=_new_id(),
                        old_state="idle",
                        new_state="listening",
                    ),
                )

            threading.Thread(target=emit_state, daemon=True).start()
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

        if isinstance(req, ConversationSignalRequest):
            signals_received.append(req.signal)
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

        if isinstance(req, ConversationStopRequest):
            def emit_stop():
                time.sleep(0.05)
                write_voice_frame(
                    p.worker_out,
                    ConversationStoppedEvent(
                        id=_new_id(),
                        reason=req.reason,
                    ),
                )

            threading.Thread(target=emit_stop, daemon=True).start()
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceConversationService(conn, config)

    observed_states = []
    service.set_state_callback(lambda s: observed_states.append(s))

    stopped_reasons = []
    service.set_stopped_callback(lambda r: stopped_reasons.append(r))

    assert service.state == ConversationState.IDLE

    service.start()

    deadline = time.time() + 2.0
    while not observed_states and time.time() < deadline:
        time.sleep(0.05)

    assert service.state == ConversationState.LISTENING
    assert observed_states == [ConversationState.LISTENING]

    # Test signals
    service.reply_started()
    service.speaking_started()
    service.speaking_finished()
    service.reply_finished()

    time.sleep(0.1)
    assert signals_received == [
        "reply_started",
        "speaking_started",
        "speaking_finished",
        "reply_finished",
    ]

    # Test stop
    service.stop()
    deadline = time.time() + 2.0
    while not stopped_reasons and time.time() < deadline:
        time.sleep(0.05)

    assert service.state == ConversationState.IDLE
    assert stopped_reasons == ["user"]

    conn.close()


def test_conversation_service_events(pipes):
    """Transcript and error events dispatches to registered callbacks."""
    _start_responder(pipes)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceConversationService(conn, config)

    conn.connect()

    transcripts = []
    errors = []
    service.set_transcript_callback(lambda t: transcripts.append(t))
    service.set_error_callback(lambda e: errors.append(e))

    write_voice_frame(
        pipes.worker_out,
        ConversationTranscriptEvent(
            id=_new_id(),
            text="what is server load?",
        ),
    )

    write_voice_frame(
        pipes.worker_out,
        ConversationErrorEvent(
            id=_new_id(),
            message="Audio device was unplugged",
        ),
    )

    deadline = time.time() + 2.0
    while (not transcripts or not errors) and time.time() < deadline:
        time.sleep(0.05)

    assert transcripts == ["what is server load?"]
    assert errors == ["Audio device was unplugged"]

    conn.close()


def test_conversation_service_worker_disconnect_resets_idle(pipes):
    """Unexpected worker disconnection lands active conversation in IDLE."""
    _start_responder(pipes)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceConversationService(conn, config)

    conn.connect()

    write_voice_frame(
        pipes.worker_out,
        ConversationStateEvent(
            id=_new_id(),
            old_state="idle",
            new_state="listening",
        ),
    )

    deadline = time.time() + 1.0
    while service.state != ConversationState.LISTENING and time.time() < deadline:
        time.sleep(0.05)

    stopped_reasons = []
    service.set_stopped_callback(lambda r: stopped_reasons.append(r))

    conn.close()

    time.sleep(0.1)
    assert service.state == ConversationState.IDLE
    assert stopped_reasons == ["worker_disconnected"]


# ---------------------------------------------------------------------------
# Factory Tests
# ---------------------------------------------------------------------------


def test_build_desktop_voice_services_factory(pipes):
    """build_desktop_voice_services constructs and shares the connection."""
    _start_responder(pipes)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()

    in_svc, out_svc, conv_svc = build_desktop_voice_services(
        config=config,
        connection=conn,
        auto_connect=True,
    )

    assert isinstance(in_svc, DesktopVoiceInputService)
    assert isinstance(out_svc, DesktopVoiceOutputService)
    assert isinstance(conv_svc, DesktopVoiceConversationService)
    assert in_svc._connection is conn
    assert out_svc._connection is conn
    assert conv_svc._connection is conn
    assert conn.is_connected is True

    conn.close()


# ---------------------------------------------------------------------------
# End-to-end against a real VoiceWorker, and timing behaviour
# ---------------------------------------------------------------------------

from typing import Dict, List

from servonaut.desktop.voice.connection import VoiceConnectionPolicy
from servonaut.desktop.voice.protocol import VoiceWorkerConfig
from servonaut.desktop.voice.worker import VoiceServiceFactory, VoiceWorker


class _WorkerInput:
    """Worker-side capture double; ``start_delay`` imitates a model load."""

    def __init__(self, start_delay: float = 0.0) -> None:
        self.start_delay = start_delay
        self.is_recording = False
        self.hit_recording_cap = False
        self.events: List[str] = []

    def is_available(self) -> bool:
        return True

    def unavailable_reason(self) -> str:
        return ""

    def start_recording(self) -> None:
        time.sleep(self.start_delay)
        self.is_recording = True
        self.events.append("start")

    def cancel_recording(self) -> None:
        self.is_recording = False
        self.events.append("cancel")

    def stop_and_transcribe(self, initial_prompt: str = "") -> str:
        self.is_recording = False
        return "text"

    def set_frame_callback(self, callback: Any) -> None:
        pass


class _WorkerOutput:
    """Worker-side playback double with the real service's epoch rules."""

    def __init__(self) -> None:
        self.epoch = 100
        self.spoken: List[str] = []

    def is_available(self) -> bool:
        return True

    def unavailable_reason(self) -> str:
        return ""

    def current_epoch(self) -> int:
        return self.epoch

    def speak(self, text: str, *, epoch: Optional[int] = None) -> None:
        if epoch is None or epoch == self.epoch:
            self.spoken.append(text)

    def enqueue(self, text: str, *, epoch: Optional[int] = None) -> None:
        self.speak(text, epoch=epoch)

    def stop(self) -> None:
        self.epoch += 1

    def close(self) -> None:
        pass


class _WorkerConversation:
    def __init__(self) -> None:
        self.callbacks: Dict[str, Callable[..., None]] = {}

    def set_state_callback(self, cb: Callable[..., None]) -> None:
        self.callbacks["state"] = cb

    def set_transcript_callback(self, cb: Callable[..., None]) -> None:
        self.callbacks["transcript"] = cb

    def set_error_callback(self, cb: Callable[..., None]) -> None:
        self.callbacks["error"] = cb

    def set_stopped_callback(self, cb: Callable[..., None]) -> None:
        self.callbacks["stopped"] = cb

    def start(self) -> None:
        self.callbacks["state"](ConversationState.LISTENING)
        threading.Timer(0.05, lambda: self.callbacks["transcript"]("restart nginx")).start()

    def stop(self, *, join: bool = True) -> None:
        self.callbacks["stopped"]("user")


class _Factory(VoiceServiceFactory):
    def __init__(self, input_delay: float = 0.0) -> None:
        self.input = _WorkerInput(input_delay)
        self.output = _WorkerOutput()
        self.conversation = _WorkerConversation()

    def build_input(self, config: VoiceConfig, *, streaming: bool) -> Any:
        return self.input

    def build_output(self, config: VoiceConfig) -> Any:
        return self.output

    def build_conversation(self, config: VoiceConfig, *, input_service: Any, output_service: Any) -> Any:
        return self.conversation


def _real_worker(pipes: PipeTransport, factory: _Factory, **policy: float) -> VoiceConnection:
    worker = VoiceWorker(stdin=pipes.worker_in, stdout=pipes.worker_out, service_factory=factory)
    threading.Thread(target=worker.run, daemon=True).start()
    return VoiceConnection(
        stdin=pipes.parent_out, stdout=pipes.parent_in, policy=VoiceConnectionPolicy(**policy),
    )


def _wait_for(predicate: Callable[[], bool], timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


def test_transcript_handler_can_stop_playback_without_stalling(pipes):
    """A hands-free turn: the transcript handler interrupts speech at once."""
    factory = _Factory()
    conn = _real_worker(pipes, factory, request_timeout_seconds=3.0)
    output = DesktopVoiceOutputService(conn, VoiceConfig())
    conversation = DesktopVoiceConversationService(conn, VoiceConfig())
    ui_queue: "queue.Queue[Callable[[], None]]" = queue.Queue()
    stalls: List[float] = []

    def on_transcript(text: str) -> None:
        done = threading.Event()

        def on_ui() -> None:
            started = time.monotonic()
            output.stop()
            stalls.append(time.monotonic() - started)
            done.set()

        ui_queue.put(on_ui)  # like call_from_thread: wait until the UI ran it
        done.wait(10)

    threading.Thread(target=lambda: [ui_queue.get()() for _ in range(1)], daemon=True).start()
    conversation.set_transcript_callback(on_transcript)
    conversation.start()
    assert _wait_for(lambda: bool(stalls), 5.0)
    assert stalls[0] < 0.5
    conn.close()


def test_worker_exit_voids_playback_queued_for_it(pipes):
    factory = _Factory()
    conn = _real_worker(pipes, factory)
    output = DesktopVoiceOutputService(conn, VoiceConfig())
    session = output.begin_utterance()
    before = output.current_epoch()
    pipes.worker_out.close()  # the worker's output ends: the session is over
    assert _wait_for(lambda: session.is_settled)
    assert output.current_epoch() == before + 1
    conn.close()


def test_stop_before_connect_does_not_silence_later_replies(pipes):
    factory = _Factory()
    conn = _real_worker(pipes, factory)
    output = DesktopVoiceOutputService(conn, VoiceConfig())
    output.stop()  # e.g. a chat send before voice was ever used
    output.speak("first reply")
    assert factory.output.spoken == ["first reply"]
    conn.close()


def test_conversation_state_from_a_real_worker_reaches_the_parent(pipes):
    factory = _Factory()
    conn = _real_worker(pipes, factory)
    conversation = DesktopVoiceConversationService(conn, VoiceConfig())
    states: List[Any] = []
    conversation.set_state_callback(states.append)
    conversation.start()
    assert _wait_for(lambda: bool(states))
    assert states[0] is ConversationState.LISTENING
    assert conversation.state is ConversationState.LISTENING
    conn.close()


def test_start_timeout_sends_a_compensating_cancel(pipes):
    factory = _Factory(input_delay=0.6)
    conn = _real_worker(pipes, factory, request_timeout_seconds=0.1, model_load_timeout_seconds=0.1)
    service = DesktopVoiceInputService(conn, VoiceConfig())
    with pytest.raises(VoiceInputError, match="timed out"):
        service.start_recording()
    assert service.is_recording is False
    assert _wait_for(lambda: factory.input.events == ["start", "cancel"])
    assert factory.input.is_recording is False
    conn.close()


def test_cancel_during_an_in_flight_start_closes_the_microphone(pipes):
    factory = _Factory(input_delay=0.3)
    conn = _real_worker(pipes, factory)
    service = DesktopVoiceInputService(conn, VoiceConfig())
    starter = threading.Thread(target=service.start_recording)
    starter.start()
    assert _wait_for(lambda: service._start_in_flight)
    service.cancel_recording()
    starter.join(5)
    assert service.is_recording is False
    assert _wait_for(lambda: factory.input.events == ["start", "cancel"])
    conn.close()


def test_conversation_start_timeout_sends_a_compensating_stop(pipes):
    requests: List[Any] = []

    def on_request(req: VoiceRequest, p: PipeTransport):
        requests.append(req)
        if isinstance(req, ConversationStartRequest):
            return None  # never answered: the parent times out
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(
        stdin=pipes.parent_out, stdout=pipes.parent_in,
        policy=VoiceConnectionPolicy(request_timeout_seconds=0.1, model_load_timeout_seconds=0.1),
    )
    conversation = DesktopVoiceConversationService(conn, VoiceConfig())
    with pytest.raises(VoiceConversationError, match="timed out"):
        conversation.start()
    assert _wait_for(lambda: any(isinstance(r, ConversationStopRequest) for r in requests))
    conn.close()


def test_speak_has_no_fixed_time_cap(pipes):
    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, OutputSpeakRequest):
            time.sleep(0.5)  # longer than the request timeout below
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(
        stdin=pipes.parent_out, stdout=pipes.parent_in,
        policy=VoiceConnectionPolicy(request_timeout_seconds=0.1),
    )
    DesktopVoiceOutputService(conn, VoiceConfig()).speak("a long reply")
    conn.close()


@pytest.mark.parametrize(("max_recording_seconds", "succeeds"), [(2, True), (1, False)])
def test_transcribe_timeout_follows_the_recording_cap(pipes, max_recording_seconds, succeeds):
    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, InputStopRequest):
            time.sleep(1.5)
            return VoiceResponse(
                id=f"resp-{req.id}", ref_id=req.id, ok=True,
                payload=InputStopResponsePayload(text="done", hit_cap=False).to_dict(),
            )
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(
        stdin=pipes.parent_out, stdout=pipes.parent_in,
        policy=VoiceConnectionPolicy(request_timeout_seconds=0.1, model_load_timeout_seconds=0.0),
    )
    service = DesktopVoiceInputService(conn, VoiceConfig(max_recording_seconds=max_recording_seconds))
    service.start_recording()
    if succeeds:
        assert service.stop_and_transcribe() == "done"
    else:
        with pytest.raises(VoiceInputError, match="timed out"):
            service.stop_and_transcribe()
    conn.close()


def test_streamed_frames_reach_the_worker_in_order(pipes):
    order: List[str] = []

    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, OutputUtteranceBeginRequest):
            order.append("begin")
        elif isinstance(req, OutputUtteranceEnqueueRequest):
            order.append(req.text)
        elif isinstance(req, OutputUtteranceEndRequest):
            order.append("end")
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    service = DesktopVoiceOutputService(conn, VoiceConfig())
    session = service.begin_utterance()
    sentences = [f"sentence {index}" for index in range(30)]
    for sentence in sentences:
        session.enqueue(sentence)
    session.end()
    assert _wait_for(lambda: len(order) == len(sentences) + 2)
    assert order == ["begin", *sentences, "end"]
    conn.close()


def test_factory_hands_the_user_settings_to_the_handshake(pipes):
    seen: List[Any] = []

    def worker() -> None:
        req = read_voice_frame(pipes.worker_in)
        seen.append(req)
        write_voice_frame(pipes.worker_out, VoiceResponse(
            id="r", ref_id=req.id, ok=True, payload=_default_handshake_payload(),
        ))

    threading.Thread(target=worker, daemon=True).start()
    config = VoiceConfig(engine="nemotron", language="de", tts_voice="bf_emma", barge_in=True)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    build_desktop_voice_services(config, connection=conn, auto_connect=True)
    assert seen[0].config == VoiceWorkerConfig.from_voice_config(config)
    conn.close()


# ---------------------------------------------------------------------------
# Frame limits, sender robustness, session-end epoch
# ---------------------------------------------------------------------------


def _recording_responder(pipes: PipeTransport, texts: List[str]) -> None:
    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, (OutputEnqueueRequest, OutputUtteranceEnqueueRequest)):
            texts.append(req.text)
        if isinstance(req, OutputUtteranceEndRequest):
            write_voice_frame(p.worker_out, UtteranceCompletedEvent(
                id=_new_id(), session_id=req.session_id, played_to_end=True,
            ))
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)


def test_oversized_sentence_is_split_and_later_sentences_still_arrive(pipes):
    texts: List[str] = []
    _recording_responder(pipes, texts)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    service = DesktopVoiceOutputService(conn, VoiceConfig())
    long_sentence = "word " * 20_000

    service.enqueue(long_sentence)
    service.enqueue("short sentence")

    assert _wait_for(lambda: texts and texts[-1] == "short sentence")
    assert "".join(texts[:-1]) == long_sentence
    assert conn._pending == {}
    conn.close()


def test_sender_survives_a_request_that_cannot_be_sent(pipes):
    texts: List[str] = []
    _recording_responder(pipes, texts)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    service = DesktopVoiceOutputService(conn, VoiceConfig())
    conn.connect()
    failed = threading.Event()

    service._post(OutputEnqueueRequest(id=_new_id(), text="x" * 70_000, epoch=0), on_failure=failed.set)
    service._post(OutputEnqueueRequest(id=_new_id(), text="after", epoch=0))

    assert failed.wait(2.0)
    assert _wait_for(lambda: texts == ["after"])
    assert conn._pending == {}
    conn.close()


def test_speaking_text_longer_than_a_frame_plays_it_all(pipes):
    texts: List[str] = []
    _recording_responder(pipes, texts)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    service = DesktopVoiceOutputService(conn, VoiceConfig())
    reply = "sentence. " * 10_000

    speaker = threading.Thread(target=service.speak, args=(reply,))
    speaker.start()
    speaker.join(5.0)

    assert not speaker.is_alive()  # returned once the worker reported completion
    assert "".join(texts) == reply
    conn.close()


def test_worker_exit_advances_the_epoch_before_any_respawn(pipes):
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    output = DesktopVoiceOutputService(conn, VoiceConfig())
    conn.subscribe(InputPartialEvent, lambda event: time.sleep(1.0))  # a busy UI thread
    _start_responder(pipes)
    conn.connect()
    before = output.current_epoch()
    write_voice_frame(pipes.worker_out, InputPartialEvent(id=_new_id(), text="hi"))
    time.sleep(0.1)  # the dispatcher is now inside the slow subscriber

    pipes.worker_out.close()  # the worker exits

    assert _wait_for(lambda: output.current_epoch() == before + 1, 0.5)
    conn.close()
