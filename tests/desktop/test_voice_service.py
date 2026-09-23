"""Unit tests for parent-side Desktop Voice Service proxies."""

from __future__ import annotations

import logging
import os
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


def test_input_service_cancel_and_cap_hit(pipes):
    """Cancel recording resets state; CapHit event sets hit_recording_cap flag."""
    cancelled = []

    def on_request(req: VoiceRequest, p: PipeTransport):
        if isinstance(req, InputStartRequest):
            def emit_cap():
                time.sleep(0.05)
                write_voice_frame(p.worker_out, InputCapHitEvent(id=_new_id()))

            threading.Thread(target=emit_cap, daemon=True).start()
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

        if isinstance(req, InputCancelRequest):
            cancelled.append(True)
            return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})
        return VoiceResponse(id=f"resp-{req.id}", ref_id=req.id, ok=True, payload={})

    _start_responder(pipes, on_request)
    conn = VoiceConnection(stdin=pipes.parent_out, stdout=pipes.parent_in)
    config = VoiceConfig()
    service = DesktopVoiceInputService(conn, config)

    service.start_recording()
    deadline = time.time() + 2.0
    while not service.hit_recording_cap and time.time() < deadline:
        time.sleep(0.05)

    assert service.hit_recording_cap is True
    service.cancel_recording()
    assert service.is_recording is False

    time.sleep(0.1)
    assert cancelled == [True]
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
    assert len(stop_requests) == 1
    assert stop_requests[0] == service.current_epoch()

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
                        old_state="IDLE",
                        new_state="LISTENING",
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
            old_state="IDLE",
            new_state="LISTENING",
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
