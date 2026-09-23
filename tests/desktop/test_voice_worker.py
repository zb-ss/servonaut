"""Comprehensive unit tests for the companion voice worker daemon.

Verifies the stdio protocol loop, handshake gate, local audio/transcription
dispatch, speech synthesis, utterance session tracking, conversation loop
bridging, error handling, and clean shutdown.
"""

from __future__ import annotations

import io
import time
from typing import Any, Callable, Dict, List, Optional
import pytest

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
    VoiceEvent,
    VoiceMessage,
    VoiceRequest,
    VoiceResponse,
    WorkerErrorEvent,
    decode_voice_message,
    encode_voice_message,
    read_voice_frame,
    write_voice_frame,
)
from servonaut.desktop.voice.worker import VoiceWorker
from servonaut.services.interfaces import (
    VoiceConversationServiceInterface,
    VoiceInputServiceInterface,
    VoiceOutputServiceInterface,
)


# ---------------------------------------------------------------------------
# Test Mocks
# ---------------------------------------------------------------------------

class MockInputService(VoiceInputServiceInterface):
    def __init__(self, available: bool = True, unavailable_reason: str = "") -> None:
        self._available = available
        self._unavailable_reason = unavailable_reason
        self._recording = False
        self._hit_cap = False
        self._transcript = "test transcription"
        self._partial_cb: Optional[Callable[[str], None]] = None
        self._endpoint_cb: Optional[Callable[[], None]] = None
        self._frame_cb: Optional[Callable[[Any], None]] = None
        self.budget_resets = 0

    def is_available(self) -> bool:
        return self._available

    def unavailable_reason(self) -> str:
        return self._unavailable_reason

    def start_recording(self) -> None:
        if self._recording:
            raise RuntimeError("Already recording")
        self._recording = True

    def stop_and_transcribe(self, initial_prompt: str = "") -> str:
        self._recording = False
        return self._transcript

    def cancel_recording(self) -> None:
        self._recording = False

    @property
    def is_recording(self) -> bool:
        return self._recording

    @property
    def hit_recording_cap(self) -> bool:
        return self._hit_cap

    def set_partial_callback(self, cb: Optional[Callable[[str], None]]) -> None:
        self._partial_cb = cb

    def set_endpoint_callback(self, cb: Optional[Callable[[], None]]) -> None:
        self._endpoint_cb = cb

    def set_frame_callback(self, cb: Optional[Callable[[Any], None]]) -> None:
        self._frame_cb = cb

    def reset_recording_budget(self) -> None:
        self.budget_resets += 1


class MockUtteranceSession:
    def __init__(self, on_complete: Optional[Callable[[bool], None]], epoch: Optional[int]) -> None:
        self.on_complete = on_complete
        self.epoch = epoch
        self.enqueued: List[str] = []
        self.ended = False

    def enqueue(self, text: str) -> None:
        self.enqueued.append(text)

    def end(self) -> None:
        self.ended = True
        if self.on_complete is not None:
            self.on_complete(True)


class MockOutputService(VoiceOutputServiceInterface):
    def __init__(self, available: bool = True, unavailable_reason: str = "") -> None:
        self._available = available
        self._unavailable_reason = unavailable_reason
        self._epoch = 1
        self._speaking = False
        self.spoken_texts: List[str] = []
        self.enqueued_texts: List[str] = []
        self.sessions: List[MockUtteranceSession] = []
        self.closed = False

    def is_available(self) -> bool:
        return self._available

    def unavailable_reason(self) -> str:
        return self._unavailable_reason

    def speak(self, text: str, *, epoch: Optional[int] = None) -> None:
        self.spoken_texts.append(text)

    def enqueue(self, sentence: str, *, epoch: Optional[int] = None) -> None:
        self.enqueued_texts.append(sentence)

    def begin_utterance(
        self,
        *,
        on_complete: Optional[Callable[[bool], None]] = None,
        epoch: Optional[int] = None,
    ) -> Any:
        sess = MockUtteranceSession(on_complete=on_complete, epoch=epoch)
        self.sessions.append(sess)
        return sess

    def current_epoch(self) -> int:
        return self._epoch

    def stop(self) -> None:
        self._speaking = False
        self._epoch += 1

    def close(self) -> None:
        self.closed = True

    def is_speaking(self) -> bool:
        return self._speaking


class MockConversationService(VoiceConversationServiceInterface):
    def __init__(self) -> None:
        self._state = "idle"
        self._state_cb: Optional[Callable[[Any], None]] = None
        self._transcript_cb: Optional[Callable[[str], None]] = None
        self._error_cb: Optional[Callable[[str], None]] = None
        self._stopped_cb: Optional[Callable[[str], None]] = None
        self.started = False
        self.stopped = False
        self.interrupted = False
        self.signals: List[str] = []

    @property
    def state(self) -> Any:
        return self._state

    def start(self) -> None:
        self.started = True
        self._state = "listening"
        if self._state_cb:
            self._state_cb("listening")

    def stop(self, *, join: bool = True) -> None:
        self.stopped = True
        self._state = "idle"
        if self._state_cb:
            self._state_cb("idle")
        if self._stopped_cb:
            self._stopped_cb("user")

    def interrupt(self) -> None:
        self.interrupted = True
        self._state = "listening"
        if self._state_cb:
            self._state_cb("listening")

    def reply_started(self) -> None:
        self.signals.append("reply_started")
        self._state = "thinking"
        if self._state_cb:
            self._state_cb("thinking")

    def reply_finished(self) -> None:
        self.signals.append("reply_finished")
        self._state = "listening"
        if self._state_cb:
            self._state_cb("listening")

    def speaking_started(self) -> None:
        self.signals.append("speaking_started")
        self._state = "speaking"
        if self._state_cb:
            self._state_cb("speaking")

    def speaking_finished(self) -> None:
        self.signals.append("speaking_finished")
        self._state = "listening"
        if self._state_cb:
            self._state_cb("listening")

    def set_state_callback(self, callback: Optional[Callable[[Any], None]]) -> None:
        self._state_cb = callback

    def set_transcript_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        self._transcript_cb = callback

    def set_error_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        self._error_cb = callback

    def set_stopped_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        self._stopped_cb = callback


# ---------------------------------------------------------------------------
# Test Harness
# ---------------------------------------------------------------------------

class WorkerHarness:
    """Helper that runs VoiceWorker over in-memory pipes."""

    def __init__(
        self,
        *,
        input_service: Optional[VoiceInputServiceInterface] = None,
        streaming_input_service: Optional[VoiceInputServiceInterface] = None,
        output_service: Optional[VoiceOutputServiceInterface] = None,
        conversation_service: Optional[VoiceConversationServiceInterface] = None,
    ) -> None:
        self.parent_to_worker = io.BytesIO()
        self.worker_to_parent = io.BytesIO()
        self.worker_err = io.StringIO()

        self.input_svc = input_service or MockInputService()
        self.streaming_svc = streaming_input_service or MockInputService()
        self.output_svc = output_service or MockOutputService()
        self.conv_svc = conversation_service or MockConversationService()

        self.worker = VoiceWorker(
            stdin=self.parent_to_worker,
            stdout=self.worker_to_parent,
            stderr=self.worker_err,
            manifest_id="test-manifest-1",
            input_service=self.input_svc,
            streaming_input_service=self.streaming_svc,
            output_service=self.output_svc,
            conversation_service=self.conv_svc,
        )

    def execute(self, msg: VoiceMessage) -> List[VoiceMessage]:
        """Dispatch a single message and collect written frames."""
        self.worker_to_parent.seek(0)
        self.worker_to_parent.truncate(0)
        self.worker._dispatch(msg)
        time.sleep(0.05)
        return self.read_all_responses_and_events()

    def read_all_responses_and_events(self) -> List[VoiceMessage]:
        self.worker_to_parent.seek(0)
        messages: List[VoiceMessage] = []
        while True:
            msg = read_voice_frame(self.worker_to_parent)
            if msg is None:
                break
            messages.append(msg)
        return messages


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

class TestHandshakeGate:
    """Verify that requests require handshake first, with ping/shutdown as exceptions."""

    def test_unhandshaken_request_rejected(self) -> None:
        h = WorkerHarness()
        results = h.execute(ProbeRequest(id="req-1"))
        assert len(results) == 1
        res = results[0]
        assert isinstance(res, VoiceResponse)
        assert res.ref_id == "req-1"
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == VoiceErrorCode.NOT_HANDSHAKEN

    def test_ping_allowed_before_handshake(self) -> None:
        h = WorkerHarness()
        results = h.execute(PingRequest(id="ping-1"))
        assert len(results) == 1
        res = results[0]
        assert isinstance(res, VoiceResponse)
        assert res.ok is True
        assert res.payload.get("status") == "pending"

    def test_shutdown_allowed_before_handshake(self) -> None:
        h = WorkerHarness()
        results = h.execute(ShutdownRequest(id="shut-1"))
        assert len(results) == 1
        res = results[0]
        assert isinstance(res, VoiceResponse)
        assert res.ok is True
        assert res.payload.get("ack") is True

    def test_handshake_version_mismatch_rejected(self) -> None:
        h = WorkerHarness()
        bad_hs = HandshakeRequest(
            id="hs-bad",
            client_version="0.8.0",
            protocol_version=999,
        )
        results = h.execute(bad_hs)
        assert len(results) == 1
        res = results[0]
        assert isinstance(res, VoiceResponse)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == VoiceErrorCode.UNSUPPORTED_VERSION

    def test_valid_handshake_succeeds(self) -> None:
        h = WorkerHarness()
        hs = HandshakeRequest(
            id="hs-1",
            client_version="2.26.3",
            protocol_version=VOICE_PROTOCOL_VERSION,
        )
        results = h.execute(hs)
        assert len(results) == 1
        res = results[0]
        assert isinstance(res, VoiceResponse)
        assert res.ok is True
        payload = HandshakeResponsePayload.from_dict(res.payload)
        assert payload.protocol_version == VOICE_PROTOCOL_VERSION
        assert payload.manifest_id == "test-manifest-1"
        assert "stt_batch" in payload.capabilities
        assert h.worker._handshaken is True


class TestProbeRequest:
    """Verify probe returns input and output availability and reason."""

    def test_probe_returns_readiness(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True
        h.input_svc._available = True
        h.output_svc._available = False
        h.output_svc._unavailable_reason = "No output device"

        results = h.execute(ProbeRequest(id="pr-1"))
        assert len(results) == 1
        res = results[0]
        assert isinstance(res, VoiceResponse)
        assert res.ok is True
        payload = ProbeResponsePayload.from_dict(res.payload)
        assert payload.input_available is True
        assert payload.output_available is False
        assert payload.output_unavailable_reason == "No output device"


class TestInputFlow:
    """Verify batch and streaming voice input lifecycle."""

    def test_batch_start_stop_transcribe(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True
        h.input_svc._transcript = "transcribed text from mic"

        # Start
        res_start = h.execute(InputStartRequest(id="in-1", streaming=False))
        assert len(res_start) == 1
        assert res_start[0].ok is True
        assert h.input_svc.is_recording is True

        # Stop
        res_stop = h.execute(InputStopRequest(id="in-2", initial_prompt="prompt"))
        assert len(res_stop) == 1
        resp = res_stop[0]
        assert isinstance(resp, VoiceResponse)
        assert resp.ok is True
        payload = InputStopResponsePayload.from_dict(resp.payload)
        assert payload.text == "transcribed text from mic"
        assert payload.hit_cap is False
        assert h.input_svc.is_recording is False

    def test_input_start_when_unavailable_fails(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True
        h.input_svc._available = False
        h.input_svc._unavailable_reason = "Microphone missing"

        results = h.execute(InputStartRequest(id="in-1"))
        assert len(results) == 1
        assert results[0].ok is False
        assert results[0].error.code == VoiceErrorCode.AUDIO_DEVICE_ERROR

    def test_input_cancel(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True
        h.execute(InputStartRequest(id="in-1"))
        assert h.input_svc.is_recording is True

        results = h.execute(InputCancelRequest(id="in-cancel"))
        assert len(results) == 1
        assert results[0].ok is True
        assert h.input_svc.is_recording is False

    def test_input_reset_budget(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True
        results = h.execute(InputResetBudgetRequest(id="in-budget"))
        assert len(results) == 1
        assert results[0].ok is True
        assert h.input_svc.budget_resets == 1

    def test_streaming_input_emits_partials_and_endpoints(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True

        # Start streaming
        res = h.execute(InputStartRequest(id="in-stream", streaming=True))
        assert res[0].ok is True

        # Simulate partial callback fired by decoder
        cb = h.streaming_svc._partial_cb
        assert cb is not None

        # Reset output buffer to capture events
        h.worker_to_parent.seek(0)
        h.worker_to_parent.truncate(0)

        cb("hello")
        cb("hello world")

        # Simulate endpoint callback
        end_cb = h.streaming_svc._endpoint_cb
        assert end_cb is not None
        end_cb()

        events = h.read_all_responses_and_events()
        assert len(events) == 3
        assert isinstance(events[0], InputPartialEvent) and events[0].text == "hello"
        assert isinstance(events[1], InputPartialEvent) and events[1].text == "hello world"
        assert isinstance(events[2], InputEndpointEvent)


class TestOutputFlow:
    """Verify speech synthesis (speak, enqueue, utterance sessions, stop, close)."""

    def test_output_speak(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True

        results = h.execute(OutputSpeakRequest(id="speak-1", text="Hello world", epoch=2))
        assert len(results) == 3
        assert isinstance(results[0], OutputStateEvent) and results[0].is_speaking is True
        assert isinstance(results[1], OutputStateEvent) and results[1].is_speaking is False
        assert isinstance(results[2], VoiceResponse)
        resp = results[2]
        assert resp.ok is True
        payload = OutputSpeakResponsePayload.from_dict(resp.payload)
        assert payload.completed is True
        assert h.output_svc.spoken_texts == ["Hello world"]

    def test_output_enqueue(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True

        results = h.execute(OutputEnqueueRequest(id="enq-1", text="Queued sentence", epoch=1))
        assert len(results) == 1
        assert results[0].ok is True
        assert h.output_svc.enqueued_texts == ["Queued sentence"]

    def test_streamed_utterance_session_lifecycle(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True

        # Begin utterance
        res_begin = h.execute(
            OutputUtteranceBeginRequest(id="ub-1", session_id="sess-100", epoch=1)
        )
        assert len(res_begin) == 1
        assert res_begin[0].ok is True
        assert "sess-100" in h.worker._active_utterance_sessions

        # Enqueue chunk
        res_enq = h.execute(
            OutputUtteranceEnqueueRequest(id="ub-2", session_id="sess-100", text="chunk 1")
        )
        assert len(res_enq) == 1
        assert res_enq[0].ok is True

        # End utterance (triggers session end and on_complete callback)
        res_end = h.execute(OutputUtteranceEndRequest(id="ub-3", session_id="sess-100"))
        responses = [r for r in res_end if isinstance(r, VoiceResponse)]
        events = [r for r in res_end if isinstance(r, UtteranceCompletedEvent)]
        assert len(responses) == 1 and responses[0].ok is True
        assert len(events) == 1
        assert events[0].session_id == "sess-100"
        assert events[0].played_to_end is True

    def test_output_stop_and_close(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True

        res_stop = h.execute(OutputStopRequest(id="stop-1"))
        assert len(res_stop) == 1
        assert res_stop[0].ok is True
        assert h.output_svc.current_epoch() == 2

        res_close = h.execute(OutputCloseRequest(id="close-1"))
        assert len(res_close) == 1
        assert res_close[0].ok is True
        assert h.output_svc.closed is True


class TestConversationFlow:
    """Verify hands-free conversation loop controller bridging."""

    def test_conversation_start_stop(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True

        res_start = h.execute(ConversationStartRequest(id="c-start", barge_in=False))
        responses = [r for r in res_start if isinstance(r, VoiceResponse)]
        state_events = [r for r in res_start if isinstance(r, ConversationStateEvent)]
        assert len(responses) == 1 and responses[0].ok is True
        assert len(state_events) == 1
        assert state_events[0].new_state == "listening"

        # Stop
        res_stop = h.execute(ConversationStopRequest(id="c-stop", reason="user"))
        stopped_events = [r for r in res_stop if isinstance(r, ConversationStoppedEvent)]
        assert len(stopped_events) == 1
        assert stopped_events[0].reason == "user"

    def test_conversation_signals(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True
        h.execute(ConversationStartRequest(id="c-start"))

        h.execute(ConversationSignalRequest(id="sig-1", signal="reply_started"))
        assert "reply_started" in h.conv_svc.signals

        h.execute(ConversationSignalRequest(id="sig-2", signal="speaking_started"))
        assert "speaking_started" in h.conv_svc.signals

    def test_conversation_interrupt(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True
        h.execute(ConversationStartRequest(id="c-start"))

        res = h.execute(ConversationInterruptRequest(id="c-int"))
        responses = [r for r in res if isinstance(r, VoiceResponse)]
        assert len(responses) == 1 and responses[0].ok is True
        assert h.conv_svc.interrupted is True


class TestTeardownAndExit:
    """Verify orderly teardown on shutdown or EOF."""

    def test_teardown_cancels_active_streams(self) -> None:
        h = WorkerHarness()
        h.worker._handshaken = True
        h.input_svc._recording = True
        h.conv_svc.started = True

        h.worker.teardown()
        assert h.input_svc.is_recording is False
        assert h.output_svc.closed is True
        assert h.conv_svc.stopped is True

    def test_run_loop_handles_multiple_messages_and_clean_eof(self) -> None:
        h = WorkerHarness()
        # Feed handshake then ping, followed by EOF
        hs = HandshakeRequest(
            id="hs-1", client_version="2.26.3", protocol_version=VOICE_PROTOCOL_VERSION
        )
        ping = PingRequest(id="p-1")
        stream = io.BytesIO(encode_voice_message(hs) + encode_voice_message(ping))
        out_stream = io.BytesIO()

        worker = VoiceWorker(
            stdin=stream,
            stdout=out_stream,
            stderr=io.StringIO(),
            input_service=h.input_svc,
            output_service=h.output_svc,
            conversation_service=h.conv_svc,
        )
        assert worker.run() == 0

        out_stream.seek(0)
        res1 = read_voice_frame(out_stream)
        assert isinstance(res1, VoiceResponse) and res1.ref_id == "hs-1"
        res2 = read_voice_frame(out_stream)
        assert isinstance(res2, VoiceResponse) and res2.ref_id == "p-1"
        assert read_voice_frame(out_stream) is None
