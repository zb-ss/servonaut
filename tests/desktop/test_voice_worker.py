"""Unit tests for the companion voice worker daemon.

Verifies the stdio protocol loop, handshake gate and settings hand-over,
configure-driven service rebuilds, per-request overrides, epoch translation
at the IPC boundary, ordered lanes for slow handlers, utterance session
tracking, conversation bridging, version skew handling, and clean exit on
EOF and on SIGTERM.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Callable, List, Optional

import pytest

import servonaut
from servonaut.config.schema import VoiceConfig
from servonaut.desktop.voice.protocol import (
    VOICE_PROTOCOL_VERSION,
    ConfigureRequest,
    ConversationInterruptRequest,
    ConversationSignalRequest,
    ConversationStartRequest,
    ConversationStateEvent,
    ConversationStopRequest,
    ConversationStoppedEvent,
    HandshakeRequest,
    HandshakeResponsePayload,
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
    ShutdownRequest,
    UtteranceCompletedEvent,
    VoiceErrorCode,
    VoiceMessage,
    VoiceRequest,
    VoiceResponse,
    VoiceWorkerConfig,
    WorkerErrorEvent,
    decode_voice_message,
    encode_voice_message,
    read_voice_frame,
)
from servonaut.desktop.voice.worker import VoiceServiceFactory, VoiceWorker
from servonaut.services import voice_engines
from servonaut.services.interfaces import (
    VoiceConversationServiceInterface,
    VoiceInputServiceInterface,
    VoiceOutputServiceInterface,
)

SRC_ROOT = Path(servonaut.__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class MockInputService(VoiceInputServiceInterface):
    def __init__(self, config: VoiceConfig) -> None:
        self.config = config
        self._available = True
        self._unavailable_reason = ""
        self._recording = False
        self._transcript = "test transcription"
        self._partial_cb: Optional[Callable[[str], None]] = None
        self._endpoint_cb: Optional[Callable[[], None]] = None
        self.budget_resets = 0
        self.cancels = 0
        self.start_gate: Optional[threading.Event] = None

    def is_available(self) -> bool:
        return self._available

    def unavailable_reason(self) -> str:
        return self._unavailable_reason

    def start_recording(self) -> None:
        if self.start_gate is not None:
            self.start_gate.wait(5)
        self._recording = True

    def stop_and_transcribe(self, initial_prompt: str = "") -> str:
        self._recording = False
        return self._transcript

    def cancel_recording(self) -> None:
        self.cancels += 1
        self._recording = False

    @property
    def is_recording(self) -> bool:
        return self._recording

    @property
    def hit_recording_cap(self) -> bool:
        return False

    def set_partial_callback(self, cb: Optional[Callable[[str], None]]) -> None:
        self._partial_cb = cb

    def set_endpoint_callback(self, cb: Optional[Callable[[], None]]) -> None:
        self._endpoint_cb = cb

    def set_frame_callback(self, cb: Optional[Callable[[Any], None]]) -> None:
        pass

    def reset_recording_budget(self) -> None:
        self.budget_resets += 1


class MockUtteranceSession:
    def __init__(self, on_complete: Optional[Callable[[bool], None]]) -> None:
        self.on_complete = on_complete
        self.enqueued: List[str] = []

    def enqueue(self, text: str) -> None:
        self.enqueued.append(text)

    def end(self) -> None:
        if self.on_complete is not None:
            self.on_complete(True)


class MockOutputService(VoiceOutputServiceInterface):
    """Epoch semantics of the real service: a stale epoch drops the call."""

    def __init__(self, config: VoiceConfig) -> None:
        self.config = config
        self._available = True
        self._unavailable_reason = ""
        self._epoch = 5  # deliberately unrelated to the parent's numbering
        self.spoken_texts: List[str] = []
        self.enqueued_texts: List[str] = []
        self.stops = 0
        self.closed = False
        self.settle_immediately = False

    def is_available(self) -> bool:
        return self._available

    def unavailable_reason(self) -> str:
        return self._unavailable_reason

    def speak(self, text: str, *, epoch: Optional[int] = None) -> None:
        if epoch is None or epoch == self._epoch:
            self.spoken_texts.append(text)

    def enqueue(self, sentence: str, *, epoch: Optional[int] = None) -> None:
        if epoch is None or epoch == self._epoch:
            self.enqueued_texts.append(sentence)

    def begin_utterance(
        self,
        *,
        on_complete: Optional[Callable[[bool], None]] = None,
        epoch: Optional[int] = None,
    ) -> Any:
        session = MockUtteranceSession(on_complete)
        if self.settle_immediately and on_complete is not None:
            on_complete(False)  # born superseded: settles before returning
        return session

    def current_epoch(self) -> int:
        return self._epoch

    def stop(self) -> None:
        self.stops += 1
        self._epoch += 1

    def close(self) -> None:
        self.closed = True

    def is_speaking(self) -> bool:
        return False


class MockConversationService(VoiceConversationServiceInterface):
    def __init__(
        self,
        config: VoiceConfig,
        input_service: Callable[[], Any],
        output_service: Callable[[], Any],
    ) -> None:
        self.config = config
        self.input_provider = input_service
        self.output_provider = output_service
        self._state_cb: Optional[Callable[[Any], None]] = None
        self._stopped_cb: Optional[Callable[[str], None]] = None
        self.started = False
        self.stopped = False
        self.interrupted = False
        self.barge_in_at_start: Optional[bool] = None
        self.signals: List[str] = []

    @property
    def state(self) -> Any:
        return "idle"

    def start(self) -> None:
        self.started = True
        self.barge_in_at_start = self.config.barge_in
        if self._state_cb:
            self._state_cb("listening")

    def stop(self, *, join: bool = True) -> None:
        self.stopped = True
        if self._state_cb:
            self._state_cb("idle")
        if self._stopped_cb:
            self._stopped_cb("user")

    def interrupt(self) -> None:
        self.interrupted = True

    def reply_started(self) -> None:
        self.signals.append("reply_started")

    def reply_finished(self) -> None:
        self.signals.append("reply_finished")

    def speaking_started(self) -> None:
        self.signals.append("speaking_started")

    def speaking_finished(self) -> None:
        self.signals.append("speaking_finished")

    def set_state_callback(self, callback: Optional[Callable[[Any], None]]) -> None:
        self._state_cb = callback

    def set_transcript_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        pass

    def set_error_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        pass

    def set_stopped_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        self._stopped_cb = callback


class RecordingFactory(VoiceServiceFactory):
    """Builds fresh mocks and records every build."""

    def __init__(self) -> None:
        self.inputs: List[MockInputService] = []
        self.streaming_inputs: List[MockInputService] = []
        self.outputs: List[MockOutputService] = []
        self.conversations: List[MockConversationService] = []

    def build_input(self, config: VoiceConfig, *, streaming: bool) -> MockInputService:
        svc = MockInputService(config)
        (self.streaming_inputs if streaming else self.inputs).append(svc)
        return svc

    def build_output(self, config: VoiceConfig) -> MockOutputService:
        svc = MockOutputService(config)
        self.outputs.append(svc)
        return svc

    def build_conversation(
        self,
        config: VoiceConfig,
        *,
        input_service: Callable[[], Any],
        output_service: Callable[[], Any],
    ) -> MockConversationService:
        svc = MockConversationService(config, input_service, output_service)
        self.conversations.append(svc)
        return svc


class FrameSink:
    """Thread-safe stand-in for the worker's stdout: one write per frame."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._frames: List[bytes] = []

    def write(self, data: bytes) -> int:
        with self._lock:
            self._frames.append(bytes(data))
        return len(data)

    def flush(self) -> None:
        pass

    def messages(self) -> List[VoiceMessage]:
        with self._lock:
            frames = list(self._frames)
        return [decode_voice_message(frame) for frame in frames]


class WorkerHarness:
    """Drives a VoiceWorker's dispatcher directly and collects its output."""

    def __init__(self) -> None:
        self.sink = FrameSink()
        self.factory = RecordingFactory()
        self.worker = VoiceWorker(
            stdin=io.BytesIO(),
            stdout=self.sink,  # type: ignore[arg-type]
            manifest_id="test-manifest-1",
            service_factory=self.factory,
        )

    def execute(self, msg: VoiceRequest, *, timeout: float = 2.0) -> List[VoiceMessage]:
        """Dispatch *msg* and return every frame written until its response."""
        start = len(self.sink.messages())
        self.worker._dispatch(msg)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            written = self.sink.messages()[start:]
            if any(isinstance(m, VoiceResponse) and m.ref_id == msg.id for m in written):
                return written
            time.sleep(0.005)
        raise AssertionError(f"no response to {msg.name} within {timeout}s")

    def handshake(self, *, epoch: int = 0, **config: Any) -> HandshakeResponsePayload:
        results = self.execute(HandshakeRequest(
            id="hs", client_version="test", config=VoiceWorkerConfig(**config), epoch=epoch,
        ))
        return HandshakeResponsePayload.from_dict(_response(results).payload)

    @property
    def input_svc(self) -> MockInputService:
        return self.factory.inputs[-1]

    @property
    def streaming_svc(self) -> MockInputService:
        return self.factory.streaming_inputs[-1]

    @property
    def output_svc(self) -> MockOutputService:
        return self.factory.outputs[-1]

    @property
    def conv_svc(self) -> MockConversationService:
        return self.factory.conversations[-1]


def _response(results: List[VoiceMessage]) -> VoiceResponse:
    responses = [m for m in results if isinstance(m, VoiceResponse)]
    assert len(responses) == 1, results
    return responses[0]


def _events(results: List[VoiceMessage], kind: type) -> List[Any]:
    return [m for m in results if isinstance(m, kind)]


# ---------------------------------------------------------------------------
# Handshake and settings
# ---------------------------------------------------------------------------


class TestHandshakeGate:
    def test_unhandshaken_request_rejected(self) -> None:
        res = _response(WorkerHarness().execute(ProbeRequest(id="req-1")))
        assert res.ok is False
        assert res.error is not None and res.error.code == VoiceErrorCode.NOT_HANDSHAKEN

    def test_ping_allowed_before_handshake(self) -> None:
        res = _response(WorkerHarness().execute(PingRequest(id="ping-1")))
        assert res.ok is True and res.payload.get("status") == "pending"

    def test_shutdown_allowed_before_handshake(self) -> None:
        h = WorkerHarness()
        res = _response(h.execute(ShutdownRequest(id="shut-1", reason="client_close")))
        assert res.ok is True and res.payload.get("ack") is True
        assert h.worker._shutdown is True

    def test_handshake_version_mismatch_rejected(self) -> None:
        res = _response(WorkerHarness().execute(
            HandshakeRequest(id="hs-bad", client_version="0.8.0", protocol_version=999)
        ))
        assert res.error is not None and res.error.code == VoiceErrorCode.UNSUPPORTED_VERSION

    def test_valid_handshake_reports_the_product_version(self) -> None:
        h = WorkerHarness()
        payload = h.handshake()
        assert payload.protocol_version == VOICE_PROTOCOL_VERSION
        assert payload.worker_version == servonaut.__version__
        assert payload.manifest_id == "test-manifest-1"
        assert "stt_batch" in payload.capabilities
        assert h.worker._handshaken is True


class TestSettingsHandOver:
    def test_services_are_built_from_the_handshake_settings(self) -> None:
        h = WorkerHarness()
        h.handshake(language="de", input_device="USB mic", tts_voice="bm_george", tts_speed=1.5)
        h.execute(ProbeRequest(id="pr"))
        assert h.input_svc.config.language == "de"
        assert h.input_svc.config.input_device == "USB mic"
        assert h.output_svc.config.tts_voice == "bm_george"
        assert h.output_svc.config.tts_speed == 1.5

    def test_configure_updates_live_settings_without_a_rebuild(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ProbeRequest(id="pr"))
        output = h.output_svc

        res = _response(h.execute(ConfigureRequest(
            id="cfg", config=VoiceWorkerConfig(tts_speed=1.25, language="fr"),
        )))

        assert res.ok is True
        assert h.output_svc is output
        assert output.config.tts_speed == 1.25
        assert h.input_svc.config.language == "fr"

    def test_configure_rebuilds_services_whose_model_changed(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ProbeRequest(id="pr"))
        old_input, old_output = h.input_svc, h.output_svc

        h.execute(ConfigureRequest(
            id="cfg", config=VoiceWorkerConfig(model_size="base", output_device="HDMI"),
        ))
        h.execute(ProbeRequest(id="pr-2"))

        assert old_input.cancels == 1
        assert old_output.closed is True
        assert h.input_svc is not old_input and h.input_svc.config.model_size == "base"
        assert h.output_svc is not old_output and h.output_svc.config.output_device == "HDMI"

    def test_request_max_seconds_caps_the_recording(self) -> None:
        h = WorkerHarness()
        h.handshake(max_recording_seconds=60)
        h.execute(InputStartRequest(id="in", max_seconds=12.5))
        assert h.input_svc.config.max_recording_seconds == 13

    def test_request_barge_in_reaches_the_loop(self) -> None:
        h = WorkerHarness()
        h.handshake(barge_in=False)
        h.execute(ConversationStartRequest(id="c", barge_in=True))
        assert h.conv_svc.barge_in_at_start is True

    @pytest.mark.parametrize(("engine", "streaming"), [("whisper", False), ("nemotron", True)])
    def test_conversation_listens_with_the_configured_engine(self, engine: str, streaming: bool) -> None:
        h = WorkerHarness()
        h.handshake(engine=engine)
        h.execute(ConversationStartRequest(id="c"))
        capture = h.conv_svc.input_provider()
        expected = h.streaming_svc if streaming else h.input_svc
        assert capture is expected


class TestModelsStatus:
    def test_status_comes_from_the_engine_path_helpers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(voice_engines, "VOICE_MODEL_ROOT", tmp_path)
        monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path / "hub"))
        kokoro = voice_engines.kokoro_model_dir()
        for name in voice_engines.KOKORO_REQUIRED_FILES:
            (kokoro / name).parent.mkdir(parents=True, exist_ok=True)
            (kokoro / name).write_bytes(b"x")
        nemotron = voice_engines.nemotron_model_dir(160)
        nemotron.mkdir(parents=True)
        for name in voice_engines.NEMOTRON_FILES.values():
            (nemotron / name).write_bytes(b"x")

        status = WorkerHarness().handshake(nemotron_latency_ms=160).models_status

        assert status == {"whisper": False, "nemotron": True, "kokoro": True, "silero": False}

    def test_models_root_flag_reaches_services_and_status(self, tmp_path: Path) -> None:
        kokoro = voice_engines.kokoro_model_dir(tmp_path)
        for name in voice_engines.KOKORO_REQUIRED_FILES:
            (kokoro / name).parent.mkdir(parents=True, exist_ok=True)
            (kokoro / name).write_bytes(b"x")
        code = (
            "import sys\n"
            "from servonaut.desktop.voice import worker\n"
            "from servonaut.services import voice_engines\n"
            "worker.run_worker = lambda **kw: print(voice_engines.voice_models_root(),"
            " voice_engines.is_kokoro_model_present()) or 0\n"
            f"sys.exit(worker.main(['--models-root', {str(tmp_path)!r}]))\n"
        )
        out = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
            env={**os.environ, "PYTHONPATH": str(SRC_ROOT)},
        )
        assert out.returncode == 0, out.stderr
        assert out.stdout.split() == [str(tmp_path), "True"]


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------


class TestInputFlow:
    def test_batch_start_stop_transcribe(self) -> None:
        h = WorkerHarness()
        h.handshake()
        assert _response(h.execute(InputStartRequest(id="in-1"))).ok is True
        assert h.input_svc.is_recording is True

        res = _response(h.execute(InputStopRequest(id="in-2", initial_prompt="prompt")))
        payload = InputStopResponsePayload.from_dict(res.payload)
        assert payload.text == "test transcription"
        assert h.input_svc.is_recording is False

    def test_input_start_when_unavailable_fails(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ProbeRequest(id="pr"))
        h.input_svc._available = False
        h.input_svc._unavailable_reason = "Microphone missing"
        res = _response(h.execute(InputStartRequest(id="in-1")))
        assert res.error is not None and res.error.code == VoiceErrorCode.AUDIO_DEVICE_ERROR

    def test_input_cancel(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(InputStartRequest(id="in-1"))
        assert _response(h.execute(InputCancelRequest(id="in-cancel"))).ok is True
        assert h.input_svc.is_recording is False

    def test_input_reset_budget(self) -> None:
        h = WorkerHarness()
        h.handshake()
        assert _response(h.execute(InputResetBudgetRequest(id="in-budget"))).ok is True
        assert h.input_svc.budget_resets == 1

    def test_streaming_input_emits_partials_and_endpoints(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(InputStartRequest(id="in-stream", streaming=True))
        start = len(h.sink.messages())
        h.streaming_svc._partial_cb("hello")  # type: ignore[misc]
        h.streaming_svc._endpoint_cb()  # type: ignore[misc]
        events = h.sink.messages()[start:]
        assert isinstance(events[0], InputPartialEvent) and events[0].text == "hello"
        assert isinstance(events[1], InputEndpointEvent)


class TestLanes:
    def test_slow_start_does_not_block_the_main_loop(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ProbeRequest(id="pr"))
        gate = threading.Event()
        h.input_svc.start_gate = gate

        h.worker._dispatch(InputStartRequest(id="slow-start"))
        assert _response(h.execute(PingRequest(id="ping"))).ok is True
        gate.set()

    def test_cancel_sent_after_a_slow_start_runs_after_it(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ProbeRequest(id="pr"))
        gate = threading.Event()
        h.input_svc.start_gate = gate

        h.worker._dispatch(InputStartRequest(id="slow-start"))
        h.worker._dispatch(InputCancelRequest(id="cancel"))
        time.sleep(0.05)
        assert h.input_svc.cancels == 0  # still queued behind the start
        gate.set()
        deadline = time.monotonic() + 2
        while h.input_svc.cancels == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert h.input_svc.cancels == 1
        assert h.input_svc.is_recording is False


# ---------------------------------------------------------------------------
# Output and epochs
# ---------------------------------------------------------------------------


class TestOutputFlow:
    def test_output_speak(self) -> None:
        h = WorkerHarness()
        h.handshake()
        results = h.execute(OutputSpeakRequest(id="speak-1", text="Hello world", epoch=0))
        states = _events(results, OutputStateEvent)
        assert [s.is_speaking for s in states] == [True, False]
        payload = OutputSpeakResponsePayload.from_dict(_response(results).payload)
        assert payload.completed is True
        assert h.output_svc.spoken_texts == ["Hello world"]

    def test_output_enqueue(self) -> None:
        h = WorkerHarness()
        h.handshake()
        assert _response(h.execute(OutputEnqueueRequest(id="enq-1", text="Queued", epoch=0))).ok
        assert h.output_svc.enqueued_texts == ["Queued"]

    def test_streamed_utterance_session_lifecycle(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(OutputUtteranceBeginRequest(id="ub-1", session_id="sess-100", epoch=0))
        assert "sess-100" in h.worker._active_utterance_sessions
        assert _response(h.execute(
            OutputUtteranceEnqueueRequest(id="ub-2", session_id="sess-100", text="chunk 1")
        )).ok
        results = h.execute(OutputUtteranceEndRequest(id="ub-3", session_id="sess-100"))
        completed = _events(results, UtteranceCompletedEvent)
        assert [(e.session_id, e.played_to_end) for e in completed] == [("sess-100", True)]
        assert h.worker._active_utterance_sessions == {}

    def test_output_stop_and_close(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ProbeRequest(id="pr"))
        output = h.output_svc
        assert _response(h.execute(OutputStopRequest(id="stop-1", epoch=1))).ok
        assert output.stops == 1
        assert _response(h.execute(OutputCloseRequest(id="close-1"))).ok
        assert output.closed is True


class TestEpochTranslation:
    def test_stop_before_the_worker_existed_does_not_drop_later_speech(self) -> None:
        # The parent stopped playback (epoch 0 -> 1) before this worker ran.
        h = WorkerHarness()
        h.handshake(epoch=1)
        results = h.execute(OutputSpeakRequest(id="s", text="first reply", epoch=1))
        assert OutputSpeakResponsePayload.from_dict(_response(results).payload).completed is True
        assert h.output_svc.spoken_texts == ["first reply"]

        h.execute(OutputStopRequest(id="stop", epoch=2))
        h.execute(OutputSpeakRequest(id="s2", text="second reply", epoch=2))
        assert h.output_svc.spoken_texts == ["first reply", "second reply"]

    def test_stale_speech_reports_not_completed(self) -> None:
        h = WorkerHarness()
        h.handshake(epoch=3)
        results = h.execute(OutputSpeakRequest(id="s", text="old", epoch=2))
        payload = OutputSpeakResponsePayload.from_dict(_response(results).payload)
        assert payload.completed is False
        assert payload.epoch == 3
        assert h.output_svc.spoken_texts == []
        assert _events(results, OutputStateEvent) == []

    def test_parent_epoch_ahead_catches_the_worker_up(self) -> None:
        h = WorkerHarness()
        h.handshake(epoch=0)
        h.execute(OutputEnqueueRequest(id="e", text="new turn", epoch=4))
        assert h.output_svc.stops == 1
        assert h.output_svc.enqueued_texts == ["new turn"]

    def test_only_a_newer_stop_stops_playback(self) -> None:
        h = WorkerHarness()
        h.handshake(epoch=0)
        h.execute(OutputEnqueueRequest(id="e", text="new turn", epoch=3))  # catches up: one stop
        assert h.output_svc.stops == 1

        h.execute(OutputStopRequest(id="stale", epoch=3))  # already accounted for
        assert h.output_svc.stops == 1
        assert h.output_svc.enqueued_texts == ["new turn"]

        h.execute(OutputStopRequest(id="newer", epoch=4))
        h.execute(OutputStopRequest(id="unpinned", epoch=None))
        assert h.output_svc.stops == 3

    def test_stale_utterance_completes_without_being_tracked(self) -> None:
        h = WorkerHarness()
        h.handshake(epoch=7)
        for index in range(3):
            results = h.execute(
                OutputUtteranceBeginRequest(id=f"b{index}", session_id=f"s{index}", epoch=6)
            )
            assert [e.played_to_end for e in _events(results, UtteranceCompletedEvent)] == [False]
        assert h.worker._active_utterance_sessions == {}

    def test_session_superseded_at_birth_is_not_leaked(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ProbeRequest(id="pr"))
        h.output_svc.settle_immediately = True
        results = h.execute(OutputUtteranceBeginRequest(id="b", session_id="born-dead", epoch=0))
        assert [e.played_to_end for e in _events(results, UtteranceCompletedEvent)] == [False]
        assert h.worker._active_utterance_sessions == {}


# ---------------------------------------------------------------------------
# Conversation
# ---------------------------------------------------------------------------


class TestConversationFlow:
    def test_conversation_start_stop(self) -> None:
        h = WorkerHarness()
        h.handshake()
        results = h.execute(ConversationStartRequest(id="c-start"))
        assert _response(results).ok
        assert [e.new_state for e in _events(results, ConversationStateEvent)] == ["listening"]

        results = h.execute(ConversationStopRequest(id="c-stop", reason="user"))
        assert [e.reason for e in _events(results, ConversationStoppedEvent)] == ["user"]

    def test_conversation_signals(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ConversationStartRequest(id="c-start"))
        h.execute(ConversationSignalRequest(id="sig-1", signal="reply_started"))
        h.execute(ConversationSignalRequest(id="sig-2", signal="speaking_started"))
        assert h.conv_svc.signals == ["reply_started", "speaking_started"]

    def test_conversation_interrupt(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ConversationStartRequest(id="c-start"))
        assert _response(h.execute(ConversationInterruptRequest(id="c-int"))).ok
        assert h.conv_svc.interrupted is True


# ---------------------------------------------------------------------------
# Main loop, skew and exit
# ---------------------------------------------------------------------------


def _run_worker_over(frames: bytes) -> List[VoiceMessage]:
    sink = FrameSink()
    worker = VoiceWorker(
        stdin=io.BytesIO(frames), stdout=sink, service_factory=RecordingFactory(),  # type: ignore[arg-type]
    )
    assert worker.run() == 0
    return sink.messages()


class TestMainLoop:
    def test_handles_messages_until_clean_eof(self) -> None:
        hs = HandshakeRequest(id="hs-1", client_version="test")
        messages = _run_worker_over(encode_voice_message(hs) + encode_voice_message(PingRequest(id="p-1")))
        assert [m.ref_id for m in messages if isinstance(m, VoiceResponse)] == ["hs-1", "p-1"]

    def test_hostile_integer_frame_is_survived(self) -> None:
        hostile = (
            '{"version": %d, "msg_type": "request", "id": "x", "name": "output_stop", '
            '"payload": {"epoch": %s}}\n' % (VOICE_PROTOCOL_VERSION, "9" * 5000)
        ).encode()
        messages = _run_worker_over(hostile + encode_voice_message(PingRequest(id="after")))
        assert isinstance(messages[0], WorkerErrorEvent)
        assert messages[0].code is VoiceErrorCode.PROTOCOL_VIOLATION
        assert isinstance(messages[1], VoiceResponse) and messages[1].ref_id == "after"

    def test_request_from_another_protocol_version_is_answered(self) -> None:
        foreign = b'{"version": 1, "msg_type": "request", "id": "old-hs", "name": "handshake", "payload": {}}\n'
        messages = _run_worker_over(foreign)
        assert len(messages) == 1
        res = messages[0]
        assert isinstance(res, VoiceResponse) and res.ref_id == "old-hs" and res.ok is False
        assert res.error is not None and res.error.code is VoiceErrorCode.UNSUPPORTED_VERSION

    def test_unreadable_input_ends_the_loop_like_eof(self) -> None:
        class ClosedInput(io.RawIOBase):
            def readable(self) -> bool:
                return True

            def readinto(self, buffer: Any) -> int:
                raise ValueError("I/O operation on closed file")

        factory = RecordingFactory()
        worker = VoiceWorker(stdin=ClosedInput(), stdout=FrameSink(), service_factory=factory)  # type: ignore[arg-type]
        worker._dispatch(HandshakeRequest(id="hs", client_version="t"))
        worker._dispatch(ProbeRequest(id="pr"))
        time.sleep(0.05)
        assert worker.run() == 0
        assert factory.outputs[-1].closed is True  # the teardown ran

    def test_nothing_is_written_after_teardown(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.worker.teardown()
        before = len(h.sink.messages())
        h.worker._send(PingRequest(id="late"))  # e.g. a speak thread finishing late
        assert len(h.sink.messages()) == before

    def test_teardown_releases_every_service(self) -> None:
        h = WorkerHarness()
        h.handshake()
        h.execute(ProbeRequest(id="pr"))
        h.execute(InputStartRequest(id="in"))
        h.execute(ConversationStartRequest(id="c"))
        h.worker.teardown()
        assert h.input_svc.is_recording is False
        assert h.output_svc.closed is True
        assert h.conv_svc.stopped is True


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal delivery")
class TestSignals:
    @pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
    def test_signal_ends_a_worker_blocked_on_stdin(self, signum: int) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-m", "servonaut.desktop.voice.worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONPATH": str(SRC_ROOT)},
        )
        try:
            proc.stdin.write(encode_voice_message(PingRequest(id="ready")))  # type: ignore[union-attr]
            proc.stdin.flush()  # type: ignore[union-attr]
            assert isinstance(read_voice_frame(proc.stdout), VoiceResponse)  # type: ignore[arg-type]
            proc.send_signal(signum)
            assert proc.wait(timeout=10) == 0
            assert b"tearing down" in proc.stderr.read()  # type: ignore[union-attr]
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()
