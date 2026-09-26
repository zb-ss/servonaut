"""Comprehensive unit tests for the managed voice worker protocol.

Verifies protocol framing, typed request/response/event models, strict JSON
validation, error taxonomy, stream codecs, and error recovery.
"""

from __future__ import annotations

import io
import sys
import pytest

from servonaut.desktop.voice.protocol import (
    MAX_FRAME_BYTES,
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
    VoiceErrorPayload,
    VoiceMessage,
    VoiceProtocolEofError,
    VoiceProtocolError,
    VoiceResponse,
    WorkerErrorEvent,
    ConfigureRequest,
    VoiceFrameReader,
    VoiceProtocolVersionError,
    VoiceWorkerConfig,
    decode_voice_message,
    encode_voice_message,
    read_voice_frame,
    write_voice_frame,
)
from servonaut.config.schema import VoiceConfig


class TestPureStdlibBoundary:
    """Verify that protocol module does not import heavy audio or third-party packages."""

    def test_no_native_voice_imports(self) -> None:
        forbidden = [
            "sounddevice",
            "sherpa_onnx",
            "faster_whisper",
            "ctranslate2",
            "numpy",
            "torch",
        ]
        for mod in forbidden:
            assert mod not in sys.modules, f"Forbidden module {mod} was imported!"


class TestFramingCodec:
    """Verify line framing, length limits, null rejection, and stream behavior."""

    def test_encode_decode_roundtrip_simple(self) -> None:
        req = PingRequest(id="req-1")
        encoded = encode_voice_message(req)
        assert encoded.endswith(b"\n")
        assert not encoded.endswith(b"\r\n")
        decoded = decode_voice_message(encoded)
        assert isinstance(decoded, PingRequest)
        assert decoded.id == "req-1"
        assert decoded.name == "ping"

    def test_read_single_frame(self) -> None:
        req = ShutdownRequest(id="shut-1")
        data = encode_voice_message(req)
        stream = io.BytesIO(data)
        msg = read_voice_frame(stream)
        assert isinstance(msg, ShutdownRequest)
        assert msg.id == "shut-1"

    def test_read_multiple_frames_and_eof(self) -> None:
        req1 = PingRequest(id="1")
        req2 = ProbeRequest(id="2")
        stream = io.BytesIO(encode_voice_message(req1) + encode_voice_message(req2))

        m1 = read_voice_frame(stream)
        assert isinstance(m1, PingRequest)
        assert m1.id == "1"

        m2 = read_voice_frame(stream)
        assert isinstance(m2, ProbeRequest)
        assert m2.id == "2"

        # Clean EOF on line boundary
        assert read_voice_frame(stream) is None

    def test_crlf_line_endings_accepted(self) -> None:
        req = PingRequest(id="crlf-1")
        data = encode_voice_message(req).replace(b"\n", b"\r\n")
        stream = io.BytesIO(data)
        msg = read_voice_frame(stream)
        assert isinstance(msg, PingRequest)
        assert msg.id == "crlf-1"

    def test_mid_frame_eof_raises(self) -> None:
        stream = io.BytesIO((b'{"version": %d, "msg_type": "request"' % VOICE_PROTOCOL_VERSION))
        with pytest.raises(VoiceProtocolEofError, match="Stream closed mid-frame"):
            read_voice_frame(stream)

    def test_null_byte_in_stream_raises(self) -> None:
        stream = io.BytesIO((b'{"version": %d, "msg_type":\x00 "request"}\n' % VOICE_PROTOCOL_VERSION))
        with pytest.raises(VoiceProtocolError) as exc_info:
            read_voice_frame(stream)
        assert exc_info.value.code == VoiceErrorCode.PROTOCOL_VIOLATION
        assert "null byte" in exc_info.value.message.lower()

    def test_null_byte_in_decode_raises(self) -> None:
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message((b'{"version": %d, "msg_type": \x00 "ping"}\n' % VOICE_PROTOCOL_VERSION))
        assert exc_info.value.code == VoiceErrorCode.PROTOCOL_VIOLATION

    def test_oversized_frame_rejected_on_encode(self) -> None:
        # Prompt larger than MAX_FRAME_BYTES
        huge_prompt = "x" * (MAX_FRAME_BYTES + 100)
        req = InputStopRequest(id="huge-1", initial_prompt=huge_prompt)
        with pytest.raises(VoiceProtocolError) as exc_info:
            encode_voice_message(req)
        assert exc_info.value.code == VoiceErrorCode.PROTOCOL_VIOLATION
        assert "exceeds" in exc_info.value.message

    def test_oversized_frame_rejected_on_read(self) -> None:
        oversized = b"a" * (MAX_FRAME_BYTES + 10) + b"\n"
        stream = io.BytesIO(oversized)
        with pytest.raises(VoiceProtocolError) as exc_info:
            read_voice_frame(stream)
        assert exc_info.value.code == VoiceErrorCode.PROTOCOL_VIOLATION
        assert "exceeds maximum length" in exc_info.value.message

    def test_write_voice_frame_flushes(self) -> None:
        class MockStream(io.BytesIO):
            def __init__(self) -> None:
                super().__init__()
                self.flushed = False

            def flush(self) -> None:
                super().flush()
                self.flushed = True

        stream = MockStream()
        req = PingRequest(id="p1")
        write_voice_frame(stream, req)
        assert stream.flushed
        assert stream.getvalue() == encode_voice_message(req)


class TestJsonSafety:
    """Verify strict JSON parsing: duplicate keys, forbidden constants, and non-dicts."""

    def test_duplicate_keys_rejected(self) -> None:
        raw = (b'{"version": %d, "version": %d, "msg_type": "request", "id": "1", "name": "ping", "payload": {}}\n' % (VOICE_PROTOCOL_VERSION, VOICE_PROTOCOL_VERSION))
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message(raw)
        assert exc_info.value.code == VoiceErrorCode.PROTOCOL_VIOLATION
        assert "Duplicate key" in exc_info.value.message

    def test_nan_constant_rejected(self) -> None:
        raw = (b'{"version": %d, "msg_type": "request", "id": "1", "name": "input_start", "payload": {"max_seconds": NaN}}\n' % VOICE_PROTOCOL_VERSION)
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message(raw)
        assert exc_info.value.code == VoiceErrorCode.PROTOCOL_VIOLATION
        assert "Forbidden JSON constant" in exc_info.value.message

    def test_infinity_constant_rejected(self) -> None:
        raw = (b'{"version": %d, "msg_type": "request", "id": "1", "name": "input_start", "payload": {"max_seconds": Infinity}}\n' % VOICE_PROTOCOL_VERSION)
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message(raw)
        assert exc_info.value.code == VoiceErrorCode.PROTOCOL_VIOLATION

    def test_non_dict_root_rejected(self) -> None:
        raw = b'["version", 1]\n'
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message(raw)
        assert exc_info.value.code == VoiceErrorCode.PROTOCOL_VIOLATION

    def test_unsupported_protocol_version(self) -> None:
        raw = b'{"version": 999, "msg_type": "request", "id": "1", "name": "ping", "payload": {}}\n'
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message(raw)
        assert exc_info.value.code == VoiceErrorCode.UNSUPPORTED_VERSION


class TestRequestModelsRoundtrip:
    """Verify serialization and deserialization for all 19 request types."""

    def _roundtrip(self, req: VoiceMessage) -> VoiceMessage:
        data = encode_voice_message(req)
        return decode_voice_message(data)

    def test_handshake_request(self) -> None:
        req = HandshakeRequest(
            id="hs-1",
            client_version="0.8.0",
            protocol_version=VOICE_PROTOCOL_VERSION,
            capabilities_requested=("stt_batch", "stt_streaming", "tts"),
        )
        res = self._roundtrip(req)
        assert isinstance(res, HandshakeRequest)
        assert res.id == "hs-1"
        assert res.client_version == "0.8.0"
        assert res.protocol_version == VOICE_PROTOCOL_VERSION
        assert res.capabilities_requested == ("stt_batch", "stt_streaming", "tts")
        assert res.config == VoiceWorkerConfig()
        assert res.epoch == 0

    def test_probe_request(self) -> None:
        req = ProbeRequest(id="pr-1")
        res = self._roundtrip(req)
        assert isinstance(res, ProbeRequest)
        assert res.id == "pr-1"

    def test_input_start_request(self) -> None:
        req = InputStartRequest(id="in-1", streaming=True, max_seconds=45.5)
        res = self._roundtrip(req)
        assert isinstance(res, InputStartRequest)
        assert res.streaming is True
        assert res.max_seconds == 45.5

    def test_input_stop_request(self) -> None:
        req = InputStopRequest(id="in-2", initial_prompt="prod-cluster")
        res = self._roundtrip(req)
        assert isinstance(res, InputStopRequest)
        assert res.initial_prompt == "prod-cluster"

    def test_input_cancel_request(self) -> None:
        req = InputCancelRequest(id="in-3")
        res = self._roundtrip(req)
        assert isinstance(res, InputCancelRequest)

    def test_input_reset_budget_request(self) -> None:
        req = InputResetBudgetRequest(id="in-4")
        res = self._roundtrip(req)
        assert isinstance(res, InputResetBudgetRequest)

    def test_output_speak_request(self) -> None:
        req1 = OutputSpeakRequest(id="out-1", text="Hello world", epoch=None)
        res1 = self._roundtrip(req1)
        assert isinstance(res1, OutputSpeakRequest)
        assert res1.text == "Hello world"
        assert res1.epoch is None

        req2 = OutputSpeakRequest(id="out-2", text="Hello world 2", epoch=42)
        res2 = self._roundtrip(req2)
        assert isinstance(res2, OutputSpeakRequest)
        assert res2.epoch == 42

    def test_output_enqueue_request(self) -> None:
        req = OutputEnqueueRequest(id="out-3", text="Next sentence", epoch=12)
        res = self._roundtrip(req)
        assert isinstance(res, OutputEnqueueRequest)
        assert res.text == "Next sentence"
        assert res.epoch == 12

    def test_output_utterance_begin_request(self) -> None:
        req = OutputUtteranceBeginRequest(id="out-4", session_id="sess-abc", epoch=5)
        res = self._roundtrip(req)
        assert isinstance(res, OutputUtteranceBeginRequest)
        assert res.session_id == "sess-abc"
        assert res.epoch == 5

    def test_output_utterance_enqueue_request(self) -> None:
        req = OutputUtteranceEnqueueRequest(id="out-5", session_id="sess-abc", text="Chunk one")
        res = self._roundtrip(req)
        assert isinstance(res, OutputUtteranceEnqueueRequest)
        assert res.session_id == "sess-abc"
        assert res.text == "Chunk one"

    def test_output_utterance_end_request(self) -> None:
        req = OutputUtteranceEndRequest(id="out-6", session_id="sess-abc")
        res = self._roundtrip(req)
        assert isinstance(res, OutputUtteranceEndRequest)
        assert res.session_id == "sess-abc"

    def test_output_stop_request(self) -> None:
        req = OutputStopRequest(id="out-7", epoch=100)
        res = self._roundtrip(req)
        assert isinstance(res, OutputStopRequest)
        assert res.epoch == 100

    def test_output_close_request(self) -> None:
        req = OutputCloseRequest(id="out-8")
        res = self._roundtrip(req)
        assert isinstance(res, OutputCloseRequest)

    def test_conversation_start_request(self) -> None:
        req = ConversationStartRequest(id="conv-1", barge_in=True)
        res = self._roundtrip(req)
        assert isinstance(res, ConversationStartRequest)
        assert res.barge_in is True

    def test_conversation_stop_request(self) -> None:
        req = ConversationStopRequest(id="conv-2", reason="manual-stop")
        res = self._roundtrip(req)
        assert isinstance(res, ConversationStopRequest)
        assert res.reason == "manual-stop"

    def test_conversation_interrupt_request(self) -> None:
        req = ConversationInterruptRequest(id="conv-3")
        res = self._roundtrip(req)
        assert isinstance(res, ConversationInterruptRequest)

    def test_conversation_signal_request(self) -> None:
        req = ConversationSignalRequest(id="conv-4", signal="reply_started")
        res = self._roundtrip(req)
        assert isinstance(res, ConversationSignalRequest)
        assert res.signal == "reply_started"

    def test_ping_request(self) -> None:
        req = PingRequest(id="p-1")
        res = self._roundtrip(req)
        assert isinstance(res, PingRequest)

    def test_shutdown_request(self) -> None:
        req = ShutdownRequest(id="sd-1")
        res = self._roundtrip(req)
        assert isinstance(res, ShutdownRequest)
        assert res.reason == "client"

    def test_shutdown_request_carries_its_reason(self) -> None:
        res = self._roundtrip(ShutdownRequest(id="sd-2", reason="client_close"))
        assert isinstance(res, ShutdownRequest)
        assert res.reason == "client_close"

    def test_handshake_carries_config_and_epoch(self) -> None:
        config = VoiceWorkerConfig(engine="nemotron", input_device="USB mic", barge_in=True)
        res = self._roundtrip(HandshakeRequest(id="hs-2", client_version="x", config=config, epoch=7))
        assert isinstance(res, HandshakeRequest)
        assert res.config == config
        assert res.epoch == 7

    def test_configure_request(self) -> None:
        config = VoiceWorkerConfig(tts_voice="bf_emma", tts_speed=1.25, max_recording_seconds=90)
        res = self._roundtrip(ConfigureRequest(id="cfg-1", config=config))
        assert isinstance(res, ConfigureRequest)
        assert res.config == config


class TestResponseModelsRoundtrip:
    """Verify serialization and deserialization of responses and typed payloads."""

    def test_handshake_response_payload(self) -> None:
        payload = HandshakeResponsePayload(
            worker_version="0.8.0",
            protocol_version=1,
            manifest_id="mf-x86-v1",
            python_version="3.12.14",
            platform="linux",
            architecture="x86_64",
            capabilities=("stt_batch", "tts", "vad"),
            models_status={"whisper": True, "kokoro": True, "silero": False},
            audio_devices={"input_count": 2, "output_count": 1},
        )
        resp = VoiceResponse(
            id="resp-1",
            ref_id="hs-1",
            ok=True,
            payload=payload.to_dict(),
        )
        data = encode_voice_message(resp)
        decoded = decode_voice_message(data)
        assert isinstance(decoded, VoiceResponse)
        assert decoded.ref_id == "hs-1"
        assert decoded.ok is True
        assert decoded.error is None

        # Re-parse payload with typed helper
        parsed_payload = HandshakeResponsePayload.from_dict(decoded.payload)
        assert parsed_payload.worker_version == "0.8.0"
        assert parsed_payload.manifest_id == "mf-x86-v1"
        assert parsed_payload.capabilities == ("stt_batch", "tts", "vad")
        assert parsed_payload.models_status["silero"] is False
        assert parsed_payload.audio_devices["input_count"] == 2

    def test_probe_response_payload(self) -> None:
        payload = ProbeResponsePayload(
            input_available=True,
            input_unavailable_reason="",
            output_available=False,
            output_unavailable_reason="No audio output device found",
            devices={"default_input": "hw:0,0"},
        )
        resp = VoiceResponse(id="resp-2", ref_id="pr-1", ok=True, payload=payload.to_dict())
        data = encode_voice_message(resp)
        decoded = decode_voice_message(data)
        assert isinstance(decoded, VoiceResponse)

        parsed = ProbeResponsePayload.from_dict(decoded.payload)
        assert parsed.input_available is True
        assert parsed.output_available is False
        assert parsed.output_unavailable_reason == "No audio output device found"

    def test_input_stop_response_payload(self) -> None:
        payload = InputStopResponsePayload(text="transcribed voice text", hit_cap=True)
        resp = VoiceResponse(id="resp-3", ref_id="in-2", ok=True, payload=payload.to_dict())
        decoded = decode_voice_message(encode_voice_message(resp))
        assert isinstance(decoded, VoiceResponse)
        parsed = InputStopResponsePayload.from_dict(decoded.payload)
        assert parsed.text == "transcribed voice text"
        assert parsed.hit_cap is True

    def test_output_speak_response_payload(self) -> None:
        payload = OutputSpeakResponsePayload(completed=True, epoch=7)
        resp = VoiceResponse(id="resp-4", ref_id="out-1", ok=True, payload=payload.to_dict())
        decoded = decode_voice_message(encode_voice_message(resp))
        assert isinstance(decoded, VoiceResponse)
        parsed = OutputSpeakResponsePayload.from_dict(decoded.payload)
        assert parsed.completed is True
        assert parsed.epoch == 7

    def test_error_response_with_details(self) -> None:
        err = VoiceErrorPayload(
            code=VoiceErrorCode.AUDIO_DEVICE_ERROR,
            message="Microphone permission denied",
            details={"device_index": 0},
        )
        resp = VoiceResponse(
            id="resp-err",
            ref_id="in-1",
            ok=False,
            payload={},
            error=err,
        )
        data = encode_voice_message(resp)
        decoded = decode_voice_message(data)
        assert isinstance(decoded, VoiceResponse)
        assert decoded.ok is False
        assert decoded.error is not None
        assert decoded.error.code == VoiceErrorCode.AUDIO_DEVICE_ERROR
        assert decoded.error.message == "Microphone permission denied"
        assert decoded.error.details == {"device_index": 0}


class TestEventModelsRoundtrip:
    """Verify serialization and deserialization for all 10 asynchronous event types."""

    def _roundtrip(self, evt: VoiceMessage) -> VoiceMessage:
        return decode_voice_message(encode_voice_message(evt))

    def test_input_partial_event(self) -> None:
        evt = InputPartialEvent(id="ev-1", text="listening to sp...")
        res = self._roundtrip(evt)
        assert isinstance(res, InputPartialEvent)
        assert res.id == "ev-1"
        assert res.text == "listening to sp..."

    def test_input_endpoint_event(self) -> None:
        evt = InputEndpointEvent(id="ev-2")
        res = self._roundtrip(evt)
        assert isinstance(res, InputEndpointEvent)

    def test_input_cap_hit_event(self) -> None:
        evt = InputCapHitEvent(id="ev-3")
        res = self._roundtrip(evt)
        assert isinstance(res, InputCapHitEvent)

    def test_output_state_event(self) -> None:
        evt = OutputStateEvent(id="ev-4", is_speaking=True, current_epoch=8)
        res = self._roundtrip(evt)
        assert isinstance(res, OutputStateEvent)
        assert res.is_speaking is True
        assert res.current_epoch == 8

    def test_utterance_completed_event(self) -> None:
        evt = UtteranceCompletedEvent(id="ev-5", session_id="sess-xyz", played_to_end=True)
        res = self._roundtrip(evt)
        assert isinstance(res, UtteranceCompletedEvent)
        assert res.session_id == "sess-xyz"
        assert res.played_to_end is True

    def test_conversation_state_event(self) -> None:
        evt = ConversationStateEvent(id="ev-6", old_state="IDLE", new_state="LISTENING")
        res = self._roundtrip(evt)
        assert isinstance(res, ConversationStateEvent)
        assert res.old_state == "IDLE"
        assert res.new_state == "LISTENING"

    def test_conversation_transcript_event(self) -> None:
        evt = ConversationTranscriptEvent(id="ev-7", text="User utterance complete")
        res = self._roundtrip(evt)
        assert isinstance(res, ConversationTranscriptEvent)
        assert res.text == "User utterance complete"

    def test_conversation_error_event(self) -> None:
        evt = ConversationErrorEvent(
            id="ev-8", message="VAD timeout", code=VoiceErrorCode.CONVERSATION_ERROR
        )
        res = self._roundtrip(evt)
        assert isinstance(res, ConversationErrorEvent)
        assert res.message == "VAD timeout"
        assert res.code == VoiceErrorCode.CONVERSATION_ERROR

    def test_conversation_stopped_event(self) -> None:
        evt = ConversationStoppedEvent(id="ev-9", reason="user")
        res = self._roundtrip(evt)
        assert isinstance(res, ConversationStoppedEvent)
        assert res.reason == "user"

    def test_worker_error_event(self) -> None:
        evt = WorkerErrorEvent(
            id="ev-10",
            code=VoiceErrorCode.MODEL_LOAD_ERROR,
            message="Failed to load Kokoro TTS weights",
            fatal=True,
        )
        res = self._roundtrip(evt)
        assert isinstance(res, WorkerErrorEvent)
        assert res.code == VoiceErrorCode.MODEL_LOAD_ERROR
        assert res.message == "Failed to load Kokoro TTS weights"
        assert res.fatal is True


class TestValidationAndTypeStrictness:
    """Verify strict validation against type confusion and malformed payloads."""

    def test_bool_where_int_required_rejected(self) -> None:
        # In Python isinstance(True, int) is True, so check int rejection of bool
        raw = b'{"version": true, "msg_type": "request", "id": "1", "name": "ping", "payload": {}}\n'
        with pytest.raises(VoiceProtocolError):
            decode_voice_message(raw)

    def test_int_where_bool_required_rejected(self) -> None:
        raw = (b'{"version": %d, "msg_type": "request", "id": "1", "name": "input_start", "payload": {"streaming": 1}}\n' % VOICE_PROTOCOL_VERSION)
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message(raw)
        assert "must be bool" in exc_info.value.message

    def test_string_where_int_required_rejected(self) -> None:
        raw = b'{"version": "1", "msg_type": "request", "id": "1", "name": "ping", "payload": {}}\n'
        with pytest.raises(VoiceProtocolError):
            decode_voice_message(raw)

    def test_unknown_operation_rejected(self) -> None:
        raw = (b'{"version": %d, "msg_type": "request", "id": "1", "name": "execute_arbitrary_code", "payload": {}}\n' % VOICE_PROTOCOL_VERSION)
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message(raw)
        assert "Unknown request operation" in exc_info.value.message

    def test_unknown_event_rejected(self) -> None:
        raw = (b'{"version": %d, "msg_type": "event", "id": "1", "name": "unknown_event_name", "payload": {}}\n' % VOICE_PROTOCOL_VERSION)
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message(raw)
        assert "Unknown event name" in exc_info.value.message

    def test_dataclass_immutability(self) -> None:
        req = PingRequest(id="p-1")
        with pytest.raises(AttributeError):
            req.id = "p-2"  # type: ignore[misc]

    def test_error_code_all_enum_values_string(self) -> None:
        for code in VoiceErrorCode:
            assert isinstance(code.value, str)
            assert code.value == code.name


def _request_frame(name: str, payload: str) -> bytes:
    return (
        '{"version": %d, "msg_type": "request", "id": "1", "name": "%s", "payload": %s}\n'
        % (VOICE_PROTOCOL_VERSION, name, payload)
    ).encode()


class TestWorkerConfig:
    """The settings object the parent hands to the worker."""

    def test_defaults_match_the_application_defaults(self) -> None:
        assert VoiceWorkerConfig.from_voice_config(VoiceConfig()) == VoiceWorkerConfig()

    def test_snapshot_copies_every_worker_setting(self) -> None:
        source = VoiceConfig(
            engine="nemotron", model_size="base", nemotron_latency_ms=160, language="de",
            input_device="mic-2", output_device="speakers-1", max_recording_seconds=45,
            auto_submit=True, tts_voice="bm_george", tts_speed=1.5, vad_silence_ms=1200,
            vad_min_speech_ms=300, conversation_idle_seconds=120, barge_in=True,
        )
        config = VoiceWorkerConfig.from_voice_config(source)
        for key, value in config.to_dict().items():
            assert value == getattr(source, key), key

    def test_snapshot_falls_back_on_unusable_values(self) -> None:
        source = VoiceConfig()
        source.max_recording_seconds = "forever"  # type: ignore[assignment]
        source.input_device = ""
        config = VoiceWorkerConfig.from_voice_config(source)
        assert config.max_recording_seconds == VoiceWorkerConfig().max_recording_seconds
        assert config.input_device is None

    def test_unknown_key_rejected(self) -> None:
        data = dict(VoiceWorkerConfig().to_dict(), shell_command="rm")
        with pytest.raises(VoiceProtocolError, match="Unknown voice config keys: shell_command"):
            VoiceWorkerConfig.from_dict(data)

    def test_missing_key_rejected(self) -> None:
        data = VoiceWorkerConfig().to_dict()
        del data["engine"]
        with pytest.raises(VoiceProtocolError, match="Missing voice config keys: engine"):
            VoiceWorkerConfig.from_dict(data)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("max_recording_seconds", 0),
            ("max_recording_seconds", True),
            ("tts_speed", -1.0),
            ("barge_in", 1),
            ("input_device", 3),
            ("engine", None),
        ],
    )
    def test_bad_values_rejected(self, key: str, value: object) -> None:
        data = dict(VoiceWorkerConfig().to_dict(), **{key: value})
        with pytest.raises(VoiceProtocolError):
            VoiceWorkerConfig.from_dict(data)

    def test_handshake_with_unknown_config_key_rejected_on_decode(self) -> None:
        config = dict(VoiceWorkerConfig().to_dict(), extra=1)
        frame = (
            '{"version": %d, "msg_type": "request", "id": "1", "name": "handshake", '
            '"payload": {"client_version": "x", "epoch": 0, "config": %s}}\n'
            % (VOICE_PROTOCOL_VERSION, __import__("json").dumps(config))
        ).encode()
        with pytest.raises(VoiceProtocolError, match="Unknown voice config keys"):
            decode_voice_message(frame)


class TestHostileFrames:
    def test_integer_past_the_digit_limit_is_a_protocol_error(self) -> None:
        frame = _request_frame("output_speak", '{"text": "x", "epoch": %s}' % ("9" * 5000))
        with pytest.raises(VoiceProtocolError) as exc_info:
            decode_voice_message(frame)
        assert exc_info.value.code is VoiceErrorCode.PROTOCOL_VIOLATION

    @pytest.mark.parametrize("value", ["0", "-3", "1e400"])
    def test_max_seconds_must_be_finite_and_positive(self, value: str) -> None:
        with pytest.raises(VoiceProtocolError, match="max_seconds"):
            decode_voice_message(_request_frame("input_start", '{"max_seconds": %s}' % value))

    def test_negative_epoch_rejected(self) -> None:
        with pytest.raises(VoiceProtocolError, match="epoch"):
            decode_voice_message(_request_frame("output_stop", '{"epoch": -1}'))


class TestVersionSkew:
    def test_foreign_version_reports_what_it_could_read(self) -> None:
        frame = b'{"version": 1, "msg_type": "response", "id": "r1", "ref_id": "q1", "ok": true}\n'
        with pytest.raises(VoiceProtocolVersionError) as exc_info:
            decode_voice_message(frame)
        err = exc_info.value
        assert err.code is VoiceErrorCode.UNSUPPORTED_VERSION
        assert (err.received_version, err.msg_type, err.msg_id, err.ref_id) == (1, "response", "r1", "q1")


class TestFrameReader:
    def test_reads_frames_from_a_raw_pipe(self) -> None:
        import os

        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as reader_stream, os.fdopen(write_fd, "wb") as writer:
            for index in range(3):
                write_voice_frame(writer, PingRequest(id=f"p{index}"))
            writer.close()
            reader = VoiceFrameReader(reader_stream)
            ids = [reader.read_frame().id for _ in range(3)]  # type: ignore[union-attr]
            assert ids == ["p0", "p1", "p2"]
            assert reader.read_frame() is None

    def test_oversized_frame_raises_once_then_resynchronises(self) -> None:
        stream = io.BytesIO(
            b"x" * (MAX_FRAME_BYTES + 10) + b"\n" + encode_voice_message(PingRequest(id="after"))
        )
        reader = VoiceFrameReader(stream)
        with pytest.raises(VoiceProtocolError, match="maximum length"):
            reader.read_frame()
        frame = reader.read_frame()
        assert isinstance(frame, PingRequest) and frame.id == "after"
        assert reader.read_frame() is None

    def test_mid_frame_eof_raises(self) -> None:
        reader = VoiceFrameReader(io.BytesIO(b'{"version": 2'))
        with pytest.raises(VoiceProtocolEofError):
            reader.read_frame()


class TestTableDrivenCodec:
    """Every message type round-trips; the wire shape stays what it was."""

    CONFIG = VoiceWorkerConfig(engine="nemotron", language="de", input_device="mic", tts_speed=1.5)

    SAMPLES: dict = {
        "handshake": lambda: HandshakeRequest(
            id="1", client_version="9.9", config=TestTableDrivenCodec.CONFIG, epoch=4,
            protocol_version=VOICE_PROTOCOL_VERSION, capabilities_requested=("tts", "vad"),
        ),
        "configure": lambda: ConfigureRequest(id="1", config=TestTableDrivenCodec.CONFIG),
        "probe": lambda: ProbeRequest(id="1"),
        "input_start": lambda: InputStartRequest(id="1", streaming=True, max_seconds=12.5),
        "input_stop": lambda: InputStopRequest(id="1", initial_prompt="kubectl"),
        "input_cancel": lambda: InputCancelRequest(id="1"),
        "input_reset_budget": lambda: InputResetBudgetRequest(id="1"),
        "output_speak": lambda: OutputSpeakRequest(id="1", text="hello", epoch=3),
        "output_enqueue": lambda: OutputEnqueueRequest(id="1", text="next", epoch=0),
        "output_utterance_begin": lambda: OutputUtteranceBeginRequest(id="1", session_id="s", epoch=2),
        "output_utterance_enqueue": lambda: OutputUtteranceEnqueueRequest(id="1", session_id="s", text="t"),
        "output_utterance_end": lambda: OutputUtteranceEndRequest(id="1", session_id="s"),
        "output_stop": lambda: OutputStopRequest(id="1", epoch=7),
        "output_close": lambda: OutputCloseRequest(id="1"),
        "conversation_start": lambda: ConversationStartRequest(id="1", barge_in=True),
        "conversation_stop": lambda: ConversationStopRequest(id="1", reason="start_timeout"),
        "conversation_interrupt": lambda: ConversationInterruptRequest(id="1"),
        "conversation_signal": lambda: ConversationSignalRequest(id="1", signal="reply_started"),
        "ping": lambda: PingRequest(id="1"),
        "shutdown": lambda: ShutdownRequest(id="1", reason="client_close"),
        "input_partial": lambda: InputPartialEvent(id="1", text="partial"),
        "input_endpoint": lambda: InputEndpointEvent(id="1"),
        "input_cap_hit": lambda: InputCapHitEvent(id="1"),
        "output_state": lambda: OutputStateEvent(id="1", is_speaking=True, current_epoch=5),
        "utterance_completed": lambda: UtteranceCompletedEvent(id="1", session_id="s", played_to_end=False),
        "conversation_state": lambda: ConversationStateEvent(id="1", old_state="idle", new_state="listening"),
        "conversation_transcript": lambda: ConversationTranscriptEvent(id="1", text="restart nginx"),
        "conversation_error": lambda: ConversationErrorEvent(
            id="1", message="mic gone", code=VoiceErrorCode.AUDIO_DEVICE_ERROR,
        ),
        "conversation_stopped": lambda: ConversationStoppedEvent(id="1", reason="idle_timeout"),
        "worker_error": lambda: WorkerErrorEvent(
            id="1", code=VoiceErrorCode.MODEL_MISSING, message="no model", fatal=True,
        ),
    }

    # Payload keys of every message as the hand-written codec emitted them.
    WIRE_KEYS: dict = {
        "handshake": {"client_version", "protocol_version", "capabilities_requested", "config", "epoch"},
        "configure": {"config"},
        "probe": set(), "input_cancel": set(), "input_reset_budget": set(), "output_close": set(),
        "conversation_interrupt": set(), "ping": set(),
        "input_start": {"streaming", "max_seconds"},
        "input_stop": {"initial_prompt"},
        "output_speak": {"text", "epoch"},
        "output_enqueue": {"text", "epoch"},
        "output_utterance_begin": {"session_id", "epoch"},
        "output_utterance_enqueue": {"session_id", "text"},
        "output_utterance_end": {"session_id"},
        "output_stop": {"epoch"},
        "conversation_start": {"barge_in"},
        "conversation_stop": {"reason"},
        "conversation_signal": {"signal"},
        "shutdown": {"reason"},
        "input_partial": {"text"}, "input_endpoint": set(), "input_cap_hit": set(),
        "output_state": {"is_speaking", "current_epoch"},
        "utterance_completed": {"session_id", "played_to_end"},
        "conversation_state": {"old_state", "new_state"},
        "conversation_transcript": {"text"},
        "conversation_error": {"message", "code"},
        "conversation_stopped": {"reason"},
        "worker_error": {"code", "message", "fatal"},
    }

    def test_samples_cover_every_message_type(self) -> None:
        from typing import get_args

        from servonaut.desktop.voice.protocol import VoiceEvent, VoiceRequest

        names = {cls.__dataclass_fields__["name"].default for cls in get_args(VoiceRequest) + get_args(VoiceEvent)}
        assert names == set(self.SAMPLES) == set(self.WIRE_KEYS)

    @pytest.mark.parametrize("name", sorted(SAMPLES))
    def test_every_message_round_trips(self, name: str) -> None:
        message = self.SAMPLES[name]()
        assert decode_voice_message(encode_voice_message(message)) == message

    @pytest.mark.parametrize("name", sorted(SAMPLES))
    def test_wire_payload_keys_are_unchanged(self, name: str) -> None:
        import json

        frame = json.loads(encode_voice_message(self.SAMPLES[name]()))
        assert frame["name"] == name
        assert set(frame["payload"]) == self.WIRE_KEYS[name]

    def test_error_codes_travel_as_their_value(self) -> None:
        import json

        frame = json.loads(encode_voice_message(self.SAMPLES["worker_error"]()))
        assert frame["payload"]["code"] == "MODEL_MISSING"

    def test_unknown_error_codes_degrade_instead_of_failing(self) -> None:
        worker = decode_voice_message((
            '{"version": %d, "msg_type": "event", "id": "1", "name": "worker_error", '
            '"payload": {"code": "FUTURE_CODE", "message": "m"}}' % VOICE_PROTOCOL_VERSION
        ).encode())
        conversation = decode_voice_message((
            '{"version": %d, "msg_type": "event", "id": "1", "name": "conversation_error", '
            '"payload": {"code": "FUTURE_CODE", "message": "m"}}' % VOICE_PROTOCOL_VERSION
        ).encode())
        assert worker.code is VoiceErrorCode.PROTOCOL_VIOLATION  # type: ignore[union-attr]
        assert conversation.code is VoiceErrorCode.CONVERSATION_ERROR  # type: ignore[union-attr]

    def test_defaults_fill_optional_fields(self) -> None:
        start = decode_voice_message(_request_frame("input_start", "{}"))
        assert start == InputStartRequest(id="1")

    @pytest.mark.parametrize(
        ("name", "payload", "field_name"),
        [
            ("output_speak", '{"epoch": 1}', "text"),
            ("handshake", '{"client_version": "x", "epoch": 0}', "config"),
            ("handshake", '{"client_version": "x", "config": %s}' % __import__("json").dumps(VoiceWorkerConfig().to_dict()), "epoch"),
        ],
    )
    def test_required_fields_are_enforced(self, name: str, payload: str, field_name: str) -> None:
        with pytest.raises(VoiceProtocolError, match=field_name):
            decode_voice_message(_request_frame(name, payload))

    def test_non_message_cannot_be_encoded(self) -> None:
        with pytest.raises(VoiceProtocolError, match="Not a voice protocol message"):
            encode_voice_message(VoiceWorkerConfig())  # type: ignore[arg-type]
