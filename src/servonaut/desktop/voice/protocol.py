"""Managed voice worker protocol definitions, framing, and data models.

Provides deterministic UTF-8 JSON Lines framing, strict typing, schema
validation, and error taxonomy for IPC between Servonaut and the companion
voice runtime worker.
Pure standard library — zero external or audio dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any, BinaryIO, Dict, Final, List, Literal, Mapping, Optional, Sequence, Tuple, Union

VOICE_PROTOCOL_VERSION: Final[int] = 1
MAX_FRAME_BYTES: Final[int] = 65536  # 64 KiB line limit


class VoiceErrorCode(str, Enum):
    """Structured error taxonomy for managed voice operations."""

    PROTOCOL_VIOLATION = "PROTOCOL_VIOLATION"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    NOT_HANDSHAKEN = "NOT_HANDSHAKEN"
    INVALID_STATE = "INVALID_STATE"
    AUDIO_DEVICE_ERROR = "AUDIO_DEVICE_ERROR"
    MODEL_MISSING = "MODEL_MISSING"
    MODEL_LOAD_ERROR = "MODEL_LOAD_ERROR"
    TRANSCRIPTION_ERROR = "TRANSCRIPTION_ERROR"
    SYNTHESIS_ERROR = "SYNTHESIS_ERROR"
    PLAYBACK_ERROR = "PLAYBACK_ERROR"
    CONVERSATION_ERROR = "CONVERSATION_ERROR"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    SHUTTING_DOWN = "SHUTTING_DOWN"


class VoiceProtocolError(Exception):
    """Error encountered during voice protocol encoding, decoding, or framing."""

    def __init__(self, code: VoiceErrorCode, message: str) -> None:
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message


class VoiceProtocolEofError(VoiceProtocolError):
    """Raised when EOF is reached unexpectedly mid-frame."""

    def __init__(self, message: str = "Unexpected end of stream") -> None:
        super().__init__(VoiceErrorCode.PROTOCOL_VIOLATION, message)


# ---------------------------------------------------------------------------
# Strict validation helpers
# ---------------------------------------------------------------------------

def _reject_constant(constant: str) -> None:
    raise VoiceProtocolError(
        VoiceErrorCode.PROTOCOL_VIOLATION, f"Forbidden JSON constant: {constant}"
    )


def _detect_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VoiceProtocolError(
                VoiceErrorCode.PROTOCOL_VIOLATION, f"Duplicate key in JSON object: {key}"
            )
        result[key] = value
    return result


def _check_str(val: Any, field_name: str) -> str:
    if type(val) is not str:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Field '{field_name}' must be str, got {type(val).__name__}",
        )
    return val


def _check_bool(val: Any, field_name: str) -> bool:
    if type(val) is not bool:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Field '{field_name}' must be bool, got {type(val).__name__}",
        )
    return val


def _check_int(val: Any, field_name: str) -> int:
    if type(val) is not int or type(val) is bool:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Field '{field_name}' must be int, got {type(val).__name__}",
        )
    return val


def _check_opt_int(val: Any, field_name: str) -> Optional[int]:
    if val is None:
        return None
    return _check_int(val, field_name)


def _check_float_or_int(val: Any, field_name: str) -> float:
    if type(val) is bool or not isinstance(val, (int, float)):
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Field '{field_name}' must be float/int, got {type(val).__name__}",
        )
    return float(val)


def _check_str_tuple(val: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(val, (list, tuple)):
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Field '{field_name}' must be a sequence of str, got {type(val).__name__}",
        )
    items: list[str] = []
    for idx, item in enumerate(val):
        if type(item) is not str:
            raise VoiceProtocolError(
                VoiceErrorCode.PROTOCOL_VIOLATION,
                f"Field '{field_name}[{idx}]' must be str, got {type(item).__name__}",
            )
        items.append(item)
    return tuple(items)


def _check_dict(val: Any, field_name: str) -> dict[str, Any]:
    if type(val) is not dict:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Field '{field_name}' must be dict, got {type(val).__name__}",
        )
    return val


# ---------------------------------------------------------------------------
# Request Models (Parent -> Worker)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class HandshakeRequest:
    id: str
    client_version: str
    protocol_version: int = VOICE_PROTOCOL_VERSION
    capabilities_requested: tuple[str, ...] = ()
    name: Literal["handshake"] = "handshake"


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    id: str
    name: Literal["probe"] = "probe"


@dataclass(frozen=True, slots=True)
class InputStartRequest:
    id: str
    streaming: bool = False
    max_seconds: float = 30.0
    name: Literal["input_start"] = "input_start"


@dataclass(frozen=True, slots=True)
class InputStopRequest:
    id: str
    initial_prompt: str = ""
    name: Literal["input_stop"] = "input_stop"


@dataclass(frozen=True, slots=True)
class InputCancelRequest:
    id: str
    name: Literal["input_cancel"] = "input_cancel"


@dataclass(frozen=True, slots=True)
class InputResetBudgetRequest:
    id: str
    name: Literal["input_reset_budget"] = "input_reset_budget"


@dataclass(frozen=True, slots=True)
class OutputSpeakRequest:
    id: str
    text: str
    epoch: Optional[int] = None
    name: Literal["output_speak"] = "output_speak"


@dataclass(frozen=True, slots=True)
class OutputEnqueueRequest:
    id: str
    text: str
    epoch: Optional[int] = None
    name: Literal["output_enqueue"] = "output_enqueue"


@dataclass(frozen=True, slots=True)
class OutputUtteranceBeginRequest:
    id: str
    session_id: str
    epoch: Optional[int] = None
    name: Literal["output_utterance_begin"] = "output_utterance_begin"


@dataclass(frozen=True, slots=True)
class OutputUtteranceEnqueueRequest:
    id: str
    session_id: str
    text: str
    name: Literal["output_utterance_enqueue"] = "output_utterance_enqueue"


@dataclass(frozen=True, slots=True)
class OutputUtteranceEndRequest:
    id: str
    session_id: str
    name: Literal["output_utterance_end"] = "output_utterance_end"


@dataclass(frozen=True, slots=True)
class OutputStopRequest:
    id: str
    epoch: Optional[int] = None
    name: Literal["output_stop"] = "output_stop"


@dataclass(frozen=True, slots=True)
class OutputCloseRequest:
    id: str
    name: Literal["output_close"] = "output_close"


@dataclass(frozen=True, slots=True)
class ConversationStartRequest:
    id: str
    barge_in: bool = False
    name: Literal["conversation_start"] = "conversation_start"


@dataclass(frozen=True, slots=True)
class ConversationStopRequest:
    id: str
    reason: str = "user"
    name: Literal["conversation_stop"] = "conversation_stop"


@dataclass(frozen=True, slots=True)
class ConversationInterruptRequest:
    id: str
    name: Literal["conversation_interrupt"] = "conversation_interrupt"


@dataclass(frozen=True, slots=True)
class ConversationSignalRequest:
    id: str
    signal: str
    name: Literal["conversation_signal"] = "conversation_signal"


@dataclass(frozen=True, slots=True)
class PingRequest:
    id: str
    name: Literal["ping"] = "ping"


@dataclass(frozen=True, slots=True)
class ShutdownRequest:
    id: str
    name: Literal["shutdown"] = "shutdown"


VoiceRequest = Union[
    HandshakeRequest,
    ProbeRequest,
    InputStartRequest,
    InputStopRequest,
    InputCancelRequest,
    InputResetBudgetRequest,
    OutputSpeakRequest,
    OutputEnqueueRequest,
    OutputUtteranceBeginRequest,
    OutputUtteranceEnqueueRequest,
    OutputUtteranceEndRequest,
    OutputStopRequest,
    OutputCloseRequest,
    ConversationStartRequest,
    ConversationStopRequest,
    ConversationInterruptRequest,
    ConversationSignalRequest,
    PingRequest,
    ShutdownRequest,
]


# ---------------------------------------------------------------------------
# Response Models (Worker -> Parent)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class VoiceErrorPayload:
    code: VoiceErrorCode
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VoiceErrorPayload:
        code_str = _check_str(data.get("code"), "code")
        try:
            code = VoiceErrorCode(code_str)
        except ValueError:
            raise VoiceProtocolError(
                VoiceErrorCode.PROTOCOL_VIOLATION, f"Unknown error code: {code_str}"
            ) from None
        message = _check_str(data.get("message"), "message")
        details = _check_dict(data.get("details", {}), "details")
        return cls(code=code, message=message, details=details)


@dataclass(frozen=True, slots=True)
class VoiceResponse:
    id: str
    ref_id: str
    ok: bool
    payload: dict[str, Any] = field(default_factory=dict)
    error: Optional[VoiceErrorPayload] = None


# Typed payload helpers for standard responses
@dataclass(frozen=True, slots=True)
class HandshakeResponsePayload:
    worker_version: str
    protocol_version: int
    manifest_id: str
    python_version: str
    platform: str
    architecture: str
    capabilities: tuple[str, ...]
    models_status: dict[str, bool]
    audio_devices: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_version": self.worker_version,
            "protocol_version": self.protocol_version,
            "manifest_id": self.manifest_id,
            "python_version": self.python_version,
            "platform": self.platform,
            "architecture": self.architecture,
            "capabilities": list(self.capabilities),
            "models_status": self.models_status,
            "audio_devices": self.audio_devices,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HandshakeResponsePayload:
        return cls(
            worker_version=_check_str(data.get("worker_version"), "worker_version"),
            protocol_version=_check_int(data.get("protocol_version"), "protocol_version"),
            manifest_id=_check_str(data.get("manifest_id"), "manifest_id"),
            python_version=_check_str(data.get("python_version"), "python_version"),
            platform=_check_str(data.get("platform"), "platform"),
            architecture=_check_str(data.get("architecture"), "architecture"),
            capabilities=_check_str_tuple(data.get("capabilities", ()), "capabilities"),
            models_status={
                _check_str(k, "models_status key"): _check_bool(v, f"models_status[{k}]")
                for k, v in _check_dict(data.get("models_status", {}), "models_status").items()
            },
            audio_devices=_check_dict(data.get("audio_devices", {}), "audio_devices"),
        )


@dataclass(frozen=True, slots=True)
class ProbeResponsePayload:
    input_available: bool
    input_unavailable_reason: str
    output_available: bool
    output_unavailable_reason: str
    devices: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_available": self.input_available,
            "input_unavailable_reason": self.input_unavailable_reason,
            "output_available": self.output_available,
            "output_unavailable_reason": self.output_unavailable_reason,
            "devices": self.devices,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProbeResponsePayload:
        return cls(
            input_available=_check_bool(data.get("input_available"), "input_available"),
            input_unavailable_reason=_check_str(
                data.get("input_unavailable_reason", ""), "input_unavailable_reason"
            ),
            output_available=_check_bool(data.get("output_available"), "output_available"),
            output_unavailable_reason=_check_str(
                data.get("output_unavailable_reason", ""), "output_unavailable_reason"
            ),
            devices=_check_dict(data.get("devices", {}), "devices"),
        )


@dataclass(frozen=True, slots=True)
class InputStopResponsePayload:
    text: str
    hit_cap: bool

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "hit_cap": self.hit_cap}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InputStopResponsePayload:
        return cls(
            text=_check_str(data.get("text", ""), "text"),
            hit_cap=_check_bool(data.get("hit_cap", False), "hit_cap"),
        )


@dataclass(frozen=True, slots=True)
class OutputSpeakResponsePayload:
    completed: bool
    epoch: int

    def to_dict(self) -> dict[str, Any]:
        return {"completed": self.completed, "epoch": self.epoch}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OutputSpeakResponsePayload:
        return cls(
            completed=_check_bool(data.get("completed", False), "completed"),
            epoch=_check_int(data.get("epoch", 0), "epoch"),
        )


# ---------------------------------------------------------------------------
# Event Models (Worker -> Parent, Asynchronous)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class InputPartialEvent:
    id: str
    text: str
    name: Literal["input_partial"] = "input_partial"


@dataclass(frozen=True, slots=True)
class InputEndpointEvent:
    id: str
    name: Literal["input_endpoint"] = "input_endpoint"


@dataclass(frozen=True, slots=True)
class InputCapHitEvent:
    id: str
    name: Literal["input_cap_hit"] = "input_cap_hit"


@dataclass(frozen=True, slots=True)
class OutputStateEvent:
    id: str
    is_speaking: bool
    current_epoch: int
    name: Literal["output_state"] = "output_state"


@dataclass(frozen=True, slots=True)
class UtteranceCompletedEvent:
    id: str
    session_id: str
    played_to_end: bool
    name: Literal["utterance_completed"] = "utterance_completed"


@dataclass(frozen=True, slots=True)
class ConversationStateEvent:
    id: str
    old_state: str
    new_state: str
    name: Literal["conversation_state"] = "conversation_state"


@dataclass(frozen=True, slots=True)
class ConversationTranscriptEvent:
    id: str
    text: str
    name: Literal["conversation_transcript"] = "conversation_transcript"


@dataclass(frozen=True, slots=True)
class ConversationErrorEvent:
    id: str
    message: str
    code: VoiceErrorCode = VoiceErrorCode.CONVERSATION_ERROR
    name: Literal["conversation_error"] = "conversation_error"


@dataclass(frozen=True, slots=True)
class ConversationStoppedEvent:
    id: str
    reason: str
    name: Literal["conversation_stopped"] = "conversation_stopped"


@dataclass(frozen=True, slots=True)
class WorkerErrorEvent:
    id: str
    code: VoiceErrorCode
    message: str
    fatal: bool = False
    name: Literal["worker_error"] = "worker_error"


VoiceEvent = Union[
    InputPartialEvent,
    InputEndpointEvent,
    InputCapHitEvent,
    OutputStateEvent,
    UtteranceCompletedEvent,
    ConversationStateEvent,
    ConversationTranscriptEvent,
    ConversationErrorEvent,
    ConversationStoppedEvent,
    WorkerErrorEvent,
]

VoiceMessage = Union[VoiceRequest, VoiceResponse, VoiceEvent]


# ---------------------------------------------------------------------------
# Serialization & Deserialization
# ---------------------------------------------------------------------------

def encode_voice_message(msg: VoiceMessage) -> bytes:
    """Encode a typed VoiceMessage into a UTF-8 JSON Lines frame.

    Raises:
        VoiceProtocolError: If the resulting frame exceeds MAX_FRAME_BYTES.
    """
    version = VOICE_PROTOCOL_VERSION
    if isinstance(msg, VoiceResponse):
        payload_dict = msg.payload.to_dict() if hasattr(msg.payload, "to_dict") else msg.payload
        raw_dict = {
            "version": version,
            "msg_type": "response",
            "id": msg.id,
            "ref_id": msg.ref_id,
            "ok": msg.ok,
            "payload": payload_dict,
            "error": msg.error.to_dict() if msg.error is not None else None,
        }
    elif isinstance(msg, (
        InputPartialEvent,
        InputEndpointEvent,
        InputCapHitEvent,
        OutputStateEvent,
        UtteranceCompletedEvent,
        ConversationStateEvent,
        ConversationTranscriptEvent,
        ConversationErrorEvent,
        ConversationStoppedEvent,
        WorkerErrorEvent,
    )):
        event_dict: dict[str, Any] = {"version": version, "msg_type": "event", "id": msg.id, "name": msg.name}
        payload: dict[str, Any] = {}
        if isinstance(msg, InputPartialEvent):
            payload["text"] = msg.text
        elif isinstance(msg, (InputEndpointEvent, InputCapHitEvent)):
            pass
        elif isinstance(msg, OutputStateEvent):
            payload["is_speaking"] = msg.is_speaking
            payload["current_epoch"] = msg.current_epoch
        elif isinstance(msg, UtteranceCompletedEvent):
            payload["session_id"] = msg.session_id
            payload["played_to_end"] = msg.played_to_end
        elif isinstance(msg, ConversationStateEvent):
            payload["old_state"] = msg.old_state
            payload["new_state"] = msg.new_state
        elif isinstance(msg, ConversationTranscriptEvent):
            payload["text"] = msg.text
        elif isinstance(msg, ConversationErrorEvent):
            payload["message"] = msg.message
            payload["code"] = msg.code.value
        elif isinstance(msg, ConversationStoppedEvent):
            payload["reason"] = msg.reason
        elif isinstance(msg, WorkerErrorEvent):
            payload["code"] = msg.code.value
            payload["message"] = msg.message
            payload["fatal"] = msg.fatal
        event_dict["payload"] = payload
        raw_dict = event_dict
    else:
        # VoiceRequest
        req_dict: dict[str, Any] = {"version": version, "msg_type": "request", "id": msg.id, "name": msg.name}
        payload = {}
        if isinstance(msg, HandshakeRequest):
            payload["client_version"] = msg.client_version
            payload["protocol_version"] = msg.protocol_version
            payload["capabilities_requested"] = list(msg.capabilities_requested)
        elif isinstance(msg, (ProbeRequest, InputCancelRequest, InputResetBudgetRequest, OutputCloseRequest, ConversationInterruptRequest, PingRequest, ShutdownRequest)):
            pass
        elif isinstance(msg, InputStartRequest):
            payload["streaming"] = msg.streaming
            payload["max_seconds"] = msg.max_seconds
        elif isinstance(msg, InputStopRequest):
            payload["initial_prompt"] = msg.initial_prompt
        elif isinstance(msg, (OutputSpeakRequest, OutputEnqueueRequest)):
            payload["text"] = msg.text
            payload["epoch"] = msg.epoch
        elif isinstance(msg, OutputUtteranceBeginRequest):
            payload["session_id"] = msg.session_id
            payload["epoch"] = msg.epoch
        elif isinstance(msg, OutputUtteranceEnqueueRequest):
            payload["session_id"] = msg.session_id
            payload["text"] = msg.text
        elif isinstance(msg, OutputUtteranceEndRequest):
            payload["session_id"] = msg.session_id
        elif isinstance(msg, OutputStopRequest):
            payload["epoch"] = msg.epoch
        elif isinstance(msg, ConversationStartRequest):
            payload["barge_in"] = msg.barge_in
        elif isinstance(msg, ConversationStopRequest):
            payload["reason"] = msg.reason
        elif isinstance(msg, ConversationSignalRequest):
            payload["signal"] = msg.signal
        req_dict["payload"] = payload
        raw_dict = req_dict

    text = json.dumps(raw_dict, separators=(",", ":"), ensure_ascii=False)
    encoded = (text + "\n").encode("utf-8")
    if len(encoded) > MAX_FRAME_BYTES:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Encoded frame exceeds {MAX_FRAME_BYTES} bytes ({len(encoded)} bytes)",
        )
    return encoded


def decode_voice_message(raw: Union[bytes, str]) -> VoiceMessage:
    """Decode a UTF-8 JSON Lines frame into a strongly typed VoiceMessage.

    Raises:
        VoiceProtocolError: If framing, JSON parsing, or schema validation fails.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8")
    else:
        raw_bytes = raw

    if len(raw_bytes) > MAX_FRAME_BYTES:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Frame exceeds maximum length {MAX_FRAME_BYTES} bytes",
        )
    if b"\0" in raw_bytes:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, "Forbidden null byte in frame"
        )

    try:
        text = raw_bytes.decode("utf-8").strip()
        data = json.loads(
            text,
            object_pairs_hook=_detect_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as e:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Malformed JSON: {e}"
        ) from None

    if type(data) is not dict:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, "Frame root must be a JSON object"
        )

    version = _check_int(data.get("version"), "version")
    if version != VOICE_PROTOCOL_VERSION:
        raise VoiceProtocolError(
            VoiceErrorCode.UNSUPPORTED_VERSION,
            f"Unsupported protocol version {version} (expected {VOICE_PROTOCOL_VERSION})",
        )

    msg_type = _check_str(data.get("msg_type"), "msg_type")
    msg_id = _check_str(data.get("id"), "id")
    payload = _check_dict(data.get("payload", {}), "payload")

    if msg_type == "response":
        ref_id = _check_str(data.get("ref_id"), "ref_id")
        ok = _check_bool(data.get("ok"), "ok")
        err_dict = data.get("error")
        error_payload = None
        if err_dict is not None:
            error_payload = VoiceErrorPayload.from_dict(_check_dict(err_dict, "error"))
        return VoiceResponse(id=msg_id, ref_id=ref_id, ok=ok, payload=payload, error=error_payload)

    name = _check_str(data.get("name"), "name")

    if msg_type == "request":
        return _decode_request(msg_id, name, payload)
    elif msg_type == "event":
        return _decode_event(msg_id, name, payload)
    else:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Unknown msg_type: {msg_type}"
        )


def _decode_request(msg_id: str, name: str, payload: dict[str, Any]) -> VoiceRequest:
    if name == "handshake":
        return HandshakeRequest(
            id=msg_id,
            client_version=_check_str(payload.get("client_version"), "client_version"),
            protocol_version=_check_int(
                payload.get("protocol_version", VOICE_PROTOCOL_VERSION), "protocol_version"
            ),
            capabilities_requested=_check_str_tuple(
                payload.get("capabilities_requested", ()), "capabilities_requested"
            ),
        )
    elif name == "probe":
        return ProbeRequest(id=msg_id)
    elif name == "input_start":
        return InputStartRequest(
            id=msg_id,
            streaming=_check_bool(payload.get("streaming", False), "streaming"),
            max_seconds=_check_float_or_int(payload.get("max_seconds", 30.0), "max_seconds"),
        )
    elif name == "input_stop":
        return InputStopRequest(
            id=msg_id,
            initial_prompt=_check_str(payload.get("initial_prompt", ""), "initial_prompt"),
        )
    elif name == "input_cancel":
        return InputCancelRequest(id=msg_id)
    elif name == "input_reset_budget":
        return InputResetBudgetRequest(id=msg_id)
    elif name == "output_speak":
        return OutputSpeakRequest(
            id=msg_id,
            text=_check_str(payload.get("text"), "text"),
            epoch=_check_opt_int(payload.get("epoch"), "epoch"),
        )
    elif name == "output_enqueue":
        return OutputEnqueueRequest(
            id=msg_id,
            text=_check_str(payload.get("text"), "text"),
            epoch=_check_opt_int(payload.get("epoch"), "epoch"),
        )
    elif name == "output_utterance_begin":
        return OutputUtteranceBeginRequest(
            id=msg_id,
            session_id=_check_str(payload.get("session_id"), "session_id"),
            epoch=_check_opt_int(payload.get("epoch"), "epoch"),
        )
    elif name == "output_utterance_enqueue":
        return OutputUtteranceEnqueueRequest(
            id=msg_id,
            session_id=_check_str(payload.get("session_id"), "session_id"),
            text=_check_str(payload.get("text"), "text"),
        )
    elif name == "output_utterance_end":
        return OutputUtteranceEndRequest(
            id=msg_id,
            session_id=_check_str(payload.get("session_id"), "session_id"),
        )
    elif name == "output_stop":
        return OutputStopRequest(
            id=msg_id,
            epoch=_check_opt_int(payload.get("epoch"), "epoch"),
        )
    elif name == "output_close":
        return OutputCloseRequest(id=msg_id)
    elif name == "conversation_start":
        return ConversationStartRequest(
            id=msg_id,
            barge_in=_check_bool(payload.get("barge_in", False), "barge_in"),
        )
    elif name == "conversation_stop":
        return ConversationStopRequest(
            id=msg_id,
            reason=_check_str(payload.get("reason", "user"), "reason"),
        )
    elif name == "conversation_interrupt":
        return ConversationInterruptRequest(id=msg_id)
    elif name == "conversation_signal":
        return ConversationSignalRequest(
            id=msg_id,
            signal=_check_str(payload.get("signal"), "signal"),
        )
    elif name == "ping":
        return PingRequest(id=msg_id)
    elif name == "shutdown":
        return ShutdownRequest(id=msg_id)
    else:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Unknown request operation: {name}"
        )


def _decode_event(msg_id: str, name: str, payload: dict[str, Any]) -> VoiceEvent:
    if name == "input_partial":
        return InputPartialEvent(
            id=msg_id,
            text=_check_str(payload.get("text", ""), "text"),
        )
    elif name == "input_endpoint":
        return InputEndpointEvent(id=msg_id)
    elif name == "input_cap_hit":
        return InputCapHitEvent(id=msg_id)
    elif name == "output_state":
        return OutputStateEvent(
            id=msg_id,
            is_speaking=_check_bool(payload.get("is_speaking"), "is_speaking"),
            current_epoch=_check_int(payload.get("current_epoch"), "current_epoch"),
        )
    elif name == "utterance_completed":
        return UtteranceCompletedEvent(
            id=msg_id,
            session_id=_check_str(payload.get("session_id"), "session_id"),
            played_to_end=_check_bool(payload.get("played_to_end"), "played_to_end"),
        )
    elif name == "conversation_state":
        return ConversationStateEvent(
            id=msg_id,
            old_state=_check_str(payload.get("old_state"), "old_state"),
            new_state=_check_str(payload.get("new_state"), "new_state"),
        )
    elif name == "conversation_transcript":
        return ConversationTranscriptEvent(
            id=msg_id,
            text=_check_str(payload.get("text"), "text"),
        )
    elif name == "conversation_error":
        code_str = _check_str(payload.get("code", VoiceErrorCode.CONVERSATION_ERROR.value), "code")
        try:
            code = VoiceErrorCode(code_str)
        except ValueError:
            code = VoiceErrorCode.CONVERSATION_ERROR
        return ConversationErrorEvent(
            id=msg_id,
            message=_check_str(payload.get("message"), "message"),
            code=code,
        )
    elif name == "conversation_stopped":
        return ConversationStoppedEvent(
            id=msg_id,
            reason=_check_str(payload.get("reason", "user"), "reason"),
        )
    elif name == "worker_error":
        code_str = _check_str(payload.get("code"), "code")
        try:
            code = VoiceErrorCode(code_str)
        except ValueError:
            code = VoiceErrorCode.PROTOCOL_VIOLATION
        return WorkerErrorEvent(
            id=msg_id,
            code=code,
            message=_check_str(payload.get("message"), "message"),
            fatal=_check_bool(payload.get("fatal", False), "fatal"),
        )
    else:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Unknown event name: {name}"
        )


# ---------------------------------------------------------------------------
# Stream I/O
# ---------------------------------------------------------------------------

def read_voice_frame(stream: BinaryIO) -> Optional[VoiceMessage]:
    """Read and decode a single voice message frame from stream.

    Returns:
        The decoded VoiceMessage, or None if stream hit EOF before reading any bytes.

    Raises:
        VoiceProtocolError: If frame length exceeds MAX_FRAME_BYTES or contains null bytes.
        VoiceProtocolEofError: If stream hits EOF mid-frame before a newline terminator.
    """
    buffer = bytearray()
    while True:
        chunk = stream.read(1)
        if not chunk:
            if not buffer:
                return None  # Clean EOF at line boundary
            raise VoiceProtocolEofError("Stream closed mid-frame")

        byte = chunk[0]
        if byte == ord("\n"):
            # End of line
            break
        elif byte == ord("\r"):
            # Ignore carriage return
            continue
        elif byte == 0:
            raise VoiceProtocolError(
                VoiceErrorCode.PROTOCOL_VIOLATION, "Forbidden null byte in frame"
            )

        buffer.append(byte)
        if len(buffer) > MAX_FRAME_BYTES:
            raise VoiceProtocolError(
                VoiceErrorCode.PROTOCOL_VIOLATION,
                f"Frame exceeds maximum length {MAX_FRAME_BYTES} bytes",
            )

    return decode_voice_message(bytes(buffer))


def write_voice_frame(stream: BinaryIO, msg: VoiceMessage) -> None:
    """Encode and write a VoiceMessage frame to stream, followed by a flush.

    Raises:
        VoiceProtocolError: If encoding fails or exceeds MAX_FRAME_BYTES.
    """
    data = encode_voice_message(msg)
    stream.write(data)
    stream.flush()
