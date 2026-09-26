"""Managed voice worker protocol definitions, framing, and data models.

Provides deterministic UTF-8 JSON Lines framing, strict typing, schema
validation, and error taxonomy for IPC between Servonaut and the companion
voice runtime worker.
Pure standard library — zero external or audio dependencies.
"""

from __future__ import annotations

from dataclasses import MISSING, Field, dataclass, field, fields
from enum import Enum
import io
import json
import math
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    Final,
    Literal,
    Mapping,
    Optional,
    Tuple,
    Union,
    get_args,
)

VOICE_PROTOCOL_VERSION: Final[int] = 2
MAX_FRAME_BYTES: Final[int] = 65536  # 64 KiB line limit
_READ_CHUNK_BYTES: Final[int] = 4096


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


class VoiceProtocolVersionError(VoiceProtocolError):
    """Raised for a well-formed frame written in another protocol version.

    Carries what could still be read from the envelope so the receiver can
    answer the request (or fail the pending call) instead of waiting for a
    reply it will never be able to decode.
    """

    def __init__(
        self,
        received_version: int,
        *,
        msg_type: Optional[str] = None,
        msg_id: Optional[str] = None,
        ref_id: Optional[str] = None,
    ) -> None:
        super().__init__(
            VoiceErrorCode.UNSUPPORTED_VERSION,
            f"Peer speaks voice protocol v{received_version}; "
            f"this side speaks v{VOICE_PROTOCOL_VERSION}",
        )
        self.received_version = received_version
        self.msg_type = msg_type
        self.msg_id = msg_id
        self.ref_id = ref_id


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


def _check_non_negative_int(val: Any, field_name: str) -> int:
    number = _check_int(val, field_name)
    if number < 0:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Field '{field_name}' must not be negative"
        )
    return number


def _check_opt_epoch(val: Any, field_name: str) -> Optional[int]:
    if val is None:
        return None
    return _check_non_negative_int(val, field_name)


def _check_positive_int(val: Any, field_name: str) -> int:
    number = _check_int(val, field_name)
    if number <= 0:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Field '{field_name}' must be positive"
        )
    return number


def _check_float_or_int(val: Any, field_name: str) -> float:
    if type(val) is bool or not isinstance(val, (int, float)):
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Field '{field_name}' must be float/int, got {type(val).__name__}",
        )
    return float(val)


def _check_positive_float(val: Any, field_name: str) -> float:
    number = _check_float_or_int(val, field_name)
    if not math.isfinite(number) or number <= 0:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION,
            f"Field '{field_name}' must be a finite positive number",
        )
    return number


def _check_opt_str(val: Any, field_name: str) -> Optional[str]:
    if val is None:
        return None
    return _check_str(val, field_name)


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
# Worker configuration (Parent -> Worker)
# ---------------------------------------------------------------------------

# Validator per declared field type of VoiceWorkerConfig.
_CONFIG_CHECKS: Final[Mapping[str, Callable[[Any, str], Any]]] = {
    "str": _check_str,
    "Optional[str]": _check_opt_str,
    "int": _check_positive_int,
    "float": _check_positive_float,
    "bool": _check_bool,
}


def _coerce_optional_str(value: Any) -> Optional[str]:
    return None if value in (None, "") else str(value)


# Lenient converters used when snapshotting a user's settings object.
_CONFIG_COERCIONS: Final[Mapping[str, Callable[[Any], Any]]] = {
    "str": str,
    "Optional[str]": _coerce_optional_str,
    "int": int,
    "float": float,
    "bool": bool,
}


@dataclass(frozen=True, slots=True)
class VoiceWorkerConfig:
    """The voice settings the worker builds its services from.

    A validated subset of the user's voice configuration: only what the
    worker-side capture, recognition, synthesis and conversation loop read.
    Defaults mirror the application's voice defaults. Every value is
    type-checked on construction, and unknown keys are rejected on decode.
    """

    engine: str = "whisper"
    model_size: str = "small"
    nemotron_latency_ms: int = 320
    language: str = "en"
    input_device: Optional[str] = None
    output_device: Optional[str] = None
    max_recording_seconds: int = 60
    auto_submit: bool = False
    tts_voice: str = "af_heart"
    tts_speed: float = 1.0
    vad_silence_ms: int = 800
    vad_min_speech_ms: int = 250
    conversation_idle_seconds: int = 60
    barge_in: bool = False

    def __post_init__(self) -> None:
        for f in fields(self):
            checked = _CONFIG_CHECKS[f.type](getattr(self, f.name), f"config.{f.name}")
            object.__setattr__(self, f.name, checked)

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VoiceWorkerConfig:
        """Decode a config object received over the wire, strictly."""
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - known)
        if unknown:
            raise VoiceProtocolError(
                VoiceErrorCode.PROTOCOL_VIOLATION,
                f"Unknown voice config keys: {', '.join(unknown)}",
            )
        missing = sorted(known - set(data))
        if missing:
            raise VoiceProtocolError(
                VoiceErrorCode.PROTOCOL_VIOLATION,
                f"Missing voice config keys: {', '.join(missing)}",
            )
        return cls(**data)

    @classmethod
    def from_voice_config(cls, config: Any) -> VoiceWorkerConfig:
        """Snapshot the worker-relevant fields of a user's voice settings.

        Lenient like the settings loader itself: a value that cannot be
        converted (a hand-edited config, say) falls back to its default
        rather than taking voice down.
        """
        defaults = cls()
        values: dict[str, Any] = {}
        for f in fields(cls):
            default = getattr(defaults, f.name)
            raw = getattr(config, f.name, default)
            try:
                value = _CONFIG_COERCIONS[f.type](raw)
                _CONFIG_CHECKS[f.type](value, f.name)
            except (TypeError, ValueError, OverflowError, VoiceProtocolError):
                value = default
            values[f.name] = value
        return cls(**values)


def _lenient_error_code(fallback: VoiceErrorCode) -> Callable[[Any, str], VoiceErrorCode]:
    """Decoder for an error code in an event: unknown codes degrade to *fallback*."""

    def check(val: Any, field_name: str) -> VoiceErrorCode:
        try:
            return VoiceErrorCode(_check_str(val, field_name))
        except ValueError:
            return fallback

    return check


# Field metadata read by the codec below: ``check`` replaces the validator
# the field's declared type implies; ``required`` makes a field with a
# default mandatory on the wire anyway.
_EPOCH: Final[Mapping[str, Any]] = {"check": _check_opt_epoch}


# ---------------------------------------------------------------------------
# Request Models (Parent -> Worker)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class HandshakeRequest:
    """Opens a session: negotiates the version and hands over the settings.

    ``epoch`` is the parent's current playback-cancellation epoch, so a
    worker started after the parent already stopped playback agrees on
    which utterances are current.
    """

    id: str
    client_version: str
    config: VoiceWorkerConfig = field(
        default_factory=VoiceWorkerConfig, metadata={"required": True},
    )
    epoch: int = field(default=0, metadata={"check": _check_non_negative_int, "required": True})
    protocol_version: int = VOICE_PROTOCOL_VERSION
    capabilities_requested: tuple[str, ...] = ()
    name: Literal["handshake"] = "handshake"


@dataclass(frozen=True, slots=True)
class ConfigureRequest:
    """Applies changed settings to a running worker without a restart."""

    id: str
    config: VoiceWorkerConfig
    name: Literal["configure"] = "configure"


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    id: str
    name: Literal["probe"] = "probe"


@dataclass(frozen=True, slots=True)
class InputStartRequest:
    id: str
    streaming: bool = False
    max_seconds: float = field(default=30.0, metadata={"check": _check_positive_float})
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
    epoch: Optional[int] = field(default=None, metadata=_EPOCH)
    name: Literal["output_speak"] = "output_speak"


@dataclass(frozen=True, slots=True)
class OutputEnqueueRequest:
    id: str
    text: str
    epoch: Optional[int] = field(default=None, metadata=_EPOCH)
    name: Literal["output_enqueue"] = "output_enqueue"


@dataclass(frozen=True, slots=True)
class OutputUtteranceBeginRequest:
    id: str
    session_id: str
    epoch: Optional[int] = field(default=None, metadata=_EPOCH)
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
    epoch: Optional[int] = field(default=None, metadata=_EPOCH)
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
    reason: str = "client"
    name: Literal["shutdown"] = "shutdown"


VoiceRequest = Union[
    HandshakeRequest,
    ConfigureRequest,
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
    code: VoiceErrorCode = field(
        default=VoiceErrorCode.CONVERSATION_ERROR,
        metadata={"check": _lenient_error_code(VoiceErrorCode.CONVERSATION_ERROR)},
    )
    name: Literal["conversation_error"] = "conversation_error"


@dataclass(frozen=True, slots=True)
class ConversationStoppedEvent:
    id: str
    reason: str
    name: Literal["conversation_stopped"] = "conversation_stopped"


@dataclass(frozen=True, slots=True)
class WorkerErrorEvent:
    id: str
    code: VoiceErrorCode = field(
        metadata={"check": _lenient_error_code(VoiceErrorCode.PROTOCOL_VIOLATION)},
    )
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
# Table-driven payload codec
# ---------------------------------------------------------------------------
#
# A request's or event's payload is every dataclass field except ``id`` and
# ``name``. Encoders and validators are chosen by the field's declared type;
# a field's ``check`` metadata overrides the validator, and ``required``
# metadata makes a field with a default mandatory on the wire.

def _decode_worker_config(val: Any, field_name: str) -> VoiceWorkerConfig:
    return VoiceWorkerConfig.from_dict(_check_dict(val, field_name))


_FIELD_ENCODERS: Final[Mapping[str, Callable[[Any], Any]]] = {
    "tuple[str, ...]": list,
    "VoiceWorkerConfig": lambda config: config.to_dict(),
    "VoiceErrorCode": lambda code: code.value,
}

_FIELD_DECODERS: Final[Mapping[str, Callable[[Any, str], Any]]] = {
    "str": _check_str,
    "bool": _check_bool,
    "int": _check_int,
    "float": _check_float_or_int,
    "tuple[str, ...]": _check_str_tuple,
    "VoiceWorkerConfig": _decode_worker_config,
}


def _registry(union: Any) -> Dict[str, type]:
    """Message classes of *union*, keyed by their wire ``name``."""
    return {cls.__dataclass_fields__["name"].default: cls for cls in get_args(union)}


_REQUEST_TYPES: Final[Dict[str, type]] = _registry(VoiceRequest)
_EVENT_TYPES: Final[Dict[str, type]] = _registry(VoiceEvent)
_MESSAGE_KINDS: Final[Dict[type, str]] = {
    **{cls: "request" for cls in _REQUEST_TYPES.values()},
    **{cls: "event" for cls in _EVENT_TYPES.values()},
}
_PAYLOAD_FIELDS: Final[Dict[type, Tuple[Field[Any], ...]]] = {
    cls: tuple(f for f in fields(cls) if f.name not in ("id", "name"))
    for cls in _MESSAGE_KINDS
}


def _field_decoder(f: Field[Any]) -> Callable[[Any, str], Any]:
    return f.metadata.get("check") or _FIELD_DECODERS[f.type]  # type: ignore[index]


def _assert_codec_complete() -> None:
    """Fail at import, not on the first frame, if a field has no validator."""
    for cls, payload_fields in _PAYLOAD_FIELDS.items():
        for f in payload_fields:
            if "check" not in f.metadata and f.type not in _FIELD_DECODERS:
                raise TypeError(f"{cls.__name__}.{f.name}: no wire validator for type {f.type!r}")


_assert_codec_complete()


def _has_default(f: Field[Any]) -> bool:
    return f.default is not MISSING or f.default_factory is not MISSING


def _identity(value: Any) -> Any:
    return value


def _encode_payload(msg: Any) -> dict[str, Any]:
    return {
        f.name: _FIELD_ENCODERS.get(f.type, _identity)(getattr(msg, f.name))  # type: ignore[arg-type]
        for f in _PAYLOAD_FIELDS[type(msg)]
    }


def _decode_payload(cls: type, msg_id: str, payload: dict[str, Any]) -> Any:
    values: dict[str, Any] = {"id": msg_id}
    for f in _PAYLOAD_FIELDS[cls]:
        if f.name not in payload and _has_default(f) and not f.metadata.get("required"):
            continue  # the dataclass default applies
        values[f.name] = _field_decoder(f)(payload.get(f.name), f.name)
    return cls(**values)


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
    else:
        kind = _MESSAGE_KINDS.get(type(msg))
        if kind is None:
            raise VoiceProtocolError(
                VoiceErrorCode.PROTOCOL_VIOLATION,
                f"Not a voice protocol message: {type(msg).__name__}",
            )
        raw_dict = {
            "version": version,
            "msg_type": kind,
            "id": msg.id,
            "name": msg.name,
            "payload": _encode_payload(msg),
        }

    try:
        text = json.dumps(raw_dict, separators=(",", ":"), ensure_ascii=False)
        encoded = (text + "\n").encode("utf-8")
    except (TypeError, ValueError) as e:
        # Unserialisable payload values, or text that is not valid Unicode
        # (a lone surrogate): the frame cannot be sent at all.
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Cannot encode frame: {e}"
        ) from None
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
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        # ValueError also covers JSONDecodeError and the integer
        # string-conversion limit a hostile frame can trigger.
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Malformed JSON: {e}"
        ) from None

    if type(data) is not dict:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, "Frame root must be a JSON object"
        )

    version = _check_int(data.get("version"), "version")
    if version != VOICE_PROTOCOL_VERSION:
        raise VoiceProtocolVersionError(
            version,
            msg_type=_optional_envelope_str(data, "msg_type"),
            msg_id=_optional_envelope_str(data, "id"),
            ref_id=_optional_envelope_str(data, "ref_id"),
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


def _optional_envelope_str(data: dict[str, Any], key: str) -> Optional[str]:
    value = data.get(key)
    return value if type(value) is str else None


def _decode_request(msg_id: str, name: str, payload: dict[str, Any]) -> VoiceRequest:
    cls = _REQUEST_TYPES.get(name)
    if cls is None:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Unknown request operation: {name}"
        )
    return _decode_payload(cls, msg_id, payload)


def _decode_event(msg_id: str, name: str, payload: dict[str, Any]) -> VoiceEvent:
    cls = _EVENT_TYPES.get(name)
    if cls is None:
        raise VoiceProtocolError(
            VoiceErrorCode.PROTOCOL_VIOLATION, f"Unknown event name: {name}"
        )
    return _decode_payload(cls, msg_id, payload)


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


def raw_chunk_reader(stream: BinaryIO) -> Callable[[int], bytes]:
    """Chunk reader for *stream* that never parks inside buffered IO.

    File-backed streams are read through their unbuffered raw file object:
    a thread blocked there holds no ``BufferedReader`` lock, so interpreter
    shutdown cannot abort on a reader thread still waiting for its peer,
    and a closed stream still raises instead of reading a reused
    descriptor. In-memory streams fall back to ``read1``/``read``.
    """
    raw = stream if isinstance(stream, io.RawIOBase) else getattr(stream, "raw", None)
    if isinstance(raw, io.RawIOBase):
        return lambda size: raw.read(size) or b""
    return getattr(stream, "read1", stream.read)


class VoiceFrameReader:
    """Incremental, chunked frame reader (see :func:`raw_chunk_reader`).

    An oversized frame raises once and is then skipped up to its newline,
    so the stream re-synchronises on the next frame.
    """

    def __init__(self, stream: BinaryIO) -> None:
        self._read = raw_chunk_reader(stream)
        self._buffer = bytearray()
        self._skipping = False

    def read_frame(self) -> Optional[VoiceMessage]:
        """Return the next decoded frame, or None on a clean EOF.

        Raises:
            VoiceProtocolError: For an oversized, malformed or foreign frame.
            VoiceProtocolEofError: If the stream ends mid-frame.
        """
        while True:
            line = self._take_line()
            if line is not None:
                return decode_voice_message(line)
            chunk = self._read(_READ_CHUNK_BYTES)
            if not chunk:
                pending = bool(self._buffer) and not self._skipping
                self._buffer.clear()
                if pending:
                    raise VoiceProtocolEofError("Stream closed mid-frame")
                return None
            self._buffer += chunk

    def _take_line(self) -> Optional[bytes]:
        while True:
            newline = self._buffer.find(b"\n")
            if newline < 0:
                if len(self._buffer) > MAX_FRAME_BYTES and not self._skipping:
                    self._buffer.clear()
                    self._skipping = True
                    raise VoiceProtocolError(
                        VoiceErrorCode.PROTOCOL_VIOLATION,
                        f"Frame exceeds maximum length {MAX_FRAME_BYTES} bytes",
                    )
                if self._skipping:
                    self._buffer.clear()
                return None
            line = bytes(self._buffer[:newline])
            del self._buffer[: newline + 1]
            if self._skipping:
                self._skipping = False
                continue
            if len(line) > MAX_FRAME_BYTES:
                raise VoiceProtocolError(
                    VoiceErrorCode.PROTOCOL_VIOLATION,
                    f"Frame exceeds maximum length {MAX_FRAME_BYTES} bytes",
                )
            return line


def write_voice_frame(stream: BinaryIO, msg: VoiceMessage) -> None:
    """Encode and write a VoiceMessage frame to stream, followed by a flush.

    Raises:
        VoiceProtocolError: If encoding fails or exceeds MAX_FRAME_BYTES.
    """
    data = encode_voice_message(msg)
    stream.write(data)
    stream.flush()
