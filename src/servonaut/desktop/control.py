"""Deterministic frame codec and one-shot startup gates for the desktop shell.

This module contains no subprocess, socket, or GUI dependencies.
"""

from __future__ import annotations

import base64
import binascii
import json
import struct
from typing import BinaryIO, Final

from servonaut.desktop.model import (
    _BASE64URL_ALPHABET,
    _MAX_WINDOWS_LISTENER_BYTES,
    ControlMessage,
    DesktopChildErrorCode,
    ErrorResponse,
    PosixListener,
    ReadyResponse,
    SecretToken,
    StartRequest,
    WindowsSharedListener,
    _validate_origin,
)

_PROTOCOL_VERSION: Final = 1
_MAX_PAYLOAD_BYTES: Final = 8192


class DesktopControlError(RuntimeError):
    """Fixed protocol, framing, or validation failure without exposing secrets."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject_constant(constant: str) -> None:
    raise DesktopControlError("invalid-frame")


def _detect_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DesktopControlError("invalid-frame")
        result[key] = value
    return result


def _encode_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(encoded: str) -> bytes:
    if type(encoded) is not str or not encoded or not encoded.isascii():
        raise DesktopControlError("invalid-frame")
    if not set(encoded).issubset(_BASE64URL_ALPHABET):
        raise DesktopControlError("invalid-frame")
    pad = (4 - len(encoded) % 4) % 4
    if pad == 3:
        raise DesktopControlError("invalid-frame")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * pad)
    except (ValueError, binascii.Error):
        raise DesktopControlError("invalid-frame") from None
    if len(raw) < 1 or len(raw) > _MAX_WINDOWS_LISTENER_BYTES:
        raise DesktopControlError("invalid-frame")
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if canonical != encoded:
        raise DesktopControlError("invalid-frame")
    return raw


def _parse_json_payload(body: bytes) -> dict[str, object]:
    try:
        text = body.decode("utf-8")
        data = json.loads(
            text,
            object_pairs_hook=_detect_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise DesktopControlError("invalid-frame") from None
    if type(data) is not dict:
        raise DesktopControlError("invalid-frame")
    return data


def _parse_start_request(
    data: dict[str, object], *, platform_name: str
) -> StartRequest:
    if set(data.keys()) != {"version", "type", "origin", "token", "listener"}:
        raise DesktopControlError("invalid-frame")
    if type(data["version"]) is not int or data["version"] != _PROTOCOL_VERSION:
        raise DesktopControlError("invalid-frame")
    if data["type"] != "start":
        raise DesktopControlError("invalid-frame")

    origin = data["origin"]
    if type(origin) is not str:
        raise DesktopControlError("invalid-frame")
    try:
        _validate_origin(origin)
    except (ValueError, TypeError):
        raise DesktopControlError("invalid-frame") from None

    token_str = data["token"]
    if type(token_str) is not str:
        raise DesktopControlError("invalid-frame")
    try:
        token = SecretToken.from_encoded(token_str)
    except (ValueError, TypeError):
        raise DesktopControlError("invalid-frame") from None

    listener_data = data["listener"]
    if type(listener_data) is not dict:
        raise DesktopControlError("invalid-frame")

    kind = listener_data.get("kind")
    if kind == "posix-fd":
        if platform_name != "posix":
            raise DesktopControlError("invalid-frame")
        if set(listener_data.keys()) != {"kind", "fd"}:
            raise DesktopControlError("invalid-frame")
        fd = listener_data["fd"]
        if type(fd) is not int:
            raise DesktopControlError("invalid-frame")
        try:
            listener = PosixListener(fd=fd)
        except (ValueError, TypeError):
            raise DesktopControlError("invalid-frame") from None
    elif kind == "windows-share":
        if platform_name != "nt":
            raise DesktopControlError("invalid-frame")
        if set(listener_data.keys()) != {"kind", "data"}:
            raise DesktopControlError("invalid-frame")
        b64_data = listener_data["data"]
        if type(b64_data) is not str:
            raise DesktopControlError("invalid-frame")
        decoded_data = _decode_b64url(b64_data)
        try:
            listener = WindowsSharedListener(data=decoded_data)
        except (ValueError, TypeError):
            raise DesktopControlError("invalid-frame") from None
    else:
        raise DesktopControlError("invalid-frame")

    return StartRequest(origin=origin, token=token, listener=listener)


def _parse_child_response(data: dict[str, object]) -> ReadyResponse | ErrorResponse:
    version = data.get("version")
    if type(version) is not int or version != _PROTOCOL_VERSION:
        raise DesktopControlError("invalid-frame")

    msg_type = data.get("type")
    if msg_type == "ready":
        if set(data.keys()) != {"version", "type", "origin"}:
            raise DesktopControlError("invalid-frame")
        origin = data["origin"]
        if type(origin) is not str:
            raise DesktopControlError("invalid-frame")
        try:
            return ReadyResponse(origin=origin)
        except (ValueError, TypeError):
            raise DesktopControlError("invalid-frame") from None
    elif msg_type == "error":
        if set(data.keys()) != {"version", "type", "code"}:
            raise DesktopControlError("invalid-frame")
        raw_code = data["code"]
        if type(raw_code) is not str:
            raise DesktopControlError("invalid-frame")
        try:
            error_code = DesktopChildErrorCode(raw_code)
            return ErrorResponse(code=error_code)
        except (ValueError, TypeError):
            raise DesktopControlError("invalid-frame") from None
    else:
        raise DesktopControlError("invalid-frame")


def encode_control_frame(message: ControlMessage) -> bytes:
    """Encode a control message into a length-prefixed compact JSON frame."""
    if isinstance(message, StartRequest):
        if isinstance(message.listener, PosixListener):
            listener_dict: dict[str, object] = {
                "kind": "posix-fd",
                "fd": message.listener.fd,
            }
        elif isinstance(message.listener, WindowsSharedListener):
            listener_dict = {
                "kind": "windows-share",
                "data": _encode_b64url(message.listener.data),
            }
        else:
            raise DesktopControlError("invalid-frame")
        payload: dict[str, object] = {
            "version": _PROTOCOL_VERSION,
            "type": "start",
            "origin": message.origin,
            "token": message.token.encoded_value(),
            "listener": listener_dict,
        }
    elif isinstance(message, ReadyResponse):
        payload = {
            "version": _PROTOCOL_VERSION,
            "type": "ready",
            "origin": message.origin,
        }
    elif isinstance(message, ErrorResponse):
        payload = {
            "version": _PROTOCOL_VERSION,
            "type": "error",
            "code": message.code.value,
        }
    else:
        raise DesktopControlError("invalid-frame")

    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    if len(body) > _MAX_PAYLOAD_BYTES:
        raise DesktopControlError("frame-too-large")
    return struct.pack(">I", len(body)) + body


def _unpack_frame_payload(frame: bytes) -> bytes:
    if len(frame) < 4:
        raise DesktopControlError("truncated-frame")
    (length,) = struct.unpack(">I", frame[:4])
    if length > _MAX_PAYLOAD_BYTES:
        raise DesktopControlError("frame-too-large")
    if length == 0:
        raise DesktopControlError("invalid-frame")
    expected_total = 4 + length
    if len(frame) < expected_total:
        raise DesktopControlError("truncated-frame")
    if len(frame) > expected_total:
        raise DesktopControlError("trailing-data")
    return frame[4:expected_total]


def decode_parent_frame(frame: bytes, *, platform_name: str) -> StartRequest:
    """Decode a single complete parent-to-child start frame from bytes."""
    body = _unpack_frame_payload(frame)
    data = _parse_json_payload(body)
    return _parse_start_request(data, platform_name=platform_name)


def decode_child_frame(frame: bytes) -> ReadyResponse | ErrorResponse:
    """Decode a single complete child-to-parent response frame from bytes."""
    body = _unpack_frame_payload(frame)
    data = _parse_json_payload(body)
    return _parse_child_response(data)


def _read_exact(stream: BinaryIO, count: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < count:
        chunk = stream.read(count - len(buffer))
        if not chunk:
            raise DesktopControlError("truncated-frame")
        buffer.extend(chunk)
    return bytes(buffer)


def _read_frame_payload(stream: BinaryIO) -> bytes:
    header = _read_exact(stream, 4)
    (length,) = struct.unpack(">I", header)
    if length > _MAX_PAYLOAD_BYTES:
        raise DesktopControlError("frame-too-large")
    if length == 0:
        raise DesktopControlError("invalid-frame")
    return _read_exact(stream, length)


def read_parent_frame(stream: BinaryIO, *, platform_name: str) -> StartRequest:
    """Read exactly one framed parent-to-child start request from a stream."""
    body = _read_frame_payload(stream)
    data = _parse_json_payload(body)
    return _parse_start_request(data, platform_name=platform_name)


def read_child_frame(stream: BinaryIO) -> ReadyResponse | ErrorResponse:
    """Read exactly one framed child-to-parent response from a stream."""
    body = _read_frame_payload(stream)
    data = _parse_json_payload(body)
    return _parse_child_response(data)


class ChildStartGate:
    """Accepts exactly one valid StartRequest in the child process."""

    def __init__(self) -> None:
        self._latched = False

    def accept(self, message: ControlMessage, platform_name: str) -> StartRequest:
        """Accept the initial start request or fail with a fixed error code."""
        if not isinstance(message, StartRequest):
            raise DesktopControlError("unexpected-message")
        if self._latched:
            raise DesktopControlError("duplicate-start")
        if platform_name == "posix" and not isinstance(message.listener, PosixListener):
            raise DesktopControlError("invalid-frame")
        if platform_name == "nt" and not isinstance(
            message.listener, WindowsSharedListener
        ):
            raise DesktopControlError("invalid-frame")
        if platform_name not in {"posix", "nt"}:
            raise DesktopControlError("invalid-frame")
        self._latched = True
        return message


class ParentStartupGate:
    """Accepts exactly one terminal startup response in the parent process."""

    def __init__(self, expected_origin: str) -> None:
        _validate_origin(expected_origin)
        self._expected_origin = expected_origin
        self._terminal_response: ReadyResponse | ErrorResponse | None = None

    @property
    def expected_origin(self) -> str:
        return self._expected_origin

    @property
    def response(self) -> ReadyResponse | ErrorResponse | None:
        return self._terminal_response

    def accept(self, message: ControlMessage) -> ReadyResponse | ErrorResponse:
        """Accept a terminal response matching expected origin or fail with fixed code."""
        if isinstance(message, StartRequest):
            raise DesktopControlError("unexpected-message")
        if self._terminal_response is not None:
            raise DesktopControlError("duplicate-response")
        if isinstance(message, ReadyResponse):
            if message.origin != self._expected_origin:
                raise DesktopControlError("origin-mismatch")
            self._terminal_response = message
            return message
        if isinstance(message, ErrorResponse):
            self._terminal_response = message
            return message
        raise DesktopControlError("unexpected-message")
