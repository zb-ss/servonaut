"""Contract and fuzz tests for the desktop control protocol and framing."""

from __future__ import annotations

import io
import struct

import pytest

from servonaut.desktop.control import (
    ChildStartGate,
    DesktopControlError,
    ParentStartupGate,
    decode_child_frame,
    decode_parent_frame,
    encode_control_frame,
    read_child_frame,
    read_parent_frame,
)
from servonaut.desktop.model import (
    DesktopChildErrorCode,
    ErrorResponse,
    PosixListener,
    ReadyResponse,
    SecretToken,
    StartRequest,
    WindowsSharedListener,
)


class FragmentedBytesIO(io.BytesIO):
    """A stream that returns at most chunk_size bytes per read call."""

    def __init__(self, initial_bytes: bytes, chunk_size: int = 1) -> None:
        super().__init__(initial_bytes)
        self.chunk_size = chunk_size

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return super().read()
        return super().read(min(size, self.chunk_size))


def test_posix_start_frame_round_trip() -> None:
    token = SecretToken.generate()
    listener = PosixListener(fd=7)
    request = StartRequest(
        origin="http://127.0.0.1:49152",
        token=token,
        listener=listener,
    )

    frame = encode_control_frame(request)
    assert len(frame) > 4
    (length,) = struct.unpack(">I", frame[:4])
    assert len(frame) == 4 + length

    decoded = decode_parent_frame(frame, platform_name="posix")
    assert decoded.origin == "http://127.0.0.1:49152"
    assert decoded.token.encoded_value() == token.encoded_value()
    assert isinstance(decoded.listener, PosixListener)
    assert decoded.listener.fd == 7


def test_windows_start_frame_round_trip() -> None:
    token = SecretToken.generate()
    raw_data = b"windows-socket-duplicate-bytes-12345"
    listener = WindowsSharedListener(data=raw_data)
    request = StartRequest(
        origin="http://127.0.0.1:50000",
        token=token,
        listener=listener,
    )

    frame = encode_control_frame(request)
    decoded = decode_parent_frame(frame, platform_name="nt")
    assert decoded.origin == "http://127.0.0.1:50000"
    assert decoded.token.encoded_value() == token.encoded_value()
    assert isinstance(decoded.listener, WindowsSharedListener)
    assert decoded.listener.data == raw_data


def test_ready_response_round_trip() -> None:
    response = ReadyResponse(origin="http://127.0.0.1:49152")
    frame = encode_control_frame(response)
    decoded = decode_child_frame(frame)
    assert isinstance(decoded, ReadyResponse)
    assert decoded.origin == "http://127.0.0.1:49152"


@pytest.mark.parametrize(
    "code",
    [
        DesktopChildErrorCode.INVALID_START,
        DesktopChildErrorCode.LISTENER_REJECTED,
        DesktopChildErrorCode.STARTUP_FAILED,
    ],
)
def test_error_response_round_trip(code: DesktopChildErrorCode) -> None:
    response = ErrorResponse(code=code)
    frame = encode_control_frame(response)
    decoded = decode_child_frame(frame)
    assert isinstance(decoded, ErrorResponse)
    assert decoded.code == code


def test_stream_reading_fragmented_and_trailing() -> None:
    token = SecretToken.generate()
    request = StartRequest(
        origin="http://127.0.0.1:49152",
        token=token,
        listener=PosixListener(fd=9),
    )
    frame = encode_control_frame(request)
    trailing_sentinel = b"trailing_stream_data_should_stay_unread"
    stream = FragmentedBytesIO(frame + trailing_sentinel, chunk_size=1)

    read_msg = read_parent_frame(stream, platform_name="posix")
    assert read_msg.origin == "http://127.0.0.1:49152"
    assert read_msg.listener.fd == 9
    assert stream.read() == trailing_sentinel


def test_child_stream_reading_fragmented() -> None:
    response = ReadyResponse(origin="http://127.0.0.1:49152")
    frame = encode_control_frame(response)
    stream = FragmentedBytesIO(frame, chunk_size=2)
    read_msg = read_child_frame(stream)
    assert isinstance(read_msg, ReadyResponse)
    assert read_msg.origin == "http://127.0.0.1:49152"


def test_decode_parent_rejects_trailing_bytes() -> None:
    token = SecretToken.generate()
    frame = encode_control_frame(
        StartRequest(
            origin="http://127.0.0.1:49152",
            token=token,
            listener=PosixListener(fd=3),
        )
    )
    with pytest.raises(DesktopControlError, match="trailing-data"):
        decode_parent_frame(frame + b"extra", platform_name="posix")


def test_decode_child_rejects_trailing_bytes() -> None:
    frame = encode_control_frame(ReadyResponse(origin="http://127.0.0.1:49152"))
    with pytest.raises(DesktopControlError, match="trailing-data"):
        decode_child_frame(frame + b"x")


@pytest.mark.parametrize("cut_point", [0, 1, 2, 3, 4, 10, 20])
def test_stream_reading_eof_at_boundaries(cut_point: int) -> None:
    token = SecretToken.generate()
    frame = encode_control_frame(
        StartRequest(
            origin="http://127.0.0.1:49152",
            token=token,
            listener=PosixListener(fd=3),
        )
    )
    truncated = frame[:cut_point]
    stream = io.BytesIO(truncated)
    with pytest.raises(DesktopControlError, match="truncated-frame"):
        read_parent_frame(stream, platform_name="posix")


def test_zero_length_payload_rejected() -> None:
    header = struct.pack(">I", 0)
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_parent_frame(header, platform_name="posix")
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        read_parent_frame(io.BytesIO(header), platform_name="posix")


def test_payload_exceeding_max_bytes_rejected() -> None:
    oversize = struct.pack(">I", 8193) + b"x" * 8193
    with pytest.raises(DesktopControlError, match="frame-too-large"):
        decode_parent_frame(oversize, platform_name="posix")
    with pytest.raises(DesktopControlError, match="frame-too-large"):
        read_parent_frame(io.BytesIO(oversize), platform_name="posix")


def test_exact_max_payload_supported() -> None:
    token = SecretToken.generate()
    max_listener_data = b"a" * 4096
    request = StartRequest(
        origin="http://127.0.0.1:49152",
        token=token,
        listener=WindowsSharedListener(data=max_listener_data),
    )
    frame = encode_control_frame(request)
    (length,) = struct.unpack(">I", frame[:4])
    assert length <= 8192
    decoded = decode_parent_frame(frame, platform_name="nt")
    assert isinstance(decoded.listener, WindowsSharedListener)
    assert decoded.listener.data == max_listener_data

    exact_8192_frame = struct.pack(">I", 8192) + b"{" + b" " * 8190 + b"}"
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_parent_frame(exact_8192_frame, platform_name="posix")

    mismatch_frame = struct.pack(">I", 100) + b"short"
    with pytest.raises(DesktopControlError, match="truncated-frame"):
        decode_parent_frame(mismatch_frame, platform_name="posix")


def test_malformed_utf8_and_invalid_json() -> None:
    bad_utf8 = struct.pack(">I", 4) + b"\xff\xfe\xfd\xfc"
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_parent_frame(bad_utf8, platform_name="posix")

    bad_json = struct.pack(">I", 6) + b"{not-j"
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_parent_frame(bad_json, platform_name="posix")


def test_duplicate_keys_rejected() -> None:
    raw_json = (
        b'{"version":1,"version":1,"type":"ready","origin":"http://127.0.0.1:49152"}'
    )
    frame = struct.pack(">I", len(raw_json)) + raw_json
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_child_frame(frame)

    raw_json_nested = (
        b'{"version":1,"type":"start","origin":"http://127.0.0.1:49152",'
        b'"token":"abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE",'
        b'"listener":{"kind":"posix-fd","fd":5,"fd":5}}'
    )
    frame_nested = struct.pack(">I", len(raw_json_nested)) + raw_json_nested
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_parent_frame(frame_nested, platform_name="posix")


def test_non_standard_constants_rejected() -> None:
    for constant in (b"NaN", b"Infinity", b"-Infinity"):
        raw_json = b'{"version":1,"type":"ready","origin":' + constant + b"}"
        frame = struct.pack(">I", len(raw_json)) + raw_json
        with pytest.raises(DesktopControlError, match="invalid-frame"):
            decode_child_frame(frame)


def test_type_confusion_and_booleans_rejected() -> None:
    raw_json = b'{"version":true,"type":"ready","origin":"http://127.0.0.1:49152"}'
    frame = struct.pack(">I", len(raw_json)) + raw_json
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_child_frame(frame)

    raw_json_fd = (
        b'{"version":1,"type":"start","origin":"http://127.0.0.1:49152",'
        b'"token":"abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE",'
        b'"listener":{"kind":"posix-fd","fd":true}}'
    )
    frame_fd = struct.pack(">I", len(raw_json_fd)) + raw_json_fd
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_parent_frame(frame_fd, platform_name="posix")


def test_recursion_and_nesting_pressure_rejected() -> None:
    nested = b"[" * 500 + b"]" * 500
    frame = struct.pack(">I", len(nested)) + nested
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_child_frame(frame)


def test_unknown_and_missing_fields_rejected() -> None:
    raw_unknown = (
        b'{"version":1,"type":"ready","origin":"http://127.0.0.1:49152","extra":"bad"}'
    )
    frame = struct.pack(">I", len(raw_unknown)) + raw_unknown
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_child_frame(frame)

    raw_missing = b'{"version":1,"type":"ready"}'
    frame_missing = struct.pack(">I", len(raw_missing)) + raw_missing
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_child_frame(frame_missing)


def test_platform_listener_discrimination() -> None:
    token = SecretToken.generate()
    posix_req = StartRequest(
        origin="http://127.0.0.1:49152",
        token=token,
        listener=PosixListener(fd=5),
    )
    posix_frame = encode_control_frame(posix_req)
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_parent_frame(posix_frame, platform_name="nt")

    win_req = StartRequest(
        origin="http://127.0.0.1:49152",
        token=token,
        listener=WindowsSharedListener(data=b"data"),
    )
    win_frame = encode_control_frame(win_req)
    with pytest.raises(DesktopControlError, match="invalid-frame"):
        decode_parent_frame(win_frame, platform_name="posix")


def test_secret_token_validation_and_redaction() -> None:
    token = SecretToken.generate()
    encoded = token.encoded_value()
    assert len(encoded) == 43
    assert token.constant_time_compare(encoded)
    assert token.constant_time_compare(token)
    assert not token.constant_time_compare("wrong")

    assert str(token) == "<redacted>"
    assert repr(token) == "SecretToken(<redacted>)"
    req = StartRequest(
        origin="http://127.0.0.1:49152",
        token=token,
        listener=PosixListener(fd=4),
    )
    container_repr = repr(req)
    assert encoded not in container_repr
    assert "<redacted>" in container_repr

    with pytest.raises(ValueError, match="encoding"):
        SecretToken.from_encoded(encoded[:42])
    with pytest.raises(ValueError, match="encoding"):
        SecretToken.from_encoded(encoded + "A")
    with pytest.raises(ValueError, match="encoding"):
        SecretToken.from_encoded(encoded[:-1] + "=")

    class StrSubclass(str):
        pass

    with pytest.raises(TypeError, match="encoding"):
        SecretToken.from_encoded(StrSubclass(encoded))


def test_posix_listener_fd_bounds() -> None:
    with pytest.raises(ValueError, match="descriptor"):
        PosixListener(fd=0)
    with pytest.raises(ValueError, match="descriptor"):
        PosixListener(fd=1)
    with pytest.raises(ValueError, match="descriptor"):
        PosixListener(fd=2)
    with pytest.raises(ValueError, match="descriptor"):
        PosixListener(fd=2_147_483_648)
    with pytest.raises(TypeError, match="descriptor"):
        PosixListener(fd=True)  # type: ignore[arg-type]


def test_windows_shared_listener_bounds_and_redaction() -> None:
    listener = WindowsSharedListener(data=b"secret-socket-handle")
    assert str(listener) == "<redacted>"
    assert repr(listener) == "WindowsSharedListener(<redacted>)"

    with pytest.raises(ValueError, match="data"):
        WindowsSharedListener(data=b"")
    with pytest.raises(ValueError, match="data"):
        WindowsSharedListener(data=b"x" * 4097)
    with pytest.raises(TypeError, match="data"):
        WindowsSharedListener(data="not-bytes")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "valid_origin",
    [
        "http://127.0.0.1:1",
        "http://127.0.0.1:80",
        "http://127.0.0.1:49152",
        "http://127.0.0.1:65535",
    ],
)
def test_valid_origins_accepted(valid_origin: str) -> None:
    ready = ReadyResponse(origin=valid_origin)
    assert ready.origin == valid_origin


@pytest.mark.parametrize(
    "invalid_origin",
    [
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:080",
        "http://localhost:49152",
        "http://127.0.0.2:49152",
        "http://[::1]:49152",
        "https://127.0.0.1:49152",
        "http://user@127.0.0.1:49152",
        "http://127.0.0.1:49152/",
        "http://127.0.0.1:49152?query=1",
        "http://127.0.0.1:49152#fragment",
        "http://127.0.0.1:49152\x00",
    ],
)
def test_invalid_origins_rejected(invalid_origin: str) -> None:
    with pytest.raises(ValueError, match="origin"):
        ReadyResponse(origin=invalid_origin)


def test_child_start_gate_lifecycle() -> None:
    gate = ChildStartGate()
    token = SecretToken.generate()
    request = StartRequest(
        origin="http://127.0.0.1:49152",
        token=token,
        listener=PosixListener(fd=6),
    )

    accepted = gate.accept(request, platform_name="posix")
    assert accepted is request

    with pytest.raises(DesktopControlError, match="duplicate-start"):
        gate.accept(request, platform_name="posix")

    with pytest.raises(DesktopControlError, match="unexpected-message"):
        gate.accept(
            ReadyResponse(origin="http://127.0.0.1:49152"), platform_name="posix"
        )


def test_parent_startup_gate_lifecycle() -> None:
    gate = ParentStartupGate(expected_origin="http://127.0.0.1:49152")
    assert gate.expected_origin == "http://127.0.0.1:49152"
    assert gate.response is None

    token = SecretToken.generate()
    with pytest.raises(DesktopControlError, match="unexpected-message"):
        gate.accept(
            StartRequest(
                origin="http://127.0.0.1:49152",
                token=token,
                listener=PosixListener(fd=4),
            )
        )

    with pytest.raises(DesktopControlError, match="origin-mismatch"):
        gate.accept(ReadyResponse(origin="http://127.0.0.1:50000"))

    ready = ReadyResponse(origin="http://127.0.0.1:49152")
    accepted = gate.accept(ready)
    assert accepted is ready
    assert gate.response is ready

    with pytest.raises(DesktopControlError, match="duplicate-response"):
        gate.accept(ready)
    with pytest.raises(DesktopControlError, match="duplicate-response"):
        gate.accept(ErrorResponse(code=DesktopChildErrorCode.STARTUP_FAILED))


def test_parent_startup_gate_error_terminal() -> None:
    gate = ParentStartupGate(expected_origin="http://127.0.0.1:49152")
    error = ErrorResponse(code=DesktopChildErrorCode.STARTUP_FAILED)
    accepted = gate.accept(error)
    assert accepted is error
    assert gate.response is error

    with pytest.raises(DesktopControlError, match="duplicate-response"):
        gate.accept(error)
