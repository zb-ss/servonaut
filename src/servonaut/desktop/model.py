"""Pure model and finite-code types for the desktop control protocol.

This module contains no I/O, subprocess, socket, or GUI dependencies.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import re
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Final

_MAX_WINDOWS_LISTENER_BYTES: Final = 4096
_ORIGIN_PATTERN: Final = re.compile(r"^http://127\.0\.0\.1:([1-9][0-9]{0,4})$")
_BASE64URL_ALPHABET: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


class DesktopChildErrorCode(str, Enum):
    """Finite error codes emitted by the desktop child during startup."""

    INVALID_START = "invalid-start"
    LISTENER_REJECTED = "listener-rejected"
    STARTUP_FAILED = "startup-failed"


@dataclass(frozen=True, slots=True, repr=False)
class SecretToken:
    """Canonical 43-character unpadded base64url secret token of 32 random bytes.

    Tokens are never revealed through str, repr, or container reprs.
    """

    _encoded: str

    @classmethod
    def generate(cls) -> SecretToken:
        """Generate a fresh secret token from 32 cryptographically secure random bytes."""
        random_bytes = secrets.token_bytes(32)
        encoded = base64.urlsafe_b64encode(random_bytes).rstrip(b"=").decode("ascii")
        return cls(_encoded=encoded)

    @classmethod
    def from_encoded(cls, encoded: str) -> SecretToken:
        """Parse and canonicalize an unpadded base64url-encoded secret token."""
        if type(encoded) is not str:
            raise TypeError("Invalid secret token encoding.")
        if not encoded.isascii() or len(encoded) != 43:
            raise ValueError("Invalid secret token encoding.")
        if not set(encoded).issubset(_BASE64URL_ALPHABET):
            raise ValueError("Invalid secret token encoding.")
        try:
            raw = base64.urlsafe_b64decode(encoded + "=")
        except (ValueError, binascii.Error) as error:
            raise ValueError("Invalid secret token encoding.") from error
        if len(raw) != 32:
            raise ValueError("Invalid secret token encoding.")
        canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        if canonical != encoded:
            raise ValueError("Invalid secret token encoding.")
        return cls(_encoded=encoded)

    def encoded_value(self) -> str:
        """Return the encoded token for private codec serialization."""
        return self._encoded

    def constant_time_compare(self, other: SecretToken | str) -> bool:
        """Compare this token with another token or string in constant time."""
        if isinstance(other, SecretToken):
            other_value = other._encoded
        elif type(other) is str:
            other_value = other
        else:
            return False
        return hmac.compare_digest(self._encoded, other_value)

    def __repr__(self) -> str:
        return "SecretToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class PosixListener:
    """A pre-bound POSIX file descriptor passed from parent to child."""

    fd: int

    def __post_init__(self) -> None:
        if type(self.fd) is not int:
            raise TypeError("Invalid POSIX listener file descriptor.")
        if self.fd < 3 or self.fd > 2_147_483_647:
            raise ValueError("Invalid POSIX listener file descriptor.")


@dataclass(frozen=True, slots=True, repr=False)
class WindowsSharedListener:
    """A duplicated Windows socket protocol info blob transferred to the child."""

    data: bytes

    def __post_init__(self) -> None:
        if type(self.data) is not bytes:
            raise TypeError("Invalid Windows listener data.")
        if len(self.data) < 1 or len(self.data) > _MAX_WINDOWS_LISTENER_BYTES:
            raise ValueError("Invalid Windows listener data.")

    def __repr__(self) -> str:
        return "WindowsSharedListener(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


def _validate_origin(origin: str) -> None:
    """Validate that origin matches exactly http://127.0.0.1:<port> without extras."""
    if type(origin) is not str:
        raise TypeError("Invalid origin format.")
    match = _ORIGIN_PATTERN.match(origin)
    if not match:
        raise ValueError("Invalid origin format.")
    port = int(match.group(1))
    if port < 1 or port > 65535:
        raise ValueError("Invalid origin port.")


@dataclass(frozen=True, slots=True)
class StartRequest:
    """Parent-to-child startup request conveying origin, token, and listener."""

    origin: str
    token: SecretToken
    listener: PosixListener | WindowsSharedListener

    def __post_init__(self) -> None:
        _validate_origin(self.origin)
        if not isinstance(self.token, SecretToken):
            raise TypeError("Invalid secret token.")
        if not isinstance(self.listener, (PosixListener, WindowsSharedListener)):
            raise TypeError("Invalid listener.")


@dataclass(frozen=True, slots=True)
class ReadyResponse:
    """Child-to-parent startup success response with confirmed origin."""

    origin: str

    def __post_init__(self) -> None:
        _validate_origin(self.origin)


@dataclass(frozen=True, slots=True)
class ErrorResponse:
    """Child-to-parent startup failure response with finite error code."""

    code: DesktopChildErrorCode

    def __post_init__(self) -> None:
        if not isinstance(self.code, DesktopChildErrorCode):
            raise TypeError("Invalid error code.")


ControlMessage = StartRequest | ReadyResponse | ErrorResponse
