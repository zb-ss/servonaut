"""One-shot native JS bridge delivering secret token to pywebview bootstrap.

The bridge is exposed to the browser engine via pywebview's native JS bridge.
It enforces strict origin matching, one-shot retrieval, and immediate reference
dropping so the secret token cannot be retrieved more than once or intercepted.
"""

from __future__ import annotations

import contextlib
import logging
import threading
import urllib.parse
from collections.abc import Callable
from typing import Final

from servonaut.desktop.model import SecretToken, _validate_origin

logger = logging.getLogger(__name__)

_ALLOWED_PATHS: Final[frozenset[str]] = frozenset({"", "/", "/index.html", "/ws"})


class DesktopBridgeError(RuntimeError):
    """Raised when bridge operations fail or violate security policies."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = message


def validate_navigation_url(url: str, expected_origin: str) -> bool:
    """Verify that a URL belongs strictly to the expected root document.

    Rejects any destination outside the expected loopback origin, including
    foreign schemes, external hosts, differing ports, unexpected paths,
    query parameters, or fragments.
    """
    if not isinstance(url, str) or not url.strip():
        return False

    try:
        _validate_origin(expected_origin)
    except (TypeError, ValueError):
        return False

    try:
        parsed_target = urllib.parse.urlsplit(url.strip())
        parsed_origin = urllib.parse.urlsplit(expected_origin)
    except ValueError:
        return False

    if parsed_target.scheme != parsed_origin.scheme:
        return False

    if parsed_target.hostname != parsed_origin.hostname:
        return False

    if parsed_target.port != parsed_origin.port:
        return False

    # Path must be root document or empty; query strings and fragments are forbidden
    if parsed_target.path not in _ALLOWED_PATHS:
        return False

    return not (parsed_target.query or parsed_target.fragment)


class DesktopBootstrapBridge:
    """Exposed to pywebview JavaScript as ``window.pywebview.api``.

    Provides a state-locked, one-shot ``claim_session()`` method.
    """

    def __init__(
        self,
        *,
        expected_origin: str,
        token: SecretToken,
        get_current_url: Callable[[], str | None] | None = None,
        is_socket_admitted: Callable[[], bool] | None = None,
        on_claimed: Callable[[], None] | None = None,
    ) -> None:
        _validate_origin(expected_origin)
        if not isinstance(token, SecretToken):
            raise TypeError("token must be an instance of SecretToken")

        self._expected_origin = expected_origin
        self._token: SecretToken | None = token
        self._get_current_url = get_current_url
        self._is_socket_admitted = is_socket_admitted
        self._on_claimed = on_claimed
        self._claimed = False
        self._lock = threading.Lock()

    def set_url_getter(self, getter: Callable[[], str | None]) -> None:
        """Attach or update the URL resolver callable after window creation."""
        with self._lock:
            self._get_current_url = getter

    @property
    def expected_origin(self) -> str:
        """The loopback origin authorized to claim the desktop session."""
        return self._expected_origin

    @property
    def claimed(self) -> bool:
        """Whether the session token has already been claimed."""
        with self._lock:
            return self._claimed

    def claim_session(self) -> str:
        """Claim the one-time authentication token for WebSocket subprotocol auth.

        Must be called exactly once from the authenticated root origin.
        Subsequent calls or unauthorized destinations are rejected with DesktopBridgeError.
        """
        with self._lock:
            if self._claimed or self._token is None:
                raise DesktopBridgeError("desktop-session-already-claimed")

            if self._is_socket_admitted is not None and self._is_socket_admitted():
                raise DesktopBridgeError("desktop-session-already-admitted")

            if self._get_current_url is not None:
                current_url = self._get_current_url()
                if current_url is not None and not validate_navigation_url(
                    current_url, self._expected_origin
                ):
                    raise DesktopBridgeError(f"unauthorized-origin:{current_url}")

            token_str = self._token.encoded_value()
            self._token = None
            self._claimed = True

            if self._on_claimed is not None:
                with contextlib.suppress(Exception):
                    self._on_claimed()

            return token_str

    def __repr__(self) -> str:
        return f"DesktopBootstrapBridge(expected_origin={self._expected_origin!r}, claimed={self._claimed})"

    def __str__(self) -> str:
        return f"DesktopBootstrapBridge({self._expected_origin})"
