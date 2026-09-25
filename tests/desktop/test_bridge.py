"""Contract tests for DesktopBootstrapBridge and origin validation."""

from __future__ import annotations

import inspect

import pytest

from servonaut.desktop.bridge import (
    DesktopBootstrapBridge,
    DesktopBridgeError,
    validate_navigation_url,
)
from servonaut.desktop.model import SecretToken


def test_bridge_claim_session_success() -> None:
    token = SecretToken.generate()
    bridge = DesktopBootstrapBridge(
        expected_origin="http://127.0.0.1:8080",
        token=token,
        get_current_url=lambda: "http://127.0.0.1:8080/",
    )

    assert not bridge.claimed
    assert bridge.expected_origin == "http://127.0.0.1:8080"

    result = bridge.claim_session()
    assert result == token.encoded_value()
    assert bridge.claimed
    assert bridge._token is None


def test_bridge_claim_session_second_call_fails() -> None:
    token = SecretToken.generate()
    bridge = DesktopBootstrapBridge(
        expected_origin="http://127.0.0.1:8080",
        token=token,
        get_current_url=lambda: "http://127.0.0.1:8080",
    )

    first = bridge.claim_session()
    assert first == token.encoded_value()

    with pytest.raises(DesktopBridgeError) as exc_info:
        bridge.claim_session()
    assert "already-claimed" in exc_info.value.code


def test_bridge_claim_session_wrong_origin_fails() -> None:
    token = SecretToken.generate()
    current_url = "http://attacker.example.com/"

    bridge = DesktopBootstrapBridge(
        expected_origin="http://127.0.0.1:8080",
        token=token,
        get_current_url=lambda: current_url,
    )

    with pytest.raises(DesktopBridgeError) as exc_info:
        bridge.claim_session()
    assert "unauthorized-origin" in exc_info.value.code
    # Token was not consumed on origin failure
    assert not bridge.claimed
    assert bridge._token is not None


def test_bridge_claim_session_unknown_location_fails() -> None:
    """A page whose location cannot be read is refused like a foreign one."""
    token = SecretToken.generate()
    bridge = DesktopBootstrapBridge(
        expected_origin="http://127.0.0.1:8080",
        token=token,
        get_current_url=lambda: None,
    )

    with pytest.raises(DesktopBridgeError) as exc_info:
        bridge.claim_session()
    assert "unauthorized-origin" in exc_info.value.code
    assert not bridge.claimed
    assert bridge._token is not None


def test_bridge_token_redaction_in_repr_and_str() -> None:
    token = SecretToken.generate()
    raw = token.encoded_value()
    bridge = DesktopBootstrapBridge(
        expected_origin="http://127.0.0.1:8080",
        token=token,
        get_current_url=lambda: None,
    )

    assert raw not in repr(bridge)
    assert raw not in str(bridge)


def test_validate_navigation_url() -> None:
    origin = "http://127.0.0.1:9090"

    # Valid URLs
    assert validate_navigation_url("http://127.0.0.1:9090", origin)
    assert validate_navigation_url("http://127.0.0.1:9090/", origin)
    assert validate_navigation_url("http://127.0.0.1:9090/index.html", origin)
    assert validate_navigation_url("http://127.0.0.1:9090/ws", origin)

    # Invalid URLs
    assert not validate_navigation_url("https://127.0.0.1:9090/", origin)  # https
    assert not validate_navigation_url("http://127.0.0.1:9091/", origin)  # wrong port
    assert not validate_navigation_url("http://localhost:9090/", origin)  # wrong host
    assert not validate_navigation_url("http://attacker.com:9090/", origin)
    assert not validate_navigation_url("http://127.0.0.1:9090/other.html", origin)
    assert not validate_navigation_url(
        "http://127.0.0.1:9090/?param=1", origin
    )  # query
    assert not validate_navigation_url(
        "http://127.0.0.1:9090/#hash", origin
    )  # fragment
    assert not validate_navigation_url("javascript:alert(1)", origin)
    assert not validate_navigation_url("", origin)
    assert not validate_navigation_url("invalid", origin)


def test_bridge_exposes_only_claim_session_to_the_page() -> None:
    """pywebview hands every public method to the page's JavaScript."""
    bridge = DesktopBootstrapBridge(
        expected_origin="http://127.0.0.1:8080",
        token=SecretToken.generate(),
        get_current_url=lambda: "http://127.0.0.1:8080/",
    )

    exposed = [
        name
        for name in dir(bridge)
        if not name.startswith("_")
        and (
            inspect.ismethod(getattr(bridge, name))
            or inspect.isfunction(getattr(bridge, name))
        )
    ]
    assert exposed == ["claim_session"]
