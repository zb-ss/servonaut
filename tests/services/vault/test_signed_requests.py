"""Exact-byte signing and bounded retry tests for Team Vault transport."""
from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from servonaut.services.api_client import APIClient, APIError
from servonaut.services.vault.crypto import request_message, verify
from servonaut.services.vault.identity_store import LocalDevice


@pytest.mark.asyncio
async def test_signed_request_serializes_once_and_signs_exact_bytes() -> None:
    auth = MagicMock(access_token="token")
    auth.refresh_token = AsyncMock(return_value=False)
    device = LocalDevice("11111111-1111-4111-8111-111111111111", b"a" * 32, b"b" * 32)
    recorded: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append(request)
        return httpx.Response(200, json={"ok": True})

    client = APIClient(auth)
    client.transport = httpx.MockTransport(handler)
    result = await client.request_signed(
        "POST", "/api/v1/vaults?cursor=next", json={"unicode": "£", "n": 1}, device=device,
    )

    request = recorded[0]
    raw = request.content
    assert raw == b'{"unicode":"\xc2\xa3","n":1}'
    nonce = base64.b64decode(request.headers["X-Servonaut-Nonce"])
    signature = base64.b64decode(request.headers["X-Servonaut-Signature"])
    assert verify(
        device.signing_public_key,
        request_message("POST", "/api/v1/vaults?cursor=next", int(request.headers["X-Servonaut-Timestamp"]), nonce, device.device_id, raw),
        signature,
    )
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_signed_request_corrects_clock_once() -> None:
    auth = MagicMock(access_token="token")
    auth.refresh_token = AsyncMock(return_value=False)
    device = LocalDevice("11111111-1111-4111-8111-111111111111", b"a" * 32, b"b" * 32)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(403, json={"error": {"code": "device_signature_expired", "message": "clock", "details": {"server_time": 2_000_000_000}}})
        return httpx.Response(200, json={"ok": True})

    client = APIClient(auth)
    client.transport = httpx.MockTransport(handler)
    assert await client.request_signed("GET", "/api/v1/vault/devices", device=device) == {"ok": True}
    assert calls == 2


@pytest.mark.asyncio
async def test_401_refresh_reuses_body_but_uses_a_fresh_nonce_and_signature() -> None:
    auth = MagicMock(access_token="first-token")
    auth.refresh_token = AsyncMock(return_value=True)
    device = LocalDevice("11111111-1111-4111-8111-111111111111", b"a" * 32, b"b" * 32)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(401 if len(requests) == 1 else 200, json={"ok": True})

    client = APIClient(auth)
    client.transport = httpx.MockTransport(handler)
    assert await client.request_signed("POST", "/api/v1/vaults", json={"same": True}, device=device) == {"ok": True}
    assert auth.refresh_token.await_count == 1
    assert len(requests) == 2
    assert requests[0].content == requests[1].content == b'{"same":true}'
    assert requests[0].headers["X-Servonaut-Nonce"] != requests[1].headers["X-Servonaut-Nonce"]
    assert requests[0].headers["X-Servonaut-Signature"] != requests[1].headers["X-Servonaut-Signature"]


@pytest.mark.asyncio
async def test_clock_retry_gets_a_fresh_nonce_and_non_retryable_failure_stops() -> None:
    auth = MagicMock(access_token="token")
    auth.refresh_token = AsyncMock(return_value=False)
    device = LocalDevice("11111111-1111-4111-8111-111111111111", b"a" * 32, b"b" * 32)
    requests: list[httpx.Request] = []

    def clock_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(403, json={"error": {"code": "device_signature_expired", "message": "clock", "details": {"server_time": 2_000_000_000}}})
        return httpx.Response(200, json={"ok": True})

    client = APIClient(auth)
    client.transport = httpx.MockTransport(clock_handler)
    await client.request_signed("POST", "/api/v1/vaults", body=b"raw", device=device)
    assert requests[0].headers["X-Servonaut-Nonce"] != requests[1].headers["X-Servonaut-Nonce"]

    calls = 0
    def no_retry_handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"error": {"code": "feature_disabled", "message": "disabled"}})

    client.transport = httpx.MockTransport(no_retry_handler)
    with pytest.raises(APIError):
        await client.request_signed("GET", "/api/v1/vaults", device=device)
    assert calls == 1


@pytest.mark.asyncio
async def test_second_clock_refusal_is_not_retried() -> None:
    auth = MagicMock(access_token="token")
    device = LocalDevice("11111111-1111-4111-8111-111111111111", b"a" * 32, b"b" * 32)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(403, json={"error": {"code": "device_signature_expired", "message": "clock", "details": {"server_time": 2_000_000_000}}})

    client = APIClient(auth)
    client.transport = httpx.MockTransport(handler)
    with pytest.raises(APIError):
        await client.request_signed("GET", "/api/v1/vaults", device=device)
    assert calls == 2


@pytest.mark.asyncio
async def test_boolean_server_time_does_not_trigger_clock_correction() -> None:
    auth = MagicMock(access_token="token")
    device = LocalDevice("11111111-1111-4111-8111-111111111111", b"a" * 32, b"b" * 32)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(403, json={"error": {"code": "device_signature_expired", "message": "clock", "details": {"server_time": True}}})

    client = APIClient(auth)
    client.transport = httpx.MockTransport(handler)
    with pytest.raises(APIError):
        await client.request_signed("GET", "/api/v1/vaults", device=device)
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["relative", "/api/v1/vaults#fragment", "/api/v1/%76aults"])
async def test_signed_request_rejects_ambiguous_targets(target: str) -> None:
    auth = MagicMock(access_token="token")
    device = LocalDevice("11111111-1111-4111-8111-111111111111", b"a" * 32, b"b" * 32)
    with pytest.raises(ValueError):
        await APIClient(auth).request_signed("GET", target, device=device)


@pytest.mark.asyncio
async def test_signed_request_rejects_two_or_non_bytes_bodies() -> None:
    auth = MagicMock(access_token="token")
    device = LocalDevice("11111111-1111-4111-8111-111111111111", b"a" * 32, b"b" * 32)
    client = APIClient(auth)
    with pytest.raises(ValueError):
        await client.request_signed("POST", "/api/v1/vaults", body=b"x", json={}, device=device)
    with pytest.raises(TypeError):
        await client.request_signed("POST", "/api/v1/vaults", body="x", device=device)  # type: ignore[arg-type]
