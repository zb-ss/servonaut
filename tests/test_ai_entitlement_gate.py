"""Tests for the ``require_premium_ai`` / ``require_premium_ai_stream`` decorators.

The decorators belong to the Servonaut provider and act synchronously
on the bound instance's ``_auth_service`` (or ``_auth``) attribute. We
exercise both the plain coroutine variant (used on ``chat`` /
``analyze``) and the async-generator variant (used on ``stream_chat``).
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AIProviderConfig
from servonaut.services.ai_providers import ServonautProvider
from servonaut.services.ai_providers._guards import (
    require_premium_ai,
    require_premium_ai_stream,
)
from servonaut.services.api_client import APIClient, ForbiddenEntitlementError


# Canonical buffered response so `chat()` returns successfully when the
# gate lets the call through.
_OK_RESPONSE = {
    "conversation_id": "conv-uuid-123",
    "content": "ok",
    "model": "servonaut-flash",
    "vendor": "gemini",
    "input_tokens": 10,
    "output_tokens": 5,
    "cached_tokens": 0,
    "tool_calls_count": 0,
    "fallback_used": False,
    "quota": None,
    "usage_persisted": True,
    "warning": "",
}


def run(coro):
    """Synchronous asyncio wrapper — matches project test convention."""
    return asyncio.run(coro)


def _make_provider(
    *,
    authenticated: bool = True,
    premium: bool = True,
):
    """Build a real ServonautProvider with mocked APIClient + AuthService."""
    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(return_value=dict(_OK_RESPONSE))

    auth = MagicMock()
    auth.is_authenticated = authenticated
    auth.has_feature = MagicMock(return_value=premium)

    provider = ServonautProvider(api_client=api, auth_service=auth)
    return provider, api, auth


def _ai_config() -> AIProviderConfig:
    return AIProviderConfig(provider="servonaut", api_key="", model="")


# ---------------------------------------------------------------------------
# 1. Unauth → blocked
# ---------------------------------------------------------------------------


def test_require_premium_ai_blocks_unauth():
    """``chat`` raises ForbiddenEntitlementError when unauthenticated.

    Critical: the API client is NEVER called — the gate trips before the
    request leaves the box (defense-in-depth + saves a 403 round-trip).
    """
    provider, api, _auth = _make_provider(
        authenticated=False, premium=False,
    )

    with pytest.raises(ForbiddenEntitlementError) as exc_info:
        run(provider.chat(
            [{"role": "user", "content": "hi"}], "", _ai_config(),
        ))

    assert exc_info.value.status == 403
    assert exc_info.value.code == "entitlement_required"
    api.post.assert_not_called()


# ---------------------------------------------------------------------------
# 2. Authed but no premium_ai → blocked
# ---------------------------------------------------------------------------


def test_require_premium_ai_blocks_free_user():
    """Authed but ``has_feature("premium_ai")`` False → 403, no network call."""
    provider, api, _auth = _make_provider(
        authenticated=True, premium=False,
    )

    with pytest.raises(ForbiddenEntitlementError) as exc_info:
        run(provider.chat(
            [{"role": "user", "content": "hi"}], "", _ai_config(),
        ))

    assert exc_info.value.status == 403
    api.post.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Solo subscriber passes through
# ---------------------------------------------------------------------------


def test_require_premium_ai_passes_for_solo():
    """Authed + premium_ai True → ``chat`` reaches the network and returns."""
    provider, api, _auth = _make_provider(
        authenticated=True, premium=True,
    )

    result = run(provider.chat(
        [{"role": "user", "content": "hi"}], "", _ai_config(),
    ))

    assert result["content"] == "ok"
    api.post.assert_awaited_once()


def test_require_premium_ai_blocks_analyze():
    """``analyze`` shares the same gate — same blocking behaviour."""
    provider, api, _auth = _make_provider(
        authenticated=True, premium=False,
    )

    with pytest.raises(ForbiddenEntitlementError):
        run(provider.analyze("some logs", "", _ai_config()))

    api.post.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Stream variant blocks before the first yield
# ---------------------------------------------------------------------------


def test_require_premium_ai_stream_blocks_before_first_yield():
    """The stream decorator must raise before any yield reaches the consumer.

    The consumer would otherwise see a partial stream and have no way to
    distinguish a denied call from a genuine empty stream.
    """

    class _DummyProvider:
        """Standalone fixture — no servonaut_provider import needed."""

        def __init__(self, auth):
            self._auth = auth

        @require_premium_ai_stream
        async def stream(self):
            # If the gate fails to fire we'll see this yield in the test.
            yield {"event": "token", "data": {"text": "should-not-reach"}}

    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=False)

    provider = _DummyProvider(auth)

    async def _consume():
        items = []
        async for item in provider.stream():
            items.append(item)
        return items

    with pytest.raises(ForbiddenEntitlementError):
        run(_consume())


def test_require_premium_ai_stream_passes_when_entitled():
    """Stream variant lets entitled users through and yields normally."""

    class _DummyProvider:
        def __init__(self, auth):
            self._auth = auth

        @require_premium_ai_stream
        async def stream(self):
            for chunk in ("hello", "world"):
                yield {"event": "token", "data": {"text": chunk}}

    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)

    provider = _DummyProvider(auth)

    async def _consume():
        return [item async for item in provider.stream()]

    items = run(_consume())
    assert [i["data"]["text"] for i in items] == ["hello", "world"]


# ---------------------------------------------------------------------------
# 5. Plain decorator works on standalone functions too
# ---------------------------------------------------------------------------


def test_require_premium_ai_with_alternative_auth_attribute():
    """Decorator finds ``_auth_service`` when ``_auth`` is absent."""

    class _AltProvider:
        def __init__(self, auth):
            self._auth_service = auth  # non-default name

        @require_premium_ai
        async def call(self):
            return "ok"

    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)

    provider = _AltProvider(auth)
    assert run(provider.call()) == "ok"
