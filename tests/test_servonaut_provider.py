"""Tests for ServonautProvider (premium AI)."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AIProviderConfig
from servonaut.services.ai_analysis_service import ServonautProvider


def run_async(coro):
    """Run a coroutine synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def mock_api():
    api = MagicMock()
    api.post = AsyncMock()
    return api


@pytest.fixture
def provider(mock_api):
    return ServonautProvider(api_client=mock_api)


@pytest.fixture
def ai_config():
    return AIProviderConfig(provider="servonaut")


class TestServonautProvider:
    def test_analyze_calls_api(self, provider, mock_api, ai_config):
        mock_api.post.return_value = {
            "analysis": "Log looks healthy.",
            "tokens_used": 150,
            "input_tokens": 100,
            "output_tokens": 50,
            "model": "claude-sonnet",
        }
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", True):
            result = run_async(provider.analyze("some logs", "analyze this", ai_config))
        assert result["content"] == "Log looks healthy."
        assert result["tokens_used"] == 150
        mock_api.post.assert_called_once()
        call_args = mock_api.post.call_args
        assert call_args[0][0] == "/api/v1/ai/analyze"

    def test_analyze_without_api_returns_message(self, ai_config):
        provider = ServonautProvider(api_client=None)
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", True):
            result = run_async(provider.analyze("text", "prompt", ai_config))
        assert "login" in result["content"].lower() or "subscription" in result["content"].lower()
        assert result["tokens_used"] == 0

    def test_analyze_handles_api_error(self, provider, mock_api, ai_config):
        mock_api.post.side_effect = RuntimeError("API error (500): Internal error")
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", True):
            result = run_async(provider.analyze("text", "prompt", ai_config))
        assert "error" in result["content"].lower()

    def test_is_available_with_httpx_and_api(self, mock_api):
        provider = ServonautProvider(api_client=mock_api)
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", True):
            assert provider.is_available()

    def test_is_available_without_api(self):
        provider = ServonautProvider(api_client=None)
        assert not provider.is_available()

    def test_chat_calls_api(self, provider, mock_api, ai_config):
        mock_api.post.return_value = {
            "content": "Hello!",
            "tool_calls": [],
            "tokens_used": 50,
            "model": "claude-sonnet",
            "stop_reason": "end_turn",
        }
        messages = [{"role": "user", "content": "Hi"}]
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", True):
            result = run_async(provider.chat(messages, "system", ai_config))
        assert result["content"] == "Hello!"
        assert result["stop_reason"] == "end_turn"
