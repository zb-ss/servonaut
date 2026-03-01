"""Tests for AI analysis service — all three providers and the orchestration service."""

from __future__ import annotations

import asyncio
import sys
import types
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AIProviderConfig, AppConfig
from servonaut.services.ai_analysis_service import (
    AIAnalysisService,
    AnthropicProvider,
    OllamaProvider,
    OpenAIProvider,
)


def run_async(coro):
    """Run a coroutine synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@contextmanager
def _mock_httpx(mock_client):
    """Inject a mock httpx module and set HAS_HTTPX=True for the duration."""
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value = mock_client

    import servonaut.services.ai_analysis_service as svc_module

    original = sys.modules.get("httpx")
    original_flag = svc_module.HAS_HTTPX
    original_httpx_attr = getattr(svc_module, "httpx", None)

    sys.modules["httpx"] = mock_httpx
    svc_module.httpx = mock_httpx
    svc_module.HAS_HTTPX = True
    try:
        yield mock_httpx
    finally:
        svc_module.HAS_HTTPX = original_flag
        svc_module.httpx = original_httpx_attr
        if original is None:
            sys.modules.pop("httpx", None)
        else:
            sys.modules["httpx"] = original


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config_manager(ai_provider=None, chunk_size=4000):
    """Build a mock config_manager returning AppConfig with given ai_provider."""
    ai_provider = ai_provider or AIProviderConfig()
    config = AppConfig(
        ai_provider=ai_provider,
        ai_chunk_size=chunk_size,
        ai_system_prompt="Test prompt",
    )
    manager = MagicMock()
    manager.get.return_value = config
    return manager


def _make_httpx_response(json_data):
    """Build a mock httpx response."""
    response = MagicMock()
    response.json.return_value = json_data
    response.raise_for_status = MagicMock()
    return response


# ---------------------------------------------------------------------------
# OpenAIProvider
# ---------------------------------------------------------------------------

class TestOpenAIProvider:
    def test_is_available_with_httpx(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", True):
            p = OpenAIProvider()
            assert p.is_available() is True

    def test_is_available_without_httpx(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", False):
            p = OpenAIProvider()
            assert p.is_available() is False

    def test_analyze_no_httpx_returns_message(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", False):
            p = OpenAIProvider()
            result = run_async(p.analyze("text", "prompt", AIProviderConfig()))
            assert "httpx not installed" in result["content"]
            assert result["tokens_used"] == 0

    def test_analyze_sends_correct_request(self):
        config = AIProviderConfig(
            provider="openai",
            api_key="sk-test",
            model="gpt-4o-mini",
            max_tokens=100,
            temperature=0.5,
        )

        response_data = {
            "choices": [{"message": {"content": "Analysis result"}}],
            "usage": {"total_tokens": 50},
        }

        mock_response = _make_httpx_response(response_data)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with _mock_httpx(mock_client):
            p = OpenAIProvider()
            result = run_async(p.analyze("log text", "system prompt", config))

        assert result["content"] == "Analysis result"
        assert result["tokens_used"] == 50
        assert result["model"] == "gpt-4o-mini"

        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs["headers"]
        assert headers["Authorization"] == "Bearer sk-test"

        body = call_kwargs.kwargs["json"]
        assert body["model"] == "gpt-4o-mini"
        assert body["messages"][0]["role"] == "system"
        assert body["messages"][1]["role"] == "user"
        assert body["temperature"] == 0.5

    def test_resolve_env_var_api_key(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "env-key-value")
        config = AIProviderConfig(api_key="$OPENAI_API_KEY")

        response_data = {
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"total_tokens": 10},
        }

        mock_response = _make_httpx_response(response_data)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with _mock_httpx(mock_client):
            p = OpenAIProvider()
            run_async(p.analyze("text", "prompt", config))

        headers = mock_client.post.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer env-key-value"

    def test_uses_default_model_when_empty(self):
        config = AIProviderConfig(api_key="sk-test", model="")

        response_data = {
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"total_tokens": 5},
        }
        mock_response = _make_httpx_response(response_data)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with _mock_httpx(mock_client):
            p = OpenAIProvider()
            result = run_async(p.analyze("text", "prompt", config))

        assert result["model"] == OpenAIProvider.DEFAULT_MODEL
        body = mock_client.post.call_args.kwargs["json"]
        assert body["model"] == OpenAIProvider.DEFAULT_MODEL


# ---------------------------------------------------------------------------
# AnthropicProvider
# ---------------------------------------------------------------------------

class TestAnthropicProvider:
    def test_is_available_with_httpx(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", True):
            p = AnthropicProvider()
            assert p.is_available() is True

    def test_analyze_no_httpx(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", False):
            p = AnthropicProvider()
            result = run_async(p.analyze("text", "prompt", AIProviderConfig()))
            assert "httpx not installed" in result["content"]

    def test_analyze_correct_headers_and_response(self):
        config = AIProviderConfig(
            provider="anthropic",
            api_key="ant-key",
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            temperature=0.2,
        )

        response_data = {
            "content": [{"text": "Claude analysis"}],
            "usage": {"input_tokens": 30, "output_tokens": 20},
        }

        mock_response = _make_httpx_response(response_data)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with _mock_httpx(mock_client):
            p = AnthropicProvider()
            result = run_async(p.analyze("log text", "system prompt", config))

        assert result["content"] == "Claude analysis"
        assert result["tokens_used"] == 50  # input + output
        assert result["model"] == "claude-sonnet-4-20250514"

        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs["headers"]
        assert headers["x-api-key"] == "ant-key"
        assert headers["anthropic-version"] == "2023-06-01"

        body = call_kwargs.kwargs["json"]
        assert body["system"] == "system prompt"
        assert body["messages"][0]["role"] == "user"
        assert body["messages"][0]["content"] == "log text"

    def test_resolve_env_var_api_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_KEY", "env-ant-key")
        config = AIProviderConfig(provider="anthropic", api_key="$ANTHROPIC_KEY")

        response_data = {
            "content": [{"text": "ok"}],
            "usage": {"input_tokens": 5, "output_tokens": 5},
        }
        mock_response = _make_httpx_response(response_data)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with _mock_httpx(mock_client):
            p = AnthropicProvider()
            run_async(p.analyze("text", "prompt", config))

        headers = mock_client.post.call_args.kwargs["headers"]
        assert headers["x-api-key"] == "env-ant-key"


# ---------------------------------------------------------------------------
# OllamaProvider
# ---------------------------------------------------------------------------

class TestOllamaProvider:
    def test_is_available_with_httpx(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", True):
            p = OllamaProvider()
            assert p.is_available() is True

    def test_analyze_no_httpx(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", False):
            p = OllamaProvider()
            result = run_async(p.analyze("text", "prompt", AIProviderConfig()))
            assert "httpx not installed" in result["content"]

    def test_analyze_correct_url_and_no_auth(self):
        config = AIProviderConfig(
            provider="ollama",
            model="llama3",
            base_url="http://localhost:11434",
            temperature=0.7,
        )

        response_data = {
            "message": {"content": "Ollama analysis"},
            "eval_count": 200,
        }

        mock_response = _make_httpx_response(response_data)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with _mock_httpx(mock_client):
            p = OllamaProvider()
            result = run_async(p.analyze("log text", "system prompt", config))

        assert result["content"] == "Ollama analysis"
        assert result["tokens_used"] == 200
        assert result["model"] == "llama3"

        # Verify no Authorization header
        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert "Authorization" not in headers

        body = call_kwargs.kwargs["json"]
        assert body["model"] == "llama3"
        assert body["stream"] is False
        assert body["options"]["temperature"] == 0.7

    def test_uses_default_base_url(self):
        config = AIProviderConfig(provider="ollama", base_url="")

        response_data = {"message": {"content": "ok"}, "eval_count": 0}
        mock_response = _make_httpx_response(response_data)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with _mock_httpx(mock_client):
            p = OllamaProvider()
            run_async(p.analyze("text", "prompt", config))

        url_called = mock_client.post.call_args.args[0]
        assert "localhost:11434" in url_called


# ---------------------------------------------------------------------------
# AIAnalysisService
# ---------------------------------------------------------------------------

class TestAIAnalysisService:
    def test_estimate_tokens_approx_4_chars(self):
        manager = _make_config_manager()
        service = AIAnalysisService(manager)
        assert service.estimate_tokens("a" * 400) == 100
        assert service.estimate_tokens("") == 0
        assert service.estimate_tokens("x" * 4000) == 1000

    def test_chunk_text_short_returns_single(self):
        manager = _make_config_manager(chunk_size=4000)
        service = AIAnalysisService(manager)
        chunks = service.chunk_text("short text", 4000)
        assert chunks == ["short text"]

    def test_chunk_text_long_splits_with_overlap(self):
        manager = _make_config_manager(chunk_size=100)
        service = AIAnalysisService(manager)
        text = "x" * 250
        chunks = service.chunk_text(text, 100)
        assert len(chunks) > 1
        for chunk in chunks:
            assert len(chunk) <= 100

    def test_chunk_text_uses_config_chunk_size(self):
        manager = _make_config_manager(chunk_size=50)
        service = AIAnalysisService(manager)
        text = "a" * 200
        chunks = service.chunk_text(text)  # no explicit chunk_size → uses config
        assert len(chunks) > 1

    def test_is_available_true(self):
        manager = _make_config_manager()
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", True):
            service = AIAnalysisService(manager)
            assert service.is_available() is True

    def test_is_available_false(self):
        manager = _make_config_manager()
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", False):
            service = AIAnalysisService(manager)
            assert service.is_available() is False

    def test_estimate_cost_known_model(self):
        manager = _make_config_manager()
        service = AIAnalysisService(manager)
        cost = service._estimate_cost(1000, "gpt-4o-mini")
        assert abs(cost - 0.00015) < 1e-10

    def test_estimate_cost_unknown_model(self):
        manager = _make_config_manager()
        service = AIAnalysisService(manager)
        assert service._estimate_cost(1000, "unknown-model") == 0

    def test_analyze_text_single_chunk(self):
        ai_config = AIProviderConfig(provider="openai", api_key="sk-test")
        manager = _make_config_manager(ai_provider=ai_config, chunk_size=4000)
        service = AIAnalysisService(manager)

        mock_provider = MagicMock()
        mock_provider.analyze = AsyncMock(return_value={
            "content": "Analysis done",
            "tokens_used": 100,
            "model": "gpt-4o-mini",
        })
        service._providers["openai"] = mock_provider

        result = run_async(service.analyze_text("short text"))

        assert result["content"] == "Analysis done"
        assert result["tokens_used"] == 100
        assert result["model"] == "gpt-4o-mini"
        assert "estimated_cost" in result

    def test_analyze_text_combines_chunks(self):
        ai_config = AIProviderConfig(provider="openai", api_key="sk-test")
        manager = _make_config_manager(ai_provider=ai_config, chunk_size=10)
        service = AIAnalysisService(manager)

        call_count = [0]

        async def mock_analyze(text, prompt, config):
            call_count[0] += 1
            return {
                "content": f"chunk-{call_count[0]}",
                "tokens_used": 10,
                "model": "gpt-4o-mini",
            }

        mock_provider = MagicMock()
        mock_provider.analyze = mock_analyze
        service._providers["openai"] = mock_provider

        long_text = "x" * 50
        result = run_async(service.analyze_text(long_text))

        assert call_count[0] > 1
        assert "---" in result["content"]
        assert result["tokens_used"] == 10 * call_count[0]

    def test_analyze_text_unknown_provider(self):
        ai_config = AIProviderConfig(provider="nonexistent")
        manager = _make_config_manager(ai_provider=ai_config)
        service = AIAnalysisService(manager)

        result = run_async(service.analyze_text("text"))
        assert "Unknown provider" in result["content"]
        assert result["tokens_used"] == 0

    def test_analyze_text_uses_config_system_prompt(self):
        ai_config = AIProviderConfig(provider="openai", api_key="sk-test")
        manager = _make_config_manager(ai_provider=ai_config)
        service = AIAnalysisService(manager)

        received_prompts = []

        async def mock_analyze(text, prompt, config):
            received_prompts.append(prompt)
            return {"content": "ok", "tokens_used": 0, "model": "gpt-4o-mini"}

        mock_provider = MagicMock()
        mock_provider.analyze = mock_analyze
        service._providers["openai"] = mock_provider

        run_async(service.analyze_text("text"))
        assert received_prompts[0] == "Test prompt"

    def test_analyze_text_custom_system_prompt_overrides(self):
        ai_config = AIProviderConfig(provider="openai", api_key="sk-test")
        manager = _make_config_manager(ai_provider=ai_config)
        service = AIAnalysisService(manager)

        received_prompts = []

        async def mock_analyze(text, prompt, config):
            received_prompts.append(prompt)
            return {"content": "ok", "tokens_used": 0, "model": "gpt-4o-mini"}

        mock_provider = MagicMock()
        mock_provider.analyze = mock_analyze
        service._providers["openai"] = mock_provider

        run_async(service.analyze_text("text", system_prompt="Custom prompt"))
        assert received_prompts[0] == "Custom prompt"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_text_chunk_returns_single_empty(self):
        manager = _make_config_manager(chunk_size=4000)
        service = AIAnalysisService(manager)
        chunks = service.chunk_text("")
        assert chunks == [""]

    def test_estimate_tokens_large_text(self):
        manager = _make_config_manager()
        service = AIAnalysisService(manager)
        text = "x" * 40000
        assert service.estimate_tokens(text) == 10000

    def test_openai_missing_httpx_graceful(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", False):
            p = OpenAIProvider()
            result = run_async(p.analyze("text", "prompt", AIProviderConfig(api_key="k")))
            assert result["tokens_used"] == 0
            assert result["model"] == ""

    def test_anthropic_missing_httpx_graceful(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", False):
            p = AnthropicProvider()
            result = run_async(p.analyze("text", "prompt", AIProviderConfig(api_key="k")))
            assert result["tokens_used"] == 0

    def test_ollama_missing_httpx_graceful(self):
        with patch("servonaut.services.ai_analysis_service.HAS_HTTPX", False):
            p = OllamaProvider()
            result = run_async(p.analyze("text", "prompt", AIProviderConfig()))
            assert result["tokens_used"] == 0
