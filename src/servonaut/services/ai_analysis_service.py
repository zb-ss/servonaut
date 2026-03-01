"""AI log analysis service supporting OpenAI, Anthropic, and Ollama providers."""

from __future__ import annotations

import logging
import os
from typing import Dict, List, TYPE_CHECKING

from .interfaces import AIProviderInterface, AIAnalysisServiceInterface

if TYPE_CHECKING:
    from servonaut.config.schema import AIProviderConfig

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    HAS_HTTPX = False


class OpenAIProvider(AIProviderInterface):
    """OpenAI API provider adapter."""

    DEFAULT_MODEL = "gpt-4o-mini"

    async def analyze(self, text: str, system_prompt: str, config: 'AIProviderConfig') -> dict:
        if not HAS_HTTPX:
            return {
                'content': 'httpx not installed. Install with: pip install httpx',
                'tokens_used': 0,
                'model': '',
            }

        api_key = self._resolve_key(config.api_key)
        model = config.model or self.DEFAULT_MODEL
        base_url = config.base_url or "https://api.openai.com"

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{base_url}/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": text},
                    ],
                    "max_tokens": config.max_tokens,
                    "temperature": config.temperature,
                },
            )
            response.raise_for_status()
            data = response.json()

        usage = data.get('usage', {})
        return {
            'content': data['choices'][0]['message']['content'],
            'tokens_used': usage.get('total_tokens', 0),
            'model': model,
        }

    def is_available(self) -> bool:
        return HAS_HTTPX

    def _resolve_key(self, key: str) -> str:
        if key.startswith('$'):
            return os.environ.get(key[1:], '')
        return key


class AnthropicProvider(AIProviderInterface):
    """Anthropic Claude API provider adapter."""

    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    async def analyze(self, text: str, system_prompt: str, config: 'AIProviderConfig') -> dict:
        if not HAS_HTTPX:
            return {'content': 'httpx not installed', 'tokens_used': 0, 'model': ''}

        api_key = self._resolve_key(config.api_key)
        model = config.model or self.DEFAULT_MODEL
        base_url = config.base_url or "https://api.anthropic.com"

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{base_url}/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": text}],
                    "max_tokens": config.max_tokens,
                    "temperature": config.temperature,
                },
            )
            response.raise_for_status()
            data = response.json()

        usage = data.get('usage', {})
        return {
            'content': data['content'][0]['text'],
            'tokens_used': usage.get('input_tokens', 0) + usage.get('output_tokens', 0),
            'model': model,
        }

    def is_available(self) -> bool:
        return HAS_HTTPX

    def _resolve_key(self, key: str) -> str:
        if key.startswith('$'):
            return os.environ.get(key[1:], '')
        return key


class OllamaProvider(AIProviderInterface):
    """Ollama local inference provider adapter."""

    DEFAULT_MODEL = "llama3"

    async def analyze(self, text: str, system_prompt: str, config: 'AIProviderConfig') -> dict:
        if not HAS_HTTPX:
            return {'content': 'httpx not installed', 'tokens_used': 0, 'model': ''}

        model = config.model or self.DEFAULT_MODEL
        base_url = config.base_url or "http://localhost:11434"

        async with httpx.AsyncClient(timeout=300) as client:
            response = await client.post(
                f"{base_url}/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": text},
                    ],
                    "stream": False,
                    "options": {"temperature": config.temperature},
                },
            )
            response.raise_for_status()
            data = response.json()

        return {
            'content': data.get('message', {}).get('content', ''),
            'tokens_used': data.get('eval_count', 0),
            'model': model,
        }

    def is_available(self) -> bool:
        return HAS_HTTPX


class AIAnalysisService(AIAnalysisServiceInterface):
    """Orchestrates AI analysis across multiple providers with chunking support."""

    PROVIDERS: Dict[str, type] = {
        'openai': OpenAIProvider,
        'anthropic': AnthropicProvider,
        'ollama': OllamaProvider,
    }

    # Rough cost estimates per 1K tokens (input)
    COST_PER_1K: Dict[str, float] = {
        'gpt-4o-mini': 0.00015,
        'gpt-4o': 0.005,
        'claude-sonnet-4-20250514': 0.003,
        'claude-haiku-4-5-20251001': 0.001,
    }

    def __init__(self, config_manager: object) -> None:
        self._config_manager = config_manager
        self._providers: Dict[str, AIProviderInterface] = {
            k: v() for k, v in self.PROVIDERS.items()
        }

    async def analyze_text(self, text: str, system_prompt: str = "") -> dict:
        config = self._config_manager.get()
        ai_config = config.ai_provider

        if not system_prompt:
            system_prompt = config.ai_system_prompt

        provider = self._providers.get(ai_config.provider)
        if not provider:
            return {
                'content': f'Unknown provider: {ai_config.provider}',
                'tokens_used': 0,
                'model': '',
                'estimated_cost': 0,
            }

        chunks = self.chunk_text(text, config.ai_chunk_size)
        all_content: List[str] = []
        total_tokens = 0
        model = ''

        for i, chunk in enumerate(chunks):
            if len(chunks) > 1:
                chunk_prompt = f"{system_prompt}\n\n[Analyzing chunk {i + 1}/{len(chunks)}]"
            else:
                chunk_prompt = system_prompt

            result = await provider.analyze(chunk, chunk_prompt, ai_config)
            all_content.append(result['content'])
            total_tokens += result.get('tokens_used', 0)
            model = result.get('model', '')

        combined = '\n\n---\n\n'.join(all_content)
        return {
            'content': combined,
            'tokens_used': total_tokens,
            'model': model,
            'estimated_cost': self._estimate_cost(total_tokens, model),
        }

    def estimate_tokens(self, text: str) -> int:
        return len(text) // 4

    def chunk_text(self, text: str, chunk_size: int = 0) -> List[str]:
        config = self._config_manager.get()
        if not chunk_size:
            chunk_size = config.ai_chunk_size

        if len(text) <= chunk_size:
            return [text]

        overlap = min(200, chunk_size // 10)
        chunks: List[str] = []
        start = 0
        while start < len(text):
            end = start + chunk_size
            chunks.append(text[start:end])
            start = end - overlap
        return chunks

    def is_available(self) -> bool:
        return HAS_HTTPX

    def _estimate_cost(self, tokens: int, model: str) -> float:
        rate = self.COST_PER_1K.get(model, 0)
        return (tokens / 1000) * rate
