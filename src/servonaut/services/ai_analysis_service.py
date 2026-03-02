"""AI log analysis service supporting OpenAI, Anthropic, Ollama, and Gemini providers."""

from __future__ import annotations

import logging
from typing import Dict, List, Tuple, TYPE_CHECKING

from .interfaces import AIProviderInterface, AIAnalysisServiceInterface

from servonaut.config.secrets import resolve_secret

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

        api_key = resolve_secret(config.api_key)
        model = config.model or self.DEFAULT_MODEL
        base_url = config.base_url or "https://api.openai.com"

        # GPT-5 family requires max_completion_tokens and doesn't support
        # custom temperature (only default 1 is allowed)
        is_gpt5 = model.startswith("gpt-5")
        if is_gpt5:
            token_param = {"max_completion_tokens": config.max_tokens}
        else:
            token_param = {"max_tokens": config.max_tokens}

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text},
            ],
            **token_param,
        }
        if not is_gpt5:
            payload["temperature"] = config.temperature

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{base_url}/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if response.status_code >= 400:
                try:
                    body = response.json()
                    msg = body.get("error", {}).get("message", response.text)
                except Exception:
                    msg = response.text
                raise RuntimeError(f"OpenAI API error ({response.status_code}): {msg}")
            data = response.json()

        usage = data.get('usage', {})
        input_tokens = usage.get('prompt_tokens', 0)
        output_tokens = usage.get('completion_tokens', 0)
        return {
            'content': data['choices'][0]['message']['content'],
            'tokens_used': input_tokens + output_tokens,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'model': model,
        }

    def is_available(self) -> bool:
        return HAS_HTTPX


class AnthropicProvider(AIProviderInterface):
    """Anthropic Claude API provider adapter."""

    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    async def analyze(self, text: str, system_prompt: str, config: 'AIProviderConfig') -> dict:
        if not HAS_HTTPX:
            return {'content': 'httpx not installed', 'tokens_used': 0, 'model': ''}

        api_key = resolve_secret(config.api_key)
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
            if response.status_code >= 400:
                try:
                    body = response.json()
                    msg = body.get("error", {}).get("message", response.text)
                except Exception:
                    msg = response.text
                raise RuntimeError(f"Anthropic API error ({response.status_code}): {msg}")
            data = response.json()

        usage = data.get('usage', {})
        input_tokens = usage.get('input_tokens', 0)
        output_tokens = usage.get('output_tokens', 0)
        return {
            'content': data['content'][0]['text'],
            'tokens_used': input_tokens + output_tokens,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'model': model,
        }

    def is_available(self) -> bool:
        return HAS_HTTPX


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
            if response.status_code >= 400:
                try:
                    body = response.json()
                    msg = body.get("error", response.text)
                except Exception:
                    msg = response.text
                raise RuntimeError(f"Ollama API error ({response.status_code}): {msg}")
            data = response.json()

        eval_count = data.get('eval_count', 0)
        prompt_count = data.get('prompt_eval_count', 0)
        return {
            'content': data.get('message', {}).get('content', ''),
            'tokens_used': prompt_count + eval_count,
            'input_tokens': prompt_count,
            'output_tokens': eval_count,
            'model': model,
        }

    def is_available(self) -> bool:
        return HAS_HTTPX


class GeminiProvider(AIProviderInterface):
    """Google Gemini API provider adapter."""

    DEFAULT_MODEL = "gemini-2.0-flash"
    DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com"

    async def analyze(self, text: str, system_prompt: str, config: 'AIProviderConfig') -> dict:
        if not HAS_HTTPX:
            return {'content': 'httpx not installed', 'tokens_used': 0, 'model': ''}

        api_key = resolve_secret(config.api_key)
        model = config.model or self.DEFAULT_MODEL
        base_url = config.base_url or self.DEFAULT_BASE_URL

        url = f"{base_url}/v1beta/models/{model}:generateContent?key={api_key}"

        payload = {
            "contents": [{"role": "user", "parts": [{"text": text}]}],
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "generationConfig": {
                "maxOutputTokens": config.max_tokens,
                "temperature": config.temperature,
            },
        }

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(url, json=payload)
            if response.status_code >= 400:
                try:
                    body = response.json()
                    msg = body.get("error", {}).get("message", response.text)
                except Exception:
                    msg = response.text
                raise RuntimeError(f"Gemini API error ({response.status_code}): {msg}")
            data = response.json()

        candidates = data.get("candidates", [])
        if not candidates:
            content = (
                "The AI provider filtered this response. "
                "Try rephrasing your prompt."
            )
        else:
            parts = candidates[0].get("content", {}).get("parts", [])
            content = parts[0].get("text", "") if parts else ""

        usage = data.get("usageMetadata", {})
        input_tokens = usage.get("promptTokenCount", 0)
        output_tokens = usage.get("candidatesTokenCount", 0)
        return {
            "content": content,
            "tokens_used": input_tokens + output_tokens,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "model": model,
        }

    def is_available(self) -> bool:
        return HAS_HTTPX


class AIAnalysisService(AIAnalysisServiceInterface):
    """Orchestrates AI analysis across multiple providers with chunking support."""

    PROVIDERS: Dict[str, type] = {
        'openai': OpenAIProvider,
        'anthropic': AnthropicProvider,
        'ollama': OllamaProvider,
        'gemini': GeminiProvider,
    }

    # Per-million-token pricing (input, output) by model prefix.
    # Sorted longest-prefix-first so "gpt-4o-mini" matches before "gpt-4o".
    # Source: https://pricepertoken.com  (March 2026)
    _MODEL_PRICING: List[Tuple[str, float, float]] = [
        # OpenAI — prefix, $/M input, $/M output
        ("gpt-5.2-pro",     21.00,  168.00),
        ("gpt-5.2",          1.75,   14.00),
        ("gpt-5.1",          1.25,   10.00),
        ("gpt-5-pro",       15.00,  120.00),
        ("gpt-5-nano",       0.05,    0.40),
        ("gpt-5-mini",       0.25,    2.00),
        ("gpt-5",            1.25,   10.00),
        ("gpt-4.1-nano",     0.10,    0.40),
        ("gpt-4.1-mini",     0.40,    1.60),
        ("gpt-4.1",          2.00,    8.00),
        ("gpt-4o-mini",      0.15,    0.60),
        ("gpt-4o",           2.50,   10.00),
        ("gpt-4-turbo",     10.00,   30.00),
        ("o4-mini",          1.10,    4.40),
        ("o3-mini",          1.10,    4.40),
        ("o3",               2.00,    8.00),
        ("o1-mini",          1.10,    4.40),
        ("o1",              15.00,   60.00),
        # Anthropic — prefix, $/M input, $/M output
        ("claude-opus-4.5",  5.00,   25.00),
        ("claude-opus-4.1", 15.00,   75.00),
        ("claude-opus-4",   15.00,   75.00),
        ("claude-opus",      5.00,   25.00),
        ("claude-sonnet",    3.00,   15.00),
        ("claude-haiku-4.5", 1.00,    5.00),
        ("claude-haiku",     0.80,    4.00),
        ("claude-3.5-haiku", 0.80,    4.00),
        # Google Gemini — prefix, $/M input, $/M output
        ("gemini-2.5-pro",   1.25,   10.00),
        ("gemini-2.0-flash", 0.10,    0.40),
        ("gemini-1.5-pro",   1.25,    5.00),
        ("gemini-1.5-flash", 0.075,   0.30),
    ]

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
                'input_tokens': 0,
                'output_tokens': 0,
                'model': '',
                'estimated_cost': None,
            }

        chunks = self.chunk_text(text, config.ai_chunk_size)
        all_content: List[str] = []
        total_tokens = 0
        total_input = 0
        total_output = 0
        model = ''

        for i, chunk in enumerate(chunks):
            if len(chunks) > 1:
                chunk_prompt = f"{system_prompt}\n\n[Analyzing chunk {i + 1}/{len(chunks)}]"
            else:
                chunk_prompt = system_prompt

            result = await provider.analyze(chunk, chunk_prompt, ai_config)
            all_content.append(result['content'])
            total_tokens += result.get('tokens_used', 0)
            total_input += result.get('input_tokens', 0)
            total_output += result.get('output_tokens', 0)
            model = result.get('model', '')

        combined = '\n\n---\n\n'.join(all_content)
        return {
            'content': combined,
            'tokens_used': total_tokens,
            'input_tokens': total_input,
            'output_tokens': total_output,
            'model': model,
            'estimated_cost': self._estimate_cost(total_input, total_output, model),
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

    def _estimate_cost(
        self, input_tokens: int, output_tokens: int, model: str
    ) -> float | None:
        """Estimate cost using prefix-matched per-million-token rates.

        Returns None if the model is not recognized (distinguishes from
        0.0 which means genuinely free, e.g. Ollama).
        """
        model_lower = model.lower()
        for prefix, input_rate, output_rate in self._MODEL_PRICING:
            if model_lower.startswith(prefix):
                return (
                    (input_tokens / 1_000_000) * input_rate
                    + (output_tokens / 1_000_000) * output_rate
                )
        # Ollama / local models are free
        if any(model_lower.startswith(p) for p in (
            "llama", "mistral", "codellama", "phi", "gemma", "qwen",
            "deepseek", "mixtral", "vicuna", "orca",
        )):
            return 0.0
        return None  # unknown model
