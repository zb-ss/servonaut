"""AI provider adapters.

Re-exports the four legacy providers that still live in
:mod:`servonaut.services.ai_analysis_service` alongside the new
hosted :class:`ServonautProvider`. New code should import from this
package; existing imports against ``ai_analysis_service`` continue to
work via the legacy module.
"""

from __future__ import annotations

from ..ai_analysis_service import (
    AnthropicProvider,
    GeminiProvider,
    OllamaProvider,
    OpenAIProvider,
)
from .servonaut_provider import ServonautProvider

__all__ = [
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "GeminiProvider",
    "ServonautProvider",
]
