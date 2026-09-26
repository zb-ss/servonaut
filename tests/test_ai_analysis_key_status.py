"""The AI Analysis screen's provider line reports per-provider API keys.

Keys are stored per provider (``openai_api_key`` etc.); the legacy shared
``api_key`` is only a fallback for the provider it was saved for. The
provider line must read through ``AIProviderConfig.key_for``.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AIProviderConfig, AppConfig
from servonaut.screens.ai_analysis import AIAnalysisScreen


@pytest.mark.parametrize(
    "config, expected",
    [
        # Per-provider key only — the case that used to read "not set".
        (AIProviderConfig(provider="anthropic", anthropic_api_key="sk-ant-x"), "set"),
        (AIProviderConfig(provider="gemini", gemini_api_key="g-key"), "set"),
        # Legacy shared key still counts for the provider it was saved for.
        (AIProviderConfig(provider="openai", api_key="sk-legacy"), "set"),
        # ...but a key stored for another provider does not.
        (AIProviderConfig(provider="anthropic", openai_api_key="sk-openai"), "not set"),
        (AIProviderConfig(provider="openai"), "not set"),
        # Ollama: a key is optional (Ollama Cloud only).
        (AIProviderConfig(provider="ollama", ollama_api_key="oc-key"), "set"),
        (AIProviderConfig(provider="ollama"), "n/a"),
        (AIProviderConfig(provider="servonaut"), "OAuth bearer"),
        (AIProviderConfig(provider="openai", openai_api_key="$UNSET_TEST_VAR_X"), "ref unresolved"),
    ],
)
def test_key_status_reads_the_selected_providers_key(monkeypatch, config, expected):
    monkeypatch.delenv("UNSET_TEST_VAR_X", raising=False)
    assert expected in AIAnalysisScreen._key_status_markup(config)


def test_provider_line_shows_per_provider_key_as_set():
    app = MagicMock()
    app.config_manager.get.return_value = AppConfig(
        ai_provider=AIProviderConfig(
            provider="anthropic", anthropic_api_key="sk-ant-x",
        ),
    )
    app.auth_service = None

    class _Screen(AIAnalysisScreen):
        pass

    _Screen.app = property(lambda _self: app)
    screen = _Screen.__new__(_Screen)

    provider_line = screen._compose_provider_picker_lines()[-1]
    assert "API Key: [green]set[/green]" in provider_line
