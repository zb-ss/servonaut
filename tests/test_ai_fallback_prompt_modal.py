"""Tests for :class:`AIFallbackPromptModal` copy overrides.

The modal serves two paths: the T10 auto-fallback (Servonaut AI broke
twice in 60s) AND the user-driven session-switch button on the chat
panel. Without override args, the title hardcoded "Servonaut AI is
unavailable." which made the user-driven path look like an outage
notice every time the user clicked the provider button on a working
chat. These tests pin the override behaviour so the user-driven copy
can't silently regress.
"""
from __future__ import annotations

import pytest

from servonaut.screens.ai_fallback_prompt_modal import AIFallbackPromptModal


def test_default_copy_preserves_t10_title_and_keep_label():
    """The T10 caller passes no overrides — its alarm-style copy must
    survive unchanged so an actual upstream failure still reads as one."""
    modal = AIFallbackPromptModal(["openai"], reason="upstream timeout")

    assert modal._title == "Servonaut AI is unavailable."
    assert modal._keep_label == "Keep retrying"
    assert "local providers" in modal._body


def test_override_title_body_and_keep_label():
    modal = AIFallbackPromptModal(
        ["openai", "ollama"],
        title="Switch AI provider",
        body="Pick the provider to use for this chat session.",
        keep_label="Cancel",
    )

    assert modal._title == "Switch AI provider"
    assert modal._body == "Pick the provider to use for this chat session."
    assert modal._keep_label == "Cancel"


def test_overrides_are_keyword_only():
    """Positional misuse should fail — the overrides are keyword-only
    so future additions don't shift positional meaning silently."""
    with pytest.raises(TypeError):
        AIFallbackPromptModal(["openai"], "reason", "title-positional")


def test_empty_overrides_fall_back_to_defaults():
    """Empty / whitespace-only overrides must fall back to the defaults
    rather than render a blank header / button (UI footgun)."""
    modal = AIFallbackPromptModal(
        ["openai"],
        title="   ",
        body="",
        keep_label=None,
    )

    assert modal._title == "Servonaut AI is unavailable."
    assert "local providers" in modal._body
    assert modal._keep_label == "Keep retrying"


def test_provider_normalisation_dedupes_and_lowercases():
    """Pre-existing contract — re-pinned here because the manual
    switcher feeds the modal a list assembled from two different
    sources (auth + resolver) and a duplicate slipping through would
    render two identical buttons."""
    modal = AIFallbackPromptModal(
        ["OpenAI", "openai", "  Ollama  ", "", None],  # type: ignore[list-item]
    )

    assert modal._available == ["openai", "ollama"]
