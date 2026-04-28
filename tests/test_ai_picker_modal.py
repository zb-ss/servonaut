"""Tests for the T4.5 first-run + empty-state provider picker modals.

Uses Textual's ``App.run_test`` pattern (matches
``tests/test_confirm_action.py``) so we exercise the real button IDs +
dismiss values rather than introspecting compose() output. Also covers
the small label-formatting helpers since they're load-bearing for
"Currently configured: [Ollama @ localhost:11434]".
"""
from __future__ import annotations

import pytest
from textual.app import App
from textual.widgets import Button

from servonaut.screens.ai_picker_modal import (
    AIEmptyStateModal,
    AIProviderFirstRunModal,
    _format_existing_provider_label,
    _short_provider_name,
)


# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------


def test_format_existing_provider_label_ollama_default():
    """Default Ollama URL renders as "Ollama @ localhost:11434"."""
    label = _format_existing_provider_label(
        "ollama", "http://localhost:11434",
    )
    assert label == "Ollama @ localhost:11434"


def test_format_existing_provider_label_ollama_https_strip():
    """The scheme is stripped for both http:// and https:// for compactness."""
    label = _format_existing_provider_label(
        "ollama", "https://gpu-box.example:443",
    )
    assert label == "Ollama @ gpu-box.example:443"


def test_format_existing_provider_label_openai_capitalised():
    """Cloud providers render as their canonical label, not lowercase."""
    assert _format_existing_provider_label("openai") == "OpenAI"
    assert _format_existing_provider_label("anthropic") == "Anthropic"
    assert _format_existing_provider_label("gemini") == "Gemini"


def test_short_provider_name_known_providers():
    """The short name is used in the "Keep [Ollama]" button label."""
    assert _short_provider_name("ollama") == "Ollama"
    assert _short_provider_name("openai") == "OpenAI"
    assert _short_provider_name("") == "Existing"


# ---------------------------------------------------------------------------
# First-run modal — buttons + dismiss values
# ---------------------------------------------------------------------------


class _WrapperApp(App):
    """Minimal host app to push a modal for testing."""

    def __init__(self, modal) -> None:
        super().__init__()
        self._modal = modal
        self.dismissed = []

    def on_mount(self) -> None:
        # Capture the dismiss return value via callback so the test can
        # verify what the modal returned without subclassing dismiss().
        self.push_screen(self._modal, callback=self.dismissed.append)


@pytest.mark.asyncio
async def test_first_run_modal_returns_servonaut_on_switch_button():
    """Clicking "Switch to Servonaut AI" dismisses with ``"servonaut"``."""
    modal = AIProviderFirstRunModal(
        existing_provider="ollama",
        base_url="http://localhost:11434",
    )
    app = _WrapperApp(modal)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.click("#btn_pick_servonaut")
        await pilot.pause()

    assert app.dismissed == ["servonaut"]


@pytest.mark.asyncio
async def test_first_run_modal_returns_other_provider_on_keep_button():
    """Clicking "Keep Ollama" dismisses with the canonical provider name."""
    modal = AIProviderFirstRunModal(
        existing_provider="ollama",
        base_url="http://localhost:11434",
    )
    app = _WrapperApp(modal)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.click("#btn_pick_existing")
        await pilot.pause()

    assert app.dismissed == ["ollama"]


@pytest.mark.asyncio
async def test_first_run_modal_returns_none_on_escape():
    """Escape dismisses with ``None`` (no preference written)."""
    modal = AIProviderFirstRunModal(existing_provider="openai")
    app = _WrapperApp(modal)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()

    assert app.dismissed == [None]


@pytest.mark.asyncio
async def test_first_run_modal_button_ids_present():
    """Smoke: the documented button IDs are mounted."""
    modal = AIProviderFirstRunModal(existing_provider="ollama")
    app = _WrapperApp(modal)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        ids = {
            b.id for b in app.screen.query("Button").results(Button)
            if b.id is not None
        }
        assert "btn_pick_servonaut" in ids
        assert "btn_pick_existing" in ids


# ---------------------------------------------------------------------------
# Empty-state modal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_state_modal_returns_subscribe():
    """Subscribe button → dismiss with ``"subscribe"``."""
    modal = AIEmptyStateModal()
    app = _WrapperApp(modal)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.click("#btn_empty_subscribe")
        await pilot.pause()

    assert app.dismissed == ["subscribe"]


@pytest.mark.asyncio
async def test_empty_state_modal_returns_add_api_key():
    """Add-API-key button → dismiss with ``"add_api_key"``."""
    modal = AIEmptyStateModal()
    app = _WrapperApp(modal)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.click("#btn_empty_add_key")
        await pilot.pause()

    assert app.dismissed == ["add_api_key"]


@pytest.mark.asyncio
async def test_empty_state_modal_returns_ollama():
    """Set up Ollama button → dismiss with ``"ollama"``."""
    modal = AIEmptyStateModal()
    app = _WrapperApp(modal)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.click("#btn_empty_ollama")
        await pilot.pause()

    assert app.dismissed == ["ollama"]
