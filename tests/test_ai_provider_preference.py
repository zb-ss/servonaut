"""Tests for the T4.5 ProviderPreferenceResolver.

Covers the 6-row decision table, transition detection, lapse fallback
ranking, banner gating, dismiss-forever persistence, and reset.

Strategy: real :class:`ConfigManager` instances backed by tmp-dir
fixtures, mocked :class:`AuthService` via ``MagicMock`` configured with
the relevant ``_token`` attributes. The resolver is pure so we can call
``resolve()`` end-to-end without a TUI.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AIProviderConfig, AppConfig, CONFIG_VERSION
from servonaut.services.ai_provider_preference import (
    CAPABILITY_BANNER_ID,
    PAYING_TWICE_BANNER_ID,
    ProviderDecision,
    ProviderPreferenceEvent,
    ProviderPreferenceResolver,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_config_manager(
    tmp_path: Path,
    *,
    ai_provider: AIProviderConfig | None = None,
) -> "MagicMock":
    """Build a MagicMock-backed ConfigManager whose ``get`` returns a real AppConfig.

    The resolver only ever calls ``config_manager.get()`` and
    ``config_manager.save(config)`` so a thin mock is plenty — no JSON
    round-trip needed for these tests. We DO let ``save`` mutate a stored
    reference so ``commit_first_run_choice`` / ``dismiss_banner`` /
    ``reset`` can be tested for persistence.
    """
    state = {
        "config": AppConfig(
            ai_provider=ai_provider or AIProviderConfig(),
        ),
    }
    cm = MagicMock()
    cm.get.side_effect = lambda: state["config"]

    def _save(new_config: AppConfig) -> None:
        state["config"] = new_config

    cm.save.side_effect = _save
    return cm


def _make_auth(
    *,
    authenticated: bool = True,
    has_features: dict | None = None,
    premium_ai_was_active: bool = False,
    last_used_provider: str = "",
    settings_last_visited_at: float = 0.0,
    entitlements: dict | None = None,
) -> MagicMock:
    """Build a MagicMock auth service with the AuthToken attrs the resolver reads."""
    has_features = has_features or {}

    def _has_feature(name: str) -> bool:
        return bool(has_features.get(name, False))

    token = SimpleNamespace(
        premium_ai_was_active=premium_ai_was_active,
        last_used_provider=last_used_provider,
        settings_last_visited_at=settings_last_visited_at,
        entitlements=entitlements or {},
    )
    auth = MagicMock()
    auth.is_authenticated = authenticated
    auth.has_feature = MagicMock(side_effect=_has_feature)
    auth._token = token if authenticated else None
    return auth


# ---------------------------------------------------------------------------
# Decision-table tests
# ---------------------------------------------------------------------------


def test_subscribed_no_other_providers_uses_servonaut(tmp_path):
    """Row 3: subscribed, no other provider → active = servonaut, no events."""
    cm = _make_config_manager(tmp_path, ai_provider=AIProviderConfig())
    auth = _make_auth(has_features={"premium_ai": True})

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "servonaut"
    assert decision.events == []


def test_subscribed_with_ollama_no_preference_emits_first_run_modal(tmp_path):
    """Row 2: subscribed + ollama configured + no preference → modal fires."""
    ai = AIProviderConfig(base_url="http://localhost:11434")
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(has_features={"premium_ai": True})

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "servonaut"
    assert ProviderPreferenceEvent.SHOW_FIRST_RUN_MODAL in decision.events


def test_subscribed_with_ollama_preference_servonaut_uses_servonaut(tmp_path):
    """Row 1 — preference servonaut wins, modal does NOT fire again."""
    ai = AIProviderConfig(
        base_url="http://localhost:11434",
        provider_preference="servonaut",
    )
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(has_features={"premium_ai": True})

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "servonaut"
    assert ProviderPreferenceEvent.SHOW_FIRST_RUN_MODAL not in decision.events


def test_subscribed_with_ollama_preference_ollama_uses_ollama(tmp_path):
    """Row 1 — preference ollama wins; user chose to keep their local provider."""
    ai = AIProviderConfig(
        base_url="http://localhost:11434",
        provider_preference="ollama",
    )
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(has_features={"premium_ai": True})

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "ollama"
    assert ProviderPreferenceEvent.SHOW_FIRST_RUN_MODAL not in decision.events


def test_unsubscribed_with_providers_no_preference_uses_first_configured(tmp_path):
    """Row 5: unsubscribed + providers configured + no preference → first wins.

    Order is openai → anthropic → ollama → gemini per ``_FALLBACK_RANK``.
    With openai configured, openai must be picked.
    """
    ai = AIProviderConfig(api_key="sk-test", base_url="http://localhost:11434")
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(has_features={"premium_ai": False})

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "openai"


def test_unsubscribed_no_providers_emits_empty_state(tmp_path):
    """Row 6: unsubscribed AND nothing configured → empty-state event."""
    cm = _make_config_manager(tmp_path, ai_provider=AIProviderConfig(api_key=""))
    auth = _make_auth(has_features={"premium_ai": False})

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == ""
    assert ProviderPreferenceEvent.SHOW_EMPTY_STATE in decision.events


# ---------------------------------------------------------------------------
# Transition + lapse handling
# ---------------------------------------------------------------------------


def test_premium_ai_activated_transition_detected(tmp_path):
    """``premium_ai_was_active=False`` and currently True → ``"activated"``."""
    cm = _make_config_manager(tmp_path)
    auth = _make_auth(
        has_features={"premium_ai": True},
        premium_ai_was_active=False,
    )

    resolver = ProviderPreferenceResolver(auth, cm)

    assert resolver.detect_premium_ai_transition() == "activated"


def test_premium_ai_lapsed_with_ollama_silent_fallback(tmp_path):
    """Lapsed sub + ollama configured → SILENT_LAPSE with fallback=ollama."""
    ai = AIProviderConfig(base_url="http://localhost:11434")
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(
        has_features={"premium_ai": False},
        premium_ai_was_active=True,
    )

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "ollama"
    assert decision.fallback_provider == "ollama"
    assert ProviderPreferenceEvent.SILENT_LAPSE in decision.events


def test_premium_ai_lapsed_with_no_provider_pinned_error(tmp_path):
    """Lapsed sub with NOTHING configured → PINNED_ERROR_NO_PROVIDER."""
    cm = _make_config_manager(tmp_path)
    auth = _make_auth(
        has_features={"premium_ai": False},
        premium_ai_was_active=True,
    )

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == ""
    assert decision.fallback_provider is None
    assert (
        ProviderPreferenceEvent.PINNED_ERROR_NO_PROVIDER in decision.events
    )


# ---------------------------------------------------------------------------
# Banner gating
# ---------------------------------------------------------------------------


def test_paying_twice_banner_for_openai_active(tmp_path):
    """premium_ai true + active=openai + Settings stale + not dismissed → banner."""
    ai = AIProviderConfig(api_key="sk-test", provider_preference="openai")
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    # settings_last_visited_at = 0.0 → treat as stale per agent brief.
    auth = _make_auth(
        has_features={"premium_ai": True},
        settings_last_visited_at=0.0,
    )

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "openai"
    assert (
        ProviderPreferenceEvent.SHOW_PAYING_TWICE_BANNER in decision.events
    )
    assert decision.dismissable_banner_id == PAYING_TWICE_BANNER_ID


def test_paying_twice_banner_NOT_for_ollama_active(tmp_path):
    """When the active provider is Ollama, the cost-framed banner does NOT fire."""
    ai = AIProviderConfig(
        base_url="http://localhost:11434",
        provider_preference="ollama",
    )
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(
        has_features={"premium_ai": True},
        settings_last_visited_at=0.0,
    )

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "ollama"
    assert (
        ProviderPreferenceEvent.SHOW_PAYING_TWICE_BANNER
        not in decision.events
    )


def test_capability_banner_for_ollama_active(tmp_path):
    """Active provider == ollama → capability-framed banner fires."""
    ai = AIProviderConfig(
        base_url="http://localhost:11434",
        provider_preference="ollama",
    )
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(has_features={"premium_ai": False})

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "ollama"
    assert (
        ProviderPreferenceEvent.SHOW_CAPABILITY_BANNER in decision.events
    )
    assert decision.dismissable_banner_id == CAPABILITY_BANNER_ID


def test_capability_banner_NOT_for_cloud_active(tmp_path):
    """Capability banner only fires when active == ollama, never for cloud."""
    ai = AIProviderConfig(api_key="sk-test", provider_preference="openai")
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    # Make Settings recent so the paying-twice banner is suppressed too,
    # isolating the assertion on capability-banner absence.
    auth = _make_auth(
        has_features={"premium_ai": True},
        settings_last_visited_at=time.time(),
    )

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert decision.active_provider == "openai"
    assert (
        ProviderPreferenceEvent.SHOW_CAPABILITY_BANNER not in decision.events
    )


def test_dismissed_banner_does_not_re_emit(tmp_path):
    """Banner ID present in dismissed_banners → resolver suppresses the event."""
    ai = AIProviderConfig(
        api_key="sk-test",
        provider_preference="openai",
        dismissed_banners=[PAYING_TWICE_BANNER_ID],
    )
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(
        has_features={"premium_ai": True},
        settings_last_visited_at=0.0,
    )

    decision = ProviderPreferenceResolver(auth, cm).resolve()

    assert (
        ProviderPreferenceEvent.SHOW_PAYING_TWICE_BANNER
        not in decision.events
    )
    assert decision.dismissable_banner_id is None


def test_dismiss_banner_persists(tmp_path):
    """``dismiss_banner`` writes the id to config and is idempotent."""
    ai = AIProviderConfig()
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(has_features={"premium_ai": True})
    resolver = ProviderPreferenceResolver(auth, cm)

    resolver.dismiss_banner(PAYING_TWICE_BANNER_ID)
    resolver.dismiss_banner(PAYING_TWICE_BANNER_ID)  # idempotent

    persisted = cm.get().ai_provider.dismissed_banners
    assert persisted == [PAYING_TWICE_BANNER_ID]


def test_reset_clears_preference_and_banners(tmp_path):
    """``reset`` clears both ``provider_preference`` and ``dismissed_banners``."""
    ai = AIProviderConfig(
        provider_preference="ollama",
        dismissed_banners=[PAYING_TWICE_BANNER_ID, CAPABILITY_BANNER_ID],
    )
    cm = _make_config_manager(tmp_path, ai_provider=ai)
    auth = _make_auth(has_features={"premium_ai": True})
    resolver = ProviderPreferenceResolver(auth, cm)

    resolver.reset()

    config = cm.get()
    assert config.ai_provider.provider_preference is None
    assert config.ai_provider.dismissed_banners == []
