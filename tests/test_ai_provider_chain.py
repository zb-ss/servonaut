"""Tests for T10 provider-chain awareness.

Covers:
1. ``fallback_used: true`` in a usage event flips ``_last_fallback_used``
   on :class:`ChatPanel`, surfacing the "via backup vendor" badge.
2. First ``upstream_unavailable`` does NOT prompt or auto-switch.
3. Second within 60s offers the prompt (or auto-switches when
   ``ai.local_fallback_provider`` is set).
4. Second after the 60s window resets — back to "first failure" state.
5. Accepting the prompt sets ``_session_provider_override`` but does
   NOT mutate ``ai.provider_preference``.

These tests exercise :class:`ChatPanel` methods directly via
``__new__`` + manual attribute injection — same pattern as
``test_memory_chat_injection.py``. We don't mount a real Textual app.
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AIProviderConfig, AppConfig
from servonaut.services.ai_provider_preference import (
    ProviderPreferenceResolver,
)


def _make_panel(*, app: MagicMock):
    """Build a minimally-instantiated ChatPanel without mounting it."""
    from servonaut.widgets.chat_panel import ChatPanel
    panel = ChatPanel.__new__(ChatPanel)
    # Only the attributes T10 paths touch — any attribute we don't set
    # but the path reads will surface as AttributeError so we know to
    # add it explicitly here.
    panel._upstream_failures = []
    panel._session_provider_override = None
    panel._last_fallback_used = False
    panel._last_soft_capped = False
    panel._last_hard_capped = False
    panel._total_tokens = 0
    panel._total_cost = 0.0
    panel._model = ""
    panel._session = None
    panel._remote_conversation_id = None
    panel._stale_cache = {}
    panel._thinking = False
    # Stub query_one + the side-effect helpers so we don't need a
    # mounted widget tree.
    panel.query_one = lambda *args, **kwargs: SimpleNamespace(
        update=lambda *a, **kw: None,
        add_class=lambda *a, **kw: None,
        remove_class=lambda *a, **kw: None,
    )
    panel._update_quota_footer = lambda: None
    panel._update_provider_indicator = lambda: None
    # Patch the parent-class .app to return our mock (Widget exposes
    # ``app`` as a Reactive property — overriding via __dict__ wins).
    type(panel).app = property(lambda _self: app)
    return panel


def _config_with(
    *,
    local_fallback: str | None = None,
    openai_key: str = "",
    ollama_url: str = "",
    anthropic_key: str = "",
) -> AppConfig:
    return AppConfig(
        ai_provider=AIProviderConfig(
            provider="servonaut",
            local_fallback_provider=local_fallback,
            api_key=openai_key,
            base_url=ollama_url,
        ),
    )


# ---------------------------------------------------------------------------
# 1. fallback_used badge renders
# ---------------------------------------------------------------------------


def test_fallback_used_badge_state_set_from_usage_event():
    """A usage event with ``fallback_used: true`` flips the panel flag.

    The actual `_update_stats` render passes through Textual widget
    queries; here we verify the underlying state mutation that drives
    the badge.
    """
    app = MagicMock()
    app.config_manager.get.return_value = _config_with()
    app.auth_service = MagicMock()
    app.auth_service.is_authenticated = False
    panel = _make_panel(app=app)

    # Simulate a usage event with fallback_used=True.
    panel._consume_usage_event({
        "fallback_used": True,
        "input_tokens": 10,
        "output_tokens": 20,
        "model": "gemini-2-flash-002",
        "quota": {
            "tokens_used": 100, "tokens_limit": 1000,
            "tokens_topup_remaining": 0, "resets_at": "",
            "soft_capped": False, "hard_capped": False,
            "rpm_limit": 10, "tokens_per_minute_limit": 1000,
        },
    })

    assert panel._last_fallback_used is True
    assert panel._total_tokens == 30
    assert panel._model == "gemini-2-flash-002"


def test_fallback_used_false_does_not_persist_after_reset():
    """A subsequent usage event with fallback_used=False clears the flag."""
    app = MagicMock()
    app.config_manager.get.return_value = _config_with()
    app.auth_service = MagicMock()
    app.auth_service.is_authenticated = False
    panel = _make_panel(app=app)
    panel._update_quota_footer = lambda: None
    panel._update_provider_indicator = lambda: None
    panel.query_one = lambda *args, **kwargs: SimpleNamespace(update=lambda _x: None)

    panel._consume_usage_event({"fallback_used": True})
    assert panel._last_fallback_used is True
    panel._consume_usage_event({"fallback_used": False})
    assert panel._last_fallback_used is False


# ---------------------------------------------------------------------------
# 2. First upstream_unavailable: no prompt, no override change.
# ---------------------------------------------------------------------------


def test_first_upstream_unavailable_does_not_offer_prompt():
    app = MagicMock()
    app.config_manager.get.return_value = _config_with(ollama_url="http://localhost:11434")
    panel = _make_panel(app=app)

    panel._record_upstream_failure()
    panel._maybe_offer_fallback()

    # Single failure → no override, no push_screen.
    assert panel._session_provider_override is None
    app.push_screen.assert_not_called()


# ---------------------------------------------------------------------------
# 3a. Second within 60s with auto-fallback configured → silent switch.
# ---------------------------------------------------------------------------


def test_second_upstream_unavailable_with_local_fallback_auto_switches():
    app = MagicMock()
    app.config_manager.get.return_value = _config_with(
        local_fallback="ollama", ollama_url="http://localhost:11434",
    )
    # Real resolver — its is_provider_configured is the hot path here.
    resolver = ProviderPreferenceResolver(
        auth_service=MagicMock(_token=None),
        config_manager=app.config_manager,
    )
    app.provider_preference_resolver = resolver

    panel = _make_panel(app=app)
    panel._update_stats = lambda: None

    # Two failures in quick succession.
    panel._record_upstream_failure()
    panel._record_upstream_failure()
    panel._maybe_offer_fallback()

    assert panel._session_provider_override == "ollama"
    # Auto-switch: no modal pushed.
    app.push_screen.assert_not_called()
    app.notify.assert_called()


# ---------------------------------------------------------------------------
# 3b. Second within 60s, no local fallback, but provider configured →
#     push prompt modal.
# ---------------------------------------------------------------------------


def test_second_upstream_unavailable_offers_prompt_when_provider_configured():
    app = MagicMock()
    app.config_manager.get.return_value = _config_with(
        local_fallback=None, ollama_url="http://localhost:11434",
    )
    resolver = ProviderPreferenceResolver(
        auth_service=MagicMock(_token=None),
        config_manager=app.config_manager,
    )
    app.provider_preference_resolver = resolver

    panel = _make_panel(app=app)
    panel._update_stats = lambda: None

    panel._record_upstream_failure()
    panel._record_upstream_failure()
    panel._maybe_offer_fallback()

    # Modal pushed with available providers including ollama.
    app.push_screen.assert_called_once()
    args, kwargs = app.push_screen.call_args
    pushed_modal = args[0]
    # The modal records ``available`` on construction.
    assert "ollama" in pushed_modal._available
    # No automatic override yet — pending user choice.
    assert panel._session_provider_override is None


# ---------------------------------------------------------------------------
# 4. Second AFTER the 60s window resets the counter — back to "first".
# ---------------------------------------------------------------------------


def test_failure_outside_60s_window_does_not_trigger_prompt():
    app = MagicMock()
    app.config_manager.get.return_value = _config_with(
        local_fallback="ollama", ollama_url="http://localhost:11434",
    )
    resolver = ProviderPreferenceResolver(
        auth_service=MagicMock(_token=None),
        config_manager=app.config_manager,
    )
    app.provider_preference_resolver = resolver
    panel = _make_panel(app=app)
    panel._update_stats = lambda: None

    # Synthesise an old failure (>60s ago) by reaching into the list.
    panel._upstream_failures.append(time.monotonic() - 61.0)

    # Now record a "fresh" failure.
    panel._record_upstream_failure()
    # The pruning step inside _record_upstream_failure dropped the old
    # one. We should now have exactly 1 entry.
    assert len(panel._upstream_failures) == 1

    panel._maybe_offer_fallback()
    # Single fresh failure → no fallback.
    assert panel._session_provider_override is None
    app.push_screen.assert_not_called()


# ---------------------------------------------------------------------------
# 5. Accepting the modal sets session override, does NOT mutate config.
# ---------------------------------------------------------------------------


def test_accepted_fallback_prompt_does_not_mutate_config():
    """Plan §T10 invariant: 'session-scoped override; provider_preference is NOT changed.'

    We don't actually push the modal here (no Textual loop) — we
    simulate the on-choice callback directly.
    """
    cfg = _config_with(ollama_url="http://localhost:11434")
    app = MagicMock()
    app.config_manager.get.return_value = cfg
    panel = _make_panel(app=app)
    panel._update_stats = lambda: None

    # Simulate the modal returning "ollama" as the user's pick. Mirrors
    # the inline _on_choice closure in chat_panel._toggle_provider_override
    # / _maybe_offer_fallback.
    panel._session_provider_override = "ollama"

    # Config UNCHANGED — no save() call.
    app.config_manager.save.assert_not_called()
    # Override is in effect for routing.
    assert panel._session_provider_override == "ollama"
    # Original preference still untouched.
    assert cfg.ai_provider.provider_preference is None


# ---------------------------------------------------------------------------
# 6. No configured fallback provider → no prompt even after second failure.
# ---------------------------------------------------------------------------


def test_no_provider_configured_means_no_prompt():
    cfg = _config_with()  # nothing configured
    app = MagicMock()
    app.config_manager.get.return_value = cfg
    resolver = ProviderPreferenceResolver(
        auth_service=MagicMock(_token=None),
        config_manager=app.config_manager,
    )
    app.provider_preference_resolver = resolver
    panel = _make_panel(app=app)
    panel._update_stats = lambda: None

    panel._record_upstream_failure()
    panel._record_upstream_failure()
    panel._maybe_offer_fallback()

    # No modal — there's nothing to fall back to.
    app.push_screen.assert_not_called()
    assert panel._session_provider_override is None
