"""First-run / empty-state modal push tests (B2).

The chat panel owns the first-run choice modal and the empty-state
onboarding modal. Each is pushed exactly once per session — re-renders
must NOT re-push (which would stomp the user's input).

The modal classes themselves are tested in
``test_ai_picker_modal.py``; here we only verify the push lifecycle.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from servonaut.screens.ai_picker_modal import (
    AIEmptyStateModal,
    AIProviderFirstRunModal,
)
from servonaut.services.ai_provider_preference import (
    ProviderDecision,
    ProviderPreferenceEvent,
)


def _build_panel():
    from servonaut.widgets.chat_panel import ChatPanel

    panel = ChatPanel.__new__(ChatPanel)
    panel._stale_cache = {}
    panel._upstream_failures = []
    panel._session_provider_override = None
    panel._last_fallback_used = False
    panel._last_soft_capped = False
    panel._last_hard_capped = False
    panel._remote_conversation_id = None
    panel._pinned_error_active = False
    panel._first_run_modal_shown = False
    panel._empty_state_modal_shown = False
    panel._thinking = False
    panel._total_tokens = 0
    panel._total_cost = 0.0
    panel._model = ""
    panel._session = None
    return panel


def _attach_app(panel, resolver):
    app = MagicMock()
    app.provider_preference_resolver = resolver
    app.push_screen = MagicMock()
    app.notify = MagicMock()

    cfg = MagicMock()
    cfg.ai_provider = MagicMock()
    cfg.ai_provider.base_url = ""
    config_manager = MagicMock()
    config_manager.get.return_value = cfg
    app.config_manager = config_manager

    type(panel).app = property(lambda self, _a=app: _a)  # type: ignore[assignment]
    return app


def test_first_run_modal_pushed_when_resolver_emits_event():
    """B2 — SHOW_FIRST_RUN_MODAL drives ``app.push_screen(AIProviderFirstRunModal)``."""
    panel = _build_panel()

    resolver = MagicMock()
    resolver.resolve.return_value = ProviderDecision(
        active_provider="servonaut",
        events=[ProviderPreferenceEvent.SHOW_FIRST_RUN_MODAL],
    )
    resolver.is_provider_configured.side_effect = lambda name: name == "ollama"

    app = _attach_app(panel, resolver)
    panel._set_banner = MagicMock()  # type: ignore[assignment]

    panel._check_provider_decision_events()

    assert app.push_screen.called, (
        "Resolver emitted SHOW_FIRST_RUN_MODAL but no modal was pushed"
    )
    pushed = app.push_screen.call_args.args[0]
    assert isinstance(pushed, AIProviderFirstRunModal)
    assert panel._first_run_modal_shown is True


def test_first_run_modal_pushed_only_once_per_session():
    """B2 — re-rendering doesn't re-push the modal.

    The flag ``_first_run_modal_shown`` is per-instance and never
    reset. Two consecutive ``_check_provider_decision_events`` calls
    with the same resolver state must result in exactly one push.
    """
    panel = _build_panel()

    resolver = MagicMock()
    resolver.resolve.return_value = ProviderDecision(
        active_provider="servonaut",
        events=[ProviderPreferenceEvent.SHOW_FIRST_RUN_MODAL],
    )
    resolver.is_provider_configured.side_effect = lambda name: name == "ollama"

    app = _attach_app(panel, resolver)
    panel._set_banner = MagicMock()  # type: ignore[assignment]

    panel._check_provider_decision_events()
    panel._check_provider_decision_events()

    assert app.push_screen.call_count == 1, (
        f"First-run modal pushed {app.push_screen.call_count} times — "
        "expected exactly 1 per session"
    )


def test_empty_state_modal_pushed_when_resolver_emits_event():
    """B2 — SHOW_EMPTY_STATE drives ``app.push_screen(AIEmptyStateModal)``."""
    panel = _build_panel()

    resolver = MagicMock()
    resolver.resolve.return_value = ProviderDecision(
        active_provider="",
        events=[ProviderPreferenceEvent.SHOW_EMPTY_STATE],
    )

    app = _attach_app(panel, resolver)
    panel._set_banner = MagicMock()  # type: ignore[assignment]

    panel._check_provider_decision_events()

    assert app.push_screen.called
    pushed = app.push_screen.call_args.args[0]
    assert isinstance(pushed, AIEmptyStateModal)
    assert panel._empty_state_modal_shown is True


def test_empty_state_modal_pushed_only_once_per_session():
    """B2 — empty-state modal is also one-shot per session."""
    panel = _build_panel()

    resolver = MagicMock()
    resolver.resolve.return_value = ProviderDecision(
        active_provider="",
        events=[ProviderPreferenceEvent.SHOW_EMPTY_STATE],
    )

    app = _attach_app(panel, resolver)
    panel._set_banner = MagicMock()  # type: ignore[assignment]

    panel._check_provider_decision_events()
    panel._check_provider_decision_events()

    assert app.push_screen.call_count == 1
