"""Pinned-error UI consumer tests (B1).

The provider preference resolver emits ``PINNED_ERROR_NO_PROVIDER`` when
the user lapses out of ``premium_ai`` AND no other provider is configured.
The chat panel must:

- Render a non-dismissable banner with /Resubscribe/ + /Add a provider/
  buttons.
- Disable the input field and Send button so the user cannot type into a
  broken pipeline.

These tests pin both behaviours by driving
:meth:`ChatPanel._check_provider_decision_events` against a stubbed
resolver that returns the pinned-error event.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from servonaut.services.ai_provider_preference import (
    ProviderDecision,
    ProviderPreferenceEvent,
)


def _build_panel():
    """Construct a :class:`ChatPanel` with init bypassed (no Textual context)."""
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


def test_pinned_error_event_disables_input_and_send():
    """B1 — receiving PINNED_ERROR_NO_PROVIDER toggles the disabled state.

    We can't mount real Textual widgets, so the test patches
    ``query_one`` to return MagicMock widgets and asserts ``disabled``
    flipped to True on each.
    """
    panel = _build_panel()

    resolver = MagicMock()
    resolver.resolve.return_value = ProviderDecision(
        active_provider="",
        events=[ProviderPreferenceEvent.PINNED_ERROR_NO_PROVIDER],
    )

    app = MagicMock()
    app.provider_preference_resolver = resolver
    type(panel).app = property(lambda self, _a=app: _a)  # type: ignore[assignment]

    banner = MagicMock()
    banner.remove_class = MagicMock()
    banner.add_class = MagicMock()

    chat_input = MagicMock()
    chat_input.disabled = False

    send_btn = MagicMock()
    send_btn.disabled = False

    def _query_one(selector, _kind=None):
        if selector == "#chat-pinned-error-banner":
            return banner
        if selector == "#chat-input":
            return chat_input
        if selector == "#btn-chat-send":
            return send_btn
        if selector == "#chat-banner":
            # ``_set_banner`` is also reachable when other events fire.
            return MagicMock()
        return MagicMock()

    panel.query_one = _query_one  # type: ignore[assignment]
    panel._set_banner = MagicMock()  # type: ignore[assignment]

    panel._check_provider_decision_events()

    assert panel._pinned_error_active is True
    assert chat_input.disabled is True, (
        "Chat input must be disabled while pinned-error is active"
    )
    assert send_btn.disabled is True, (
        "Send button must be disabled while pinned-error is active"
    )
    banner.remove_class.assert_called_with("hidden")


def test_pinned_error_clears_when_resolver_recovers():
    """B1 — a healthy resolve() un-pins the banner and re-enables input.

    Models the flow: lapse → resubscribe → first chat-screen render with
    ``premium_ai: true`` again. The pinned state must drop on the same
    tick.
    """
    panel = _build_panel()

    # First call: pinned. Second call: healthy.
    resolver = MagicMock()
    resolver.resolve.side_effect = [
        ProviderDecision(
            active_provider="",
            events=[ProviderPreferenceEvent.PINNED_ERROR_NO_PROVIDER],
        ),
        ProviderDecision(active_provider="servonaut", events=[]),
    ]

    app = MagicMock()
    app.provider_preference_resolver = resolver
    type(panel).app = property(lambda self, _a=app: _a)  # type: ignore[assignment]

    banner = MagicMock()
    chat_input = MagicMock()
    chat_input.disabled = False
    send_btn = MagicMock()
    send_btn.disabled = False

    def _query_one(selector, _kind=None):
        if selector == "#chat-pinned-error-banner":
            return banner
        if selector == "#chat-input":
            return chat_input
        if selector == "#btn-chat-send":
            return send_btn
        return MagicMock()

    panel.query_one = _query_one  # type: ignore[assignment]
    panel._set_banner = MagicMock()  # type: ignore[assignment]

    # First check — pinned.
    panel._check_provider_decision_events()
    assert panel._pinned_error_active is True

    # Second check — recovered.
    panel._check_provider_decision_events()
    assert panel._pinned_error_active is False
    assert chat_input.disabled is False
    assert send_btn.disabled is False
    banner.add_class.assert_called_with("hidden")
