"""Tests for the AI Provider panel's Servonaut-AI status row.

Historically the inline "✓ 15M tokens left" number could go stale (chat
sessions chew through tokens between Settings opens but the cache wasn't
refreshed).  The user's ask was "show an accurate number or don't show
anything".  The settings refactor resolved this by dropping the inline number
entirely: the status row now only reports the gating state
(``locked``/``ready``), so a stale count can never be shown.

Invariants under test (against ``AiProviderPanel._refresh_servonaut_status``):

1. Unauthenticated users see a login prompt and the upgrade affordance.
2. Authenticated non-premium users see the upgrade prompt.
3. Premium users see ``ready`` with NO token number and the upgrade hidden.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from servonaut.screens.settings.panels.ai_provider import AiProviderPanel


class _FakeStatus:
    def __init__(self):
        self.text = ""

    def update(self, markup):
        self.text = markup


class _FakeButton:
    def __init__(self):
        self.display = True


class _FakePanel:
    """Duck-typed stand-in: ``_refresh_servonaut_status`` only touches
    ``self.app`` and ``self.query_one``."""

    def __init__(self, *, authenticated, premium):
        self.status = _FakeStatus()
        self.upgrade = _FakeButton()

        auth = SimpleNamespace(
            is_authenticated=authenticated,
            has_feature=lambda flag: premium and flag == "premium_ai",
        )
        app = MagicMock()
        app.auth_service = auth
        self._app = app

    @property
    def app(self):  # mimic Textual Widget.app property
        return self._app

    def query_one(self, selector, _cls=None):
        if "ai_provider_servonaut_status" in selector:
            return self.status
        if "ai_provider_upgrade" in selector:
            return self.upgrade
        raise KeyError(selector)


def _refresh(panel):
    AiProviderPanel._refresh_servonaut_status(panel)  # type: ignore[arg-type]


def test_premium_user_shows_ready_no_number():
    """The fix the user asked for: premium → 'ready', never a token number."""
    panel = _FakePanel(authenticated=True, premium=True)
    _refresh(panel)
    assert "ready" in panel.status.text
    assert "tokens left" not in panel.status.text
    # No stale inline quota number can leak through.
    assert "M" not in panel.status.text
    assert panel.upgrade.display is False


def test_unauthenticated_shows_login_required():
    panel = _FakePanel(authenticated=False, premium=False)
    _refresh(panel)
    assert "Login required" in panel.status.text
    assert panel.upgrade.display is True


def test_authenticated_non_premium_shows_solo_or_teams():
    panel = _FakePanel(authenticated=True, premium=False)
    _refresh(panel)
    assert "Solo or Teams" in panel.status.text
    assert panel.upgrade.display is True
