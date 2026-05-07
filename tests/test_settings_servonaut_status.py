"""Tests for SettingsScreen's Servonaut-AI status row.

The user reported the inline "✓ 15M tokens left" number looked
hardcoded — in practice it was the cached ``entitlements.quota``
which had grown stale (chat sessions chew through tokens between
Settings opens but the cache wasn't being refreshed).

Two correctness invariants under test:

1. Without a fresh fetch, the row shows ``ready`` — never a stale
   number. (The user's explicit ask: "show an accurate number or
   don't show anything.")
2. After a successful fetch, the inline number IS shown — confirming
   the refresh path works and we're not just suppressing the count
   universally.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from servonaut.screens.settings import SettingsScreen


class _FakeStatus:
    def __init__(self):
        self.text = ""

    def update(self, markup):
        self.text = markup


class _FakeButton:
    def __init__(self):
        self.display = True


class _FakeScreen:
    """Duck-typed stand-in: ``_refresh_ai_provider_status`` only touches
    ``self.app``, ``self.query_one``, and ``self._ents_fresh``."""

    def __init__(self, *, authenticated, premium, ents_fresh, quota=None):
        self._ents_fresh = ents_fresh
        self.status = _FakeStatus()
        self.upgrade = _FakeButton()

        token = SimpleNamespace(
            entitlements=quota or {},
        )
        auth = SimpleNamespace(
            is_authenticated=authenticated,
            has_feature=lambda flag: premium and flag == "premium_ai",
            _token=token,
        )
        app = MagicMock()
        app.auth_service = auth
        self._app = app

    @property
    def app(self):  # mimic Textual Screen.app property
        return self._app

    def query_one(self, selector, _cls=None):
        if "servonaut_status" in selector:
            return self.status
        if "btn_ai_servonaut_upgrade" in selector:
            return self.upgrade
        raise KeyError(selector)


def _refresh(scr):
    # Borrow the static helper that the real method calls.
    scr._inline_quota_summary = SettingsScreen._inline_quota_summary
    SettingsScreen._refresh_ai_provider_status(scr)  # type: ignore[arg-type]


def test_premium_user_without_fresh_fetch_shows_ready_no_number():
    """The fix the user asked for: stale cache → no number, just ready."""
    scr = _FakeScreen(
        authenticated=True,
        premium=True,
        ents_fresh=False,
        quota={"quota": {"tokens_used": 0, "tokens_limit": 15_000_000}},
    )
    _refresh(scr)
    assert "ready" in scr.status.text
    assert "tokens left" not in scr.status.text
    assert "M" not in scr.status.text or scr.status.text.count("M") == 0
    assert scr.upgrade.display is False


def test_premium_user_with_fresh_fetch_shows_inline_quota():
    """Once entitlements have been refreshed, the count appears —
    confirming the refresh path actually feeds into the renderer."""
    scr = _FakeScreen(
        authenticated=True,
        premium=True,
        ents_fresh=True,
        quota={"quota": {
            "tokens_used": 0,
            "tokens_limit": 15_000_000,
            "tokens_topup_remaining": 0,
        }},
    )
    _refresh(scr)
    assert "tokens left" in scr.status.text
    assert "15M" in scr.status.text


def test_premium_user_with_fresh_fetch_but_quota_missing_falls_back_to_ready():
    """If the freshly-fetched payload doesn't carry a quota dict (free
    tier, or backend hiccup), still avoid printing a number."""
    scr = _FakeScreen(
        authenticated=True,
        premium=True,
        ents_fresh=True,
        quota={},
    )
    _refresh(scr)
    assert "ready" in scr.status.text
    assert "tokens left" not in scr.status.text


def test_unauthenticated_shows_login_required():
    scr = _FakeScreen(authenticated=False, premium=False, ents_fresh=False)
    _refresh(scr)
    assert "Login required" in scr.status.text
    assert scr.upgrade.display is True


def test_authenticated_non_premium_shows_solo_or_teams():
    scr = _FakeScreen(authenticated=True, premium=False, ents_fresh=False)
    _refresh(scr)
    assert "Solo or Teams" in scr.status.text
    assert scr.upgrade.display is True
