"""Tests for the quota display helpers in :pymod:`servonaut.utils.formatting`.

Covers the architect-plan T3 invariants for chat-panel rendering:
- ``format_tokens_remaining`` produces the documented ``"14.5M / +500K topup"``
  shape and falls back to ``"—"`` for free users.
- ``format_resets_at`` renders ISO timestamps as relative strings, never raises
  on garbage / empty input.
- ``format_soft_cap_badge`` resolves precedence (hard_capped wins).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from servonaut.utils import formatting
from servonaut.utils.formatting import (
    format_resets_at,
    format_soft_cap_badge,
    format_tokens_remaining,
)


class TestFormatTokensRemaining:
    def test_tokens_remaining_with_topup(self):
        """Standard "[14.5M / +500K topup]" rendering."""
        # 15_000_000 - 500_000 used = 14_500_000 remaining → "14.5M".
        # Plus 500_000 topup → "+500K topup".
        result = format_tokens_remaining(
            used=500_000, limit=15_000_000, topup=500_000
        )
        assert result == "14.5M / +500K topup"

    def test_tokens_remaining_no_topup(self):
        """No topup → bare remaining value."""
        result = format_tokens_remaining(
            used=500_000, limit=15_000_000, topup=0
        )
        assert result == "14.5M"

    def test_tokens_remaining_free_user(self):
        """Free user (limit=0) renders as em-dash."""
        assert format_tokens_remaining(used=0, limit=0, topup=0) == "—"

    def test_tokens_remaining_negative_topup_ignored(self):
        """Defensive: negative topup is treated as zero."""
        result = format_tokens_remaining(
            used=0, limit=10_000_000, topup=-100
        )
        assert result == "10M"

    def test_tokens_remaining_over_limit_clamps_to_zero(self):
        """Used > limit doesn't produce a negative — render as 0."""
        result = format_tokens_remaining(used=200, limit=100, topup=0)
        assert result == "0"

    def test_tokens_remaining_invalid_inputs_return_dash(self):
        """Non-int inputs degrade gracefully to em-dash."""
        result = format_tokens_remaining(  # type: ignore[arg-type]
            used="foo", limit=None, topup=0
        )
        assert result == "—"


class TestFormatResetsAt:
    def _fake_now(self, dt: datetime):
        """Return a mock object that replaces datetime.now() with ``dt``."""
        # We monkeypatch on the module so each test is independent.
        return patch.object(
            formatting, "datetime", FakeDatetime.with_now(dt)
        )

    def test_resets_at_relative_in_days(self):
        """Multi-day windows render as 'in N days'."""
        now = datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc)
        future = "2026-05-02T12:00:00+00:00"  # 4 days later
        with self._fake_now(now):
            assert format_resets_at(future) == "in 4 days"

    def test_resets_at_relative_tomorrow(self):
        """One day off renders as 'tomorrow'."""
        now = datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc)
        future = "2026-04-29T12:00:00+00:00"
        with self._fake_now(now):
            assert format_resets_at(future) == "tomorrow"

    def test_resets_at_relative_today(self):
        """Same calendar day renders as 'today'."""
        now = datetime(2026, 4, 28, 9, 0, tzinfo=timezone.utc)
        future = "2026-04-28T18:00:00+00:00"  # 9h later, same day UTC
        with self._fake_now(now):
            assert format_resets_at(future) == "today"

    def test_resets_at_overdue(self):
        """Past dates render as 'reset overdue', never raise."""
        now = datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc)
        past = "2026-04-01T00:00:00+00:00"
        with self._fake_now(now):
            assert format_resets_at(past) == "reset overdue"

    def test_resets_at_invalid_returns_empty(self):
        """Empty / None / garbage all render as ``""`` — not 'unknown'."""
        assert format_resets_at("") == ""
        assert format_resets_at("garbage") == ""
        assert format_resets_at(None) == ""  # type: ignore[arg-type]
        assert format_resets_at("not-a-date") == ""

    def test_resets_at_accepts_z_suffix(self):
        """Bare 'Z' UTC suffix (RFC 3339) is normalised to '+00:00'."""
        now = datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc)
        future = "2026-05-02T12:00:00Z"
        with self._fake_now(now):
            assert format_resets_at(future) == "in 4 days"


class TestFormatSoftCapBadge:
    def test_soft_cap_badge_priority(self):
        """Hard-cap takes precedence over soft-cap in the badge."""
        # Both flags set → hard wins.
        assert format_soft_cap_badge(soft_capped=True, hard_capped=True) == (
            "out of tokens"
        )
        # Only hard.
        assert format_soft_cap_badge(soft_capped=False, hard_capped=True) == (
            "out of tokens"
        )

    def test_soft_cap_badge_soft_only_with_model(self):
        """Soft-only with explicit model renders the dynamic downgrade label.

        D3 — "downgraded to Flash" was hardcoded; now the badge uses the
        model name from the latest ``usage`` event when available so the
        UX reflects whatever model the server actually swapped to.
        """
        assert format_soft_cap_badge(
            soft_capped=True, hard_capped=False, model="gemini-2-flash-002"
        ) == "downgraded to gemini-2-flash-002"

    def test_soft_cap_badge_soft_only_without_model(self):
        """Soft-only without a model renders a generic faster-model label.

        D3 — when ``model`` is omitted the badge falls back to the generic
        "downgraded to faster model" text rather than hardcoding "Flash".
        """
        assert format_soft_cap_badge(
            soft_capped=True, hard_capped=False
        ) == "downgraded to faster model"

    def test_soft_cap_badge_neither_returns_none(self):
        """Neither flag set → no badge (caller hides the widget)."""
        assert format_soft_cap_badge(soft_capped=False, hard_capped=False) is None


class FakeDatetime(datetime):
    """A tiny ``datetime`` subclass whose ``now()`` is fixed.

    Returned by :py:meth:`with_now` so each test can supply its own anchor
    without monkey-patching the timezone module wholesale.
    """

    _fake_now: datetime = datetime(2026, 4, 28, 12, 0, tzinfo=timezone.utc)

    @classmethod
    def with_now(cls, dt: datetime) -> type:
        """Return a fresh subclass whose now() returns ``dt``.

        Using a fresh class per test avoids cross-test pollution that would
        plague a module-global ``_fake_now``.
        """
        return type(
            "FakeDatetimeFrozen",
            (datetime,),
            {
                "now": classmethod(lambda klass, tz=None: dt if tz is None else dt.astimezone(tz)),
                "fromisoformat": classmethod(lambda klass, s: datetime.fromisoformat(s)),
            },
        )
