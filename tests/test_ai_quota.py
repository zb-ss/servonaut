"""Tests for the AIQuota dataclass.

Covers the architect-plan T3 invariants:
- 8-field roundtrip (from_dict ↔ to_dict)
- Free user (quota: null) → None
- Server-quirk tolerance (partial / empty payload)
- Estimated-queries rolling average (5k default)
- ``is_exhausted`` covers both monthly and top-up buckets
- Top-up does not subtract from the monthly remaining
"""
from __future__ import annotations

import pytest

from servonaut.services.ai_quota import AIQuota


# Canonical full payload — matches the docstring in plan-premium-ai.org §"Quota object".
_CANONICAL = {
    "tokens_used": 123_456,
    "tokens_limit": 15_000_000,
    "tokens_topup_remaining": 500_000,
    "resets_at": "2026-05-01T00:00:00+00:00",
    "soft_capped": False,
    "hard_capped": False,
    "rpm_limit": 30,
    "tokens_per_minute_limit": 600_000,
}


class TestAIQuotaRoundtrip:
    def test_full_roundtrip_all_fields(self):
        """Every documented key survives from_dict → to_dict unchanged."""
        quota = AIQuota.from_dict(_CANONICAL)
        assert quota is not None
        out = quota.to_dict()
        # Ordered set comparison so we'd see drift if a key is added/dropped.
        assert set(out.keys()) == set(_CANONICAL.keys())
        for key, value in _CANONICAL.items():
            assert out[key] == value, f"roundtrip mismatch on {key}"

    def test_to_dict_emits_only_documented_fields(self):
        """to_dict must not leak any internal fields added in future."""
        quota = AIQuota()
        out = quota.to_dict()
        assert set(out.keys()) == {
            "tokens_used",
            "tokens_limit",
            "tokens_topup_remaining",
            "resets_at",
            "soft_capped",
            "hard_capped",
            "rpm_limit",
            "tokens_per_minute_limit",
        }


class TestAIQuotaFromDict:
    def test_from_dict_none_returns_none(self):
        """Free users get ``quota: null`` from the server."""
        assert AIQuota.from_dict(None) is None

    def test_from_dict_empty_returns_defaults(self):
        """Server quirk: a partial / empty payload must not crash."""
        quota = AIQuota.from_dict({})
        assert quota is not None
        assert quota.tokens_used == 0
        assert quota.tokens_limit == 0
        assert quota.tokens_topup_remaining == 0
        assert quota.resets_at == ""
        assert quota.soft_capped is False
        assert quota.hard_capped is False
        assert quota.rpm_limit == 0
        assert quota.tokens_per_minute_limit == 0

    def test_from_dict_partial_payload_fills_defaults(self):
        """Missing keys default; present keys roundtrip."""
        quota = AIQuota.from_dict({"tokens_used": 42, "tokens_limit": 1000})
        assert quota is not None
        assert quota.tokens_used == 42
        assert quota.tokens_limit == 1000
        assert quota.tokens_topup_remaining == 0
        assert quota.soft_capped is False

    def test_from_dict_non_dict_returns_empty(self):
        """A stray ``quota: false`` shouldn't crash the chat panel."""
        # Defensive: not specified by the plan but explicitly handled.
        quota = AIQuota.from_dict(False)  # type: ignore[arg-type]
        assert quota is not None
        assert quota.tokens_limit == 0


class TestEstimatedQueriesRemaining:
    def test_estimated_queries_remaining_default_avg(self):
        """5k-token rolling average is the documented fallback."""
        # 50_000 monthly + 0 topup at 5k/query → 10 queries.
        quota = AIQuota(tokens_used=0, tokens_limit=50_000)
        assert quota.estimated_queries_remaining() == 10

    def test_estimated_queries_remaining_custom_avg(self):
        """Caller can pass their own rolling average."""
        quota = AIQuota(tokens_used=0, tokens_limit=100_000)
        # 100_000 / 10_000 = 10 queries
        assert quota.estimated_queries_remaining(avg_tokens_per_query=10_000) == 10

    def test_estimated_queries_remaining_includes_topup(self):
        """Top-up balance contributes to the query estimate."""
        quota = AIQuota(
            tokens_used=0,
            tokens_limit=10_000,
            tokens_topup_remaining=20_000,
        )
        # 30_000 total / 5k = 6 queries.
        assert quota.estimated_queries_remaining() == 6

    def test_estimated_queries_remaining_zero_avg_returns_zero(self):
        """Defensive: don't ZeroDivisionError on a bogus avg."""
        quota = AIQuota(tokens_used=0, tokens_limit=10_000)
        assert quota.estimated_queries_remaining(avg_tokens_per_query=0) == 0
        assert quota.estimated_queries_remaining(avg_tokens_per_query=-5) == 0


class TestIsExhausted:
    def test_is_exhausted_logic(self):
        """Both monthly remaining AND topup must be zero to be exhausted."""
        # Monthly drained, no topup → exhausted.
        q1 = AIQuota(tokens_used=100, tokens_limit=100, tokens_topup_remaining=0)
        assert q1.is_exhausted is True

        # Monthly drained, topup present → not exhausted.
        q2 = AIQuota(tokens_used=100, tokens_limit=100, tokens_topup_remaining=500)
        assert q2.is_exhausted is False

        # Monthly available, no topup → not exhausted.
        q3 = AIQuota(tokens_used=10, tokens_limit=100, tokens_topup_remaining=0)
        assert q3.is_exhausted is False

        # Both zero from the start (free user that somehow gets a quota object).
        q4 = AIQuota()
        assert q4.is_exhausted is True

    def test_tokens_remaining_clamped_at_zero(self):
        """Over-usage doesn't produce a negative remaining."""
        quota = AIQuota(tokens_used=500, tokens_limit=100)
        assert quota.tokens_remaining == 0


class TestTopupBucketSeparation:
    def test_topup_does_not_count_against_monthly(self):
        """Sanity: monthly bucket is independent of top-up balance.

        Critical for the chat-panel "[14.5M / +500K topup]" footer — if
        ``tokens_remaining`` accidentally subtracted top-up, the user would
        see their monthly bucket shrink the moment they bought a top-up.
        """
        quota = AIQuota(
            tokens_used=200_000,
            tokens_limit=15_000_000,
            tokens_topup_remaining=500_000,
        )
        assert quota.tokens_remaining == 14_800_000
        assert quota.tokens_topup_remaining == 500_000
        # Spending top-up never reduces monthly remaining.
        quota.tokens_topup_remaining = 0
        assert quota.tokens_remaining == 14_800_000


class TestCoercion:
    """The from_dict coercer must tolerate sloppy server payloads gracefully."""

    def test_string_ints_coerce(self):
        """Some endpoints stringify ints — accept them."""
        quota = AIQuota.from_dict({"tokens_used": "42", "tokens_limit": "1000"})
        assert quota is not None
        assert quota.tokens_used == 42
        assert quota.tokens_limit == 1000

    def test_garbage_int_falls_back_to_default(self):
        """Non-numeric strings shouldn't raise — coerce to default."""
        quota = AIQuota.from_dict({"tokens_used": "garbage"})
        assert quota is not None
        assert quota.tokens_used == 0

    def test_int_bools_for_capped_flags(self):
        """0/1 ints are accepted for the boolean cap flags."""
        quota = AIQuota.from_dict({"soft_capped": 1, "hard_capped": 0})
        assert quota is not None
        assert quota.soft_capped is True
        assert quota.hard_capped is False


def test_ai_quota_field_drift_detection():
    """D4 — schema drift between ``AIQuota`` and ``_QUOTA_FIELDS`` is caught.

    The original code lived as a module-level ``assert`` which
    ``python -O`` strips. We replaced it with a runtime check, but the
    invariant is still better surfaced as a unit-test failure than as
    an import-time crash for end users. This test mirrors the same
    equality so CI catches drift on PR.
    """
    from dataclasses import fields

    from servonaut.services.ai_quota import AIQuota, _QUOTA_FIELDS

    declared = {f.name for f in fields(AIQuota)}
    assert declared == set(_QUOTA_FIELDS), (
        f"AIQuota fields {declared} drift from _QUOTA_FIELDS "
        f"{set(_QUOTA_FIELDS)}"
    )
