"""AIQuota dataclass mirroring the backend ``/api/entitlements`` quota block.

Keys match the wire shape exactly so a buffered ``/api/ai/chat`` ``quota`` field
or an entitlements-refresh response can be marshalled directly via
:py:meth:`AIQuota.from_dict`. Free users receive ``quota: null`` from the
server — :py:meth:`from_dict` returns ``None`` in that case so callers can
``if quota is None``-guard.

This module is intentionally I/O-free; it only owns the schema + a few cheap
display helpers. Per-screen formatting lives in
:py:mod:`servonaut.utils.formatting`.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, fields
from typing import Any, Dict, Optional


# Keys the backend exposes on the quota block. Defined once so
# ``from_dict``/``to_dict`` and tests can iterate without drift.
_QUOTA_FIELDS: tuple = (
    "tokens_used",
    "tokens_limit",
    "tokens_topup_remaining",
    "resets_at",
    "soft_capped",
    "hard_capped",
    "rpm_limit",
    "tokens_per_minute_limit",
)


def _coerce_int(value: Any, default: int = 0) -> int:
    """Best-effort int coercion. Returns ``default`` for None/garbage."""
    if value is None:
        return default
    if isinstance(value, bool):
        # bools coerce to int silently otherwise; tighten that.
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Best-effort bool coercion. Accepts True/False/1/0; falls back to default."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no", ""}:
            return False
    return default


def _coerce_str(value: Any, default: str = "") -> str:
    """Best-effort string coercion. Returns ``default`` for None."""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


@dataclass
class AIQuota:
    """Mirror of the server's quota object.

    All fields default to zero-equivalents so :py:meth:`from_dict` can construct
    a usable object even when the backend ships a partial payload (server quirk
    tolerance, see plan T3 acceptance).
    """

    tokens_used: int = 0
    tokens_limit: int = 0
    tokens_topup_remaining: int = 0
    resets_at: str = ""  # ISO 8601 timestamp string
    soft_capped: bool = False
    hard_capped: bool = False
    rpm_limit: int = 0
    tokens_per_minute_limit: int = 0

    @property
    def tokens_remaining(self) -> int:
        """Tokens left in the monthly bucket (never negative)."""
        return max(0, self.tokens_limit - self.tokens_used)

    @property
    def is_exhausted(self) -> bool:
        """True iff both monthly and top-up buckets are zero."""
        return self.tokens_remaining == 0 and self.tokens_topup_remaining <= 0

    def estimated_queries_remaining(self, avg_tokens_per_query: int = 5000) -> int:
        """Rough "≈ N queries" estimate using the rolling average from the plan.

        Args:
            avg_tokens_per_query: Default 5k matches the architect plan
                (T3 invariant — "rolling-avg fallback on 5k").

        Returns:
            Combined queries remaining across monthly + top-up buckets, floored
            at zero. Returns 0 if ``avg_tokens_per_query`` is non-positive
            rather than raising.
        """
        if avg_tokens_per_query <= 0:
            return 0
        total_remaining = self.tokens_remaining + max(0, self.tokens_topup_remaining)
        return total_remaining // avg_tokens_per_query

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["AIQuota"]:
        """Construct an ``AIQuota`` from a server payload.

        Returns:
            ``None`` when ``data`` is ``None`` (free users — entitlements ships
            ``quota: null``). For ``{}`` or partial payloads, returns a quota
            with defaults filled in for missing keys (server-quirk tolerant).

        Never raises on a dict input — unknown keys are silently skipped, bad
        types coerce to defaults via the ``_coerce_*`` helpers.
        """
        if data is None:
            return None
        if not isinstance(data, dict):
            # Defensive: a stray ``quota: false`` or similar shouldn't crash.
            return cls()

        return cls(
            tokens_used=_coerce_int(data.get("tokens_used", 0)),
            tokens_limit=_coerce_int(data.get("tokens_limit", 0)),
            tokens_topup_remaining=_coerce_int(
                data.get("tokens_topup_remaining", 0)
            ),
            resets_at=_coerce_str(data.get("resets_at", "")),
            soft_capped=_coerce_bool(data.get("soft_capped", False)),
            hard_capped=_coerce_bool(data.get("hard_capped", False)),
            rpm_limit=_coerce_int(data.get("rpm_limit", 0)),
            tokens_per_minute_limit=_coerce_int(
                data.get("tokens_per_minute_limit", 0)
            ),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return the wire shape — for re-uploading to local cache.

        Uses :py:func:`dataclasses.asdict` so the field set stays in sync with
        the dataclass definition; only the 8 schema fields are emitted.
        """
        # asdict gives every field; we filter to the documented schema set so
        # any future internal-only field added below the public surface
        # doesn't accidentally leak into cache / re-upload.
        raw = asdict(self)
        return {key: raw[key] for key in _QUOTA_FIELDS if key in raw}


# Sanity check at import: dataclass schema must enumerate every documented field.
# This prevents silent drift if someone adds a field to the dataclass but
# forgets to update _QUOTA_FIELDS.
#
# D4 — was a module-level ``assert``, which ``python -O`` strips. Replaced
# with a runtime check that raises :class:`RuntimeError` so the invariant
# survives optimisation. The matching unit test
# ``test_ai_quota_field_drift_detection`` covers the same equality so a
# drift caught in CI is reported as a test failure first, not an import-time
# crash for end users.
_DECLARED_FIELDS = {f.name for f in fields(AIQuota)}
if _DECLARED_FIELDS != set(_QUOTA_FIELDS):
    raise RuntimeError(
        f"AIQuota dataclass fields {_DECLARED_FIELDS} drift from "
        f"_QUOTA_FIELDS {set(_QUOTA_FIELDS)}"
    )
