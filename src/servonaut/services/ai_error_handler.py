"""Central error handler for the Premium AI feature (T5).

Maps :class:`APIError` and :class:`SSEStreamError` instances to a
deterministic UX action — toast, modal, banner, automatic retry, or
log-only — so the chat panel can dispatch each error code uniformly
across both buffered and streaming code paths.

This module is intentionally pure: no I/O, no network, no Textual
imports. The chat panel consumes the returned :class:`ErrorActionPayload`
and drives the actual UI surface (notify / push_screen / Static
update). Tests parameterise over :func:`map_error_to_action` directly.

Plan: ``plans/cli/plan-premium-ai.org`` §"Codes the CLI must handle".
The 10 codes mapped here mirror the table verbatim; deviations would
break the acceptance criteria so any addition needs a paired test in
``tests/test_ai_error_matrix.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Union

from servonaut.services.api_client import (
    APIError,
    FeatureDisabledError,
    ForbiddenEntitlementError,
    QuotaExceededError,
    RateLimitedError,
    ValidationFailedError,
)
from servonaut.services.ai_sse import SSEStreamDead, SSEStreamError


# Pricing / top-up URL constants.
#
# Architect plan §"Critical decisions" leaves the production source of
# these URLs as the server-side settings table; until that's wired the
# CLI hard-codes them so the modal CTA buttons always have a target.
# Both URLs are user-visible only — never used to authenticate, so
# rotating them on the server side is a one-line constant change.
_PRICING_URL = "https://servonaut.dev/pricing"
_TOPUP_URL = "https://servonaut.dev/account/billing/topup"


class UserFacingAction(str, Enum):
    """One UX action per error code.

    Inherits from :class:`str` so payloads remain JSON-serialisable for
    debug dumps without a custom encoder.
    """

    TOAST_INFO = "toast_info"
    TOAST_ERROR = "toast_error"
    TOAST_WARNING = "toast_warning"
    MODAL_QUOTA_EXHAUSTED = "modal_quota_exhausted"
    MODAL_BUDGET_EXHAUSTED = "modal_budget_exhausted"
    MODAL_UPGRADE_REQUIRED = "modal_upgrade_required"
    BANNER_FEATURE_OFF = "banner_feature_off"
    BANNER_UPSTREAM_FLAKY = "banner_upstream_flaky"
    AUTO_RETRY_WITH_BACKOFF = "auto_retry_with_backoff"
    AUTO_CHUNK_AND_RETRY = "auto_chunk_and_retry"
    LOG_ONLY = "log_only"


@dataclass
class ErrorActionPayload:
    """Normalised description of how the chat panel should react.

    The chat panel inspects ``action`` and dispatches to the matching
    Textual surface (``notify``, ``push_screen``, ``Static.update``).
    All optional fields default to safe sentinels so consumers can
    unconditionally read them.
    """

    action: UserFacingAction
    user_message: str
    code: str = ""
    retry_after_seconds: Optional[int] = None
    upgrade_url: Optional[str] = None
    topup_url: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _details_of(err: Union[APIError, SSEStreamError, SSEStreamDead]) -> Dict[str, Any]:
    """Return a defensive copy of the error's ``details`` dict (or empty)."""
    raw = getattr(err, "details", None)
    if not isinstance(raw, dict):
        return {}
    # Shallow copy — callers may mutate.
    return dict(raw)


def _retry_after_of(err: Union[APIError, SSEStreamError, SSEStreamDead]) -> Optional[int]:
    """Pull a ``retry_after`` attribute if present, coerce to int."""
    raw = getattr(err, "retry_after", None)
    if raw is None:
        # APIError stores it under details on some paths.
        details = _details_of(err)
        raw = details.get("retry_after")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _code_of(err: Union[APIError, SSEStreamError, SSEStreamDead]) -> str:
    """Best-effort error-code extraction across SSE / API exception classes."""
    code = getattr(err, "code", None)
    if isinstance(code, str) and code:
        return code
    # APIError defaults to "unknown" if the server omits the code; treat
    # an explicit None as the same.
    return "unknown"


def _message_of(err: Union[APIError, SSEStreamError, SSEStreamDead], default: str = "") -> str:
    """Best-effort message extraction; falls back to ``str(err)`` then ``default``."""
    msg = getattr(err, "message", None)
    if isinstance(msg, str) and msg:
        return msg
    text = str(err) if err else ""
    return text or default


# ---------------------------------------------------------------------------
# Per-code mappers
# ---------------------------------------------------------------------------


def _map_rate_limited(err: Union[APIError, SSEStreamError]) -> ErrorActionPayload:
    """429 — auto-retry with exponential backoff + jitter.

    The provider owns the retry loop (``ServonautProvider`` honours
    ``retry_after`` up to 3 attempts); this handler only signals the
    intent so the chat panel can show a transient toast on each attempt.
    """
    return ErrorActionPayload(
        action=UserFacingAction.AUTO_RETRY_WITH_BACKOFF,
        user_message="Hit the rate limit — retrying shortly.",
        code="rate_limited",
        retry_after_seconds=_retry_after_of(err),
        details=_details_of(err),
    )


def _map_quota_exhausted(err: Union[APIError, SSEStreamError]) -> ErrorActionPayload:
    """402 — out of monthly tokens. Pop the top-up modal, do NOT auto-retry."""
    return ErrorActionPayload(
        action=UserFacingAction.MODAL_QUOTA_EXHAUSTED,
        user_message="You've run out of monthly tokens. Top up to keep going.",
        code="quota_exhausted",
        topup_url=_TOPUP_URL,
        details=_details_of(err),
    )


def _map_budget_exhausted(err: Union[APIError, SSEStreamError]) -> ErrorActionPayload:
    """402 — customer-cost hard cap. Same modal as quota_exhausted."""
    details = _details_of(err)
    return ErrorActionPayload(
        action=UserFacingAction.MODAL_BUDGET_EXHAUSTED,
        user_message="Monthly budget cap reached. Top up to continue.",
        code="budget_exhausted",
        topup_url=_TOPUP_URL,
        details=details,
    )


def _map_free_not_entitled(err: Union[APIError, SSEStreamError]) -> ErrorActionPayload:
    """403 — paid path hit on a free plan."""
    return ErrorActionPayload(
        action=UserFacingAction.MODAL_UPGRADE_REQUIRED,
        user_message="This requires a Solo or Teams plan.",
        code="free_not_entitled",
        upgrade_url=_PRICING_URL,
        details=_details_of(err),
    )


def _map_entitlement_required(err: Union[APIError, SSEStreamError]) -> ErrorActionPayload:
    """403 — premium_ai entitlement missing or stale."""
    return ErrorActionPayload(
        action=UserFacingAction.MODAL_UPGRADE_REQUIRED,
        user_message="Servonaut AI requires an active subscription.",
        code="entitlement_required",
        upgrade_url=_PRICING_URL,
        details=_details_of(err),
    )


def _map_service_unavailable(err: Union[APIError, SSEStreamError]) -> ErrorActionPayload:
    """503 — feature flag off (kill-switch). Banner + offer fallback."""
    return ErrorActionPayload(
        action=UserFacingAction.BANNER_FEATURE_OFF,
        user_message="Servonaut AI is temporarily off. Switch to a local provider for now?",
        code="service_unavailable",
        details=_details_of(err),
    )


def _map_upstream_unavailable(err: Union[APIError, SSEStreamError, SSEStreamDead]) -> ErrorActionPayload:
    """503 — vendor chain exhausted; T10 watcher counts these for second-in-60s prompt."""
    return ErrorActionPayload(
        action=UserFacingAction.BANNER_UPSTREAM_FLAKY,
        user_message="Upstream AI vendors are flaky. The system is retrying.",
        code="upstream_unavailable",
        details=_details_of(err),
    )


def _map_context_too_large(err: Union[APIError, SSEStreamError]) -> ErrorActionPayload:
    """400 — chunk-and-retry the conversation."""
    return ErrorActionPayload(
        action=UserFacingAction.AUTO_CHUNK_AND_RETRY,
        user_message="Conversation too long — chunking and retrying.",
        code="context_too_large",
        details=_details_of(err),
    )


def _map_content_blocked(err: Union[APIError, SSEStreamError]) -> ErrorActionPayload:
    """400 — safety filter caught the content. NEVER expose the raw payload."""
    # Hard rule per plan §error-table: "Toast — do not show raw response;
    # log code only". We deliberately drop ``message`` from the response
    # so a misbehaving server can't smuggle the blocked payload into the
    # user-facing string. Details are preserved for the debug log.
    return ErrorActionPayload(
        action=UserFacingAction.LOG_ONLY,
        user_message="Response blocked by safety filter.",
        code="content_blocked",
        details=_details_of(err),
    )


def _map_validation_failed(err: Union[APIError, SSEStreamError]) -> ErrorActionPayload:
    """400/422 — programmer error. Generic toast + debug log of details."""
    return ErrorActionPayload(
        action=UserFacingAction.LOG_ONLY,
        user_message="Internal error — please report this.",
        code="validation_failed",
        details=_details_of(err),
    )


# Code-to-mapper dispatch table.
_CODE_DISPATCH = {
    "rate_limited": _map_rate_limited,
    "quota_exhausted": _map_quota_exhausted,
    # Legacy alias from existing _CODE_TO_EXC table — older backends may
    # still emit this. Treat as quota_exhausted for UX parity.
    "quota_exceeded": _map_quota_exhausted,
    "budget_exhausted": _map_budget_exhausted,
    "free_not_entitled": _map_free_not_entitled,
    "entitlement_required": _map_entitlement_required,
    "forbidden_entitlement": _map_entitlement_required,  # legacy code alias
    "service_unavailable": _map_service_unavailable,
    "feature_disabled": _map_service_unavailable,  # legacy code alias
    "upstream_unavailable": _map_upstream_unavailable,
    "context_too_large": _map_context_too_large,
    "content_blocked": _map_content_blocked,
    "validation_failed": _map_validation_failed,
}


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


def map_error_to_action(
    err: Union[APIError, SSEStreamError, SSEStreamDead],
) -> ErrorActionPayload:
    """Pure mapping of an error instance to a UX action payload.

    Args:
        err: An :class:`APIError` subclass, an :class:`SSEStreamError`, or
            an :class:`SSEStreamDead`. Any other type falls through to the
            defensive default.

    Returns:
        :class:`ErrorActionPayload` — never raises.

    Note:
        Heartbeat-watchdog deaths (:class:`SSEStreamDead`) are treated as
        ``upstream_unavailable`` so the T10 second-in-60s watcher counts
        them alongside server-emitted ``upstream_unavailable`` events.
    """
    if isinstance(err, SSEStreamDead):
        # No code on SSEStreamDead — synthesise upstream_unavailable so
        # the T10 chain-aware watcher sees a consistent signal.
        return ErrorActionPayload(
            action=UserFacingAction.BANNER_UPSTREAM_FLAKY,
            user_message="Lost contact with the AI server. Retrying.",
            code="upstream_unavailable",
            details={"reason": str(err) if err else "heartbeat watchdog"},
        )

    code = _code_of(err)
    mapper = _CODE_DISPATCH.get(code)
    if mapper is not None:
        return mapper(err)

    # Defensive default — unknown code gets a generic error toast with
    # the raw message. The user sees something useful even when the
    # backend ships a code we don't know yet, and no UI path crashes.
    return ErrorActionPayload(
        action=UserFacingAction.TOAST_ERROR,
        user_message=_message_of(err, default="An unknown error occurred."),
        code=code,
        details=_details_of(err),
    )


__all__ = [
    "ErrorActionPayload",
    "UserFacingAction",
    "map_error_to_action",
]
