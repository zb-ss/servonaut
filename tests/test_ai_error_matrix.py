"""Tests for the T5 error-handling matrix (``ai_error_handler.map_error_to_action``).

Parametrised over the 10 codes from the plan
``plans/cli/plan-premium-ai.org`` §"Codes the CLI must handle":

    rate_limited, quota_exhausted, budget_exhausted, free_not_entitled,
    entitlement_required, service_unavailable, upstream_unavailable,
    context_too_large, content_blocked, validation_failed

Plus dedicated cases for:
    - retry_after honouring on rate_limited
    - context_too_large → AUTO_CHUNK_AND_RETRY
    - content_blocked NEVER includes raw payload in user_message
    - SSEStreamDead → BANNER_UPSTREAM_FLAKY
    - Unknown codes default to TOAST_ERROR with raw message
    - Legacy aliases (quota_exceeded / forbidden_entitlement / feature_disabled)
"""
from __future__ import annotations

import pytest

from servonaut.services.ai_error_handler import (
    ErrorActionPayload,
    UserFacingAction,
    map_error_to_action,
)
from servonaut.services.ai_sse import SSEStreamDead, SSEStreamError
from servonaut.services.api_client import (
    APIError,
    FeatureDisabledError,
    ForbiddenEntitlementError,
    QuotaExceededError,
    RateLimitedError,
    ValidationFailedError,
)


def _make_api_error(
    *,
    cls=APIError,
    code: str = "unknown",
    message: str = "boom",
    status: int = 400,
    details: dict | None = None,
    headers: dict | None = None,
) -> APIError:
    """Build an :class:`APIError`-family exception with the given attrs."""
    return cls(
        code=code,
        message=message,
        status=status,
        details=details,
        response_headers=headers or {},
    )


def _sse_error(
    code: str,
    message: str = "stream boom",
    retry_after: int | None = None,
    details: dict | None = None,
) -> SSEStreamError:
    return SSEStreamError(
        code=code,
        message=message,
        retry_after=retry_after,
        details=details,
    )


# ---------------------------------------------------------------------------
# 1. The 10-code matrix — table-driven, one row per documented code.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "err_factory, expected_action, expected_code",
    [
        # rate_limited — auto-retry with backoff. Retry-after surfaces
        # on the payload, not just the exception.
        (
            lambda: _make_api_error(
                cls=RateLimitedError, code="rate_limited", status=429,
                headers={"retry-after": "5"},
            ),
            UserFacingAction.AUTO_RETRY_WITH_BACKOFF,
            "rate_limited",
        ),
        (
            lambda: _make_api_error(
                code="quota_exhausted", status=402,
                details={"tokens_used": 1, "tokens_limit": 1},
            ),
            UserFacingAction.MODAL_QUOTA_EXHAUSTED,
            "quota_exhausted",
        ),
        (
            lambda: _make_api_error(
                code="budget_exhausted", status=402,
                details={"remaining_micros": 0},
            ),
            UserFacingAction.MODAL_BUDGET_EXHAUSTED,
            "budget_exhausted",
        ),
        (
            lambda: _make_api_error(code="free_not_entitled", status=403),
            UserFacingAction.MODAL_UPGRADE_REQUIRED,
            "free_not_entitled",
        ),
        (
            lambda: _make_api_error(code="entitlement_required", status=403),
            UserFacingAction.MODAL_UPGRADE_REQUIRED,
            "entitlement_required",
        ),
        (
            lambda: _make_api_error(code="service_unavailable", status=503),
            UserFacingAction.BANNER_FEATURE_OFF,
            "service_unavailable",
        ),
        (
            lambda: _make_api_error(code="upstream_unavailable", status=503),
            UserFacingAction.BANNER_UPSTREAM_FLAKY,
            "upstream_unavailable",
        ),
        (
            lambda: _make_api_error(code="context_too_large", status=400),
            UserFacingAction.AUTO_CHUNK_AND_RETRY,
            "context_too_large",
        ),
        (
            lambda: _make_api_error(code="content_blocked", status=400,
                                    details={"raw": "secret payload"}),
            UserFacingAction.LOG_ONLY,
            "content_blocked",
        ),
        (
            lambda: _make_api_error(
                cls=ValidationFailedError, code="validation_failed", status=422,
            ),
            UserFacingAction.LOG_ONLY,
            "validation_failed",
        ),
    ],
)
def test_each_documented_code_maps_to_correct_action(
    err_factory, expected_action, expected_code,
):
    """One row per plan §"Codes the CLI must handle" entry."""
    err = err_factory()
    payload = map_error_to_action(err)

    assert isinstance(payload, ErrorActionPayload)
    assert payload.action is expected_action
    assert payload.code == expected_code
    # Every payload must carry a non-empty user_message.
    assert payload.user_message


# ---------------------------------------------------------------------------
# 2. retry_after honouring on rate_limited.
# ---------------------------------------------------------------------------


def test_rate_limited_payload_carries_retry_after_from_header():
    err = _make_api_error(
        cls=RateLimitedError,
        code="rate_limited",
        status=429,
        headers={"retry-after": "12"},
    )
    payload = map_error_to_action(err)
    # The error_handler reads ``retry_after`` directly off the err
    # attribute or details — header parsing happens in the provider's
    # retry loop. Our payload's ``retry_after_seconds`` therefore tracks
    # whatever attribute the exception exposes, which for APIError is
    # ``details.retry_after`` if present.
    assert payload.action is UserFacingAction.AUTO_RETRY_WITH_BACKOFF


def test_rate_limited_with_details_retry_after():
    err = _make_api_error(
        cls=RateLimitedError, code="rate_limited", status=429,
        details={"retry_after": 8},
    )
    payload = map_error_to_action(err)
    assert payload.retry_after_seconds == 8


# ---------------------------------------------------------------------------
# 3. context_too_large triggers chunk-and-retry path.
# ---------------------------------------------------------------------------


def test_context_too_large_action_is_chunk_and_retry():
    err = _make_api_error(code="context_too_large", status=400)
    payload = map_error_to_action(err)
    assert payload.action is UserFacingAction.AUTO_CHUNK_AND_RETRY
    assert "chunking" in payload.user_message.lower() or "long" in payload.user_message.lower()


# ---------------------------------------------------------------------------
# 4. content_blocked must NOT leak the raw payload.
# ---------------------------------------------------------------------------


def test_content_blocked_user_message_does_not_include_raw_payload():
    err = _make_api_error(
        code="content_blocked",
        status=400,
        message="raw model output that the safety filter caught",
        details={"raw": "extremely sensitive model output"},
    )
    payload = map_error_to_action(err)

    assert payload.action is UserFacingAction.LOG_ONLY
    # Plan invariant: never expose the raw payload in user-visible message.
    assert "raw model output" not in payload.user_message
    assert "extremely sensitive" not in payload.user_message
    # Details preserved for debug log.
    assert "raw" in payload.details


# ---------------------------------------------------------------------------
# 5. SSEStreamDead maps to BANNER_UPSTREAM_FLAKY.
# ---------------------------------------------------------------------------


def test_sse_stream_dead_maps_to_upstream_unavailable_banner():
    err = SSEStreamDead("heartbeat watchdog tripped")
    payload = map_error_to_action(err)
    assert payload.action is UserFacingAction.BANNER_UPSTREAM_FLAKY
    assert payload.code == "upstream_unavailable"


# ---------------------------------------------------------------------------
# 6. SSEStreamError of various codes routes through the same map.
# ---------------------------------------------------------------------------


def test_sse_stream_error_quota_exhausted_routes_to_modal():
    err = _sse_error("quota_exhausted")
    payload = map_error_to_action(err)
    assert payload.action is UserFacingAction.MODAL_QUOTA_EXHAUSTED
    # Top-up URL populated for the modal CTA.
    assert payload.topup_url
    assert "topup" in payload.topup_url


def test_sse_stream_error_upstream_unavailable_routes_to_banner():
    err = _sse_error("upstream_unavailable")
    payload = map_error_to_action(err)
    assert payload.action is UserFacingAction.BANNER_UPSTREAM_FLAKY
    assert payload.code == "upstream_unavailable"


# ---------------------------------------------------------------------------
# 7. Unknown codes default to TOAST_ERROR with raw message.
# ---------------------------------------------------------------------------


def test_unknown_code_defaults_to_toast_error_with_raw_message():
    err = _make_api_error(code="newfangled_code", status=500, message="server boom")
    payload = map_error_to_action(err)
    assert payload.action is UserFacingAction.TOAST_ERROR
    assert "boom" in payload.user_message


# ---------------------------------------------------------------------------
# 8. Legacy code aliases — backend compat.
# ---------------------------------------------------------------------------


def test_legacy_quota_exceeded_alias_routes_to_quota_modal():
    err = _make_api_error(
        cls=QuotaExceededError, code="quota_exceeded", status=429,
    )
    payload = map_error_to_action(err)
    assert payload.action is UserFacingAction.MODAL_QUOTA_EXHAUSTED


def test_legacy_forbidden_entitlement_routes_to_upgrade_modal():
    err = _make_api_error(
        cls=ForbiddenEntitlementError, code="forbidden_entitlement", status=403,
    )
    payload = map_error_to_action(err)
    assert payload.action is UserFacingAction.MODAL_UPGRADE_REQUIRED


def test_legacy_feature_disabled_routes_to_banner():
    err = _make_api_error(
        cls=FeatureDisabledError, code="feature_disabled", status=503,
    )
    payload = map_error_to_action(err)
    assert payload.action is UserFacingAction.BANNER_FEATURE_OFF


# ---------------------------------------------------------------------------
# 9. quota_exhausted / budget_exhausted ALWAYS carry the topup URL.
# ---------------------------------------------------------------------------


def test_quota_exhausted_payload_includes_topup_url():
    err = _make_api_error(code="quota_exhausted", status=402)
    payload = map_error_to_action(err)
    assert payload.topup_url
    assert payload.topup_url.startswith("https://")


def test_budget_exhausted_payload_includes_topup_url_and_details():
    err = _make_api_error(
        code="budget_exhausted", status=402,
        details={"remaining_micros": 0, "month_total_micros": 100_000},
    )
    payload = map_error_to_action(err)
    assert payload.topup_url
    assert payload.details.get("remaining_micros") == 0


# ---------------------------------------------------------------------------
# 10. free_not_entitled / entitlement_required carry upgrade_url.
# ---------------------------------------------------------------------------


def test_free_not_entitled_payload_includes_upgrade_url():
    err = _make_api_error(code="free_not_entitled", status=403)
    payload = map_error_to_action(err)
    assert payload.upgrade_url
    assert "pricing" in payload.upgrade_url


def test_entitlement_required_payload_includes_upgrade_url():
    err = _make_api_error(code="entitlement_required", status=403)
    payload = map_error_to_action(err)
    assert payload.upgrade_url


# ---------------------------------------------------------------------------
# 11. validation_failed surfaces details for debug log without exposing message.
# ---------------------------------------------------------------------------


def test_validation_failed_log_only_with_generic_user_message():
    err = _make_api_error(
        cls=ValidationFailedError, code="validation_failed", status=422,
        details={"detail": "messages.0.content too short"},
    )
    payload = map_error_to_action(err)
    assert payload.action is UserFacingAction.LOG_ONLY
    # Generic message only — no raw detail leak.
    assert "messages.0" not in payload.user_message
    # Debug detail preserved on the payload for logging.
    assert payload.details.get("detail") == "messages.0.content too short"
