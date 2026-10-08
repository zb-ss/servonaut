"""Vault failure text shows actionable client messages, never server text."""
from __future__ import annotations

import pytest

from unittest.mock import MagicMock

from servonaut.services.api_client import APIClient, APIError, FeatureDisabledError
from servonaut.services.vault.errors import (
    SSH_CA_COMING_SOON,
    VaultUserError,
    is_feature_disabled,
    vault_failure_reason,
)


def test_user_error_message_is_shown_verbatim() -> None:
    exc = VaultUserError("device safety number was not confirmed; registration was rejected")

    assert vault_failure_reason(exc) == "device safety number was not confirmed; registration was rejected"
    assert isinstance(exc, RuntimeError)


def test_other_exceptions_show_only_their_class() -> None:
    assert vault_failure_reason(RuntimeError("secret-looking server text")) == "RuntimeError"
    assert vault_failure_reason(ValueError("SVRK1-AAAA-BBBB")) == "ValueError"


@pytest.mark.parametrize(("status", "expected"), [
    ("rejected", "the other device rejected this registration"),
    ("revoked", "this device was revoked"),
    ("expired", "the approval window expired"),
])
def test_inactive_device_reason_follows_server_status(status: str, expected: str) -> None:
    exc = APIError(
        code="device_not_active", message="This device is not active.", status=403,
        details={"status": status},
    )

    assert vault_failure_reason(exc).startswith(expected)


def test_api_error_shows_status_and_safe_code_but_never_message() -> None:
    exc = APIError(code="device_not_owned", message="server text", status=403)

    assert vault_failure_reason(exc) == "HTTP 403, device_not_owned"


def test_api_error_with_unsafe_code_shows_status_only() -> None:
    exc = APIError(code="Bad Code <script>", message="server text", status=500)

    assert vault_failure_reason(exc) == "HTTP 500"


def test_inactive_device_with_unknown_status_falls_back_to_code() -> None:
    exc = APIError(code="device_not_active", message="x", status=403, details={"status": "weird"})

    assert vault_failure_reason(exc) == "HTTP 403, device_not_active"


@pytest.mark.parametrize(("code", "expected"), [
    ("identity_unconfirmed", "vault identity is not confirmed yet"),
    ("mfa_required", "needs a recent MFA sign-in"),
    ("step_up_required", "needs a recent MFA sign-in"),
    ("vault_exists", "one personal vault per account and one vault per team"),
    ("no_identity", "does not hold your current vault identity"),
])
def test_actionable_refusals_say_what_to_do(code: str, expected: str) -> None:
    exc = APIError(code=code, message="server text", status=409)

    reason = vault_failure_reason(exc)

    assert expected in reason
    assert "server text" not in reason


def test_validation_refusal_names_a_safe_field_only() -> None:
    named = APIError(code="validation_failed", message="x", status=422, details={"field": "role_logins.member"})
    unsafe = APIError(code="validation_failed", message="x", status=422, details={"field": "<b>secret</b>"})

    assert vault_failure_reason(named) == "HTTP 422, validation_failed, field role_logins.member"
    assert vault_failure_reason(unsafe) == "HTTP 422, validation_failed"


def test_a_generic_wrapper_shows_the_user_safe_reason_it_was_raised_from() -> None:
    try:
        try:
            raise VaultUserError("this device has no vault identity yet")
        except VaultUserError as inner:
            raise RuntimeError("wrapper") from inner
    except RuntimeError as outer:
        assert vault_failure_reason(outer) == "this device has no vault identity yet"
    try:
        try:
            raise ValueError("server text")
        except ValueError as inner:
            raise RuntimeError("wrapper") from inner
    except RuntimeError as outer:
        assert vault_failure_reason(outer) == "RuntimeError"


@pytest.mark.parametrize(("feature", "expected"), [
    ("personal_vault", "your plan does not include a personal vault"),
    ("team_vault", "your plan does not include a team vault"),
    ("ssh_ca", "your plan does not include SSH certificates"),
    ("<b>other</b>", "your plan does not include this feature"),
])
def test_plan_refusal_names_the_missing_feature(feature: str, expected: str) -> None:
    exc = APIError(code="entitlement_required", message="server text", status=402,
                   details={"feature": feature, "upgrade_url": "https://example.com/upgrade"})

    assert vault_failure_reason(exc) == expected


def _ssh_ca_switched_off() -> FeatureDisabledError:
    return FeatureDisabledError(
        code="feature_disabled", message="server text", status=503, details={"feature": "ssh_ca"},
    )


def test_switched_off_ssh_certificates_are_announced_as_coming_soon() -> None:
    reason = vault_failure_reason(_ssh_ca_switched_off())

    assert reason == SSH_CA_COMING_SOON.rstrip(".")  # shown inside "... failed (reason)."
    assert reason.startswith("SSH certificates are coming soon")
    assert "vault keys" in reason
    assert "server text" not in reason


def test_feature_disabled_is_recognised_from_the_service_error_envelope() -> None:
    body = {"error": {
        "code": "feature_disabled", "message": "server text", "http": 503,
        "details": {"feature": "ssh_ca"}, "retry_after_seconds": None,
    }}
    response = MagicMock(status_code=503, headers={"content-type": "application/json"})
    response.json.return_value = body

    exc = APIClient(MagicMock())._parse_error(response)

    assert is_feature_disabled(exc, "ssh_ca")
    assert not is_feature_disabled(exc, "team_vault")


def test_feature_disabled_looks_through_a_generic_wrapper() -> None:
    try:
        try:
            raise _ssh_ca_switched_off()
        except APIError as inner:
            raise RuntimeError("wrapper") from inner
    except RuntimeError as outer:
        assert is_feature_disabled(outer, "ssh_ca")
        assert vault_failure_reason(outer) == SSH_CA_COMING_SOON.rstrip(".")


@pytest.mark.parametrize("exc", [
    APIError(code="feature_disabled", message="x", status=503, details={"feature": "other"}),
    APIError(code="feature_disabled", message="x", status=503, details=None),
    APIError(code="ssh_ca_unavailable", message="x", status=503, details={"feature": "ssh_ca"}),
    APIError(code="entitlement_required", message="x", status=402, details={"feature": "ssh_ca"}),
    RuntimeError("feature_disabled ssh_ca"),
])
def test_feature_disabled_needs_the_code_and_the_named_feature(exc: BaseException) -> None:
    assert not is_feature_disabled(exc, "ssh_ca")


def test_a_user_safe_error_keeps_its_own_message_over_its_cause() -> None:
    try:
        try:
            raise _ssh_ca_switched_off()
        except APIError as inner:
            raise VaultUserError("fixed client text") from inner
    except VaultUserError as outer:
        assert not is_feature_disabled(outer, "ssh_ca")
        assert vault_failure_reason(outer) == "fixed client text"


def test_another_switched_off_feature_gets_a_generic_reason() -> None:
    exc = APIError(code="feature_disabled", message="server text", status=503, details={"feature": "other"})

    assert vault_failure_reason(exc) == "this feature is switched off on this Servonaut service right now"


def test_a_service_that_cannot_sign_certificates_does_not_blame_the_user() -> None:
    exc = APIError(code="ssh_ca_unavailable", message="server text", status=503)

    assert vault_failure_reason(exc) == (
        "the Servonaut service cannot issue SSH certificates right now; "
        "nothing is wrong with your setup, so try again later"
    )
