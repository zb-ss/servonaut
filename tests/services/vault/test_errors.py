"""Vault failure text shows actionable client messages, never server text."""
from __future__ import annotations

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.vault.errors import VaultUserError, vault_failure_reason


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
