"""Every vault-custody failure maps to the client's own sentence-case text."""

from __future__ import annotations

import pytest

from servonaut.services.api_client import APIError, FeatureDisabledError, ForbiddenEntitlementError
from servonaut.services.memory.custody_errors import custody_error_message
from servonaut.services.memory.interfaces import VaultCustodyLocked, VaultCustodyUnavailable
from servonaut.services.memory.sync_errors import describe_sync_error

_SERVICE_WORDING = "Service wording that must never reach the user."

_EXPECTED = {
    "vault_not_ready": "Your vault is not ready for this. Unlock your vault on this device, confirm your vault identity, and try again.",
    "fingerprint_mismatch": "Your Memory Sync key changed on another device. Nothing was moved. Open Memory Sync and try again.",
    "memory_key_custody_vault": "Memory Sync keeps its key in your vault. Set up or unlock your vault on this device, then try again.",
    "config_key_not_ready": "Your config sync key is not in your vault yet. Unlock your vault and try again.",
    "config_key_custody_vault": "Config sync keeps its key in your vault. Set up or unlock your vault on this device, then try again.",
    "no_vault_snapshot": "Your config was not uploaded with the vault key yet, so the old copies were kept. Nothing was deleted.",
    "item_type_exists": "Your vault already holds a current and a next key of this kind. Finish the key change that is in progress, then try again.",
    "memory_key_in_use": "This vault item holds your Memory Sync key and is still in use. It was not deleted.",
    "config_key_in_use": "This vault item holds your config sync key and your snapshots still use it. It was not deleted.",
    "feature_disabled": "Keeping Memory Sync keys in the vault is not available on this Servonaut service yet. Nothing was changed. Try again later.",
    "feature_not_available": "Memory Sync is not available for your account yet.",
    "device_signature_required": "This needs your vault on this device. Unlock or add this device to your vault, then try again.",
    "stale_envelopes": "Memory changed while the summary was being prepared. Try again.",
}


def _api_error(code: str, status: int = 409, details=None) -> APIError:
    cls = FeatureDisabledError if code == "feature_disabled" else APIError
    return cls(code=code, message=_SERVICE_WORDING, status=status, details=details)


@pytest.mark.parametrize(("code", "expected"), sorted(_EXPECTED.items()))
def test_every_code_maps_to_the_client_text(code, expected) -> None:
    message = custody_error_message(_api_error(code, 503 if code == "feature_disabled" else 409))
    assert message == expected
    assert _SERVICE_WORDING not in message


@pytest.mark.parametrize("code", sorted(_EXPECTED))
def test_texts_are_sentence_case_final_stops_without_markup_or_codes(code) -> None:
    message = custody_error_message(_api_error(code))
    assert message[0].isupper()
    assert message.endswith(".")
    assert "[" not in message and "]" not in message and "<" not in message
    assert code not in message


def test_rotation_context_has_its_own_item_type_exists_text() -> None:
    message = custody_error_message(_api_error("item_type_exists"), "rotation")
    assert message == (
        "Your previous Memory Sync key is still needed for older memory, so it cannot "
        "be changed again yet. Try again after that memory ages out."
    )
    assert message != _EXPECTED["item_type_exists"]


def test_rotation_context_leaves_other_codes_alone() -> None:
    assert custody_error_message(_api_error("memory_key_in_use"), "rotation") == _EXPECTED["memory_key_in_use"]


def test_envelope_keys_validation_failure_has_its_text_and_others_do_not() -> None:
    stale = _api_error("validation_failed", 422, {"field": "envelope_keys"})
    assert custody_error_message(stale).startswith("The summary could not be started")
    assert custody_error_message(_api_error("validation_failed", 422, {"field": "type"})) is None
    assert custody_error_message(_api_error("validation_failed", 422)) is None


def test_entitlement_refusal_is_left_to_the_upgrade_prompt() -> None:
    exc = ForbiddenEntitlementError(code="forbidden_entitlement", message="x", status=403)
    assert custody_error_message(exc) is None


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("vault_locked", "Your Memory Sync key is kept in your vault. Unlock or add this device to your vault to use Memory Sync here."),
        ("needs_vault_device", "Your Memory Sync key is kept in your vault. Unlock or add this device to your vault to use Memory Sync here."),
        ("device_signature_required", _EXPECTED["device_signature_required"]),
        ("memory_key_custody_vault", _EXPECTED["memory_key_custody_vault"]),
    ],
)
def test_vault_locked_exception_maps_by_reason(reason, expected) -> None:
    assert custody_error_message(VaultCustodyLocked(reason)) == expected


def test_unrelated_errors_return_none() -> None:
    assert custody_error_message(OSError("boom")) is None
    assert custody_error_message(_api_error("rate_limited", 429)) is None
    assert custody_error_message(VaultCustodyUnavailable("x")) is None


def test_describe_sync_error_uses_the_custody_text_before_its_generic_branch() -> None:
    text = describe_sync_error(_api_error("vault_not_ready"), failure_prefix="Setup failed")
    assert text == _EXPECTED["vault_not_ready"]


def test_describe_sync_error_generic_branch_unchanged() -> None:
    assert describe_sync_error(OSError("reset"), failure_prefix="Setup failed") == "Setup failed: reset"
