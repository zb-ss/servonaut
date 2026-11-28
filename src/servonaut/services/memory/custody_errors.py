"""Plain wording for the errors the vault-custody key flows can hit.

The service's own messages are never shown: every code maps to the client's
text here, so what a person reads does not depend on the service's wording
and never carries a raw code. Results are plain text without Rich markup.
"""

from __future__ import annotations

from typing import Optional

from servonaut.services.memory.interfaces import (
    VaultCustodyLocked,
    VaultCustodyUnavailable,
)

CONTEXT_DEFAULT = "default"
CONTEXT_ROTATION = "rotation"
#: Generic Memory Sync calls (unlock, sync): a 503 ``feature_disabled`` there
#: is not about the vault switch, so it gets no vault wording.
CONTEXT_GENERAL = "general"

_VAULT_NOT_READY = (
    "Your vault is not ready for this. Unlock your vault on this device and "
    "confirm your vault identity (open the link we e-mailed you, or choose "
    "Confirm identity on the Vault screen), then try again."
)
_FEATURE_DISABLED = (
    "Keeping Memory Sync keys in the vault is not available on this Servonaut "
    "service yet. Nothing was changed. Try again later."
)
_DEVICE_SIGNATURE_REQUIRED = (
    "This needs your vault on this device. Unlock or add this device to your "
    "vault, then try again."
)
_MEMORY_KEY_CUSTODY_VAULT = (
    "Memory Sync keeps its key in your vault. Set up or unlock your vault on "
    "this device, then try again."
)
_VAULT_LOCKED = (
    "Your Memory Sync key is kept in your vault. Unlock or add this device to "
    "your vault to use Memory Sync here."
)

_CODE_MESSAGES = {
    "vault_not_ready": _VAULT_NOT_READY,
    "fingerprint_mismatch": (
        "Your Memory Sync key changed on another device. Nothing was moved. "
        "Open Memory Sync and try again."
    ),
    "memory_key_custody_vault": _MEMORY_KEY_CUSTODY_VAULT,
    "config_key_not_ready": (
        "Your config sync key is not in your vault yet. Unlock your vault and try again."
    ),
    "config_key_custody_vault": (
        "Config sync keeps its key in your vault. Set up or unlock your vault "
        "on this device, then try again."
    ),
    "no_vault_snapshot": (
        "Your config was not uploaded with the vault key yet, so the old copies "
        "were kept. Nothing was deleted."
    ),
    "item_type_exists": (
        "Your vault already holds a current and a next key of this kind. Finish "
        "the key change that is in progress, then try again."
    ),
    "memory_key_in_use": (
        "This vault item holds your Memory Sync key and is still in use. It was not deleted."
    ),
    "config_key_in_use": (
        "This vault item holds your config sync key and your snapshots still use "
        "it. It was not deleted."
    ),
    "feature_disabled": _FEATURE_DISABLED,
    "feature_not_available": "Memory Sync is not available for your account yet.",
    "device_signature_required": _DEVICE_SIGNATURE_REQUIRED,
    "stale_envelopes": "Memory changed while the summary was being prepared. Try again.",
}

# A rotation that meets the two-item limit is waiting for older memory to age
# out, not for a change in progress; the default wording would mislead.
_ROTATION_MESSAGES = {
    "item_type_exists": (
        "Your previous Memory Sync key is still needed for older memory, so it "
        "cannot be changed again yet. Try again after that memory ages out."
    ),
}

# The reason codes a failed custody lookup carries (``VaultCustodyUnavailable``).
_UNAVAILABLE_MESSAGES = {
    "vault_unreadable": (
        "Your vault could not be read right now. Check your connection and try again."
    ),
    "vault_key_invalid": (
        "The Memory Sync key in your vault could not be verified. Nothing was changed."
    ),
    "keys_me_unavailable": (
        "Servonaut could not check where your Memory Sync key is kept. Try again in a moment."
    ),
    "keys_me_limited": (
        "Servonaut checked where your Memory Sync key is kept a moment ago. "
        "Try again in a few minutes."
    ),
    "user_id_unavailable": (
        "Servonaut could not confirm your account. Check your connection and try again."
    ),
    "feature_disabled": _FEATURE_DISABLED,
}

_ENVELOPE_KEYS_MESSAGE = (
    "The summary could not be started because the memory on the service "
    "changed. Sync this server's memory and try again."
)


def custody_error_message(exc: BaseException, context: str = CONTEXT_DEFAULT) -> Optional[str]:
    """The text to show for a custody-related failure, or ``None`` when *exc* is not one.

    Args:
        exc: The exception a custody, key or summary call raised.
        context: ``"rotation"`` selects the wording for a key change;
            ``"general"`` leaves a ``feature_disabled`` answer to the caller
            (it is only a vault-switch message for vault-custody calls); any
            other value uses the default text.

    Returns:
        Plain text without Rich markup, or ``None`` so the caller falls back
        to its generic wording. A ``forbidden_entitlement`` answer is left to
        the existing upgrade prompt and returns ``None`` as well.
    """
    if isinstance(exc, VaultCustodyLocked):
        return _locked_message(exc.reason)
    if isinstance(exc, VaultCustodyUnavailable):
        return _UNAVAILABLE_MESSAGES.get(str(exc))
    code = getattr(exc, "code", None)
    if not isinstance(code, str):
        return None
    if context == CONTEXT_GENERAL and code == "feature_disabled":
        return None
    if code == "validation_failed":
        return _validation_message(exc)
    if context == CONTEXT_ROTATION and code in _ROTATION_MESSAGES:
        return _ROTATION_MESSAGES[code]
    return _CODE_MESSAGES.get(code)


_LOCKED_REASON_CODES = frozenset({"device_signature_required", "memory_key_custody_vault"})


def _locked_message(reason: str) -> str:
    return _CODE_MESSAGES[reason] if reason in _LOCKED_REASON_CODES else _VAULT_LOCKED


def _validation_message(exc: BaseException) -> Optional[str]:
    details = getattr(exc, "details", None)
    field = details.get("field") if isinstance(details, dict) else None
    return _ENVELOPE_KEYS_MESSAGE if field == "envelope_keys" else None


# Hosted-summary key release (appended; see EnvelopeKeyError in the retrieval service).
_CODE_MESSAGES.update({
    "envelope_key_unreadable": (
        "Your Memory Sync key could not open this server's memory, so no "
        "summary was started. Sync this server's memory again and try once more."
    ),
    "envelope_not_consented": (
        "The service asked for more memory than you approved, so the summary "
        "was not started. Nothing was sent."
    ),
    "envelope_mismatch": (
        "The service returned memory that does not belong to this server, so "
        "the summary was not started. Nothing was sent."
    ),
})


def custody_code_message(code: str, context: str = CONTEXT_DEFAULT) -> Optional[str]:
    """The client's text for a custody error *code*, or ``None`` when it has none.

    For callers that detect a condition locally and have no exception that
    carries the code.
    """
    if context == CONTEXT_ROTATION and code in _ROTATION_MESSAGES:
        return _ROTATION_MESSAGES[code]
    return _CODE_MESSAGES.get(code)
