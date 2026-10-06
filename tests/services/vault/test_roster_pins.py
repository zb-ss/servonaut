from __future__ import annotations

import base64

import pytest

from servonaut.services.vault import crypto
from servonaut.services.vault.roster_pins import IdentityPinChangedError, RosterPins


def _identity(seed: bytes, enc: bytes, user_id: int = 7) -> dict[str, object]:
    sig = crypto.public_from_seed(seed)
    enc_public = crypto.x25519_public(enc)
    fingerprint = crypto.identity_fingerprint(sig, enc_public)
    return {
        "identity_id": "11111111-1111-4111-8111-111111111111",
        "user_id": user_id,
        "sig_public_key": base64.b64encode(sig).decode(),
        "enc_public_key": base64.b64encode(enc_public).decode(),
        "fingerprint": fingerprint.hex(),
        "self_signature": base64.b64encode(
            crypto.self_signature(seed, "11111111-1111-4111-8111-111111111111", user_id, sig, enc_public)
        ).decode(),
    }


def test_changed_identity_needs_explicit_confirmation_and_keeps_history() -> None:
    data: dict[str, str] = {}
    pins = RosterPins(lambda: data, lambda value: data.update(value))
    first = _identity(b"a" * 32, b"b" * 32)
    pins.observe(first)
    changed = _identity(b"c" * 32, b"d" * 32)
    with pytest.raises(IdentityPinChangedError):
        pins.observe(changed)
    pins.observe(changed, confirm_changed=True)
    assert pins.is_pinned(first)
    assert pins.is_pinned(changed)


def test_boolean_user_id_is_rejected() -> None:
    pins = RosterPins(lambda: {}, lambda _value: None)
    identity = _identity(b"a" * 32, b"b" * 32)
    identity["user_id"] = True

    with pytest.raises(crypto.VaultCryptoError):
        pins.verify_identity(identity)
