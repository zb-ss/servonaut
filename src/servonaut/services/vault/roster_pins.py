"""Verified TOFU pins for Team Vault roster identities.

Pins are deliberately keyed by user id, rather than an identity id supplied by
the service.  An identity reset therefore requires an explicit confirmation
before a client can start encrypting a vault key to the replacement identity.
"""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from typing import Any

from . import crypto


class IdentityPinChangedError(crypto.IntegrityError):
    """Raised when a verified identity differs from its persisted TOFU pin."""


def decode_b64(value: Any, field: str) -> bytes:
    """Decode a strict padded base64 wire field."""
    if not isinstance(value, str):
        raise crypto.VaultCryptoError(f"{field} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise crypto.VaultCryptoError(f"{field} is not valid base64") from exc


class RosterPins:
    """Validate remote identities and maintain their local trust anchors.

    ``load`` and ``save`` operate on a plain ``{str(user_id): fingerprint}``
    mapping.  This makes the class usable with the protected local state store
    as well as an in-memory test fixture, without teaching crypto about files.
    """

    def __init__(
        self,
        load: Callable[[], Mapping[str, str]],
        save: Callable[[dict[str, str]], None],
    ) -> None:
        self._load = load
        self._save = save

    def verify_identity(self, identity: Mapping[str, Any]) -> bytes:
        """Verify an identity's self signature and return its raw fingerprint."""
        try:
            identity_id = str(identity["identity_id"])
            raw_user_id = identity["user_id"]
            if isinstance(raw_user_id, bool) or not isinstance(raw_user_id, int) or raw_user_id < 1:
                raise ValueError("user_id must be a positive integer")
            user_id = raw_user_id
            signing_key = decode_b64(identity["sig_public_key"], "sig_public_key")
            encryption_key = decode_b64(identity["enc_public_key"], "enc_public_key")
            fingerprint = bytes.fromhex(str(identity["fingerprint"]))
            signature = decode_b64(identity["self_signature"], "self_signature")
        except (KeyError, TypeError, ValueError) as exc:
            raise crypto.VaultCryptoError("identity has an invalid wire shape") from exc
        if not crypto.verify_identity(
            identity_id,
            user_id,
            signing_key,
            encryption_key,
            fingerprint,
            signature,
        ):
            raise crypto.IntegrityError("identity fingerprint or self-signature is invalid")
        return fingerprint

    def observe(
        self,
        identity: Mapping[str, Any],
        *,
        confirm_changed: bool = False,
    ) -> bytes:
        """Verify and pin an identity, requiring consent for a changed pin."""
        fingerprint = self.verify_identity(identity)
        user_id = str(self._user_id(identity))
        encoded = fingerprint.hex()
        pins = dict(self._load())
        previous = pins.get(user_id)
        if previous is not None and previous != encoded and not confirm_changed:
            raise IdentityPinChangedError(
                "identity fingerprint changed; compare the safety number and confirm it"
            )
        if previous != encoded:
            pins[user_id] = encoded
            # Keep every explicitly trusted historic identity.  A version chain
            # may legitimately be signed by a retired identity after its user
            # has reset; replacing the current pin must not make that history
            # unverifiable.
            pins[f"{user_id}:{encoded}"] = encoded
            self._save(pins)
        elif pins.get(f"{user_id}:{encoded}") != encoded:
            pins[f"{user_id}:{encoded}"] = encoded
            self._save(pins)
        return fingerprint

    def is_pinned(self, identity: Mapping[str, Any]) -> bool:
        """Return whether a verified identity matches its local pin."""
        fingerprint = self.verify_identity(identity)
        user_id = str(self._user_id(identity))
        pins = self._load()
        return (
            pins.get(user_id) == fingerprint.hex()
            or pins.get(f"{user_id}:{fingerprint.hex()}") == fingerprint.hex()
        )

    @staticmethod
    def _user_id(identity: Mapping[str, Any]) -> int:
        value = identity.get("user_id")
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise crypto.VaultCryptoError("identity user_id has an invalid wire shape")
        return value
