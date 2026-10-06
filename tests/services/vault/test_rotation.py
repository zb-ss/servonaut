from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from servonaut.services.vault import crypto
from servonaut.services.vault.rotation import RotationService


def test_exposure_resolution_requires_known_resolution() -> None:
    service = RotationService(None, None)
    with pytest.raises(ValueError):
        import asyncio
        asyncio.run(service.resolve_exposure("v", "e", resolution="unknown"))


@pytest.mark.asyncio
async def test_awaiting_approval_recipient_is_never_sealed_without_approval() -> None:
    local_seed, local_enc = b"a" * 32, b"b" * 32
    recipient_seed, recipient_enc = b"c" * 32, b"d" * 32
    local = SimpleNamespace(
        identity_id="local", user_id=1, signing_seed=local_seed,
        encryption_secret_key=local_enc,
        fingerprint=crypto.identity_fingerprint(
            crypto.public_from_seed(local_seed), crypto.x25519_public(local_enc),
        ).hex(),
    )
    recipient = {
        "identity_id": "recipient", "user_id": 2, "grantable": True,
        "enc_public_key": base64.b64encode(crypto.x25519_public(recipient_enc)).decode(),
        "fingerprint": crypto.identity_fingerprint(
            crypto.public_from_seed(recipient_seed), crypto.x25519_public(recipient_enc),
        ).hex(),
    }

    class Pins:
        def verify_identity(self, _identity):
            return bytes.fromhex(recipient["fingerprint"])

        def observe(self, _identity, **_kwargs):
            return bytes.fromhex(recipient["fingerprint"])

    service = RotationService(SimpleNamespace(_pins=Pins()), None, strict_verification=False)
    grants = await service._recipient_grants(
        {"vault_id": "v", "scope": "team:t", "roster": [{"role": "member", "status": "awaiting_approval", "identity": recipient}]},
        1, crypto.x25519_public(b"e" * 32), b"f" * 32, local, approval=None,
    )

    assert [grant["recipient_identity_id"] for grant in grants] == ["local"]
