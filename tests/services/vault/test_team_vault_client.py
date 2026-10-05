from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from servonaut.services.vault import crypto
from servonaut.services.vault.roster_pins import RosterPins
from servonaut.services.vault.team_vault_client import TeamVaultClient, VaultStateError


class _State:
    def __init__(self) -> None:
        self.data = {"vault_heads": {}}
        self.saved = False
    def load(self): return self.data
    def record_vault_head(self, vault_id, version, record_hash):
        self.saved = True
        self.data["vault_heads"][vault_id] = {"version": version, "record_hash": record_hash}


def test_invalid_current_version_does_not_persist_head() -> None:
    seed, enc = b"a" * 32, b"b" * 32
    identity_id = "11111111-1111-4111-8111-111111111111"
    vault_id = "22222222-2222-4222-8222-222222222222"
    sig, enc_public = crypto.public_from_seed(seed), crypto.x25519_public(enc)
    fingerprint = crypto.identity_fingerprint(sig, enc_public)
    identity = {"identity_id": identity_id, "user_id": 1, "grantable": True, "sig_public_key": base64.b64encode(sig).decode(), "enc_public_key": base64.b64encode(enc_public).decode(), "fingerprint": fingerprint.hex(), "self_signature": base64.b64encode(crypto.self_signature(seed, identity_id, 1, sig, enc_public)).decode()}
    vault_public = crypto.x25519_public(b"v" * 32)
    message = crypto.version_message(vault_id, "user:1", 1, vault_public, crypto.ZERO_HASH, identity_id)
    record_hash = crypto.record_hash(message, crypto.sign(seed, message))
    vault = {"vault_id": vault_id, "scope": "user:1", "current_version": 2, "versions": [{"version": 1, "public_key": base64.b64encode(vault_public).decode(), "prev_hash": base64.b64encode(crypto.ZERO_HASH).decode(), "record_hash": base64.b64encode(record_hash).decode(), "creator_identity_id": identity_id, "signature": base64.b64encode(crypto.sign(seed, message)).decode()}], "identities": {identity_id: identity}, "roster": []}
    pin_data: dict[str, str] = {}
    state = _State()
    client = TeamVaultClient(None, SimpleNamespace(identity=SimpleNamespace(identity_id=identity_id)), RosterPins(lambda: pin_data, lambda value: pin_data.update(value)), state)
    with pytest.raises(VaultStateError):
        client.verify_vault(vault)
    assert not state.saved


def _personal_vault_with_omitted_identities(*, granter_identity_id: str | None = None):
    """Build the intentionally sparse personal-vault response sent by the API."""
    signing_seed, encryption_secret, vault_secret = b"a" * 32, b"b" * 32, b"v" * 32
    identity_id = "11111111-1111-4111-8111-111111111111"
    vault_id = "22222222-2222-4222-8222-222222222222"
    signing_public = crypto.public_from_seed(signing_seed)
    encryption_public = crypto.x25519_public(encryption_secret)
    fingerprint = crypto.identity_fingerprint(signing_public, encryption_public)
    identity = SimpleNamespace(
        identity_id=identity_id,
        user_id=1,
        signing_seed=signing_seed,
        encryption_secret_key=encryption_secret,
        fingerprint=fingerprint.hex(),
    )
    version_public = crypto.x25519_public(vault_secret)
    version_message = crypto.version_message(
        vault_id, "user:1", 1, version_public, crypto.ZERO_HASH, identity_id
    )
    version_signature = crypto.sign(signing_seed, version_message)
    sealed = crypto.seal(vault_secret, encryption_public)
    granter_id = granter_identity_id or identity_id
    grant_signature = crypto.sign(
        signing_seed,
        crypto.grant_message(
            vault_id, "user:1", 1, version_public, 1, identity_id,
            fingerprint, sealed, granter_id,
        ),
    )
    vault = {
        "vault_id": vault_id,
        "kind": "personal",
        "scope": "user:1",
        "current_version": 1,
        "versions": [{
            "version": 1,
            "public_key": base64.b64encode(version_public).decode(),
            "prev_hash": base64.b64encode(crypto.ZERO_HASH).decode(),
            "record_hash": base64.b64encode(crypto.record_hash(version_message, version_signature)).decode(),
            "creator_identity_id": identity_id,
            "signature": base64.b64encode(version_signature).decode(),
        }],
        # Personal-vault response contract deliberately omits roster identities.
        "identities": {},
        "roster": [],
        "my_grant": {
            "version": 1,
            "sealed_private_key": base64.b64encode(sealed).decode(),
            "granter_identity_id": granter_id,
            "signature": base64.b64encode(grant_signature).decode(),
        },
    }
    pins = RosterPins(lambda: {}, lambda _value: None)
    return TeamVaultClient(None, SimpleNamespace(identity=identity), pins, _State()), vault, vault_secret


def test_personal_grant_uses_local_verified_signer_when_response_omits_identities() -> None:
    client, vault, vault_secret = _personal_vault_with_omitted_identities()

    assert client.open_my_grant(vault) == vault_secret


def test_personal_grant_with_omitted_foreign_signer_fails_closed() -> None:
    client, vault, _vault_secret = _personal_vault_with_omitted_identities(
        granter_identity_id="33333333-3333-4333-8333-333333333333"
    )

    with pytest.raises(VaultStateError, match="not the local identity"):
        client.open_my_grant(vault)


def _identity(seed: bytes, enc: bytes, identity_id: str, user_id: int, *, grantable: bool) -> dict:
    sig, enc_public = crypto.public_from_seed(seed), crypto.x25519_public(enc)
    return {
        "identity_id": identity_id, "user_id": user_id, "grantable": grantable,
        "sig_public_key": base64.b64encode(sig).decode(),
        "enc_public_key": base64.b64encode(enc_public).decode(),
        "fingerprint": crypto.identity_fingerprint(sig, enc_public).hex(),
        "self_signature": base64.b64encode(crypto.self_signature(seed, identity_id, user_id, sig, enc_public)).decode(),
    }


def _team_vault(*, creator_seed: bytes, creator_id: str, identities: dict, roster_ids: list[str]) -> dict:
    vault_id = "22222222-2222-4222-8222-222222222222"
    scope = "team:33333333-3333-4333-8333-333333333333"
    vault_public = crypto.x25519_public(b"v" * 32)
    message = crypto.version_message(vault_id, scope, 1, vault_public, crypto.ZERO_HASH, creator_id)
    signature = crypto.sign(creator_seed, message)
    return {
        "vault_id": vault_id, "kind": "team", "scope": scope, "current_version": 1,
        "versions": [{
            "version": 1, "public_key": base64.b64encode(vault_public).decode(),
            "prev_hash": base64.b64encode(crypto.ZERO_HASH).decode(),
            "record_hash": base64.b64encode(crypto.record_hash(message, signature)).decode(),
            "creator_identity_id": creator_id, "signature": base64.b64encode(signature).decode(),
        }],
        "identities": identities,
        "roster": [{"identity": {"identity_id": identity_id}} for identity_id in roster_ids],
    }


_OWNER_ID = "11111111-1111-4111-8111-111111111111"
_UNCONFIRMED_ID = "44444444-4444-4444-8444-444444444444"


def test_unconfirmed_active_member_does_not_block_the_vault_and_is_not_pinned() -> None:
    owner = _identity(b"a" * 32, b"b" * 32, _OWNER_ID, 1, grantable=True)
    unconfirmed = _identity(b"c" * 32, b"d" * 32, _UNCONFIRMED_ID, 2, grantable=False)
    vault = _team_vault(
        creator_seed=b"a" * 32, creator_id=_OWNER_ID,
        identities={_OWNER_ID: owner, _UNCONFIRMED_ID: unconfirmed},
        roster_ids=[_OWNER_ID, _UNCONFIRMED_ID],
    )
    pin_data: dict[str, str] = {}
    pins = RosterPins(lambda: pin_data, lambda value: pin_data.update(value))
    client = TeamVaultClient(None, SimpleNamespace(identity=None), pins, _State())

    assert client.verify_vault(vault)[0] == 1
    assert pins.is_pinned(owner)
    assert not pins.is_pinned(unconfirmed)


def test_version_signed_by_an_unconfirmed_member_fails_closed() -> None:
    owner = _identity(b"a" * 32, b"b" * 32, _OWNER_ID, 1, grantable=True)
    unconfirmed = _identity(b"c" * 32, b"d" * 32, _UNCONFIRMED_ID, 2, grantable=False)
    vault = _team_vault(
        creator_seed=b"c" * 32, creator_id=_UNCONFIRMED_ID,
        identities={_OWNER_ID: owner, _UNCONFIRMED_ID: unconfirmed},
        roster_ids=[_OWNER_ID, _UNCONFIRMED_ID],
    )
    state = _State()
    client = TeamVaultClient(None, SimpleNamespace(identity=None), RosterPins(lambda: {}, lambda _value: None), state)

    with pytest.raises(crypto.VaultCryptoError):
        client.verify_vault(vault)
    assert not state.saved


def test_unpinned_identity_outside_the_roster_still_fails_closed() -> None:
    owner = _identity(b"a" * 32, b"b" * 32, _OWNER_ID, 1, grantable=True)
    former = _identity(b"c" * 32, b"d" * 32, _UNCONFIRMED_ID, 2, grantable=True)
    vault = _team_vault(
        creator_seed=b"a" * 32, creator_id=_OWNER_ID,
        identities={_OWNER_ID: owner, _UNCONFIRMED_ID: former},
        roster_ids=[_OWNER_ID],
    )
    client = TeamVaultClient(None, SimpleNamespace(identity=None), RosterPins(lambda: {}, lambda _value: None), _State())

    with pytest.raises(VaultStateError, match="never pinned"):
        client.verify_vault(vault)


@pytest.mark.asyncio
async def test_auto_grants_skip_an_unconfirmed_member_and_grant_the_confirmed_one() -> None:
    from unittest.mock import AsyncMock

    from servonaut.services.vault.grant_processor import GrantProcessor

    owner_seed, owner_enc, vault_secret = b"a" * 32, b"b" * 32, b"v" * 32
    member_id, unconfirmed_id = "55555555-5555-4555-8555-555555555555", _UNCONFIRMED_ID
    owner = _identity(owner_seed, owner_enc, _OWNER_ID, 1, grantable=True)
    member = _identity(b"e" * 32, b"f" * 32, member_id, 3, grantable=True)
    unconfirmed = _identity(b"c" * 32, b"d" * 32, unconfirmed_id, 2, grantable=False)
    vault = _team_vault(
        creator_seed=owner_seed, creator_id=_OWNER_ID,
        identities={_OWNER_ID: owner, member_id: member, unconfirmed_id: unconfirmed},
        roster_ids=[],
    )
    vault["roster"] = [
        {"user_id": 1, "role": "owner", "status": "granted", "identity": owner},
        {"user_id": 3, "role": "member", "status": "awaiting_grant", "identity": member},
        {"user_id": 2, "role": "member", "status": "awaiting_confirmation", "identity": unconfirmed},
    ]
    version_public = base64.b64decode(vault["versions"][0]["public_key"])
    owner_fingerprint = bytes.fromhex(owner["fingerprint"])
    sealed = crypto.seal(vault_secret, crypto.x25519_public(owner_enc))
    vault["my_grant"] = {
        "version": 1, "sealed_private_key": base64.b64encode(sealed).decode(),
        "granter_identity_id": _OWNER_ID,
        "signature": base64.b64encode(crypto.sign(owner_seed, crypto.grant_message(
            vault["vault_id"], vault["scope"], 1, version_public, 1, _OWNER_ID,
            owner_fingerprint, sealed, _OWNER_ID,
        ))).decode(),
    }
    local = SimpleNamespace(
        identity_id=_OWNER_ID, user_id=1, signing_seed=owner_seed,
        encryption_secret_key=owner_enc, fingerprint=owner["fingerprint"],
    )
    pin_data: dict[str, str] = {}
    client = TeamVaultClient(
        None, SimpleNamespace(identity=local),
        RosterPins(lambda: pin_data, lambda value: pin_data.update(value)), _State(),
    )
    client._signed = AsyncMock(return_value={"accepted": [3], "skipped": []})

    result = await GrantProcessor(client).process_auto_grants(vault)

    method, path, body = client._signed.await_args.args
    assert (method, path) == ("POST", f"/api/v1/vaults/{vault['vault_id']}/grants")
    assert [grant["recipient_identity_id"] for grant in body["grants"]] == [member_id]
    assert result["pending_confirmation"] == []
