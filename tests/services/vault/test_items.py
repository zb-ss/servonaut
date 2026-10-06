from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from servonaut.services.vault import crypto
from servonaut.services.vault.items import VaultItemService
from servonaut.services.vault.roster_pins import RosterPins
from servonaut.services.vault.team_vault_client import TeamVaultClient, VaultStateError


def test_ssh_payload_rejects_non_matching_public_private_material() -> None:
    with pytest.raises(ValueError):
        VaultItemService._validate_payload(
            "ssh_key",
            {"name": "key", "notes": "", "public_key": "ssh-ed25519 AAAA", "private_key_openssh": "bad", "key_type": "ssh-ed25519", "public_fingerprint": "SHA256:bad"},
            "SHA256:bad",
        )


def test_item_metadata_rejects_boolean_revision() -> None:
    class Vaults:
        def _signer(self): return object()

    class Api:
        async def request_signed(self, *_args, **_kwargs):
            return {"revision": True}

    import asyncio

    with pytest.raises(VaultStateError):
        asyncio.run(VaultItemService(Api(), Vaults()).get_item(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        ))


def test_conflict_retry_requires_explicit_confirmation() -> None:
    import asyncio

    class Conflict(Exception):
        code = "revision_conflict"

    service = VaultItemService(object(), object())
    attempts = 0

    async def write_once(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        raise Conflict()

    service._write_once = write_once  # type: ignore[method-assign]
    with pytest.raises(VaultStateError, match="review it"):
        asyncio.run(service.write_item(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "secret", {"name": "name", "notes": "", "value": "x", "kind": "other", "tags": []},
            expected_revision=1,
        ))
    assert attempts == 1


@pytest.mark.asyncio
async def test_fresh_item_write_includes_current_wrapper_identity() -> None:
    vault_id = "11111111-1111-4111-8111-111111111111"
    item_id = "22222222-2222-4222-8222-222222222222"
    identity = SimpleNamespace(
        identity_id="33333333-3333-4333-8333-333333333333",
        signing_seed=b"a" * 32,
    )
    version_key = crypto.x25519_public(b"b" * 32)
    vault = {
        "vault_id": vault_id, "current_version": 1,
        "versions": [{"version": 1, "public_key": base64.b64encode(version_key).decode()}],
    }

    class Vaults:
        _identity_store = SimpleNamespace(identity=identity)

        async def get_vault(self, _vault_id):
            return vault

        def open_my_grant(self, _vault):
            return b"c" * 32

    service = VaultItemService(None, Vaults())
    captured: dict[str, object] = {}

    async def signed(_method, _path, payload):
        captured.update(payload)
        return {"revision": 1}

    service._signed = signed  # type: ignore[method-assign]
    await service._write_once(
        vault_id, item_id, "secret", {"name": "token", "notes": "", "value": "opaque"},
        expected_revision=0,
    )

    assert captured["author_identity_id"] == identity.identity_id
    assert captured["wrapper_identity_id"] == identity.identity_id


class _PersonalState:
    def __init__(self) -> None:
        self.data = {"vault_heads": {}}

    def load(self):
        return self.data

    def record_vault_head(self, vault_id, version, record_hash) -> None:
        self.data["vault_heads"][vault_id] = {"version": version, "record_hash": record_hash}

    def record_item_revision(self, _item_id, _revision) -> None:
        pass


def _sparse_personal_item(*, author_id: str | None = None, wrapper_id: str | None = None, bad_signatures: bool = False):
    signing_seed, encryption_secret, vault_secret = b"a" * 32, b"b" * 32, b"v" * 32
    identity_id = "11111111-1111-4111-8111-111111111111"
    vault_id = "22222222-2222-4222-8222-222222222222"
    item_id = "33333333-3333-4333-8333-333333333333"
    signing_public = crypto.public_from_seed(signing_seed)
    encryption_public = crypto.x25519_public(encryption_secret)
    fingerprint = crypto.identity_fingerprint(signing_public, encryption_public)
    identity = SimpleNamespace(
        identity_id=identity_id, user_id=1, signing_seed=signing_seed,
        encryption_secret_key=encryption_secret, fingerprint=fingerprint.hex(),
    )
    version_public = crypto.x25519_public(vault_secret)
    version_message = crypto.version_message(vault_id, "user:1", 1, version_public, crypto.ZERO_HASH, identity_id)
    version_signature = crypto.sign(signing_seed, version_message)
    sealed = crypto.seal(vault_secret, encryption_public)
    grant_signature = crypto.sign(
        signing_seed,
        crypto.grant_message(vault_id, "user:1", 1, version_public, 1, identity_id, fingerprint, sealed, identity_id),
    )
    vault = {
        "vault_id": vault_id, "kind": "personal", "scope": "user:1", "owner_user_id": 1,
        "current_version": 1,
        "versions": [{
            "version": 1, "public_key": base64.b64encode(version_public).decode(),
            "prev_hash": base64.b64encode(crypto.ZERO_HASH).decode(),
            "record_hash": base64.b64encode(crypto.record_hash(version_message, version_signature)).decode(),
            "creator_identity_id": identity_id, "signature": base64.b64encode(version_signature).decode(),
        }],
        "identities": {}, "roster": [],
        "my_grant": {"version": 1, "sealed_private_key": base64.b64encode(sealed).decode(),
                     "granter_identity_id": identity_id, "signature": base64.b64encode(grant_signature).decode()},
    }
    payload = {"name": "token", "notes": "", "value": "opaque"}
    item_key = b"k" * 32
    nonce, ciphertext = crypto.encrypt_item(
        item_key, b'{"name":"token","notes":"","value":"opaque"}',
        crypto.item_aad(vault_id, item_id, "secret", 1),
    )
    wrapped_key = crypto.seal(item_key, version_public)
    author = author_id or identity_id
    wrapper = wrapper_id or identity_id
    content_signature = crypto.sign(
        signing_seed,
        crypto.item_content_message(vault_id, item_id, "secret", 1, nonce, ciphertext, None, author),
    )
    wrap_signature = crypto.sign(
        signing_seed,
        crypto.item_wrap_message(vault_id, item_id, 1, 1, wrapped_key, ciphertext, wrapper),
    )
    if bad_signatures:
        content_signature = b"x" * len(content_signature)
        wrap_signature = b"x" * len(wrap_signature)
    item = {
        "item_id": item_id, "type": "secret", "revision": 1, "key_version": 1,
        "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode(),
        "ciphertext_sha256": base64.b64encode(crypto.sha256(ciphertext)).decode(), "public_fingerprint": None,
        "author_identity_id": author, "content_signature": base64.b64encode(content_signature).decode(),
        "wrapped_item_key": base64.b64encode(wrapped_key).decode(), "wrapper_identity_id": wrapper,
        "wrap_signature": base64.b64encode(wrap_signature).decode(),
    }
    pins = RosterPins(lambda: {}, lambda _value: None)
    client = TeamVaultClient(None, SimpleNamespace(identity=identity), pins, _PersonalState())
    return VaultItemService(None, client), vault, item, payload


def test_sparse_personal_item_reads_using_only_local_custody_signer() -> None:
    service, vault, item, payload = _sparse_personal_item()

    assert service.read_item(vault, item) == payload


@pytest.mark.parametrize("author_id,wrapper_id,bad_signatures", [
    ("44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555", False),
    (None, None, True),
])
def test_sparse_personal_item_rejects_untrusted_or_invalid_signatures(author_id, wrapper_id, bad_signatures) -> None:
    service, vault, item, _payload = _sparse_personal_item(
        author_id=author_id, wrapper_id=wrapper_id, bad_signatures=bad_signatures,
    )

    with pytest.raises(VaultStateError, match="no trusted content"):
        service.read_item(vault, item)


def test_sparse_personal_item_requires_matching_local_owner() -> None:
    service, vault, item, _payload = _sparse_personal_item()
    vault["owner_user_id"] = 2

    with pytest.raises(VaultStateError, match="ownership does not match"):
        service.read_item(vault, item)
