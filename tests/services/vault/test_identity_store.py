"""Focused tests for trusted local Team Vault identity custody."""
from __future__ import annotations

import base64
import json
import os
import stat
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.vault.crypto import (
    encode_bundle,
    endorsement_message,
    format_recovery_key,
    recovery_kek,
    seal,
    seal_wrap,
    self_signature,
    sign,
    wrap_aad,
)
from servonaut.services.vault.identity_client import (
    IdentityClient,
    IdentityProtocolError,
    _verified_server_identity,
)
from servonaut.services.vault.identity_store import IdentityStore, IdentityStoreError
from servonaut.services.vault.local_state import LocalStateError, VaultLocalState


_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="


def test_identity_round_trip_is_encrypted_private_and_signable(tmp_path) -> None:
    path = tmp_path / "vault" / "vault_keys.json"
    store = IdentityStore(path, environment_key=_KEY)
    created = store.create(
        identity_id="11111111-1111-4111-8111-111111111111", user_id=42,
    )
    store.save()

    loaded = IdentityStore(path, environment_key=_KEY).load()

    assert loaded.fingerprint == created.fingerprint
    assert loaded.device.sign(b"message") != b"message"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert created.signing_seed.hex() not in path.read_text(encoding="utf-8")


def test_default_store_migrates_owned_legacy_servonaut_root_to_private(
    tmp_path, monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    root = home / ".servonaut"
    root.mkdir(mode=0o775)
    os.chmod(root, 0o775)
    monkeypatch.setattr("servonaut.services.vault.identity_store.Path.home", lambda: home)

    store = IdentityStore(environment_key=_KEY)

    assert store.path == root / "vault" / "vault_keys.json"
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_default_store_refuses_symlinked_servonaut_root_without_touching_target(
    tmp_path, monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    os.chmod(target, 0o755)
    (home / ".servonaut").symlink_to(target, target_is_directory=True)
    monkeypatch.setattr("servonaut.services.vault.identity_store.Path.home", lambda: home)

    with pytest.raises(IdentityStoreError, match="custody root is unsafe"):
        IdentityStore(environment_key=_KEY)

    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_identity_storage_rejects_a_symlink(tmp_path) -> None:
    target = tmp_path / "target"
    target.write_text("{}", encoding="utf-8")
    path = tmp_path / "vault_keys.json"
    path.symlink_to(target)

    with pytest.raises(IdentityStoreError):
        IdentityStore(path, environment_key=_KEY).load()


def test_identity_storage_rejects_loose_permissions_and_tampering(tmp_path) -> None:
    path = tmp_path / "vault_keys.json"
    store = IdentityStore(path, environment_key=_KEY)
    store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=42)
    store.save()
    path.chmod(0o644)
    with pytest.raises(IdentityStoreError, match="permissions"):
        IdentityStore(path, environment_key=_KEY).load()
    path.chmod(0o600)
    document = path.read_text(encoding="utf-8")
    path.write_text(document.replace("blob", "blab", 1), encoding="utf-8")
    with pytest.raises(IdentityStoreError):
        IdentityStore(path, environment_key=_KEY).load()


def test_identity_storage_aad_prevents_user_account_switch(tmp_path) -> None:
    path = tmp_path / "vault_keys.json"
    store = IdentityStore(path, environment_key=_KEY)
    store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=42)
    store.save()
    document = path.read_text(encoding="utf-8")
    path.write_text(document.replace('"user_id":42', '"user_id":43'), encoding="utf-8")
    with pytest.raises(IdentityStoreError, match="authentication"):
        IdentityStore(path, environment_key=_KEY).load()


@pytest.mark.parametrize("user_id", [True, 7.0, "7"])
def test_identity_creation_rejects_noncanonical_user_ids(tmp_path, user_id) -> None:
    with pytest.raises(ValueError, match="positive"):
        IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY).create(
            identity_id="11111111-1111-4111-8111-111111111111", user_id=user_id,
        )


@pytest.mark.parametrize("user_id", [True, 42.0, "42"])
def test_identity_storage_rejects_noncanonical_user_id_json(tmp_path, user_id) -> None:
    path = tmp_path / "vault_keys.json"
    store = IdentityStore(path, environment_key=_KEY)
    store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=42)
    store.save()
    document = json.loads(path.read_text(encoding="utf-8"))
    document["user_id"] = user_id
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(IdentityStoreError, match="invalid shape"):
        IdentityStore(path, environment_key=_KEY).load()


def test_wipe_zeros_in_memory_material_and_removes_ciphertext(tmp_path) -> None:
    path = tmp_path / "vault_keys.json"
    store = IdentityStore(path, environment_key=_KEY)
    identity = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=42)
    store.store_device_ssh_private_key(b"secret-key")
    current = store.identity
    store.wipe()
    assert not path.exists()
    assert not any(identity.signing_seed)
    assert not any(identity.encryption_secret_key)
    assert not any(identity.device.signing_seed)
    assert not any(identity.device.encryption_secret_key)
    assert current is not None and current.device_ssh_private_key is not None and not any(current.device_ssh_private_key)


def test_lock_zeros_memory_but_retains_encrypted_custody(tmp_path) -> None:
    path = tmp_path / "vault" / "vault_keys.json"
    store = IdentityStore(path, environment_key=_KEY)
    created = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=42)
    store.save()
    store.lock()

    assert store.identity is None
    assert path.exists()
    assert not any(created.signing_seed)
    assert not any(created.encryption_secret_key)
    reloaded = IdentityStore(path, environment_key=_KEY).load()
    assert reloaded.fingerprint


def test_file_fallback_requires_explicit_opt_in(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("servonaut.services.vault.identity_store._set_keyring_value", lambda *_: False)
    store = IdentityStore(tmp_path / "vault_keys.json")
    store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=1)
    with pytest.raises(IdentityStoreError):
        store.save()

    fallback = IdentityStore(tmp_path / "vault_keys.json", allow_file_key_store=True)
    fallback.create(identity_id="22222222-2222-4222-8222-222222222222", user_id=1)
    fallback.save()
    assert stat.S_IMODE((tmp_path / "device-kek").stat().st_mode) == 0o600


def test_local_state_rejects_rollback(tmp_path) -> None:
    state = VaultLocalState(tmp_path / "state.json")
    state.record_vault_head("vault-1", 2, "a" * 64)
    with pytest.raises(LocalStateError, match="rollback"):
        state.record_vault_head("vault-1", 1, "b" * 64)


def test_approved_pending_bundle_is_verified_before_persistence(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY)
    source = IdentityStore.generate_identity(
        identity_id="11111111-1111-4111-8111-111111111111", user_id=7,
    )
    client = IdentityClient(None, store, timeout=1)  # type: ignore[arg-type]
    pending = client.begin_pending_device()
    signature = self_signature(
        bytes(source.signing_seed), source.identity_id, source.user_id,
        source.signing_public_key, source.encryption_public_key,
    )
    endorsement = sign(bytes(source.signing_seed), endorsement_message(
        source.identity_id, source.user_id, pending.device.device_id,
        pending.device.signing_public_key, pending.device.encryption_public_key,
    ))
    identity = {
        "identity_id": source.identity_id, "user_id": source.user_id,
        "fingerprint": source.fingerprint,
        "sig_public_key": base64.b64encode(source.signing_public_key).decode(),
        "enc_public_key": base64.b64encode(source.encryption_public_key).decode(),
        "self_signature": base64.b64encode(signature).decode(),
    }
    approval = {
        "state": "approved",
        "sealed_bundle": base64.b64encode(seal(
            encode_bundle(bytes(source.signing_seed), bytes(source.encryption_secret_key)),
            pending.device.encryption_public_key,
        )).decode(),
        "endorsement_signature": base64.b64encode(endorsement).decode(),
    }
    adopted = client.finish_pending_approval(approval=approval, identity=identity)
    assert adopted.fingerprint == source.fingerprint
    assert store.load().fingerprint == source.fingerprint


def test_pending_bundle_tamper_does_not_persist_identity(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY)
    source = IdentityStore.generate_identity(identity_id="11111111-1111-4111-8111-111111111111", user_id=7)
    client = IdentityClient(None, store, timeout=1)  # type: ignore[arg-type]
    pending = client.begin_pending_device()
    signature = self_signature(bytes(source.signing_seed), source.identity_id, source.user_id, source.signing_public_key, source.encryption_public_key)
    identity = {"identity_id": source.identity_id, "user_id": 7, "fingerprint": source.fingerprint, "sig_public_key": base64.b64encode(source.signing_public_key).decode(), "enc_public_key": base64.b64encode(source.encryption_public_key).decode(), "self_signature": base64.b64encode(signature).decode()}
    approval = {"state": "approved", "sealed_bundle": base64.b64encode(seal(encode_bundle(bytes(source.signing_seed), bytes(source.encryption_secret_key)), pending.device.encryption_public_key)).decode(), "endorsement_signature": base64.b64encode(b"x" * 64).decode()}
    with pytest.raises(IdentityProtocolError):
        client.finish_pending_approval(approval=approval, identity=identity)
    assert store.identity is None


@pytest.mark.asyncio
async def test_pending_nonce_change_discards_registration(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY)
    api = MagicMock()
    api.request_signed = AsyncMock(return_value={"state": "revealed"})
    client = IdentityClient(api, store, timeout=1)
    client.begin_pending_device()
    await client.reveal_pending_nonce({"state": "challenged", "approver_nonce": base64.b64encode(b"a" * 32).decode()})
    with pytest.raises(IdentityProtocolError, match="changed"):
        await client.reveal_pending_nonce({"state": "revealed", "approver_nonce": base64.b64encode(b"b" * 32).decode()})
    with pytest.raises(IdentityProtocolError, match="No pending"):
        client.pending_sas({"approver_nonce": base64.b64encode(b"a" * 32).decode()}, identity={})


def test_new_device_sas_uses_verified_remote_identity_without_local_identity(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY)
    source = IdentityStore.generate_identity(
        identity_id="11111111-1111-4111-8111-111111111111", user_id=7,
    )
    signature = self_signature(
        bytes(source.signing_seed), source.identity_id, source.user_id,
        source.signing_public_key, source.encryption_public_key,
    )
    identity = {
        "identity_id": source.identity_id, "user_id": source.user_id,
        "fingerprint": source.fingerprint,
        "sig_public_key": base64.b64encode(source.signing_public_key).decode(),
        "enc_public_key": base64.b64encode(source.encryption_public_key).decode(),
        "self_signature": base64.b64encode(signature).decode(),
    }
    client = IdentityClient(None, store, timeout=1)  # type: ignore[arg-type]
    client.begin_pending_device()

    safety_number = client.pending_sas(
        {"approver_nonce": base64.b64encode(b"a" * 32).decode()}, identity=identity,
    )

    assert safety_number.count(" ") == 1
    assert store.identity is None


def test_bad_remote_identity_for_pending_sas_wipes_new_device_keys(tmp_path) -> None:
    client = IdentityClient(None, IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY), timeout=1)  # type: ignore[arg-type]
    pending = client.begin_pending_device()

    with pytest.raises(IdentityProtocolError):
        client.pending_sas(
            {"approver_nonce": base64.b64encode(b"a" * 32).decode()}, identity={},
        )

    assert not any(pending.device.signing_seed)
    assert not any(pending.device.encryption_secret_key)
    assert not any(pending.device_nonce)


def test_confirmed_reset_replaces_custody_only_for_matching_verified_identity(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY)
    old = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=7)
    store.save()
    replacement = IdentityStore.generate_identity(
        identity_id="22222222-2222-4222-8222-222222222222", user_id=7,
    )
    signature = self_signature(
        bytes(replacement.signing_seed), replacement.identity_id, replacement.user_id,
        replacement.signing_public_key, replacement.encryption_public_key,
    )
    verified_status = {
        "identity": {
            "identity_id": replacement.identity_id, "user_id": replacement.user_id,
            "fingerprint": replacement.fingerprint,
            "sig_public_key": base64.b64encode(replacement.signing_public_key).decode(),
            "enc_public_key": base64.b64encode(replacement.encryption_public_key).decode(),
            "self_signature": base64.b64encode(signature).decode(),
        },
        "pending_reset": None,
    }
    client = IdentityClient(None, store, timeout=1)  # type: ignore[arg-type]

    activated = client.finish_confirmed_reset(replacement=replacement, status=verified_status)

    assert activated.fingerprint == replacement.fingerprint
    assert store.load().fingerprint == replacement.fingerprint
    assert not any(old.signing_seed)


@pytest.mark.asyncio
async def test_terminal_pending_status_wipes_new_device_keys(tmp_path) -> None:
    api = MagicMock()
    api.request_signed = AsyncMock(return_value={"state": "expired"})
    client = IdentityClient(api, IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY), timeout=1)
    pending = client.begin_pending_device()

    with pytest.raises(IdentityProtocolError, match="expired"):
        await client.pending_approval_status()

    assert not any(pending.device.signing_seed)
    assert not any(pending.device.encryption_secret_key)
    assert not any(pending.device_nonce)


@pytest.mark.asyncio
async def test_wrong_identity_recovery_wrap_is_never_persisted(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY)
    api = MagicMock()
    client = IdentityClient(api, store, timeout=1)
    client.begin_pending_device()
    source = IdentityStore.generate_identity(identity_id="11111111-1111-4111-8111-111111111111", user_id=7)
    claimed = IdentityStore.generate_identity(identity_id="22222222-2222-4222-8222-222222222222", user_id=7)
    recovery = b"r" * 32
    wrapped = seal_wrap(
        recovery_kek(recovery, source.identity_id),
        encode_bundle(bytes(source.signing_seed), bytes(source.encryption_secret_key)),
        wrap_aad("recovery", source.identity_id, source.user_id, source.fingerprint_raw),
    )
    claimed_signature = self_signature(bytes(claimed.signing_seed), claimed.identity_id, claimed.user_id, claimed.signing_public_key, claimed.encryption_public_key)
    claimed_wire = {
        "identity_id": claimed.identity_id, "user_id": claimed.user_id,
        "fingerprint": claimed.fingerprint,
        "sig_public_key": base64.b64encode(claimed.signing_public_key).decode(),
        "enc_public_key": base64.b64encode(claimed.encryption_public_key).decode(),
        "self_signature": base64.b64encode(claimed_signature).decode(),
    }
    with pytest.raises(IdentityProtocolError, match="Recovery bundle"):
        await client.activate_with_recovery(
            recovery_key=format_recovery_key(recovery),
            recovery_wrap={"blob": base64.b64encode(wrapped).decode()}, identity=claimed_wire,
        )
    assert store.identity is None
    api.request_signed.assert_not_called()


@pytest.mark.asyncio
async def test_reset_transport_failure_keeps_the_old_identity(tmp_path) -> None:
    store = IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY)
    old = store.create(identity_id="11111111-1111-4111-8111-111111111111", user_id=7)
    store.save()
    api = MagicMock()
    api.request_signed = AsyncMock(side_effect=RuntimeError("offline"))
    client = IdentityClient(api, store, timeout=1)
    replacement = IdentityStore.generate_identity(identity_id="22222222-2222-4222-8222-222222222222", user_id=7)
    with pytest.raises(RuntimeError, match="offline"):
        await client.request_reset(
            replacement=replacement, recovery_key=format_recovery_key(b"r" * 32),
            reason="rotate", device_name="test device", platform="linux", client="cli",
        )
    assert store.load().fingerprint == old.fingerprint


def test_verified_server_identity_rejects_noncanonical_numeric_user_ids() -> None:
    source = IdentityStore.generate_identity(identity_id="11111111-1111-4111-8111-111111111111", user_id=7)
    signature = self_signature(bytes(source.signing_seed), source.identity_id, source.user_id, source.signing_public_key, source.encryption_public_key)
    wire = {"identity_id": source.identity_id, "user_id": source.user_id, "fingerprint": source.fingerprint, "sig_public_key": base64.b64encode(source.signing_public_key).decode(), "enc_public_key": base64.b64encode(source.encryption_public_key).decode(), "self_signature": base64.b64encode(signature).decode()}
    for value in (True, 7.0, "7"):
        bad = dict(wire, user_id=value)
        with pytest.raises(IdentityProtocolError, match="positive integer"):
            _verified_server_identity(bad)


@pytest.mark.asyncio
async def test_pending_registration_rejects_noncanonical_user_id_before_transport(tmp_path) -> None:
    api = MagicMock()
    api.request_signed = AsyncMock()
    client = IdentityClient(api, IdentityStore(tmp_path / "vault_keys.json", environment_key=_KEY), timeout=1)
    client.begin_pending_device()
    for value in (True, 7.0, "7"):
        with pytest.raises(ValueError, match="positive integer"):
            await client.register_pending_device(user_id=value, name="device", platform="linux", client="cli")
    api.request_signed.assert_not_called()
