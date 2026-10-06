"""Team Vault v1 cryptographic test vectors and trust-boundary negatives."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import nacl.bindings
import pytest

from servonaut.services.vault import crypto


VECTORS = json.loads(
    (Path(__file__).parents[2] / "fixtures" / "vault" / "vault-test-vectors-v1.json").read_text()
)


def raw(value: str) -> bytes:
    return bytes.fromhex(value)


def deterministic_seal(plaintext: bytes, recipient_public_key: bytes, ephemeral_secret_key: bytes) -> bytes:
    """The vector-only fixed-ephemeral sealed-box construction."""
    ephemeral_public_key = crypto.x25519_public(ephemeral_secret_key)
    nonce = hashlib.blake2b(ephemeral_public_key + recipient_public_key, digest_size=24).digest()
    return ephemeral_public_key + nacl.bindings.crypto_box(
        plaintext, nonce, recipient_public_key, ephemeral_secret_key
    )


def alice() -> dict[str, object]:
    return VECTORS["identity_alice"]


def bob() -> dict[str, object]:
    return VECTORS["identity_bob"]


def test_fixture_is_verbatim_v1() -> None:
    fixture = Path(__file__).parents[2] / "fixtures" / "vault" / "vault-test-vectors-v1.json"
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == "862ebeb9ebe5f6df27e4d69aff977061859d7119f85a40bc795eb5428fa6c140"


def test_lp_encoding_vector() -> None:
    vector = VECTORS["lp_encoding"]
    fields = vector["fields"]
    assert crypto.msg(
        vector["domain"],
        fields["uuid"].encode(),
        crypto.u64(fields["u64"]),
        fields["utf8"].encode(),
        raw(fields["bytes_hex"]),
    ).hex() == vector["expected_hex"]
    assert crypto.lst([item.encode() for item in vector["list_example"]["items"]]).hex() == vector[
        "list_example"
    ]["expected_hex"]


@pytest.mark.parametrize("value", [True, False, -1, 1 << 64, "1", 1.0])
def test_u64_rejects_noncanonical_numeric_values(value: object) -> None:
    with pytest.raises(crypto.VaultCryptoError):
        crypto.u64(value)  # type: ignore[arg-type]


def test_version_chain_rejects_boolean_version() -> None:
    records, pinned = _version_records()
    records[0]["version"] = True
    with pytest.raises(crypto.IntegrityError):
        crypto.verify_version_chain(records, pinned)


@pytest.mark.parametrize("cert_type", [True, False, 1.0, "1"])
def test_certificate_builder_rejects_noncanonical_certificate_type(cert_type: object) -> None:
    with pytest.raises(crypto.VaultCryptoError):
        crypto.build_ed25519_certificate(
            b"a" * 32,
            1,
            cert_type,  # type: ignore[arg-type]
            "key-id",
            [],
            0,
            1,
            {},
            [],
            b"b" * 32,
            b"c" * 32,
            b"d" * 32,
        )


@pytest.mark.parametrize("name", ["identity_alice", "identity_bob"])
def test_identity_vectors(name: str) -> None:
    vector = VECTORS[name]
    seed = raw(vector["sig_seed_hex"])
    enc_secret = raw(vector["enc_secret_key_hex"])
    sig_public = crypto.public_from_seed(seed)
    enc_public = crypto.x25519_public(enc_secret)
    fingerprint = crypto.identity_fingerprint(sig_public, enc_public)
    message = crypto.self_signature_message(vector["identity_id"], vector["user_id"], sig_public, enc_public)
    signature = crypto.self_signature(seed, vector["identity_id"], vector["user_id"], sig_public, enc_public)
    assert sig_public.hex() == vector["sig_public_key_hex"]
    assert enc_public.hex() == vector["enc_public_key_hex"]
    assert fingerprint.hex() == vector["fingerprint_hex"]
    assert message.hex() == vector["self_signature_message_hex"]
    assert signature.hex() == vector["self_signature_hex"]
    assert crypto.verify_identity(vector["identity_id"], vector["user_id"], sig_public, enc_public, fingerprint, signature)
    assert crypto.safety_number(fingerprint) == vector["safety_number"]
    bundle = crypto.encode_bundle(seed, enc_secret)
    assert bundle.hex() == vector["bundle_hex"]
    assert crypto.decode_bundle(bundle) == (seed, enc_secret)


def test_recovery_vector_and_checksum_before_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    vector = VECTORS["recovery_wrap"]
    identity = alice()
    recovery_key = raw(vector["recovery_key_raw_hex"])
    fingerprint = raw(identity["fingerprint_hex"])
    assert crypto.recovery_checksum(recovery_key).hex() == vector["checksum_hex"]
    assert crypto.format_recovery_key(recovery_key) == vector["recovery_key_display"]
    assert crypto.parse_recovery_key(vector["recovery_key_display"]) == recovery_key
    kek = crypto.recovery_kek(recovery_key, identity["identity_id"])
    aad = crypto.wrap_aad("recovery", identity["identity_id"], identity["user_id"], fingerprint)
    assert kek.hex() == vector["kek_hex"]
    assert aad.hex() == vector["aad_hex"]
    assert crypto.seal_wrap(kek, raw(vector["plaintext_bundle_hex"]), aad, raw(vector["nonce_hex"])).hex() == vector["blob_hex"]
    assert crypto.open_wrap(kek, raw(vector["blob_hex"]), aad) == raw(vector["plaintext_bundle_hex"])
    monkeypatch.setattr(crypto, "recovery_kek", lambda *_: pytest.fail("KDF must not run"))
    with pytest.raises(crypto.IntegrityError):
        crypto.parse_recovery_key(vector["recovery_key_display"].replace("0", "1", 1))


def test_device_and_request_vectors() -> None:
    vector = VECTORS["device_approval"]
    identity = alice()
    signing_seed = raw(vector["device_sig_seed_hex"])
    signing_public = crypto.public_from_seed(signing_seed)
    encryption_secret = raw(vector["device_enc_secret_key_hex"])
    encryption_public = crypto.x25519_public(encryption_secret)
    commitment = crypto.device_commitment(vector["device_id"], signing_public, encryption_public, raw(vector["device_nonce_hex"]))
    registration = crypto.device_registration_message(vector["device_id"], vector["user_id"], signing_public, encryption_public, commitment)
    assert signing_public.hex() == vector["device_sig_public_key_hex"]
    assert encryption_public.hex() == vector["device_enc_public_key_hex"]
    assert commitment.hex() == vector["commitment_hex"]
    assert crypto.msg(
        "svn-dev-commit-v1", vector["device_id"].encode(), signing_public, encryption_public, raw(vector["device_nonce_hex"])
    ).hex() == vector["commitment_message_hex"]
    assert registration.hex() == vector["registration_message_hex"]
    assert crypto.verify(signing_public, registration, raw(vector["registration_signature_hex"]))
    sas_hash = crypto.sha256(crypto.msg("svn-dev-sas-v1", vector["device_id"].encode(), raw(vector["identity_fingerprint_hex"]), signing_public, encryption_public, raw(vector["device_nonce_hex"]), raw(vector["approver_nonce_hex"])))
    assert sas_hash.hex() == vector["sas_hash_hex"]
    assert crypto.sas(vector["device_id"], raw(vector["identity_fingerprint_hex"]), signing_public, encryption_public, raw(vector["device_nonce_hex"]), raw(vector["approver_nonce_hex"])).replace(" ", "") == vector["sas"]
    endorsement = crypto.endorsement_message(identity["identity_id"], vector["user_id"], vector["device_id"], signing_public, encryption_public)
    assert endorsement.hex() == vector["endorsement_message_hex"]
    assert crypto.sign(raw(identity["sig_seed_hex"]), endorsement).hex() == vector["endorsement_signature_hex"]
    assert crypto.verify(raw(identity["sig_public_key_hex"]), endorsement, raw(vector["endorsement_signature_hex"]))
    sealed = raw(vector["sealed_bundle_hex"])
    assert deterministic_seal(raw(identity["bundle_hex"]), encryption_public, raw(vector["sealed_bundle_ephemeral_secret_hex"])) == sealed
    assert crypto.open_sealed(sealed, encryption_public, encryption_secret) == raw(identity["bundle_hex"])

    request = VECTORS["request_signature"]
    message = crypto.request_message(request["method"], request["request_target"], request["timestamp"], base64.b64decode(request["nonce_b64"]), request["device_id"], request["body_utf8"].encode())
    assert message.hex() == request["message_hex"]
    assert crypto.sign(signing_seed, message).hex() == request["signature_hex"]
    assert crypto.verify(signing_public, message, base64.b64decode(request["signature_b64"]))


def _version_records() -> tuple[list[dict[str, object]], dict[str, bytes]]:
    versions = VECTORS["vault_versions"]
    records: list[dict[str, object]] = []
    for version in (1, 2):
        row = versions[f"v{version}"]
        records.append(
            {
                "vault_id": versions["vault_id"], "scope": versions["scope"], "version": version,
                "public_key": raw(row["tvk_public_key_hex"]), "prev_hash": raw(row["prev_hash_hex"]),
                "creator_identity_id": versions["creator_identity_id"], "signature": raw(row["signature_hex"]),
                "record_hash": raw(row["record_hash_hex"]),
            }
        )
    return records, {versions["creator_identity_id"]: raw(bob()["sig_public_key_hex"])}


def test_vault_versions_and_grant_vectors() -> None:
    versions = VECTORS["vault_versions"]
    records, pinned = _version_records()
    assert crypto.verify_version_chain(records, pinned) == (2, raw(versions["v2"]["record_hash_hex"]))
    previous = crypto.ZERO_HASH
    for version in (1, 2):
        row = versions[f"v{version}"]
        message = crypto.version_message(versions["vault_id"], versions["scope"], version, raw(row["tvk_public_key_hex"]), previous, versions["creator_identity_id"])
        assert message.hex() == row["message_hex"]
        assert crypto.sign(raw(bob()["sig_seed_hex"]), message).hex() == row["signature_hex"]
        previous = crypto.record_hash(message, raw(row["signature_hex"]))
        assert previous.hex() == row["record_hash_hex"]
    with pytest.raises(crypto.IntegrityError):
        crypto.verify_version_chain(records[:1], pinned, (2, raw(versions["v2"]["record_hash_hex"])))
    broken = [dict(record) for record in records]
    broken[1]["prev_hash"] = b"x" * 32
    with pytest.raises(crypto.IntegrityError):
        crypto.verify_version_chain(broken, pinned)

    grant = VECTORS["grant"]
    sealed = raw(grant["sealed_private_key_hex"])
    recipient_public = raw(alice()["enc_public_key_hex"])
    recipient_secret = raw(alice()["enc_secret_key_hex"])
    assert deterministic_seal(raw(versions["v1"]["tvk_secret_key_hex"]), recipient_public, raw(grant["ephemeral_secret_hex"])) == sealed
    assert crypto.open_grant(sealed, recipient_public, recipient_secret, raw(versions["v1"]["tvk_public_key_hex"])) == raw(versions["v1"]["tvk_secret_key_hex"])
    with pytest.raises(crypto.IntegrityError):
        crypto.open_grant(sealed, recipient_public, recipient_secret, raw(versions["v2"]["tvk_public_key_hex"]))
    message = crypto.grant_message(grant["vault_id"], grant["scope"], grant["version"], raw(versions["v1"]["tvk_public_key_hex"]), grant["recipient_user_id"], grant["recipient_identity_id"], raw(alice()["fingerprint_hex"]), sealed, grant["granter_identity_id"])
    assert message.hex() == grant["message_hex"]
    assert crypto.sign(raw(bob()["sig_seed_hex"]), message).hex() == grant["signature_hex"]
    assert crypto.verify(raw(bob()["sig_public_key_hex"]), message, raw(grant["signature_hex"]))


def test_item_and_binding_vectors_and_tamper_detection() -> None:
    vector = VECTORS["item"]
    plaintext = vector["payload_utf8"].encode()
    key, nonce = raw(vector["item_key_hex"]), raw(vector["nonce_hex"])
    aad = crypto.item_aad(vector["vault_id"], vector["item_id"], vector["type"], vector["revision"])
    assert crypto.item_bucket(len(plaintext)) == vector["bucket"]
    assert crypto.pad_item(plaintext).hex() == vector["padded_plaintext_hex"]
    actual_nonce, ciphertext = crypto.encrypt_item(key, plaintext, aad, nonce)
    assert actual_nonce == nonce
    assert aad.hex() == vector["aad_hex"]
    assert ciphertext.hex() == vector["ciphertext_hex"]
    assert crypto.sha256(ciphertext).hex() == vector["ciphertext_sha256_hex"]
    assert crypto.decrypt_item(key, nonce, ciphertext, aad) == plaintext
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1
    with pytest.raises(crypto.IntegrityError):
        crypto.decrypt_item(key, nonce, bytes(tampered), aad)
    content = crypto.item_content_message(vector["vault_id"], vector["item_id"], vector["type"], vector["revision"], nonce, ciphertext, vector["public_fingerprint"], vector["author_identity_id"])
    assert content.hex() == vector["content_message_hex"]
    assert crypto.sign(raw(alice()["sig_seed_hex"]), content).hex() == vector["content_signature_hex"]
    assert crypto.verify(raw(alice()["sig_public_key_hex"]), content, raw(vector["content_signature_hex"]))
    for name, signing_public in (("wrap_v1", raw(alice()["sig_public_key_hex"])), ("wrap_v2_after_rotation", raw(bob()["sig_public_key_hex"]))):
        wrap = vector[name]
        wrapped_key = raw(wrap["wrapped_item_key_hex"])
        message = crypto.item_wrap_message(vector["vault_id"], vector["item_id"], vector["revision"], wrap["key_version"], wrapped_key, ciphertext, wrap["wrapper_identity_id"])
        assert crypto.item_wrap_message_from_hash(
            vector["vault_id"], vector["item_id"], vector["revision"], wrap["key_version"],
            wrapped_key, raw(vector["ciphertext_sha256_hex"]), wrap["wrapper_identity_id"],
        ) == message
        assert deterministic_seal(key, raw(VECTORS["vault_versions"][f"v{wrap['key_version']}"]["tvk_public_key_hex"]), raw(wrap["ephemeral_secret_hex"])) == wrapped_key
        assert message.hex() == wrap["message_hex"]
        signing_seed = raw(alice()["sig_seed_hex"]) if name == "wrap_v1" else raw(bob()["sig_seed_hex"])
        assert crypto.sign(signing_seed, message).hex() == wrap["signature_hex"]
        assert crypto.verify(signing_public, message, raw(wrap["signature_hex"]))
    tombstone = vector["tombstone"]
    tombstone_message = crypto.item_tombstone_message(vector["vault_id"], vector["item_id"], tombstone["revision"], tombstone["deleter_identity_id"])
    assert tombstone_message.hex() == tombstone["message_hex"]
    assert crypto.sign(raw(bob()["sig_seed_hex"]), tombstone_message).hex() == tombstone["signature_hex"]
    binding = VECTORS["credential_binding"]
    binding_message = crypto.binding_message(binding["scope"], binding["target"], binding["hostname"], binding["port"], binding["login_user"], binding["vault_id"], binding["vault_item_id"], binding["public_fingerprint"], reversed(binding["host_keys"]), binding["binding_revision"], binding["binder_identity_id"])
    assert binding_message.hex() == binding["message_hex"]
    assert crypto.sign(raw(bob()["sig_seed_hex"]), binding_message).hex() == binding["signature_hex"]
    assert crypto.verify(raw(bob()["sig_public_key_hex"]), binding_message, raw(binding["signature_hex"]))


def test_ssh_ca_vectors() -> None:
    vector = VECTORS["ssh_user_certificate"]
    ca_seed = raw(vector["ca_seed_hex"])
    ca_public = crypto.public_from_seed(ca_seed)
    assert "ssh-ed25519 " + base64.b64encode(crypto.ssh_ed25519_public_blob(ca_public)).decode() == vector["ca_public_key_openssh"]
    user_blob = base64.b64decode(vector["user_public_key_openssh"].split()[1])
    assert crypto.ssh_public_fingerprint(vector["user_public_key_openssh"]) == vector["user_key_fingerprint"]
    subject_public = user_blob[19:]
    certificate_blobs: dict[int, bytes] = {}
    for case in vector["cases"]:
        tbs, signature, blob = crypto.build_ed25519_certificate(subject_public, case["serial"], case["cert_type"], case["key_id"], case["principals"], case["valid_after"], case["valid_before"], case["critical_options"], case["extensions"], raw(case["nonce_hex"]), ca_public, ca_seed)
        assert tbs.hex() == case["tbs_hex"]
        assert signature.hex() == case["signature_hex"]
        assert "ssh-ed25519-cert-v01@openssh.com " + base64.b64encode(blob).decode() + " " + case["key_id"] == case["certificate_openssh"]
        certificate_blobs[case["serial"]] = blob
    ecdsa = VECTORS["ecdsa_signature_encoding"]
    assert crypto.ssh_ecdsa_signature_blob(raw(ecdsa["raw_r_hex"]), raw(ecdsa["raw_s_hex"])).hex() == ecdsa["ssh_signature_blob_hex"]
    previous = b"\0" * 32
    for entry, case in zip(VECTORS["issuance_log"]["entries"], vector["cases"]):
        previous = crypto.issuance_entry_hash(previous, "7c9e6679-7425-40de-944b-e07fc1f90ae7", entry["serial"], case["key_id"], 4242, case["key_id"].split()[1][2:], case["principals"], case["valid_after"], case["valid_before"], certificate_blobs[entry["serial"]], entry["issued_at"])
        assert previous.hex() == entry["entry_hash_hex"]
    krl = VECTORS["krl"]
    assert crypto.build_krl(ca_public, krl["krl_version"], krl["generated_date"], krl["revoked_serials"]).hex() == krl["krl_hex"]
