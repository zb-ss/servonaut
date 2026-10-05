"""Canonical Team Vault cryptography.

This module intentionally deals in bytes and primitive wire values.  Callers
serialize its results as standard padded base64 only at the HTTP boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

import nacl.bindings
import nacl.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_ssh_private_key
from nacl.signing import SigningKey, VerifyKey


KEY_BYTES = 32
SIGNATURE_BYTES = 64
NONCE_BYTES = 24
FINGERPRINT_BYTES = 32
ZERO_HASH = b"\0" * FINGERPRINT_BYTES
MAX_ITEM_PLAINTEXT = 65_536
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_DECODE = {char: index for index, char in enumerate(CROCKFORD_ALPHABET)}
_CROCKFORD_DECODE.update({"O": 0, "I": 1, "L": 1})


class VaultCryptoError(ValueError):
    """Raised when a vault cryptographic value is malformed or untrusted."""


class IntegrityError(VaultCryptoError):
    """Raised when authentication or a signed invariant does not verify."""


def _require_length(value: bytes | bytearray, length: int, name: str) -> bytes:
    if len(value) != length:
        raise VaultCryptoError(f"{name} must be {length} bytes")
    return bytes(value)


def _text(value: str) -> bytes:
    return value.encode("utf-8")


def _ascii(value: str) -> bytes:
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise VaultCryptoError("domain must be ASCII") from exc


def lp(value: bytes) -> bytes:
    """Return a u32 length-prefixed byte string."""
    if len(value) > 0xFFFF_FFFF:
        raise VaultCryptoError("length-prefixed value is too large")
    return struct.pack(">I", len(value)) + value


def u64(value: int) -> bytes:
    """Return an unsigned 64-bit integer in big-endian order."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
        raise VaultCryptoError("u64 value is outside the unsigned range")
    return struct.pack(">Q", value)


def msg(domain: str, *fields: bytes) -> bytes:
    """Build a domain-separated canonical message."""
    return lp(_ascii(domain)) + b"".join(lp(field) for field in fields)


def lst(items: Sequence[bytes]) -> bytes:
    """Encode a list as one canonical message field."""
    if len(items) > 0xFFFF_FFFF:
        raise VaultCryptoError("list has too many entries")
    return struct.pack(">I", len(items)) + b"".join(lp(item) for item in items)


def sha256(value: bytes) -> bytes:
    """Return a raw SHA-256 digest."""
    return hashlib.sha256(value).digest()


def public_from_seed(seed: bytes) -> bytes:
    """Derive an Ed25519 public key from a 32-byte signing seed."""
    return bytes(SigningKey(_require_length(seed, KEY_BYTES, "signing seed")).verify_key)


def x25519_public(secret_key: bytes) -> bytes:
    """Derive an X25519 public key from a 32-byte secret key."""
    return nacl.bindings.crypto_scalarmult_base(
        _require_length(secret_key, KEY_BYTES, "X25519 secret key")
    )


def sign(seed: bytes, message: bytes) -> bytes:
    """Sign canonical *message* with a 32-byte Ed25519 seed."""
    return SigningKey(_require_length(seed, KEY_BYTES, "signing seed")).sign(message).signature


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return whether an Ed25519 signature verifies, without leaking errors."""
    try:
        VerifyKey(_require_length(public_key, KEY_BYTES, "signing public key")).verify(
            message, _require_length(signature, SIGNATURE_BYTES, "signature")
        )
    except (ValueError, nacl.exceptions.BadSignatureError):
        return False
    return True


def identity_fingerprint(sig_public_key: bytes, enc_public_key: bytes) -> bytes:
    """Return the raw 32-byte identity fingerprint."""
    return sha256(
        msg(
            "svn-vi-fp-v1",
            _require_length(sig_public_key, KEY_BYTES, "identity signing public key"),
            _require_length(enc_public_key, KEY_BYTES, "identity encryption public key"),
        )
    )


def self_signature_message(
    identity_id: str, user_id: int, sig_public_key: bytes, enc_public_key: bytes
) -> bytes:
    return msg(
        "svn-vi-self-v1",
        _text(identity_id),
        u64(user_id),
        _require_length(sig_public_key, KEY_BYTES, "identity signing public key"),
        _require_length(enc_public_key, KEY_BYTES, "identity encryption public key"),
    )


def self_signature(
    seed: bytes, identity_id: str, user_id: int, sig_public_key: bytes, enc_public_key: bytes
) -> bytes:
    return sign(seed, self_signature_message(identity_id, user_id, sig_public_key, enc_public_key))


def verify_identity(
    identity_id: str,
    user_id: int,
    sig_public_key: bytes,
    enc_public_key: bytes,
    fingerprint: bytes,
    signature: bytes,
) -> bool:
    """Verify all public identity invariants received from the server."""
    return (
        identity_fingerprint(sig_public_key, enc_public_key) == fingerprint
        and verify(
            sig_public_key,
            self_signature_message(identity_id, user_id, sig_public_key, enc_public_key),
            signature,
        )
    )


def safety_number(fingerprint: bytes) -> str:
    """Format the 12 five-digit identity safety-number groups."""
    _require_length(fingerprint, FINGERPRINT_BYTES, "fingerprint")
    digest = hashlib.sha512(msg("svn-vi-sn-v1", fingerprint)).digest()[:60]
    return " ".join(
        f"{int.from_bytes(digest[index : index + 5], 'big') % 100_000:05d}"
        for index in range(0, 60, 5)
    )


def encode_bundle(signing_seed: bytes, encryption_secret_key: bytes) -> bytes:
    """Encode the v1 identity bundle, which must only be stored encrypted."""
    return b"svib\x01" + _require_length(signing_seed, KEY_BYTES, "signing seed") + _require_length(
        encryption_secret_key, KEY_BYTES, "X25519 secret key"
    )


def decode_bundle(bundle: bytes) -> tuple[bytes, bytes]:
    """Decode and strictly validate a v1 identity bundle."""
    if len(bundle) != 69 or not bundle.startswith(b"svib\x01"):
        raise VaultCryptoError("invalid identity bundle")
    return bundle[5:37], bundle[37:69]


def recovery_checksum(recovery_key: bytes) -> bytes:
    return sha256(msg("svn-rk-check-v1", _require_length(recovery_key, KEY_BYTES, "recovery key")))[:2]


def crockford_encode(value: bytes) -> str:
    """Encode bytes in unpadded Crockford Base32, preserving leading zeros."""
    bit_count = len(value) * 8
    characters = (bit_count + 4) // 5
    number = int.from_bytes(value, "big") << (characters * 5 - bit_count)
    return "".join(
        CROCKFORD_ALPHABET[(number >> (5 * (characters - index - 1))) & 31]
        for index in range(characters)
    )


def crockford_decode(value: str, expected_bytes: int | None = None) -> bytes:
    """Decode Crockford Base32 with the protocol's human-entry aliases."""
    cleaned = "".join(character for character in value.upper() if not character.isspace() and character != "-")
    if not cleaned:
        raise VaultCryptoError("recovery key is empty")
    try:
        number = 0
        for character in cleaned:
            number = (number << 5) | _CROCKFORD_DECODE[character]
    except KeyError as exc:
        raise VaultCryptoError("recovery key contains an invalid Crockford character") from exc
    if expected_bytes is None:
        bit_count = len(cleaned) * 5
        byte_count = bit_count // 8
    else:
        byte_count = expected_bytes
        if len(cleaned) != (byte_count * 8 + 4) // 5:
            raise VaultCryptoError("recovery key has an invalid length")
    padding_bits = len(cleaned) * 5 - byte_count * 8
    if padding_bits < 0 or number & ((1 << padding_bits) - 1):
        raise VaultCryptoError("recovery key has non-canonical Base32 padding")
    return (number >> padding_bits).to_bytes(byte_count, "big")


def format_recovery_key(recovery_key: bytes, prefix: str = "SVRK1") -> str:
    """Format a recovery or escrow key for one-time human display."""
    raw = _require_length(recovery_key, KEY_BYTES, "recovery key") + recovery_checksum(recovery_key)
    encoded = crockford_encode(raw)
    return prefix + "-" + "-".join(encoded[index : index + 5] for index in range(0, len(encoded), 5))


def parse_recovery_key(value: str, prefix: str = "SVRK1") -> bytes:
    """Parse and checksum a recovery key before any KDF work occurs."""
    normalized = value.strip().upper()
    expected_prefix = prefix.upper() + "-"
    if not normalized.startswith(expected_prefix):
        raise VaultCryptoError(f"recovery key must start with {prefix}-")
    raw = crockford_decode(normalized[len(expected_prefix) :], expected_bytes=34)
    key, supplied_checksum = raw[:KEY_BYTES], raw[KEY_BYTES:]
    if not hmac.compare_digest(recovery_checksum(key), supplied_checksum):
        raise IntegrityError("recovery key checksum does not match")
    return key


def recovery_kek(recovery_key: bytes, identity_id: str) -> bytes:
    """Derive the v1 recovery KEK after checksum validation by the caller."""
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES, salt=_text(identity_id), info=b"svn-vi-recovery-kek-v1"
    ).derive(_require_length(recovery_key, KEY_BYTES, "recovery key"))


def wrap_aad(kind: str, identity_id: str, user_id: int, fingerprint: bytes) -> bytes:
    return msg("svn-vi-wrap-v1", _text(kind), _text(identity_id), u64(user_id), _require_length(fingerprint, 32, "fingerprint"))


def seal_wrap(key: bytes, plaintext: bytes, aad: bytes, nonce: bytes | None = None) -> bytes:
    """Encrypt an identity bundle in the protocol's v1 wrap envelope."""
    key = _require_length(key, KEY_BYTES, "wrap key")
    nonce = os.urandom(NONCE_BYTES) if nonce is None else _require_length(nonce, NONCE_BYTES, "wrap nonce")
    ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return b"\x01" + nonce + ciphertext


def open_wrap(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Authenticate and decrypt a v1 identity bundle wrap."""
    _require_length(key, KEY_BYTES, "wrap key")
    if len(blob) < 1 + NONCE_BYTES + nacl.bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES or blob[:1] != b"\x01":
        raise VaultCryptoError("invalid wrapped bundle")
    try:
        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(blob[25:], aad, blob[1:25], key)
    except nacl.exceptions.CryptoError as exc:
        raise IntegrityError("wrapped bundle authentication failed") from exc


def device_commitment(device_id: str, device_sig_public_key: bytes, device_enc_public_key: bytes, device_nonce: bytes) -> bytes:
    return sha256(msg("svn-dev-commit-v1", _text(device_id), _require_length(device_sig_public_key, 32, "device signing public key"), _require_length(device_enc_public_key, 32, "device encryption public key"), _require_length(device_nonce, 32, "device nonce")))


def device_registration_message(device_id: str, user_id: int, device_sig_public_key: bytes, device_enc_public_key: bytes, commitment: bytes) -> bytes:
    return msg("svn-dev-reg-v1", _text(device_id), u64(user_id), _require_length(device_sig_public_key, 32, "device signing public key"), _require_length(device_enc_public_key, 32, "device encryption public key"), _require_length(commitment, 32, "device commitment"))


def sas(device_id: str, identity_fingerprint_raw: bytes, device_sig_public_key: bytes, device_enc_public_key: bytes, device_nonce: bytes, approver_nonce: bytes) -> str:
    digest = sha256(msg("svn-dev-sas-v1", _text(device_id), _require_length(identity_fingerprint_raw, 32, "identity fingerprint"), _require_length(device_sig_public_key, 32, "device signing public key"), _require_length(device_enc_public_key, 32, "device encryption public key"), _require_length(device_nonce, 32, "device nonce"), _require_length(approver_nonce, 32, "approver nonce")))
    digits = f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"
    return digits[:3] + " " + digits[3:]


def endorsement_message(identity_id: str, user_id: int, device_id: str, device_sig_public_key: bytes, device_enc_public_key: bytes) -> bytes:
    return msg("svn-dev-endorse-v1", _text(identity_id), u64(user_id), _text(device_id), _require_length(device_sig_public_key, 32, "device signing public key"), _require_length(device_enc_public_key, 32, "device encryption public key"))


def request_message(method: str, request_target: str, timestamp: int, nonce: bytes, device_id: str, body: bytes) -> bytes:
    return msg("svn-req-v1", _ascii(method.upper()), _text(request_target), u64(timestamp), _require_length(nonce, 16, "request nonce"), _text(device_id), sha256(body))


def version_message(vault_id: str, scope: str, version: int, public_key: bytes, prev_hash: bytes, creator_identity_id: str) -> bytes:
    return msg("svn-tv-version-v1", _text(vault_id), _text(scope), u64(version), _require_length(public_key, 32, "vault public key"), _require_length(prev_hash, 32, "previous record hash"), _text(creator_identity_id))


def record_hash(version_message_bytes: bytes, signature: bytes) -> bytes:
    return sha256(msg("svn-tv-version-hash-v1", version_message_bytes, _require_length(signature, 64, "version signature")))


def grant_message(vault_id: str, scope: str, version: int, vault_public_key: bytes, recipient_user_id: int, recipient_identity_id: str, recipient_fingerprint: bytes, sealed_private_key: bytes, granter_identity_id: str) -> bytes:
    return msg("svn-tv-grant-v1", _text(vault_id), _text(scope), u64(version), _require_length(vault_public_key, 32, "vault public key"), u64(recipient_user_id), _text(recipient_identity_id), _require_length(recipient_fingerprint, 32, "recipient fingerprint"), sha256(sealed_private_key), _text(granter_identity_id))


def escrow_message(vault_id: str, escrow_id: str, enc_public_key: bytes, label: str, owner_identity_id: str) -> bytes:
    return msg("svn-tv-escrow-v1", _text(vault_id), _text(escrow_id), _require_length(enc_public_key, 32, "escrow encryption public key"), _text(label), _text(owner_identity_id))


def recipient_approval_message(vault_id: str, recipient_user_id: int, recipient_identity_id: str, recipient_fingerprint: bytes, approver_identity_id: str) -> bytes:
    return msg("svn-vi-approve-v1", _text(vault_id), u64(recipient_user_id), _text(recipient_identity_id), _require_length(recipient_fingerprint, 32, "recipient fingerprint"), _text(approver_identity_id))


def seal(plaintext: bytes, recipient_public_key: bytes) -> bytes:
    """Seal using libsodium randomness; deterministic sealing is test-only."""
    return nacl.bindings.crypto_box_seal(plaintext, _require_length(recipient_public_key, 32, "recipient encryption public key"))


def open_sealed(ciphertext: bytes, recipient_public_key: bytes, recipient_secret_key: bytes) -> bytes:
    try:
        return nacl.bindings.crypto_box_seal_open(ciphertext, _require_length(recipient_public_key, 32, "recipient encryption public key"), _require_length(recipient_secret_key, 32, "recipient encryption secret key"))
    except nacl.exceptions.CryptoError as exc:
        raise IntegrityError("sealed box authentication failed") from exc


def open_grant(sealed_private_key: bytes, recipient_public_key: bytes, recipient_secret_key: bytes, version_public_key: bytes) -> bytes:
    private_key = open_sealed(sealed_private_key, recipient_public_key, recipient_secret_key)
    if x25519_public(private_key) != _require_length(version_public_key, 32, "vault version public key"):
        raise IntegrityError("grant does not match its vault version public key")
    return private_key


def item_bucket(payload_length: int) -> int:
    if isinstance(payload_length, bool) or not isinstance(payload_length, int) or payload_length < 0:
        raise VaultCryptoError("payload length must be non-negative")
    bucket = 256
    while bucket < payload_length + 1:
        bucket *= 2
    if bucket > MAX_ITEM_PLAINTEXT:
        raise VaultCryptoError("item plaintext exceeds the v1 limit")
    return bucket


def pad_item(plaintext: bytes) -> bytes:
    return nacl.bindings.sodium_pad(plaintext, item_bucket(len(plaintext)))


def unpad_item(padded: bytes) -> bytes:
    if len(padded) < 256 or len(padded) > MAX_ITEM_PLAINTEXT or len(padded) & (len(padded) - 1):
        raise VaultCryptoError("item padding bucket is invalid")
    try:
        return nacl.bindings.sodium_unpad(padded, len(padded))
    except nacl.exceptions.CryptoError as exc:
        raise IntegrityError("item padding is invalid") from exc


def item_aad(vault_id: str, item_id: str, item_type: str, revision: int) -> bytes:
    return msg("svn-vault-item-v1", _text(vault_id), _text(item_id), _text(item_type), u64(revision))


def encrypt_item(item_key: bytes, plaintext: bytes, aad: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    nonce = os.urandom(24) if nonce is None else _require_length(nonce, 24, "item nonce")
    ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(pad_item(plaintext), aad, nonce, _require_length(item_key, 32, "item key"))
    return nonce, ciphertext


def decrypt_item(item_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        padded = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, _require_length(nonce, 24, "item nonce"), _require_length(item_key, 32, "item key"))
    except nacl.exceptions.CryptoError as exc:
        raise IntegrityError("item ciphertext authentication failed") from exc
    return unpad_item(padded)


def item_content_message(vault_id: str, item_id: str, item_type: str, revision: int, nonce: bytes, ciphertext: bytes, public_fingerprint: str | None, author_identity_id: str) -> bytes:
    return msg("svn-vault-item-content-v1", _text(vault_id), _text(item_id), _text(item_type), u64(revision), _require_length(nonce, 24, "item nonce"), sha256(ciphertext), b"" if public_fingerprint is None else _text(public_fingerprint), _text(author_identity_id))


def item_wrap_message(vault_id: str, item_id: str, revision: int, key_version: int, wrapped_item_key: bytes, ciphertext: bytes, wrapper_identity_id: str) -> bytes:
    return item_wrap_message_from_hash(
        vault_id,
        item_id,
        revision,
        key_version,
        wrapped_item_key,
        sha256(ciphertext),
        wrapper_identity_id,
    )


def item_wrap_message_from_hash(
    vault_id: str,
    item_id: str,
    revision: int,
    key_version: int,
    wrapped_item_key: bytes,
    ciphertext_sha256: bytes,
    wrapper_identity_id: str,
) -> bytes:
    """Build an item-wrap message from list-safe ciphertext metadata."""
    return msg(
        "svn-vault-item-wrap-v1",
        _text(vault_id),
        _text(item_id),
        u64(revision),
        u64(key_version),
        sha256(wrapped_item_key),
        _require_length(ciphertext_sha256, 32, "item ciphertext hash"),
        _text(wrapper_identity_id),
    )


def item_tombstone_message(vault_id: str, item_id: str, revision: int, deleter_identity_id: str) -> bytes:
    return msg("svn-vault-item-delete-v1", _text(vault_id), _text(item_id), u64(revision), _text(deleter_identity_id))


def binding_message(scope: str, target: str, hostname: str, port: int, login_user: str, vault_id: str, vault_item_id: str, public_fingerprint: str, host_keys: Iterable[str], binding_revision: int, binder_identity_id: str) -> bytes:
    sorted_keys = sorted((_text(host_key) for host_key in host_keys))
    return msg("svn-binding-v1", _text(scope), _text(target), _text(hostname), u64(port), _text(login_user), _text(vault_id), _text(vault_item_id), _text(public_fingerprint), lst(sorted_keys), u64(binding_revision), _text(binder_identity_id))


def issuance_entry_hash(prev_hash: bytes, team_id: str, serial: int, key_id: str, user_id: int, device_id: str | None, principals: Sequence[str], valid_after: int, valid_before: int, certificate_blob: bytes, issued_at: int) -> bytes:
    return issuance_entry_hash_from_certificate_hash(
        prev_hash,
        team_id,
        serial,
        key_id,
        user_id,
        device_id,
        principals,
        valid_after,
        valid_before,
        sha256(certificate_blob),
        issued_at,
    )


def issuance_entry_hash_from_certificate_hash(
    prev_hash: bytes,
    team_id: str,
    serial: int,
    key_id: str,
    user_id: int,
    device_id: str | None,
    principals: Sequence[str],
    valid_after: int,
    valid_before: int,
    certificate_sha256: bytes,
    issued_at: int,
) -> bytes:
    """Build an issuance-chain entry from the list-safe certificate digest."""
    return sha256(msg("svn-ca-issuance-v1", _require_length(prev_hash, 32, "previous issuance hash"), _text(team_id), u64(serial), _text(key_id), u64(user_id), b"" if device_id is None else _text(device_id), lst([_text(principal) for principal in principals]), u64(valid_after), u64(valid_before), _require_length(certificate_sha256, 32, "certificate hash"), u64(issued_at)))


def ssh_string(value: bytes) -> bytes:
    """Encode an SSH wire ``string``."""
    return lp(value)


def ssh_mpint(value: bytes) -> bytes:
    """Encode a non-negative SSH mpint from an unsigned big-endian value."""
    normalized = value.lstrip(b"\0")
    if normalized and normalized[0] & 0x80:
        normalized = b"\0" + normalized
    return ssh_string(normalized)


def ssh_ed25519_public_blob(public_key: bytes) -> bytes:
    return ssh_string(b"ssh-ed25519") + ssh_string(_require_length(public_key, 32, "Ed25519 public key"))


def openssh_fingerprint(public_blob: bytes) -> str:
    """Return the standard OpenSSH SHA256 fingerprint for a public-key blob."""
    import base64

    return "SHA256:" + base64.b64encode(sha256(public_blob)).decode("ascii").rstrip("=")


def ssh_public_fingerprint(public_line: str) -> str:
    """Validate an OpenSSH public-key line and return its SHA256 fingerprint."""
    import base64

    parts = public_line.strip().split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        raise VaultCryptoError("SSH public key is malformed")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise VaultCryptoError("SSH public key has invalid base64") from exc
    if not blob:
        raise VaultCryptoError("SSH public key is empty")
    return openssh_fingerprint(blob)


def openssh_public_key_from_private(private_key: bytes | bytearray) -> str:
    """Derive an OpenSSH public line from private key bytes without a file."""
    try:
        key = load_ssh_private_key(bytes(private_key), password=None)
        return key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
    except Exception as exc:
        raise VaultCryptoError("SSH private key cannot be parsed") from exc


def ssh_ecdsa_signature_blob(raw_r: bytes, raw_s: bytes) -> bytes:
    """Encode a raw P-256 ``r || s`` pair as an SSH signature blob."""
    return ssh_string(b"ecdsa-sha2-nistp256") + ssh_string(ssh_mpint(raw_r) + ssh_mpint(raw_s))


def _ssh_options(options: Mapping[str, str | None]) -> bytes:
    encoded = b""
    for name in sorted(options):
        value = options[name]
        encoded += ssh_string(_text(name)) + ssh_string(b"" if value is None else ssh_string(_text(value)))
    return encoded


def build_ed25519_certificate(
    subject_public_key: bytes,
    serial: int,
    cert_type: int,
    key_id: str,
    principals: Sequence[str],
    valid_after: int,
    valid_before: int,
    critical_options: Mapping[str, str | None],
    extensions: Sequence[str],
    nonce: bytes,
    ca_public_key: bytes,
    ca_signing_seed: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Build an Ed25519 OpenSSH certificate and return ``(tbs, sig, blob)``.

    The server creates certificates; keeping this verifier-compatible builder
    here lets the client independently reproduce and check canonical vectors.
    """
    if isinstance(cert_type, bool) or not isinstance(cert_type, int) or cert_type not in {1, 2}:
        raise VaultCryptoError("SSH certificate type must be user (1) or host (2)")
    ca_blob = ssh_ed25519_public_blob(ca_public_key)
    tbs = (
        ssh_string(b"ssh-ed25519-cert-v01@openssh.com")
        + ssh_string(_require_length(nonce, 32, "certificate nonce"))
        + ssh_string(_require_length(subject_public_key, 32, "subject public key"))
        + u64(serial)
        + struct.pack(">I", cert_type)
        + ssh_string(_text(key_id))
        + ssh_string(b"".join(ssh_string(_text(principal)) for principal in principals))
        + u64(valid_after)
        + u64(valid_before)
        + ssh_string(_ssh_options(critical_options))
        + ssh_string(_ssh_options({extension: None for extension in extensions}))
        + ssh_string(b"")
        + ssh_string(ca_blob)
    )
    signature = sign(ca_signing_seed, tbs)
    blob = tbs + ssh_string(ssh_string(b"ssh-ed25519") + ssh_string(signature))
    return tbs, signature, blob


def build_krl(ca_public_key: bytes, krl_version: int, generated_date: int, revoked_serials: Sequence[int]) -> bytes:
    """Build the v1 serial-only OpenSSH KRL for one Ed25519 CA."""
    serials = b"".join(u64(serial) for serial in sorted(revoked_serials))
    section = ssh_string(ssh_ed25519_public_blob(ca_public_key)) + ssh_string(b"") + b"\x20" + ssh_string(serials)
    return (
        u64(0x5353484B524C0A00)
        + struct.pack(">I", 1)
        + u64(krl_version)
        + u64(generated_date)
        + u64(0)
        + ssh_string(b"")
        + ssh_string(b"")
        + b"\x01"
        + ssh_string(section)
    )


def verify_version_chain(records: Sequence[Mapping[str, Any]], identity_keys: Mapping[str, bytes], highest_seen: tuple[int, bytes] | None = None) -> tuple[int, bytes]:
    """Verify a complete, strictly increasing version chain against pinned keys.

    Records deliberately use decoded byte values, allowing the HTTP layer to own
    base64 conversion and reject malformed response fields before this boundary.
    """
    if not records:
        raise IntegrityError("vault version chain is empty")
    previous_hash = ZERO_HASH
    for expected_version, record in enumerate(records, start=1):
        version = record.get("version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise IntegrityError("vault version must be an unsigned integer")
        if version != expected_version or record["prev_hash"] != previous_hash:
            raise IntegrityError("vault version chain has a gap or invalid predecessor")
        creator = str(record["creator_identity_id"])
        try:
            signing_key = identity_keys[creator]
        except KeyError as exc:
            raise IntegrityError("vault version creator is not pinned") from exc
        message = version_message(str(record["vault_id"]), str(record["scope"]), version, record["public_key"], record["prev_hash"], creator)
        if not verify(signing_key, message, record["signature"]):
            raise IntegrityError("vault version signature is invalid")
        actual_hash = record_hash(message, record["signature"])
        if actual_hash != record["record_hash"]:
            raise IntegrityError("vault version record hash is invalid")
        previous_hash = actual_hash
    head = (len(records), previous_hash)
    if highest_seen is not None and (head[0] < highest_seen[0] or (head[0] == highest_seen[0] and head[1] != highest_seen[1])):
        raise IntegrityError("vault version chain rolled back or forked")
    return head
