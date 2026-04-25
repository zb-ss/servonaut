"""Unit tests for services/memory/crypto.py.

Covers:
- KeyPair generation and fingerprint
- Password-score estimator
- Private-key wrap / unwrap round-trip
- Envelope encrypt / decrypt round-trip (single and multi-recipient)
- §3.3 dek_wraps shape and §3.7 wrapped_dek shape
- Validator edge cases (iv, tag, ciphertext, public_key, wrapped_dek)
- secure_zero
- Frozen fixture snapshot (catches accidental wire-format regressions)

Fixture regeneration:
  cd /home/zashboy/projects/servonaut
  PYTHONPATH=src python3 -c "
import base64, json, sys
sys.path.insert(0, 'src')
from servonaut.services.memory.crypto import wrap_private_key, encrypt_envelope, fingerprint
import nacl.public
SEED = bytes(range(1, 33))
priv = nacl.public.PrivateKey(SEED)
pub = bytes(priv.public_key)
wrapped = wrap_private_key(bytes(priv), 'TestCrypto2026!StrongEnough', strength='interactive')
env = encrypt_envelope(b'hello servonaut memory v1', self_public_key=pub, self_user_id=42)
print(json.dumps({'version':1,'seed_hex':SEED.hex(),'test_passphrase':'TestCrypto2026!StrongEnough','test_user_id':42,'expected_plaintext_b64':base64.b64encode(b'hello servonaut memory v1').decode(),'envelope':env.to_dict(),'wrapped_private_key':json.loads(wrapped.to_json())}, indent=2))
  " > tests/fixtures/memory_envelope_v1.json
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

import nacl.public

from servonaut.services.memory.crypto import (
    AES_IV_LEN,
    AES_KEY_LEN,
    AES_TAG_LEN,
    MAX_CIPHERTEXT_BYTES,
    X25519_KEY_LEN,
    CryptoError,
    DEKWrap,
    DecryptionFailedError,
    Envelope,
    InvalidEnvelopeError,
    KeyPair,
    NoSelfWrapError,
    WeakPassphraseError,
    WrappedKeyTooLargeError,
    WrappedPrivateKey,
    decrypt_envelope,
    encrypt_envelope,
    estimate_pw_score,
    fingerprint,
    generate_keypair,
    secure_zero,
    unwrap_private_key,
    validate_ciphertext,
    validate_iv,
    validate_public_key,
    validate_tag,
    validate_wrapped_dek,
    wrap_private_key,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "memory_envelope_v1.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_keypair_from_seed(seed: bytes) -> KeyPair:
    """Return a deterministic KeyPair from a 32-byte seed."""
    priv = nacl.public.PrivateKey(seed)
    pub_bytes = bytes(priv.public_key)
    priv_bytes = bytes(priv)
    return KeyPair(
        public_key=pub_bytes,
        private_key=priv_bytes,
        fingerprint=fingerprint(pub_bytes),
    )


# ---------------------------------------------------------------------------
# generate_keypair
# ---------------------------------------------------------------------------

def test_generate_keypair_returns_32b_pubkey_and_privkey() -> None:
    kp = generate_keypair()
    assert len(kp.public_key) == X25519_KEY_LEN
    assert len(kp.private_key) == X25519_KEY_LEN


def test_generate_keypair_fingerprint_is_64_char_hex() -> None:
    kp = generate_keypair()
    assert len(kp.fingerprint) == 64
    # Must be valid hex
    int(kp.fingerprint, 16)


def test_fingerprint_matches_sha256_of_pubkey() -> None:
    kp = generate_keypair()
    expected = hashlib.sha256(kp.public_key).hexdigest()
    assert kp.fingerprint == expected


def test_fingerprint_function_directly() -> None:
    seed = bytes(range(1, 33))
    kp = _make_keypair_from_seed(seed)
    assert fingerprint(kp.public_key) == kp.fingerprint


# ---------------------------------------------------------------------------
# estimate_pw_score
# ---------------------------------------------------------------------------

def test_estimate_pw_score_short_passphrase_returns_zero() -> None:
    assert estimate_pw_score("short") == 0


def test_estimate_pw_score_strong_passphrase_returns_at_least_3() -> None:
    assert estimate_pw_score("CorrectHorseBatteryStaple!1") >= 3


def test_estimate_pw_score_medium_length_returns_1() -> None:
    # 9 chars, no mixed class — should be score 1
    assert estimate_pw_score("abcdefghi") == 1


def test_estimate_pw_score_20_char_mixed_returns_4() -> None:
    assert estimate_pw_score("Abcde1!Fghij2@Klmno3") == 4


# ---------------------------------------------------------------------------
# wrap_private_key / unwrap_private_key
# ---------------------------------------------------------------------------

def test_wrap_with_weak_passphrase_raises_weak_passphrase_error() -> None:
    kp = generate_keypair()
    with pytest.raises(WeakPassphraseError):
        wrap_private_key(kp.private_key, "weak")


def test_wrap_unwrap_roundtrip_recovers_exact_privkey() -> None:
    kp = generate_keypair()
    passphrase = "CorrectHorseBatteryStaple!1"
    wrapped = wrap_private_key(kp.private_key, passphrase, strength="interactive")
    recovered = unwrap_private_key(wrapped, passphrase)
    assert recovered == kp.private_key


def test_unwrap_with_wrong_passphrase_raises_decryption_failed() -> None:
    kp = generate_keypair()
    wrapped = wrap_private_key(kp.private_key, "CorrectHorseBatteryStaple!1", strength="interactive")
    with pytest.raises(DecryptionFailedError) as exc_info:
        unwrap_private_key(wrapped, "WrongPassphrase!AbcDef12")
    # Error message must be generic — no leak of which step failed
    assert exc_info.value.args[0] == "decryption failed"


def test_wrapped_private_key_to_json_under_8kb() -> None:
    kp = generate_keypair()
    wrapped = wrap_private_key(kp.private_key, "CorrectHorseBatteryStaple!1", strength="interactive")
    blob = wrapped.to_json()
    assert len(blob.encode()) <= 8 * 1024


def test_wrapped_private_key_from_json_roundtrip() -> None:
    kp = generate_keypair()
    passphrase = "CorrectHorseBatteryStaple!1"
    wrapped = wrap_private_key(kp.private_key, passphrase, strength="interactive")
    blob = wrapped.to_json()
    restored = WrappedPrivateKey.from_json(blob)
    assert restored.kdf == "argon2id"
    assert restored.pw_score >= 3
    assert restored.ops_limit == wrapped.ops_limit
    recovered = unwrap_private_key(restored, passphrase)
    assert recovered == kp.private_key


# ---------------------------------------------------------------------------
# encrypt_envelope / decrypt_envelope — single self-wrap
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_single_self_wrap_recovers_plaintext() -> None:
    kp = generate_keypair()
    plaintext = b"hello world from servonaut"
    env = encrypt_envelope(plaintext, self_public_key=kp.public_key, self_user_id=1)
    recovered = decrypt_envelope(
        env,
        self_user_id=1,
        self_private_key=kp.private_key,
        self_public_key=kp.public_key,
    )
    assert recovered == plaintext


def test_encrypt_envelope_produces_aes_256_gcm_encryption_field() -> None:
    kp = generate_keypair()
    env = encrypt_envelope(b"test", self_public_key=kp.public_key, self_user_id=1)
    assert env.encryption == "aes-256-gcm"


# ---------------------------------------------------------------------------
# encrypt_envelope — multiple recipients
# ---------------------------------------------------------------------------

def test_encrypt_with_two_additional_recipients_produces_three_dek_wraps() -> None:
    owner = generate_keypair()
    alice = generate_keypair()
    bob = generate_keypair()
    plaintext = b"shared secret"

    env = encrypt_envelope(
        plaintext,
        self_public_key=owner.public_key,
        self_user_id=1,
        additional_recipients=[(2, alice.public_key), (3, bob.public_key)],
    )

    assert len(env.dek_wraps) == 3
    ids = {w.recipient_user_id for w in env.dek_wraps}
    assert ids == {1, 2, 3}


def test_each_additional_recipient_can_independently_decrypt() -> None:
    owner = generate_keypair()
    alice = generate_keypair()
    bob = generate_keypair()
    plaintext = b"shared secret"

    env = encrypt_envelope(
        plaintext,
        self_public_key=owner.public_key,
        self_user_id=1,
        additional_recipients=[(2, alice.public_key), (3, bob.public_key)],
    )

    for user_id, kp in [(1, owner), (2, alice), (3, bob)]:
        recovered = decrypt_envelope(
            env,
            self_user_id=user_id,
            self_private_key=kp.private_key,
            self_public_key=kp.public_key,
        )
        assert recovered == plaintext, f"Recipient {user_id} could not decrypt"


# ---------------------------------------------------------------------------
# decrypt_envelope — spec shape variants
# ---------------------------------------------------------------------------

def test_decrypt_accepts_spec_3_3_dek_wraps_dict() -> None:
    """Spec §3.3 shape: envelope dict with dek_wraps list."""
    kp = generate_keypair()
    plaintext = b"spec 3.3 test"
    env = encrypt_envelope(plaintext, self_public_key=kp.public_key, self_user_id=42)
    env_dict = env.to_dict()

    # Verify it uses the dek_wraps key path
    assert "dek_wraps" in env_dict
    recovered = decrypt_envelope(
        env_dict,
        self_user_id=42,
        self_private_key=kp.private_key,
        self_public_key=kp.public_key,
    )
    assert recovered == plaintext


def test_decrypt_accepts_spec_3_7_wrapped_dek_string() -> None:
    """Spec §3.7 shape: server pre-filtered to caller's wrap as a top-level string."""
    kp = generate_keypair()
    plaintext = b"spec 3.7 test"
    env = encrypt_envelope(plaintext, self_public_key=kp.public_key, self_user_id=42)
    env_dict = env.to_dict()

    # Build a §3.7-shaped dict: replace dek_wraps with a flat wrapped_dek string
    dek_wraps = env_dict.pop("dek_wraps")
    my_wrap = next(w for w in dek_wraps if w["recipient_user_id"] == 42)
    env_dict["wrapped_dek"] = my_wrap["wrapped_dek"]

    recovered = decrypt_envelope(
        env_dict,
        self_user_id=42,
        self_private_key=kp.private_key,
        self_public_key=kp.public_key,
    )
    assert recovered == plaintext


# ---------------------------------------------------------------------------
# decrypt_envelope — error cases
# ---------------------------------------------------------------------------

def test_decrypt_with_no_matching_recipient_raises_no_self_wrap_error() -> None:
    kp = generate_keypair()
    env = encrypt_envelope(b"data", self_public_key=kp.public_key, self_user_id=1)
    with pytest.raises(NoSelfWrapError):
        decrypt_envelope(
            env,
            self_user_id=999,  # not in dek_wraps
            self_private_key=kp.private_key,
            self_public_key=kp.public_key,
        )


def test_decrypt_with_tampered_tag_raises_decryption_failed() -> None:
    kp = generate_keypair()
    env = encrypt_envelope(b"sensitive data", self_public_key=kp.public_key, self_user_id=1)
    env_dict = env.to_dict()

    # Flip the last byte of the tag
    tag_bytes = bytearray(base64.b64decode(env_dict["tag"]))
    tag_bytes[-1] ^= 0xFF
    env_dict["tag"] = base64.b64encode(bytes(tag_bytes)).decode()

    with pytest.raises(DecryptionFailedError):
        decrypt_envelope(
            env_dict,
            self_user_id=1,
            self_private_key=kp.private_key,
            self_public_key=kp.public_key,
        )


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def test_validate_iv_accepts_12_bytes() -> None:
    raw = os.urandom(12)
    result = validate_iv(base64.b64encode(raw).decode())
    assert result == raw


def test_validate_iv_rejects_11_bytes() -> None:
    with pytest.raises(InvalidEnvelopeError):
        validate_iv(base64.b64encode(os.urandom(11)).decode())


def test_validate_iv_rejects_13_bytes() -> None:
    with pytest.raises(InvalidEnvelopeError):
        validate_iv(base64.b64encode(os.urandom(13)).decode())


def test_validate_tag_accepts_16_bytes() -> None:
    raw = os.urandom(16)
    result = validate_tag(base64.b64encode(raw).decode())
    assert result == raw


def test_validate_tag_rejects_15_bytes() -> None:
    with pytest.raises(InvalidEnvelopeError):
        validate_tag(base64.b64encode(os.urandom(15)).decode())


def test_validate_tag_rejects_17_bytes() -> None:
    with pytest.raises(InvalidEnvelopeError):
        validate_tag(base64.b64encode(os.urandom(17)).decode())


def test_validate_ciphertext_accepts_under_2mb() -> None:
    raw = os.urandom(100)
    result = validate_ciphertext(base64.b64encode(raw).decode())
    assert result == raw


def test_validate_ciphertext_rejects_over_2mb() -> None:
    oversized = os.urandom(MAX_CIPHERTEXT_BYTES + 1)
    with pytest.raises(InvalidEnvelopeError):
        validate_ciphertext(base64.b64encode(oversized).decode())


def test_validate_public_key_accepts_32_bytes() -> None:
    raw = os.urandom(32)
    result = validate_public_key(base64.b64encode(raw).decode())
    assert result == raw


def test_validate_public_key_rejects_31_bytes() -> None:
    with pytest.raises(InvalidEnvelopeError):
        validate_public_key(base64.b64encode(os.urandom(31)).decode())


def test_validate_public_key_rejects_33_bytes() -> None:
    with pytest.raises(InvalidEnvelopeError):
        validate_public_key(base64.b64encode(os.urandom(33)).decode())


def test_validate_wrapped_dek_accepts_32_to_256_bytes() -> None:
    for size in (32, 100, 256):
        raw = os.urandom(size)
        result = validate_wrapped_dek(base64.b64encode(raw).decode())
        assert result == raw


def test_validate_wrapped_dek_rejects_below_32_bytes() -> None:
    with pytest.raises(InvalidEnvelopeError):
        validate_wrapped_dek(base64.b64encode(os.urandom(31)).decode())


def test_validate_wrapped_dek_rejects_above_256_bytes() -> None:
    with pytest.raises(InvalidEnvelopeError):
        validate_wrapped_dek(base64.b64encode(os.urandom(257)).decode())


# ---------------------------------------------------------------------------
# secure_zero
# ---------------------------------------------------------------------------

def test_secure_zero_overwrites_all_bytes_with_zero() -> None:
    buf = bytearray(b"secret passphrase data here!")
    assert any(b != 0 for b in buf)
    secure_zero(buf)
    assert all(b == 0 for b in buf)


def test_secure_zero_on_empty_buffer_is_noop() -> None:
    buf = bytearray()
    secure_zero(buf)  # must not raise


# ---------------------------------------------------------------------------
# Frozen snapshot test
# ---------------------------------------------------------------------------

def test_snapshot_fixture_decrypts_correctly() -> None:
    """Decrypt the frozen fixture to verify wire-format stability.

    If this test fails after a code change it means the envelope format or
    the decryption logic changed in a backward-incompatible way.
    """
    fixture: Dict[str, Any] = json.loads(FIXTURE_PATH.read_text())

    seed = bytes.fromhex(fixture["seed_hex"])
    priv = nacl.public.PrivateKey(seed)
    pub_bytes = bytes(priv.public_key)
    priv_bytes = bytes(priv)

    expected_plaintext = base64.b64decode(fixture["expected_plaintext_b64"])
    user_id = fixture["test_user_id"]

    recovered = decrypt_envelope(
        fixture["envelope"],
        self_user_id=user_id,
        self_private_key=priv_bytes,
        self_public_key=pub_bytes,
    )
    assert recovered == expected_plaintext


def test_snapshot_fixture_passphrase_unwraps_private_key() -> None:
    """Verify the stored WrappedPrivateKey can be unwrapped with the test passphrase."""
    fixture: Dict[str, Any] = json.loads(FIXTURE_PATH.read_text())

    seed = bytes.fromhex(fixture["seed_hex"])
    priv = nacl.public.PrivateKey(seed)
    expected_priv_bytes = bytes(priv)

    wrapped = WrappedPrivateKey.from_json(json.dumps(fixture["wrapped_private_key"]))
    recovered = unwrap_private_key(wrapped, fixture["test_passphrase"])
    assert recovered == expected_priv_bytes
