"""Unit tests for the config_crypto module (AES-256-GCM encryption helpers)."""
from __future__ import annotations

import base64
from unittest.mock import patch

import pytest

import servonaut.services.config_crypto as config_crypto
from servonaut.services.config_crypto import (
    ASSOCIATED_DATA,
    DecryptionError,
    CryptoUnavailableError,
    derive_key,
    encrypt,
    decrypt,
    make_probe,
    verify_probe,
    PROBE_SALT,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    KEY_SIZE,
    ENCRYPTION_ALGORITHM,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PASSPHRASE = "correct-horse-battery"  # >= 8 chars
_PLAINTEXT = '{"key": "value", "number": 42}'


def _make_valid_encrypted() -> dict:
    """Return a freshly encrypted payload for _PLAINTEXT."""
    return encrypt(_PLAINTEXT, _PASSPHRASE)


# ---------------------------------------------------------------------------
# Roundtrip
# ---------------------------------------------------------------------------

class TestRoundtrip:
    def test_encrypt_decrypt_roundtrip(self):
        """Decrypt(Encrypt(plaintext)) == plaintext."""
        enc = encrypt(_PLAINTEXT, _PASSPHRASE)
        result = decrypt(enc, _PASSPHRASE)
        assert result == _PLAINTEXT

    def test_wrong_passphrase_raises_decryption_error(self):
        """Wrong passphrase raises DecryptionError with the generic message (no cause leakage)."""
        enc = encrypt(_PLAINTEXT, _PASSPHRASE)
        with pytest.raises(DecryptionError) as exc_info:
            decrypt(enc, "wrong-passphrase-long-enough")
        # The generic message must be present and must not expose cryptographic cause.
        assert str(exc_info.value) == "Decryption failed - wrong passphrase or corrupted data"


# ---------------------------------------------------------------------------
# Tampered ciphertext
# ---------------------------------------------------------------------------

class TestTampering:
    def test_tampered_ciphertext_raises(self):
        """Flipping a byte in 'data' causes DecryptionError."""
        enc = _make_valid_encrypted()
        data_bytes = bytearray(base64.b64decode(enc["data"]))
        data_bytes[0] ^= 0xFF
        enc["data"] = base64.b64encode(bytes(data_bytes)).decode()
        with pytest.raises(DecryptionError):
            decrypt(enc, _PASSPHRASE)

    def test_tampered_tag_raises(self):
        """Flipping a byte in 'tag' causes DecryptionError."""
        enc = _make_valid_encrypted()
        tag_bytes = bytearray(base64.b64decode(enc["tag"]))
        tag_bytes[0] ^= 0xFF
        enc["tag"] = base64.b64encode(bytes(tag_bytes)).decode()
        with pytest.raises(DecryptionError):
            decrypt(enc, _PASSPHRASE)

    def test_tampered_salt_raises(self):
        """Flipping a byte in 'salt' derives the wrong key, causing DecryptionError."""
        enc = _make_valid_encrypted()
        salt_bytes = bytearray(base64.b64decode(enc["salt"]))
        salt_bytes[0] ^= 0xFF
        enc["salt"] = base64.b64encode(bytes(salt_bytes)).decode()
        with pytest.raises(DecryptionError):
            decrypt(enc, _PASSPHRASE)


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

class TestEncryptOutputShape:
    def test_encrypt_output_shape(self):
        """Returned dict has the expected keys and correct field sizes."""
        enc = encrypt(_PLAINTEXT, _PASSPHRASE)

        assert set(enc.keys()) == {"encryption", "data", "salt", "iv", "tag"}
        assert enc["encryption"] == ENCRYPTION_ALGORITHM

        assert len(base64.b64decode(enc["salt"])) == SALT_SIZE       # 16 bytes
        assert len(base64.b64decode(enc["iv"])) == NONCE_SIZE         # 12 bytes
        assert len(base64.b64decode(enc["tag"])) == TAG_SIZE          # 16 bytes
        assert len(base64.b64decode(enc["data"])) >= 1

    def test_unique_salt_and_iv_per_call(self):
        """Two encryptions of the same plaintext+passphrase produce different salt and iv."""
        enc1 = encrypt(_PLAINTEXT, _PASSPHRASE)
        enc2 = encrypt(_PLAINTEXT, _PASSPHRASE)
        assert enc1["salt"] != enc2["salt"]
        assert enc1["iv"] != enc2["iv"]


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

class TestDeriveKey:
    def test_derive_key_deterministic(self):
        """Same passphrase + salt always yields the same 32-byte key."""
        salt = b"\x00" * SALT_SIZE
        k1 = derive_key(_PASSPHRASE, salt)
        k2 = derive_key(_PASSPHRASE, salt)
        assert k1 == k2
        assert len(k1) == KEY_SIZE

    def test_derive_key_salt_sensitivity(self):
        """Different salts produce different keys."""
        salt_a = b"\x00" * SALT_SIZE
        salt_b = b"\x01" * SALT_SIZE
        assert derive_key(_PASSPHRASE, salt_a) != derive_key(_PASSPHRASE, salt_b)


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

class TestProbe:
    def test_make_verify_probe_roundtrip(self):
        """verify_probe returns True for the correct passphrase and False for a different one."""
        probe = make_probe(_PASSPHRASE)
        assert verify_probe(_PASSPHRASE, probe) is True
        assert verify_probe("other-wrong-passphrase", probe) is False


# ---------------------------------------------------------------------------
# Validation — algorithm / field-size guards
# ---------------------------------------------------------------------------

class TestDecryptValidation:
    def test_decrypt_rejects_unknown_algorithm(self):
        """encryption='aes-128-cbc' is rejected before any AESGCM call."""
        enc = _make_valid_encrypted()
        enc["encryption"] = "aes-128-cbc"
        with pytest.raises(DecryptionError) as exc_info:
            decrypt(enc, _PASSPHRASE)
        assert "Decryption failed" in str(exc_info.value)

    def test_decrypt_rejects_wrong_salt_size(self):
        """15-byte salt (one byte short) raises DecryptionError."""
        enc = _make_valid_encrypted()
        enc["salt"] = base64.b64encode(b"\x00" * (SALT_SIZE - 1)).decode()
        with pytest.raises(DecryptionError):
            decrypt(enc, _PASSPHRASE)

    def test_decrypt_rejects_wrong_iv_size(self):
        """11-byte iv raises DecryptionError."""
        enc = _make_valid_encrypted()
        enc["iv"] = base64.b64encode(b"\x00" * (NONCE_SIZE - 1)).decode()
        with pytest.raises(DecryptionError):
            decrypt(enc, _PASSPHRASE)

    def test_decrypt_rejects_wrong_tag_size(self):
        """15-byte tag raises DecryptionError."""
        enc = _make_valid_encrypted()
        enc["tag"] = base64.b64encode(b"\x00" * (TAG_SIZE - 1)).decode()
        with pytest.raises(DecryptionError):
            decrypt(enc, _PASSPHRASE)

    def test_decrypt_rejects_empty_data(self):
        """Zero-byte data field raises DecryptionError."""
        enc = _make_valid_encrypted()
        enc["data"] = base64.b64encode(b"").decode()
        with pytest.raises(DecryptionError):
            decrypt(enc, _PASSPHRASE)

    def test_decrypt_rejects_non_base64(self):
        """Non-base64 salt raises DecryptionError, not binascii.Error."""
        enc = _make_valid_encrypted()
        enc["salt"] = "not!valid!base64!!!"
        with pytest.raises(DecryptionError):
            decrypt(enc, _PASSPHRASE)


# ---------------------------------------------------------------------------
# Missing cryptography package
# ---------------------------------------------------------------------------

class TestCryptoUnavailable:
    def test_missing_cryptography_raises_crypto_unavailable(self):
        """When HAS_CRYPTOGRAPHY=False, both encrypt() and decrypt() raise CryptoUnavailableError."""
        enc = _make_valid_encrypted()  # produce a real payload before disabling

        with patch.object(config_crypto, "HAS_CRYPTOGRAPHY", False):
            with pytest.raises(CryptoUnavailableError):
                encrypt(_PLAINTEXT, _PASSPHRASE)

        with patch.object(config_crypto, "HAS_CRYPTOGRAPHY", False):
            with pytest.raises(CryptoUnavailableError):
                decrypt(enc, _PASSPHRASE)


# ---------------------------------------------------------------------------
# Passphrase length validation
# ---------------------------------------------------------------------------

class TestPassphraseLength:
    def test_short_passphrase_rejected_on_encrypt(self):
        """Passphrase shorter than MIN_PASSPHRASE_LEN raises ValueError on encrypt."""
        with pytest.raises(ValueError):
            encrypt(_PLAINTEXT, "short")

    def test_short_passphrase_rejected_on_make_probe(self):
        """Passphrase shorter than MIN_PASSPHRASE_LEN raises ValueError on make_probe."""
        with pytest.raises(ValueError):
            make_probe("short")


# ---------------------------------------------------------------------------
# Associated data binding
# ---------------------------------------------------------------------------

class TestAssociatedData:
    def test_associated_data_binding(self, monkeypatch):
        """Modifying ASSOCIATED_DATA at decrypt time causes DecryptionError.

        This verifies that the GCM authentication tag binds the protocol
        version constant, preventing cross-version substitution attacks.
        """
        enc = _make_valid_encrypted()

        # Swap the module-level constant to a different value, simulating what
        # would happen if the decryption side used a different protocol version.
        monkeypatch.setattr(config_crypto, "ASSOCIATED_DATA", b"servonaut-config-v2")
        with pytest.raises(DecryptionError):
            decrypt(enc, _PASSPHRASE)
