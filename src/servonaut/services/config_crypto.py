"""Client-side AES-256-GCM encryption for config sync."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    AESGCM = None  # type: ignore[assignment,misc]
    HAS_CRYPTOGRAPHY = False

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16

ENCRYPTION_ALGORITHM = "aes-256-gcm"
MIN_PASSPHRASE_LEN = 8
# Bound as GCM associated data — binds the protocol version to the ciphertext
# so a future scheme cannot be substituted without breaking auth.
ASSOCIATED_DATA = b"servonaut-config-v1"

# Fixed salt used only for the local key-probe (not for data encryption).
# Never changes — allows fast pre-flight check without hitting the network.
# PBKDF2 accepts any salt length; this literal is 31 bytes.
PROBE_SALT = b"servonaut-sync-probe-v1\x00\x00\x00\x00\x00\x00\x00\x00"


class CryptoUnavailableError(RuntimeError):
    """Raised when the cryptography package is not installed."""


class DecryptionError(ValueError):
    """Raised when decryption fails (wrong passphrase or corrupted data)."""


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key via PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )


def encrypt(plaintext: str, passphrase: str) -> dict:
    """Encrypt a plaintext JSON string with a passphrase.

    Returns a dict with base64-encoded fields: encryption, data, salt, iv, tag.
    Each call uses a fresh random salt and nonce.

    Raises:
        CryptoUnavailableError: If the cryptography package is not installed.
        ValueError: If passphrase is shorter than MIN_PASSPHRASE_LEN.
    """
    if not HAS_CRYPTOGRAPHY:
        raise CryptoUnavailableError("Install with: pip install 'servonaut[sync]'")
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise ValueError(f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(passphrase, salt)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    # AESGCM.encrypt() appends the 16-byte GCM auth tag to the ciphertext.
    # AD binds the protocol version so a future scheme can't be substituted.
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), ASSOCIATED_DATA)
    ciphertext = ct_with_tag[:-TAG_SIZE]
    tag = ct_with_tag[-TAG_SIZE:]

    return {
        "encryption": ENCRYPTION_ALGORITHM,
        "data": base64.b64encode(ciphertext).decode(),
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def decrypt(encrypted: dict, passphrase: str) -> str:
    """Decrypt a config snapshot dict produced by encrypt().

    Validates algorithm whitelist and field sizes strictly before calling AESGCM
    so that missing or malformed fields produce a clear error rather than a
    cryptic library exception.

    Args:
        encrypted: Dict with encryption, data, salt, iv, tag (all base64-encoded).
        passphrase: User's sync passphrase.

    Returns:
        Decrypted JSON string.

    Raises:
        CryptoUnavailableError: If the cryptography package is not installed.
        DecryptionError: If passphrase is wrong, data is corrupted, or fields
            are invalid. The message is deliberately generic to avoid leaking
            whether the failure was wrong-passphrase vs. tamper.
    """
    if not HAS_CRYPTOGRAPHY:
        raise CryptoUnavailableError("Install with: pip install 'servonaut[sync]'")

    try:
        algorithm = encrypted.get("encryption", "")
        if algorithm != ENCRYPTION_ALGORITHM:
            raise DecryptionError("Decryption failed - wrong passphrase or corrupted data")

        salt_raw = base64.b64decode(encrypted["salt"])
        iv_raw = base64.b64decode(encrypted["iv"])
        tag_raw = base64.b64decode(encrypted["tag"])
        data_raw = base64.b64decode(encrypted["data"])

        if len(salt_raw) != SALT_SIZE:
            raise DecryptionError("Decryption failed - wrong passphrase or corrupted data")
        if len(iv_raw) != NONCE_SIZE:
            raise DecryptionError("Decryption failed - wrong passphrase or corrupted data")
        if len(tag_raw) != TAG_SIZE:
            raise DecryptionError("Decryption failed - wrong passphrase or corrupted data")
        if len(data_raw) < 1:
            raise DecryptionError("Decryption failed - wrong passphrase or corrupted data")

        key = derive_key(passphrase, salt_raw)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv_raw, data_raw + tag_raw, ASSOCIATED_DATA)
        return plaintext.decode("utf-8")
    except DecryptionError:
        raise
    except CryptoUnavailableError:
        raise
    except Exception:
        raise DecryptionError("Decryption failed - wrong passphrase or corrupted data")


def make_probe(passphrase: str) -> str:
    """Derive a hex fingerprint for a passphrase using the fixed PROBE_SALT.

    The probe is SHA-256 of the derived key — not the passphrase itself —
    so the passphrase cannot be recovered from the probe file.

    Returns:
        64-character lowercase hex string.

    Raises:
        ValueError: If passphrase is shorter than MIN_PASSPHRASE_LEN.
    """
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise ValueError(f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters")
    key = derive_key(passphrase, PROBE_SALT)
    return hashlib.sha256(key).hexdigest()


def verify_probe(passphrase: str, probe_hex: str) -> bool:
    """Return True if passphrase matches the stored probe hex string.

    Uses hmac.compare_digest to avoid timing side-channels.
    """
    candidate = make_probe(passphrase)
    return hmac.compare_digest(candidate, probe_hex)
