"""End-to-end encryption helpers for the server memory sync subsystem.

Crypto stack:
- X25519 keypair generation — PyNaCl (nacl.public.PrivateKey)
- Argon2id key derivation — PyNaCl (nacl.pwhash.argon2id)
- Private-key wrapping — PyNaCl SecretBox (XSalsa20-Poly1305)
- DEK wrapping — PyNaCl SealedBox (X25519 + XSalsa20-Poly1305)
- Envelope ciphertext — AES-256-GCM (cryptography.AESGCM)

See spec §3.1 (keypair), §3.3 (envelope wire shape), §3.7 (read shape), §6 (rate limits).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import nacl.encoding
import nacl.exceptions
import nacl.public
import nacl.pwhash
import nacl.pwhash.argon2id
import nacl.secret
import nacl.utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

X25519_KEY_LEN = 32
AES_KEY_LEN = 32
AES_IV_LEN = 12
AES_TAG_LEN = 16
# Raw ciphertext bytes before base64 encoding; b64 grows by ~33 %.
MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024
MAX_WRAPPED_PRIVKEY_BYTES = 8 * 1024
MIN_PW_SCORE = 3


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------

class CryptoError(Exception):
    """Base class for all memory-crypto errors."""


class WeakPassphraseError(CryptoError):
    """Raised when a passphrase scores below MIN_PW_SCORE."""


class WrappedKeyTooLargeError(CryptoError):
    """Raised when a serialised WrappedPrivateKey exceeds MAX_WRAPPED_PRIVKEY_BYTES."""


class InvalidEnvelopeError(CryptoError):
    """Raised when envelope fields fail size or format validation."""


class DecryptionFailedError(CryptoError):
    """Raised on any decryption failure — message is intentionally generic to prevent leaks."""


class NoSelfWrapError(CryptoError):
    """Raised when decrypt_envelope finds no DEK wrap addressed to self_user_id."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyPair:
    """An X25519 keypair plus a SHA-256 fingerprint of the public key.

    Attributes:
        public_key: Raw 32-byte X25519 public key.
        private_key: Raw 32-byte X25519 private key.
        fingerprint: 64-char lowercase hex sha256(public_key).
    """

    public_key: bytes
    private_key: bytes
    fingerprint: str


@dataclass(frozen=True)
class WrappedPrivateKey:
    """Argon2id-encrypted private key blob, suitable for server upload.

    Attributes:
        kdf: Always ``"argon2id"``.
        pw_score: Estimated passphrase strength score (>= MIN_PW_SCORE).
        salt: Base64-encoded Argon2id salt.
        nonce: Base64-encoded SecretBox nonce.
        ct: Base64-encoded encrypted private-key ciphertext.
        ops_limit: libsodium ops_limit constant used during KDF.
        mem_limit: libsodium mem_limit constant used during KDF.
    """

    kdf: str
    pw_score: int
    salt: str
    nonce: str
    ct: str
    ops_limit: int
    mem_limit: int

    def to_json(self) -> str:
        """Serialise to a compact JSON string.

        Raises:
            WrappedKeyTooLargeError: If the resulting string exceeds MAX_WRAPPED_PRIVKEY_BYTES.
        """
        blob = json.dumps(
            {
                "kdf": self.kdf,
                "pw_score": self.pw_score,
                "salt": self.salt,
                "nonce": self.nonce,
                "ct": self.ct,
                "ops_limit": self.ops_limit,
                "mem_limit": self.mem_limit,
            },
            separators=(",", ":"),
        )
        if len(blob.encode()) > MAX_WRAPPED_PRIVKEY_BYTES:
            raise WrappedKeyTooLargeError(
                f"WrappedPrivateKey JSON exceeds {MAX_WRAPPED_PRIVKEY_BYTES} bytes"
            )
        return blob

    @classmethod
    def from_json(cls, blob: str) -> "WrappedPrivateKey":
        """Deserialise from a JSON string produced by ``to_json()``.

        Args:
            blob: JSON string.

        Returns:
            WrappedPrivateKey instance.

        Raises:
            CryptoError: If the JSON is malformed or missing required fields.
        """
        try:
            data = json.loads(blob)
            return cls(
                kdf=data["kdf"],
                pw_score=int(data["pw_score"]),
                salt=data["salt"],
                nonce=data["nonce"],
                ct=data["ct"],
                ops_limit=int(data["ops_limit"]),
                mem_limit=int(data["mem_limit"]),
            )
        except (KeyError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise CryptoError(f"Cannot parse WrappedPrivateKey JSON: {exc}") from exc


@dataclass(frozen=True)
class DEKWrap:
    """A Data-Encryption Key wrapped for a specific recipient.

    Attributes:
        recipient_user_id: Numeric user ID of the intended recipient.
        wrapped_dek: Base64-encoded SealedBox-encrypted DEK (32–256 bytes raw).
    """

    recipient_user_id: int
    wrapped_dek: str


@dataclass(frozen=True)
class Envelope:
    """AES-256-GCM envelope with one or more DEK wraps.

    Wire format matches spec §3.3 (sync ingest).

    Attributes:
        iv: Base64-encoded 12-byte AES-GCM nonce.
        tag: Base64-encoded 16-byte AES-GCM authentication tag.
        salt: Optional base64-encoded salt (None for memory sync — no AAD needed).
        ciphertext: Base64-encoded ciphertext (≤ 2 MB raw).
        encryption: Always ``"aes-256-gcm"``.
        dek_wraps: List of per-recipient DEK wraps. Must include the sender.
    """

    iv: str
    tag: str
    salt: Optional[str]
    ciphertext: str
    encryption: str
    dek_wraps: List[DEKWrap]

    def to_dict(self) -> Dict[str, Any]:
        """Return the spec §3.3 wire-format dict for POST /memory/sync."""
        return {
            "iv": self.iv,
            "tag": self.tag,
            "salt": self.salt,
            "ciphertext": self.ciphertext,
            "encryption": self.encryption,
            "dek_wraps": [
                {
                    "recipient_user_id": w.recipient_user_id,
                    "wrapped_dek": w.wrapped_dek,
                }
                for w in self.dek_wraps
            ],
        }


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def generate_keypair() -> KeyPair:
    """Generate a fresh X25519 keypair.

    Returns:
        KeyPair with raw 32-byte public and private keys plus a 64-char hex fingerprint.
    """
    private = nacl.public.PrivateKey.generate()
    pub_bytes = bytes(private.public_key)
    priv_bytes = bytes(private)
    return KeyPair(
        public_key=pub_bytes,
        private_key=priv_bytes,
        fingerprint=fingerprint(pub_bytes),
    )


def fingerprint(public_key_bytes: bytes) -> str:
    """Compute a 64-char lowercase hex SHA-256 fingerprint of a public key.

    Args:
        public_key_bytes: Raw 32-byte X25519 public key.

    Returns:
        64-character lowercase hex string.
    """
    return hashlib.sha256(public_key_bytes).hexdigest()


def estimate_pw_score(passphrase: str) -> int:
    """Estimate the strength of a passphrase on a 0–4 scale.

    Attempts to import ``zxcvbn`` and delegates to it. Falls back to a simple
    heuristic when zxcvbn is not installed:

    - score 0: < 8 chars
    - score 1: < 12 chars
    - score 2: < 16 chars OR missing a character class
    - score 3: >= 16 chars with >= 3 distinct character classes
    - score 4: >= 20 chars with all 4 character classes (upper, lower, digit, symbol)

    Mixed-class = upper + lower + digit + symbol all present.

    Args:
        passphrase: The passphrase string to evaluate.

    Returns:
        Integer in [0, 4].
    """
    try:
        from zxcvbn import zxcvbn  # type: ignore[import]
        return zxcvbn(passphrase)["score"]
    except ImportError:
        pass

    length = len(passphrase)
    if length < 8:
        return 0
    if length < 12:
        return 1

    has_upper = any(c.isupper() for c in passphrase)
    has_lower = any(c.islower() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    has_symbol = any(not c.isalnum() for c in passphrase)
    class_count = sum([has_upper, has_lower, has_digit, has_symbol])

    if length < 16 or class_count < 3:
        return 2
    if length >= 20 and class_count == 4:
        return 4
    return 3


def wrap_private_key(
    private_key: bytes,
    passphrase: str,
    *,
    strength: str = "interactive",
) -> WrappedPrivateKey:
    """Encrypt a raw X25519 private key with Argon2id + SecretBox.

    The derived key is secure-zeroed after use (best-effort; see ``secure_zero``
    docstring for Python memory hygiene caveats).

    Args:
        private_key: Raw 32-byte X25519 private key bytes.
        passphrase: User passphrase — must score >= MIN_PW_SCORE.
        strength: Argon2id work-factor preset:
            ``"interactive"`` (default), ``"moderate"``, or ``"sensitive"``.

    Returns:
        WrappedPrivateKey ready for ``to_json()`` and server upload.

    Raises:
        WeakPassphraseError: If estimate_pw_score(passphrase) < MIN_PW_SCORE.
        ValueError: If *strength* is not a recognised preset.
        WrappedKeyTooLargeError: If the serialised blob exceeds 8 KB.
    """
    if estimate_pw_score(passphrase) < MIN_PW_SCORE:
        raise WeakPassphraseError(
            f"Passphrase is too weak (score < {MIN_PW_SCORE}). "
            "Use at least 16 characters with mixed character classes."
        )

    _STRENGTH_MAP = {
        "interactive": (
            nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
            nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE,
        ),
        "moderate": (
            nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
            nacl.pwhash.argon2id.MEMLIMIT_MODERATE,
        ),
        "sensitive": (
            nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE,
            nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE,
        ),
    }
    if strength not in _STRENGTH_MAP:
        raise ValueError(f"Unknown strength preset {strength!r}. Choose interactive/moderate/sensitive.")

    ops_limit, mem_limit = _STRENGTH_MAP[strength]
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)

    pp_bytes = bytearray(passphrase.encode("utf-8"))
    derived = bytearray(AES_KEY_LEN)
    try:
        derived[:] = nacl.pwhash.argon2id.kdf(
            AES_KEY_LEN,
            bytes(pp_bytes),
            salt,
            opslimit=ops_limit,
            memlimit=mem_limit,
        )
        box = nacl.secret.SecretBox(bytes(derived))
        # SecretBox.encrypt() prepends a 24-byte random nonce to the ciphertext.
        encrypted = box.encrypt(private_key)
        nonce_bytes = encrypted.nonce
        ct_bytes = encrypted.ciphertext

        wrapped = WrappedPrivateKey(
            kdf="argon2id",
            pw_score=estimate_pw_score(passphrase),
            salt=base64.b64encode(salt).decode(),
            nonce=base64.b64encode(nonce_bytes).decode(),
            ct=base64.b64encode(ct_bytes).decode(),
            ops_limit=ops_limit,
            mem_limit=mem_limit,
        )
        # Validate size before returning — ensures server will accept it.
        wrapped.to_json()
        return wrapped
    finally:
        secure_zero(pp_bytes)
        secure_zero(derived)


def unwrap_private_key(wrapped: WrappedPrivateKey, passphrase: str) -> bytes:
    """Decrypt a WrappedPrivateKey back to raw bytes.

    Args:
        wrapped: The WrappedPrivateKey produced by ``wrap_private_key()``.
        passphrase: The passphrase used during wrapping.

    Returns:
        Raw 32-byte X25519 private key.

    Raises:
        DecryptionFailedError: On any failure — the error message is generic to
            prevent leaking whether the passphrase or ciphertext was wrong.
    """
    pp_bytes = bytearray(passphrase.encode("utf-8"))
    derived = bytearray(AES_KEY_LEN)
    try:
        salt = base64.b64decode(wrapped.salt)
        nonce = base64.b64decode(wrapped.nonce)
        ct = base64.b64decode(wrapped.ct)

        derived[:] = nacl.pwhash.argon2id.kdf(
            AES_KEY_LEN,
            bytes(pp_bytes),
            salt,
            opslimit=wrapped.ops_limit,
            memlimit=wrapped.mem_limit,
        )
        box = nacl.secret.SecretBox(bytes(derived))
        # nonce + ciphertext must be concatenated for SecretBox.decrypt.
        plaintext = box.decrypt(nonce + ct)
        return bytes(plaintext)
    except (nacl.exceptions.CryptoError, ValueError, Exception) as exc:
        raise DecryptionFailedError("decryption failed") from exc
    finally:
        secure_zero(pp_bytes)
        secure_zero(derived)


def encrypt_envelope(
    plaintext: bytes,
    *,
    self_public_key: bytes,
    self_user_id: int,
    additional_recipients: Sequence[Tuple[int, bytes]] = (),
) -> Envelope:
    """Encrypt plaintext into an AES-256-GCM envelope with per-recipient DEK wraps.

    The DEK (Data Encryption Key) is a random 32-byte secret used to encrypt the
    plaintext with AES-256-GCM. The DEK is then wrapped (encrypted) with each
    recipient's X25519 public key via PyNaCl SealedBox. The DEK is secure-zeroed
    after use.

    No AAD is used — spec §3.3 does not include an AAD field.

    Args:
        plaintext: Raw bytes to encrypt (≤ MAX_CIPHERTEXT_BYTES).
        self_public_key: Caller's 32-byte X25519 public key (self-wrap).
        self_user_id: Caller's numeric user ID (self-wrap recipient_user_id).
        additional_recipients: Optional extra ``(user_id, public_key_bytes)`` pairs.

    Returns:
        Envelope ready for serialisation with ``to_dict()``.

    Raises:
        InvalidEnvelopeError: If *plaintext* exceeds MAX_CIPHERTEXT_BYTES.
    """
    if len(plaintext) > MAX_CIPHERTEXT_BYTES:
        raise InvalidEnvelopeError(
            f"Plaintext size {len(plaintext)} exceeds MAX_CIPHERTEXT_BYTES ({MAX_CIPHERTEXT_BYTES})"
        )

    dek = bytearray(os.urandom(AES_KEY_LEN))
    try:
        iv = os.urandom(AES_IV_LEN)
        # AESGCM.encrypt returns ciphertext || 16-byte tag
        ct_with_tag = AESGCM(bytes(dek)).encrypt(iv, plaintext, None)
        ciphertext = ct_with_tag[:-AES_TAG_LEN]
        tag = ct_with_tag[-AES_TAG_LEN:]

        # Self-wrap
        self_box = nacl.public.SealedBox(nacl.public.PublicKey(self_public_key))
        wrapped_self = self_box.encrypt(bytes(dek))

        dek_wraps: List[DEKWrap] = [
            DEKWrap(
                recipient_user_id=self_user_id,
                wrapped_dek=base64.b64encode(wrapped_self).decode(),
            )
        ]

        for uid, pubkey in additional_recipients:
            box = nacl.public.SealedBox(nacl.public.PublicKey(pubkey))
            wrapped = box.encrypt(bytes(dek))
            dek_wraps.append(
                DEKWrap(
                    recipient_user_id=uid,
                    wrapped_dek=base64.b64encode(wrapped).decode(),
                )
            )

        return Envelope(
            iv=base64.b64encode(iv).decode(),
            tag=base64.b64encode(tag).decode(),
            salt=None,
            ciphertext=base64.b64encode(ciphertext).decode(),
            encryption="aes-256-gcm",
            dek_wraps=dek_wraps,
        )
    finally:
        secure_zero(dek)


def decrypt_envelope(
    envelope: Union["Envelope", Dict[str, Any]],
    *,
    self_user_id: int,
    self_private_key: bytes,
    self_public_key: bytes,
) -> bytes:
    """Decrypt an envelope addressed to self_user_id.

    Accepts both the spec §3.3 ``dek_wraps`` array shape and the spec §3.7
    single ``wrapped_dek`` string shape (the server already addressed to caller).

    Args:
        envelope: Either an ``Envelope`` instance or a raw dict from the API.
        self_user_id: Caller's numeric user ID — used to find the correct DEK wrap.
        self_private_key: Caller's raw 32-byte X25519 private key.
        self_public_key: Caller's raw 32-byte X25519 public key (unused for decryption,
            kept for interface symmetry with encrypt_envelope).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        NoSelfWrapError: If no DEK wrap addressed to *self_user_id* is found.
        InvalidEnvelopeError: If field sizes fail validation.
        DecryptionFailedError: On any cryptographic failure — single generic message.
    """
    try:
        # Normalise to dict for uniform handling.
        if isinstance(envelope, Envelope):
            data: Dict[str, Any] = envelope.to_dict()
        else:
            data = envelope

        iv = validate_iv(data["iv"])
        tag = validate_tag(data["tag"])
        ciphertext = validate_ciphertext(data["ciphertext"])

        # Resolve the DEK wrap — supports §3.3 (dek_wraps[]) and §3.7 (wrapped_dek).
        wrapped_dek_b64: Optional[str] = None
        if "dek_wraps" in data:
            wraps = data["dek_wraps"]
            for wrap in wraps:
                if wrap.get("recipient_user_id") == self_user_id:
                    wrapped_dek_b64 = wrap["wrapped_dek"]
                    break
            if wrapped_dek_b64 is None:
                raise NoSelfWrapError(
                    f"No DEK wrap found for user_id={self_user_id}"
                )
        elif "wrapped_dek" in data:
            # §3.7 shape — server pre-filtered to the caller's wrap.
            wrapped_dek_b64 = data["wrapped_dek"]
        else:
            raise NoSelfWrapError(
                "Envelope has neither 'dek_wraps' nor 'wrapped_dek' field"
            )

        wrapped_dek_bytes = validate_wrapped_dek(wrapped_dek_b64)

        box = nacl.public.SealedBox(nacl.public.PrivateKey(self_private_key))
        dek = bytearray(box.decrypt(wrapped_dek_bytes))
        try:
            plaintext = AESGCM(bytes(dek)).decrypt(iv, ciphertext + tag, None)
            return plaintext
        finally:
            secure_zero(dek)

    except NoSelfWrapError:
        raise
    except InvalidEnvelopeError:
        raise
    except (nacl.exceptions.CryptoError, ValueError, KeyError, TypeError) as exc:
        raise DecryptionFailedError("decryption failed") from exc
    except Exception as exc:
        raise DecryptionFailedError("decryption failed") from exc


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def validate_iv(b64: str) -> bytes:
    """Decode and validate a base64-encoded AES-GCM IV (must be exactly 12 bytes).

    Args:
        b64: Base64-encoded string.

    Returns:
        12-byte IV as bytes.

    Raises:
        InvalidEnvelopeError: If the decoded length is not AES_IV_LEN.
    """
    raw = base64.b64decode(b64)
    if len(raw) != AES_IV_LEN:
        raise InvalidEnvelopeError(
            f"IV must be {AES_IV_LEN} bytes, got {len(raw)}"
        )
    return raw


def validate_tag(b64: str) -> bytes:
    """Decode and validate a base64-encoded AES-GCM tag (must be exactly 16 bytes).

    Args:
        b64: Base64-encoded string.

    Returns:
        16-byte tag as bytes.

    Raises:
        InvalidEnvelopeError: If the decoded length is not AES_TAG_LEN.
    """
    raw = base64.b64decode(b64)
    if len(raw) != AES_TAG_LEN:
        raise InvalidEnvelopeError(
            f"Tag must be {AES_TAG_LEN} bytes, got {len(raw)}"
        )
    return raw


def validate_ciphertext(b64: str) -> bytes:
    """Decode and validate a base64-encoded ciphertext (≤ MAX_CIPHERTEXT_BYTES raw).

    Args:
        b64: Base64-encoded string.

    Returns:
        Raw ciphertext bytes.

    Raises:
        InvalidEnvelopeError: If the decoded length exceeds MAX_CIPHERTEXT_BYTES.
    """
    raw = base64.b64decode(b64)
    if len(raw) > MAX_CIPHERTEXT_BYTES:
        raise InvalidEnvelopeError(
            f"Ciphertext exceeds {MAX_CIPHERTEXT_BYTES} bytes"
        )
    return raw


def validate_public_key(b64: str) -> bytes:
    """Decode and validate a base64-encoded X25519 public key (must be exactly 32 bytes).

    Args:
        b64: Base64-encoded string.

    Returns:
        32-byte public key as bytes.

    Raises:
        InvalidEnvelopeError: If the decoded length is not X25519_KEY_LEN.
    """
    raw = base64.b64decode(b64)
    if len(raw) != X25519_KEY_LEN:
        raise InvalidEnvelopeError(
            f"Public key must be {X25519_KEY_LEN} bytes, got {len(raw)}"
        )
    return raw


def validate_wrapped_dek(b64: str) -> bytes:
    """Decode and validate a base64-encoded wrapped DEK (32–256 bytes raw).

    Args:
        b64: Base64-encoded string.

    Returns:
        Raw wrapped-DEK bytes.

    Raises:
        InvalidEnvelopeError: If the decoded length is outside [32, 256].
    """
    raw = base64.b64decode(b64)
    if not (32 <= len(raw) <= 256):
        raise InvalidEnvelopeError(
            f"Wrapped DEK must be 32–256 bytes, got {len(raw)}"
        )
    return raw


# ---------------------------------------------------------------------------
# Memory hygiene
# ---------------------------------------------------------------------------

def secure_zero(buf: bytearray) -> None:
    """Overwrite every byte of *buf* with zero.

    Best-effort: CPython may have already copied the underlying bytes buffer
    when the interpreter used the bytearray in intermediate expressions.
    Always store secrets in ``bytearray`` (not ``bytes`` or ``str``) when you
    intend to zero them — ``bytes`` and ``str`` are immutable and cannot be
    zeroed at all.

    Args:
        buf: Mutable byte buffer to zero in-place.
    """
    for i in range(len(buf)):
        buf[i] = 0
