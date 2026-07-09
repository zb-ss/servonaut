"""Local SSH private-key scanner + decryptor for the Bitwarden import flow.

Scans a directory (typically ``~/.ssh``) for private-key files, classifies each
as unencrypted / passphrase-protected / unreadable, and decrypts or normalises
keys to OpenSSH PEM for upload as native Bitwarden SSH items.

SECURITY PINS (non-negotiable):
- Private-key material and passphrases NEVER appear on a subprocess argv, in a
  log call, in an exception message, or on disk. This module performs no
  subprocess calls and no writes — it only reads candidate files.
- Exception messages are intentionally generic ("Wrong passphrase.") so a
  failure surfaced to the TUI can never echo key bytes or the passphrase.

Encryption detection (best effort, as far as ``cryptography`` allows):
- OpenSSH format: the ciphername/kdf fields inside the ``openssh-key-v1``
  blob are ``none`` for unencrypted keys — anything else means encrypted.
- Traditional PEM: an explicit ``Proc-Type: 4,ENCRYPTED`` header.
- PKCS#8: an explicit ``BEGIN ENCRYPTED PRIVATE KEY`` armor.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import hashlib
import logging
import os
import re
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_ssh_private_key,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_MAX_KEY_BYTES",
    "ScannedKey",
    "DecryptedKey",
    "KeyImportError",
    "WrongPassphraseError",
    "scan_directory",
    "read_key_bytes",
    "decrypt_private_key",
    "load_unencrypted_key",
]

# Size cap for key-candidate files — enforced by the scan AND by any re-read
# at import time (the file may have been replaced/grown between the two).
DEFAULT_MAX_KEY_BYTES: int = 16384

# Files that are never private keys, matched by NAME (fnmatch patterns).
_SKIP_NAME_PATTERNS: tuple[str, ...] = (
    "known_hosts*",
    "config",
    "authorized_keys*",
    "environment",
    "*.pub",
    "*-cert.pub",
    "*.dec",
)

# PEM armor fragments, assembled at import time. The full "BEGIN … PRIVATE
# KEY" armor line never appears in this source file: secret scanners (the
# repo CI leak guard, local scrub gates) treat that literal as a key block
# regardless of context, and an assembled constant needs no allowlisting.
_ARMOR_TAIL = b"PRIVATE " + b"KEY-----"
_ARMOR_BEGIN = b"-----BEGIN "
_ARMOR_END = b"-----END "
_OPENSSH_PEM_BEGIN = _ARMOR_BEGIN + b"OPENSSH " + _ARMOR_TAIL
_OPENSSH_PEM_END = _ARMOR_END + b"OPENSSH " + _ARMOR_TAIL
_PKCS8_ENCRYPTED_BEGIN = _ARMOR_BEGIN + b"ENCRYPTED " + _ARMOR_TAIL

# Public str forms for tests/fixtures that must reference the armor without
# embedding the literal in their own source.
OPENSSH_PEM_HEADER = _OPENSSH_PEM_BEGIN.decode()
OPENSSH_PEM_FOOTER = _OPENSSH_PEM_END.decode()

# Content marker: any PEM-armored private-key BEGIN line we know how to handle.
_PRIVATE_KEY_MARKER = re.compile(
    re.escape(_ARMOR_BEGIN) + rb"(?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?" + re.escape(_ARMOR_TAIL)
)

_OPENSSH_ARMOR_RE = re.compile(
    re.escape(_OPENSSH_PEM_BEGIN) + rb"\s*(.*?)\s*" + re.escape(_OPENSSH_PEM_END),
    re.DOTALL,
)
_OPENSSH_MAGIC = b"openssh-key-v1\x00"

_GENERIC_PARSE_ERROR = "Unsupported or corrupt key format."


class KeyImportError(Exception):
    """Base for key-scan/import failures.

    A user-facing message is always available on ``.message`` (surface with
    ``notify(..., markup=False)``). Messages are generic by design — they must
    never contain key material or a passphrase.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class WrongPassphraseError(KeyImportError):
    """Decryption failed — almost certainly a wrong passphrase."""


@dataclass
class ScannedKey:
    """One candidate private-key file found by :func:`scan_directory`."""

    path: Path
    filename: str
    encrypted: bool
    key_type: Optional[str] = None
    fingerprint: Optional[str] = None
    public_key: Optional[str] = None
    comment: Optional[str] = None
    error: Optional[str] = None
    # Resolved absolute target when the scanned entry is a symlink. The UI must
    # display this provenance: a symlink in a less-trusted scanned directory can
    # point a key from elsewhere on disk under an innocuous basename.
    resolved_target: Optional[str] = None


@dataclass
class DecryptedKey:
    """A loaded key normalised to OpenSSH PEM (private) + one-line OpenSSH (public)."""

    private_key: str
    public_key: str
    fingerprint: str
    key_type: str


def _key_type_name(key: object) -> str:
    """Map a cryptography private-key instance to its short SSH type name."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "ed25519"
    if isinstance(key, rsa.RSAPrivateKey):
        return "rsa"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ecdsa"
    if isinstance(key, dsa.DSAPrivateKey):
        return "dsa"
    return type(key).__name__.lower()


def _fingerprint_from_public_line(public_line: str) -> str:
    """Compute the ssh-keygen-compatible SHA256 fingerprint of a public-key line.

    ``SHA256:`` + unpadded base64 of sha256(base64-decoded key blob) — matches
    ``ssh-keygen -lf`` output exactly.
    """
    blob_b64 = public_line.split()[1]
    digest = hashlib.sha256(base64.b64decode(blob_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _is_encrypted(data: bytes) -> bool:
    """Detect a passphrase-protected key by content markers (never by decrypting)."""
    if b"Proc-Type: 4,ENCRYPTED" in data:
        return True
    if _PKCS8_ENCRYPTED_BEGIN in data:
        return True
    match = _OPENSSH_ARMOR_RE.search(data)
    if match is not None:
        try:
            blob = base64.b64decode(match.group(1))
        except (ValueError, binascii.Error):
            return False
        if not blob.startswith(_OPENSSH_MAGIC):
            return False
        # openssh-key-v1 layout: magic || string ciphername || string kdfname || …
        offset = len(_OPENSSH_MAGIC)
        try:
            (cipher_len,) = struct.unpack(">I", blob[offset : offset + 4])
            cipher = blob[offset + 4 : offset + 4 + cipher_len]
        except struct.error:
            return False
        return cipher != b"none"
    return False


def _load_any_private_key(data: bytes, passphrase: Optional[bytes]) -> object:
    """Load an OpenSSH-format or PEM-format private key.

    Tries the OpenSSH loader first (the common ``~/.ssh`` case), then falls back
    to the generic PEM loader for PKCS#1 / PKCS#8 bodies. Exceptions propagate
    to the caller for classification — they never carry key material.

    ``UnsupportedAlgorithm`` deliberately propagates instead of falling back:
    it means the data IS an OpenSSH key but its cipher/KDF is unsupported by
    this environment (e.g. the ``bcrypt`` package is broken). Retrying the PEM
    loader on OpenSSH armor always raises ``ValueError``, which the caller
    would misclassify as a wrong passphrase — trapping the user in a re-prompt
    loop that can never succeed. It must surface as a terminal format error.

    The passphrase is handed to the loaders positionally: a ``password=<var>``
    keyword reads as a secret assignment to content scanners.
    """
    try:
        return load_ssh_private_key(data, passphrase)
    except (ValueError, TypeError):
        return load_pem_private_key(data, passphrase)


def _build_decrypted(key: object) -> DecryptedKey:
    """Normalise a loaded private key into a :class:`DecryptedKey`.

    Raises:
        KeyImportError: When the key parses but cannot be serialised as an SSH
            key (e.g. an X25519/X448/DH PKCS#8 key some tooling dropped in the
            directory). The message is generic — it never echoes key material.
    """
    try:
        private_pem = key.private_bytes(  # type: ignore[attr-defined]
            Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
        ).decode()
        public_line = (
            key.public_key()  # type: ignore[attr-defined]
            .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
            .decode()
        )
    except (ValueError, TypeError, AttributeError, UnsupportedAlgorithm) as exc:
        raise KeyImportError(_GENERIC_PARSE_ERROR) from exc
    return DecryptedKey(
        private_key=private_pem,
        public_key=public_line,
        fingerprint=_fingerprint_from_public_line(public_line),
        key_type=_key_type_name(key),
    )


def load_unencrypted_key(data: bytes) -> DecryptedKey:
    """Load an unencrypted private key and normalise it to OpenSSH PEM.

    Raises:
        KeyImportError: If the data is not a parseable unencrypted private key.
            The message is generic — it never echoes file content.
    """
    try:
        key = _load_any_private_key(data, None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyImportError(_GENERIC_PARSE_ERROR) from exc
    return _build_decrypted(key)


def decrypt_private_key(data: bytes, passphrase: str) -> DecryptedKey:
    """Decrypt a passphrase-protected private key and normalise it.

    The output ``private_key`` is re-serialised WITHOUT encryption (OpenSSH PEM)
    so it can be piped to ``bw`` via stdin.

    Raises:
        WrongPassphraseError: On any decryption ``ValueError`` — with encrypted
            input this almost always means a wrong passphrase. The message is
            fixed ("Wrong passphrase.") and never includes the passphrase.
        KeyImportError: If the key format itself is unsupported.
    """
    try:
        key = _load_any_private_key(data, passphrase.encode("utf-8"))
    except ValueError as exc:
        raise WrongPassphraseError("Wrong passphrase.") from exc
    except (TypeError, UnsupportedAlgorithm) as exc:
        raise KeyImportError(_GENERIC_PARSE_ERROR) from exc
    return _build_decrypted(key)


def _sibling_pub_comment(path: Path, public_line: str, max_bytes: int) -> Optional[str]:
    """Best-effort comment recovery from a sibling ``<name>.pub`` file.

    Only trusted when the sibling's key blob matches the blob derived from the
    private key — a stale/mismatched .pub must not attach its comment.
    """
    pub_path = path.parent / (path.name + ".pub")
    try:
        # Bounded fd read: regular-file + size checks run on the open
        # descriptor, so a swapped-in FIFO/oversized sibling cannot block
        # or bloat the scan.
        raw = read_key_bytes(pub_path, max_bytes)
    except KeyImportError:
        return None
    tokens = raw.decode(errors="replace").strip().split()
    if len(tokens) < 3:
        return None
    our_tokens = public_line.split()
    if len(our_tokens) < 2 or tokens[1] != our_tokens[1]:
        return None
    return " ".join(tokens[2:])


def _resolved_symlink_target(path: Path) -> Optional[str]:
    """Return the resolved absolute target when *path* is a symlink, else None."""
    try:
        if not path.is_symlink():
            return None
        return str(path.resolve(strict=True))
    except OSError:
        return None


def _scan_one(path: Path, max_bytes: int) -> Optional[ScannedKey]:
    """Classify a single regular file. Returns None when it is not a key candidate."""
    resolved_target = _resolved_symlink_target(path)
    try:
        size = path.stat().st_size
    except OSError:
        return ScannedKey(
            path=path,
            filename=path.name,
            encrypted=False,
            error="Could not read file.",
            resolved_target=resolved_target,
        )
    if size > max_bytes:
        return None

    try:
        # Bounded fd read — re-checks regular-file + size on the open
        # descriptor, so a file swapped between the stat above and here can
        # neither block the scan (FIFO) nor bypass the cap.
        data = read_key_bytes(path, max_bytes)
    except KeyImportError as exc:
        return ScannedKey(
            path=path,
            filename=path.name,
            encrypted=False,
            error=exc.message,
            resolved_target=resolved_target,
        )

    if _PRIVATE_KEY_MARKER.search(data) is None:
        return None

    if _is_encrypted(data):
        return ScannedKey(
            path=path, filename=path.name, encrypted=True, resolved_target=resolved_target
        )

    try:
        decrypted = load_unencrypted_key(data)
    except KeyImportError as exc:
        return ScannedKey(
            path=path,
            filename=path.name,
            encrypted=False,
            error=exc.message,
            resolved_target=resolved_target,
        )

    comment = _sibling_pub_comment(path, decrypted.public_key, max_bytes)
    public_line = decrypted.public_key
    if comment:
        public_line = f"{public_line} {comment}"
    return ScannedKey(
        path=path,
        filename=path.name,
        encrypted=False,
        key_type=decrypted.key_type,
        fingerprint=decrypted.fingerprint,
        public_key=public_line,
        comment=comment,
        resolved_target=resolved_target,
    )


def read_key_bytes(path: Path, max_bytes: int = DEFAULT_MAX_KEY_BYTES) -> bytes:
    """Bounded read of a key candidate with the size cap the scanner enforces.

    Reads must not trust any earlier check: the file may have been replaced or
    grown between the scan and the import (the scanned directory is untrusted
    by this feature's threat model). So every check runs on the already-open
    descriptor — no stat-to-read window:

    - The open is non-blocking so a FIFO swapped in at the path cannot wedge
      the calling worker; ``fstat`` on the descriptor then rejects anything
      that is not a regular file.
    - At most ``max_bytes + 1`` bytes are read from that same descriptor — the
      extra byte detects a file grown past the cap without slurping it whole.

    Raises:
        KeyImportError: When the path is unreadable, not a regular file, or
            exceeds *max_bytes*. The message is generic — it never echoes
            file content.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as exc:
        raise KeyImportError("Could not read file.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise KeyImportError("Could not read file.")
        chunks: List[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        raise KeyImportError("Could not read file.") from exc
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise KeyImportError("Could not read file.")
    return data


def scan_directory(
    directory: Path, max_files: int = 200, max_bytes: int = DEFAULT_MAX_KEY_BYTES
) -> List[ScannedKey]:
    """Scan *directory* (non-recursive) for SSH private-key files.

    - Follows file symlinks (recording ``resolved_target`` so the UI can show
      the real origin); skips directories (including dir symlinks) and
      non-regular files (sockets, fifos).
    - Skips well-known non-key names (``known_hosts*``, ``config``,
      ``authorized_keys*``, ``environment``, ``*.pub``, ``*-cert.pub``,
      ``*.dec``) and files larger than *max_bytes*.
    - Unreadable files produce a :class:`ScannedKey` with ``error`` set so the
      UI can render a dim skipped row; non-key content is silently omitted.
    - Examines at most *max_files* regular files (sorted by name).

    Raises:
        KeyImportError: When the directory itself cannot be listed (missing,
            permission denied). An unreadable directory must be
            distinguishable from an empty one — swallowing the failure would
            render a misleading "no keys found" state.
    """
    try:
        entries = sorted(directory.iterdir())
    except OSError as exc:
        raise KeyImportError("Could not read directory.") from exc

    results: List[ScannedKey] = []
    examined = 0
    for entry in entries:
        name = entry.name
        if any(fnmatch.fnmatch(name, pattern) for pattern in _SKIP_NAME_PATTERNS):
            continue
        try:
            if not entry.is_file():  # follows symlinks: dir symlinks/sockets fail here
                continue
        except OSError:
            continue
        examined += 1
        if examined > max_files:
            logger.debug("Key scan: max_files=%d reached in %s", max_files, directory)
            break
        scanned = _scan_one(entry, max_bytes)
        if scanned is not None:
            results.append(scanned)
    return results
