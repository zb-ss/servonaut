"""OS keychain wrapper for the Memory Sync passphrase (optional dep).

Provides a thin, always-safe API around ``keyring`` so callers never need to
guard against ``ImportError`` or backend failures.  All functions return
``False``/``None`` when keyring is unavailable rather than raising.

Only the passphrase is stored here.  The decrypted X25519 private key is
NEVER written to the keychain or to disk — it lives in RAM only.  The
passphrase-*encrypted* keypair material is cached separately in the local
``keys.json`` file managed by :class:`~servonaut.services.memory.sync_service.MemorySyncService`.

Keychain coordinates
--------------------
- Service name: ``"servonaut-memory-sync"``
- Account name: ``"default"`` (one passphrase per OS user)
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_SERVICE = "servonaut-memory-sync"
_ACCOUNT = "default"

# Lazy import: keyring is optional.  A hard ImportError at module load would
# crash the entire app even for users who have no keychain configured.
try:
    import keyring as _keyring  # type: ignore[import-untyped]
    _HAS_KEYRING = True
except Exception:
    _keyring = None  # type: ignore[assignment]
    _HAS_KEYRING = False


def keyring_available() -> bool:
    """Return ``True`` when a known-good OS keychain backend is available.

    Uses an ALLOWLIST of known-good backend module prefixes so that any
    new or third-party backend that doesn't actually persist secrets is
    rejected by default.  The previous DENYLIST approach (checking for
    ``"fail"``/``"null"`` substrings) could silently accept an unknown
    backend that looks legitimate but loses stored passwords.

    Trusted backends:
    - ``keyring.backends.SecretService`` / ``secretservice`` — GNOME / DBus (Linux)
    - ``keyring.backends.kwallet`` — KDE Wallet (Linux)
    - ``keyring.backends.macOS`` / ``Keyring`` — macOS system keychain
    - ``keyring.backends.Windows`` / ``CredentialLocker`` — Windows Credential Store
    - ``keyring.backends.chainer`` — chains multiple backends

    Any backend whose module does NOT start with one of these prefixes is
    treated as unavailable.  This is the conservative choice: a false negative
    means "no auto-unlock" while a false positive could silently lose the
    stored passphrase.
    """
    if not _HAS_KEYRING or _keyring is None:
        return False
    try:
        backend = _keyring.get_keyring()
        module = type(backend).__module__ or ""
        _ALLOWED_PREFIXES = (
            "keyring.backends.SecretService",
            "keyring.backends.secretservice",
            "keyring.backends.kwallet",
            "keyring.backends.macOS",
            "keyring.backends.Keyring",
            "keyring.backends.Windows",
            "keyring.backends.CredentialLocker",
            "keyring.backends.chainer",
        )
        return any(module.startswith(pfx) for pfx in _ALLOWED_PREFIXES)
    except Exception:
        return False


def store_passphrase(passphrase: str) -> bool:
    """Store *passphrase* in the OS keychain.

    Returns ``True`` on success, ``False`` on any error (including keyring
    not available).  Never raises.
    """
    if not keyring_available():
        return False
    try:
        _keyring.set_password(_SERVICE, _ACCOUNT, passphrase)
        return True
    except Exception as exc:
        logger.warning("passphrase_store.store_passphrase failed: %s", exc)
        return False


def get_passphrase() -> Optional[str]:
    """Retrieve the stored passphrase from the OS keychain.

    Returns the passphrase string, or ``None`` if nothing is stored or on
    any error.  Never raises.
    """
    if not keyring_available():
        return None
    try:
        return _keyring.get_password(_SERVICE, _ACCOUNT)
    except Exception as exc:
        logger.warning("passphrase_store.get_passphrase failed: %s", exc)
        return None


def clear_passphrase() -> None:
    """Remove the stored passphrase from the OS keychain.

    No-op if nothing is stored or if keyring is unavailable.  Never raises.
    """
    if not keyring_available():
        return
    try:
        _keyring.delete_password(_SERVICE, _ACCOUNT)
    except Exception:
        # Already absent or backend error — silently ignore.
        pass
