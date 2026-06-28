"""Tests for services/memory/passphrase_store.py.

Covers:
- keyring_available returns False when keyring package is absent.
- keyring_available returns False when the backend is the fail/null backend.
- keyring_available returns True for a real backend.
- store/get/clear round-trip with a mocked keyring backend.
- All public functions swallow exceptions and never raise.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_keyring_module(
    *,
    backend_module: str = "keyring.backends.kwallet",
    set_password_exc: Optional[Exception] = None,
    get_password_return: Optional[str] = "secret123",
    get_password_exc: Optional[Exception] = None,
    delete_password_exc: Optional[Exception] = None,
):
    """Return a minimal keyring module stub."""
    # Create a dynamic class whose __module__ is the desired backend path so
    # that passphrase_store.keyring_available()'s `type(backend).__module__`
    # check works correctly.
    BackendClass = type("Keyring", (), {"__module__": backend_module})
    backend = BackendClass()

    kr = MagicMock()
    kr.get_keyring.return_value = backend

    if set_password_exc is not None:
        kr.set_password = MagicMock(side_effect=set_password_exc)
    else:
        kr.set_password = MagicMock()

    if get_password_exc is not None:
        kr.get_password = MagicMock(side_effect=get_password_exc)
    else:
        kr.get_password = MagicMock(return_value=get_password_return)

    if delete_password_exc is not None:
        kr.delete_password = MagicMock(side_effect=delete_password_exc)
    else:
        kr.delete_password = MagicMock()

    return kr


def _import_store_fresh():
    """Import passphrase_store with a fresh module state (bypasses module cache)."""
    import importlib
    import servonaut.services.memory.passphrase_store as ps
    importlib.reload(ps)
    return ps


# ---------------------------------------------------------------------------
# keyring_available
# ---------------------------------------------------------------------------


class TestKeychainAvailable:
    def test_unavailable_when_keyring_absent(self) -> None:
        """When keyring is not installed, keyring_available must return False."""
        import servonaut.services.memory.passphrase_store as ps
        with patch.object(ps, "_HAS_KEYRING", False), patch.object(ps, "_keyring", None):
            assert ps.keyring_available() is False

    def test_unavailable_when_fail_backend(self) -> None:
        """keyring.backends.fail.Keyring backend → unavailable."""
        kr = _make_keyring_module(backend_module="keyring.backends.fail")
        import servonaut.services.memory.passphrase_store as ps
        with patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr):
            assert ps.keyring_available() is False

    def test_unavailable_when_null_backend(self) -> None:
        """keyring.backends.null.Keyring backend → unavailable."""
        kr = _make_keyring_module(backend_module="keyring.backends.null")
        import servonaut.services.memory.passphrase_store as ps
        with patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr):
            assert ps.keyring_available() is False

    def test_available_when_real_backend(self) -> None:
        """A real (non-fail, non-null) backend → available."""
        kr = _make_keyring_module(backend_module="keyring.backends.SecretService")
        import servonaut.services.memory.passphrase_store as ps
        with patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr):
            assert ps.keyring_available() is True

    def test_unavailable_when_get_keyring_raises(self) -> None:
        """If get_keyring() raises, available returns False without propagating."""
        kr = MagicMock()
        kr.get_keyring.side_effect = RuntimeError("keyring daemon not running")
        import servonaut.services.memory.passphrase_store as ps
        with patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr):
            assert ps.keyring_available() is False


# ---------------------------------------------------------------------------
# store / get / clear round-trip
# ---------------------------------------------------------------------------


class TestStoreGetClear:
    def _with_real_backend(self):
        """Context manager that patches in a real-ish keyring backend."""
        import servonaut.services.memory.passphrase_store as ps
        kr = _make_keyring_module(backend_module="keyring.backends.SecretService")
        return patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr), kr

    def test_store_returns_true_on_success(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        kr = _make_keyring_module(backend_module="keyring.backends.SecretService")
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            result = ps.store_passphrase("my-passphrase")
        assert result is True
        kr.set_password.assert_called_once_with(
            "servonaut-memory-sync", "default", "my-passphrase"
        )

    def test_get_returns_stored_value(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        kr = _make_keyring_module(
            backend_module="keyring.backends.SecretService",
            get_password_return="my-passphrase",
        )
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            result = ps.get_passphrase()
        assert result == "my-passphrase"
        kr.get_password.assert_called_once_with(
            "servonaut-memory-sync", "default"
        )

    def test_clear_calls_delete(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        kr = _make_keyring_module(backend_module="keyring.backends.SecretService")
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            ps.clear_passphrase()
        kr.delete_password.assert_called_once_with(
            "servonaut-memory-sync", "default"
        )

    def test_store_returns_false_when_unavailable(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        with patch.object(ps, "_HAS_KEYRING", False), patch.object(ps, "_keyring", None):
            assert ps.store_passphrase("pw") is False

    def test_get_returns_none_when_unavailable(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        with patch.object(ps, "_HAS_KEYRING", False), patch.object(ps, "_keyring", None):
            assert ps.get_passphrase() is None

    def test_clear_noop_when_unavailable(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        with patch.object(ps, "_HAS_KEYRING", False), patch.object(ps, "_keyring", None):
            ps.clear_passphrase()  # Must not raise


# ---------------------------------------------------------------------------
# Exception swallowing
# ---------------------------------------------------------------------------


class TestExceptionSwallowing:
    def test_store_swallows_set_password_error(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        kr = _make_keyring_module(
            backend_module="keyring.backends.SecretService",
            set_password_exc=OSError("keychain locked"),
        )
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            result = ps.store_passphrase("pw")
        assert result is False  # Never raises, returns False

    def test_get_swallows_get_password_error(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        kr = _make_keyring_module(
            backend_module="keyring.backends.SecretService",
            get_password_exc=PermissionError("denied"),
        )
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            result = ps.get_passphrase()
        assert result is None  # Never raises, returns None

    def test_clear_swallows_delete_error(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        kr = _make_keyring_module(
            backend_module="keyring.backends.SecretService",
            delete_password_exc=OSError("not found"),
        )
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            ps.clear_passphrase()  # Must not raise


# ---------------------------------------------------------------------------
# M10: keyring_available ALLOWLIST — known-good backends are accepted,
# unknown/dummy backends are rejected
# ---------------------------------------------------------------------------


class TestKeyringAllowlist:
    """Verify the allowlist-based keyring_available() logic.

    An unknown backend (fail, null, or an arbitrary third-party module)
    must be rejected so we never silently lose a stored passphrase.
    """

    def _available_for(self, backend_module: str) -> bool:
        import servonaut.services.memory.passphrase_store as ps
        kr = _make_keyring_module(backend_module=backend_module)
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            return ps.keyring_available()

    # --- Accepted backends ---

    def test_secretservice_accepted(self) -> None:
        assert self._available_for("keyring.backends.SecretService") is True

    def test_secretservice_lowercase_accepted(self) -> None:
        assert self._available_for("keyring.backends.secretservice") is True

    def test_kwallet_accepted(self) -> None:
        assert self._available_for("keyring.backends.kwallet") is True

    def test_macos_accepted(self) -> None:
        assert self._available_for("keyring.backends.macOS") is True

    def test_windows_accepted(self) -> None:
        assert self._available_for("keyring.backends.Windows") is True

    def test_credential_locker_accepted(self) -> None:
        assert self._available_for("keyring.backends.CredentialLocker") is True

    def test_chainer_accepted(self) -> None:
        assert self._available_for("keyring.backends.chainer") is True

    # --- Rejected backends ---

    def test_fail_backend_rejected(self) -> None:
        assert self._available_for("keyring.backends.fail") is False

    def test_null_backend_rejected(self) -> None:
        assert self._available_for("keyring.backends.null") is False

    def test_unknown_third_party_rejected(self) -> None:
        assert self._available_for("some.third_party.KeyringBackend") is False

    def test_empty_module_rejected(self) -> None:
        assert self._available_for("") is False
