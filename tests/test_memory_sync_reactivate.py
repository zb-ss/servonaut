"""Tests for the Memory Sync startup reactivation path in ServonautApp.

Strategy: same duck-typed stub pattern as test_app_fleet_auto_scan.py —
we bind the unbound async method onto a minimal SimpleNamespace that
provides exactly the attributes the method reads, then drive it directly
with pytest-asyncio.

Covers:
- _reactivate_memory_sync no-ops when sync service is None.
- _reactivate_memory_sync no-ops when already configured.
- _reactivate_memory_sync no-ops when not enrolled locally.
- _reactivate_memory_sync no-ops when not authenticated.
- _reactivate_memory_sync no-ops when memory_sync feature absent.
- Silent path calls bootstrap with a keychain provider when
  sync_remember_device=True + keychain available + passphrase present.
- Silent path clears keychain on failure then falls through to prompt.
- Prompt-cancel (RuntimeError from bootstrap) is swallowed (no crash).
- Successful bootstrap calls _propagate_memory_key_material + _start_memory_sync_loop
  (indirectly — we just verify bootstrap_memory_cloud is called).
"""

from __future__ import annotations

import asyncio
import types
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig, MemoryConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_memory_config(*, sync_remember_device: bool = False) -> MemoryConfig:
    return MemoryConfig(sync_remember_device=sync_remember_device)


def _make_config(memory: MemoryConfig) -> AppConfig:
    return AppConfig(memory=memory)


def _make_sync_service(
    *,
    is_configured: bool = False,
    enrolled_locally: bool = True,
) -> MagicMock:
    svc = MagicMock()
    svc.is_configured = is_configured
    svc.is_enrolled_locally = MagicMock(return_value=enrolled_locally)
    return svc


def _make_auth_service(
    *,
    is_authenticated: bool = True,
    has_memory_sync: bool = True,
) -> MagicMock:
    auth = MagicMock()
    auth.is_authenticated = is_authenticated
    auth.has_feature = MagicMock(
        side_effect=lambda slug: has_memory_sync if slug == "memory_sync" else False
    )
    return auth


def _make_stub(
    *,
    sync_service=None,
    auth_service=None,
    memory_config: MemoryConfig | None = None,
    bootstrap_side_effect=None,
) -> SimpleNamespace:
    if memory_config is None:
        memory_config = _make_memory_config()
    config = _make_config(memory_config)

    config_manager = MagicMock()
    config_manager.get = MagicMock(return_value=config)
    config_manager.update = MagicMock()

    stub = SimpleNamespace(
        memory_sync_service=sync_service,
        auth_service=auth_service,
        config_manager=config_manager,
        notify=MagicMock(),
    )

    # bootstrap_memory_cloud is always async
    if bootstrap_side_effect is not None:
        stub.bootstrap_memory_cloud = AsyncMock(side_effect=bootstrap_side_effect)
    else:
        stub.bootstrap_memory_cloud = AsyncMock(return_value=None)

    # Bind the real helper methods that the orchestration coroutines call on
    # ``self`` (the silent-unlock path was extracted out of the single
    # reactivation method into these helpers).
    stub._try_silent_memory_unlock = types.MethodType(
        ServonautApp._try_silent_memory_unlock, stub
    )
    stub._clear_remember_device = types.MethodType(
        ServonautApp._clear_remember_device, stub
    )
    stub._remember_passphrase_expired = types.MethodType(
        ServonautApp._remember_passphrase_expired, stub
    )

    return stub


async def _run_reactivate(stub: SimpleNamespace) -> None:
    """Drive the SILENT-only startup reactivation (no modal)."""
    await ServonautApp._reactivate_memory_sync(stub)  # type: ignore[arg-type]


async def _run_prompt(stub: SimpleNamespace) -> None:
    """Drive the contextual unlock (silent then modal prompt)."""
    await ServonautApp.prompt_memory_sync_unlock(stub)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Guard conditions — must be no-ops
# ---------------------------------------------------------------------------


class TestReactivateGuards:
    @pytest.mark.asyncio
    async def test_noop_when_sync_service_is_none(self) -> None:
        stub = _make_stub(sync_service=None)
        await _run_reactivate(stub)
        stub.bootstrap_memory_cloud.assert_not_called()

    @pytest.mark.asyncio
    async def test_noop_when_already_configured(self) -> None:
        sync = _make_sync_service(is_configured=True)
        stub = _make_stub(sync_service=sync, auth_service=_make_auth_service())
        await _run_reactivate(stub)
        stub.bootstrap_memory_cloud.assert_not_called()

    @pytest.mark.asyncio
    async def test_noop_when_not_enrolled_locally(self) -> None:
        sync = _make_sync_service(is_configured=False, enrolled_locally=False)
        stub = _make_stub(sync_service=sync, auth_service=_make_auth_service())
        await _run_reactivate(stub)
        stub.bootstrap_memory_cloud.assert_not_called()

    @pytest.mark.asyncio
    async def test_noop_when_not_authenticated(self) -> None:
        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service(is_authenticated=False)
        stub = _make_stub(sync_service=sync, auth_service=auth)
        await _run_reactivate(stub)
        stub.bootstrap_memory_cloud.assert_not_called()

    @pytest.mark.asyncio
    async def test_noop_when_no_memory_sync_feature(self) -> None:
        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service(has_memory_sync=False)
        stub = _make_stub(sync_service=sync, auth_service=auth)
        await _run_reactivate(stub)
        stub.bootstrap_memory_cloud.assert_not_called()

    @pytest.mark.asyncio
    async def test_noop_when_auth_service_is_none(self) -> None:
        sync = _make_sync_service(enrolled_locally=True)
        stub = _make_stub(sync_service=sync, auth_service=None)
        await _run_reactivate(stub)
        stub.bootstrap_memory_cloud.assert_not_called()


# ---------------------------------------------------------------------------
# Silent path (keychain)
# ---------------------------------------------------------------------------


class TestSilentPath:
    @pytest.mark.asyncio
    async def test_silent_path_calls_bootstrap_with_keychain_provider(self) -> None:
        """When remember=True and keychain has passphrase, bootstrap is called
        with a provider that returns the stored passphrase (no modal)."""
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        mem_cfg = _make_memory_config(sync_remember_device=True)
        stub = _make_stub(sync_service=sync, auth_service=auth, memory_config=mem_cfg)

        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(
                ps,
                "_keyring",
                _make_fake_keyring(backend_module="keyring.backends.SecretService", pw="my-pw"),
            ),
        ):
            await _run_reactivate(stub)

        stub.bootstrap_memory_cloud.assert_called_once()
        # The provider was passed as a keyword arg — verify it's not None
        _, kwargs = stub.bootstrap_memory_cloud.call_args
        assert kwargs.get("passphrase_provider") is not None
        # The provider is an async callable that returns the stored passphrase
        provider = kwargs["passphrase_provider"]
        pw_returned = await provider("unlock")
        assert pw_returned == "my-pw"

    @pytest.mark.asyncio
    async def test_silent_path_skipped_when_keychain_unavailable(self) -> None:
        """When keychain is unavailable, the silent path is skipped.

        Driven through the contextual unlock (``prompt_memory_sync_unlock``):
        the silent attempt finds no keychain, so the modal prompt runs with
        NO keychain provider.
        """
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        mem_cfg = _make_memory_config(sync_remember_device=True)
        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            memory_config=mem_cfg,
            # bootstrap raises RuntimeError to simulate user cancel on the prompt
            bootstrap_side_effect=RuntimeError("cancelled"),
        )

        with patch.object(ps, "_HAS_KEYRING", False), patch.object(ps, "_keyring", None):
            await _run_prompt(stub)

        # bootstrap_memory_cloud WAS called (the prompt path), not with a
        # keychain provider but with no args (falls back to modal prompt).
        stub.bootstrap_memory_cloud.assert_called_once()
        _, kwargs = stub.bootstrap_memory_cloud.call_args
        # No passphrase_provider means the prompt path ran
        assert kwargs.get("passphrase_provider") is None

    @pytest.mark.asyncio
    async def test_silent_path_clears_keychain_on_wrong_passphrase_then_prompts(
        self,
    ) -> None:
        """MAJOR-1: when can_unwrap_local returns False (wrong/stale passphrase),
        the keychain is cleared and the prompt path runs.

        Driven through ``prompt_memory_sync_unlock``: the silent attempt detects
        the stale passphrase locally (BEFORE any bootstrap), clears it, then the
        modal prompt runs.
        """
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True)
        # Simulate wrong/stale passphrase detected locally
        sync.can_unwrap_local = MagicMock(return_value=False)
        sync.clear_local_keypair_cache = MagicMock()
        auth = _make_auth_service()
        mem_cfg = _make_memory_config(sync_remember_device=True)

        call_count = 0

        async def _bootstrap_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            # can_unwrap_local=False means we skip silent bootstrap entirely.
            # The only call is from the prompt path, which the user cancels.
            raise RuntimeError("cancelled")

        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            memory_config=mem_cfg,
            bootstrap_side_effect=_bootstrap_side_effect,
        )

        kr = _make_fake_keyring(
            backend_module="keyring.backends.SecretService", pw="stale-pw"
        )

        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            await _run_prompt(stub)

        # Keychain was cleared (wrong passphrase detected locally)
        kr.delete_password.assert_called_once()
        # Cache was cleared
        sync.clear_local_keypair_cache.assert_called_once()
        # Only the prompt call reached bootstrap (silent path skipped)
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_silent_path_success_does_not_call_prompt(self) -> None:
        """If silent reactivation succeeds, the modal prompt is NOT shown."""
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        mem_cfg = _make_memory_config(sync_remember_device=True)
        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            memory_config=mem_cfg,
            # Silent bootstrap succeeds (returns None)
        )

        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(
                ps,
                "_keyring",
                _make_fake_keyring(backend_module="keyring.backends.SecretService", pw="pw"),
            ),
        ):
            await _run_reactivate(stub)

        # Only ONE bootstrap call (the silent one), not two
        stub.bootstrap_memory_cloud.assert_called_once()


# ---------------------------------------------------------------------------
# Prompt path
# ---------------------------------------------------------------------------


class TestPromptPath:
    @pytest.mark.asyncio
    async def test_prompt_cancel_is_swallowed_no_crash(self) -> None:
        """RuntimeError from bootstrap (user cancel) must not propagate."""
        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            bootstrap_side_effect=RuntimeError("Memory keypair unlock cancelled by user"),
        )
        # Must not raise
        await _run_prompt(stub)
        stub.bootstrap_memory_cloud.assert_called_once()

    @pytest.mark.asyncio
    async def test_prompt_cancel_shows_info_notify(self) -> None:
        """A cancel leaves a brief info notification (not an error)."""
        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            bootstrap_side_effect=RuntimeError("cancelled"),
        )
        await _run_prompt(stub)
        stub.notify.assert_called()
        # severity must not be "error"
        for call_args in stub.notify.call_args_list:
            kw = call_args.kwargs
            assert kw.get("severity", "information") != "error", (
                f"Expected non-error notify on cancel, got severity={kw.get('severity')}"
            )

    @pytest.mark.asyncio
    async def test_non_runtime_error_is_swallowed(self) -> None:
        """Other exceptions (network errors etc.) are also swallowed."""
        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            bootstrap_side_effect=IOError("connection failed"),
        )
        await _run_prompt(stub)
        # Must not raise

    @pytest.mark.asyncio
    async def test_prompt_path_success_sends_no_error_notify(self) -> None:
        """Successful prompt-path reactivation does not produce an error notify."""
        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        stub = _make_stub(sync_service=sync, auth_service=auth)
        await _run_prompt(stub)
        for call_args in stub.notify.call_args_list:
            kw = call_args.kwargs
            assert kw.get("severity", "information") != "error"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_keyring(*, backend_module: str, pw: str | None = "pw"):
    """Return a minimal keyring module stub with a known backend module.

    Uses a dynamically-created class so that ``type(backend).__module__``
    returns *backend_module* — SimpleNamespace is an immutable type and
    does not allow setting ``__module__`` on its type object.
    """
    BackendClass = type("Keyring", (), {"__module__": backend_module})
    backend = BackendClass()

    kr = MagicMock()
    kr.get_keyring.return_value = backend
    kr.get_password = MagicMock(return_value=pw)
    kr.set_password = MagicMock()
    kr.delete_password = MagicMock()
    return kr


# ---------------------------------------------------------------------------
# MAJOR-1: silent-path — wrong passphrase clears, network error does NOT clear
# ---------------------------------------------------------------------------


class TestSilentPathMajor1:
    @pytest.mark.asyncio
    async def test_wrong_passphrase_clears_keychain_and_flag(self) -> None:
        """When can_unwrap_local returns False (wrong passphrase), the keychain
        entry and the sync_remember_device flag must be cleared."""
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True)
        sync.can_unwrap_local = MagicMock(return_value=False)
        sync.clear_local_keypair_cache = MagicMock()
        auth = _make_auth_service()
        mem_cfg = _make_memory_config(sync_remember_device=True)
        stub = _make_stub(sync_service=sync, auth_service=auth, memory_config=mem_cfg)
        # bootstrap is a RuntimeError (user cancel) if the prompt path runs
        stub.bootstrap_memory_cloud = AsyncMock(side_effect=RuntimeError("cancelled"))

        kr = _make_fake_keyring(
            backend_module="keyring.backends.SecretService", pw="stale-pw"
        )
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            await _run_reactivate(stub)

        # Keychain must be cleared (wrong passphrase)
        kr.delete_password.assert_called_once()
        # Local cache must be cleared
        sync.clear_local_keypair_cache.assert_called_once()
        # Config flag must be reset
        stub.config_manager.update.assert_called()

    @pytest.mark.asyncio
    async def test_network_error_after_valid_passphrase_does_not_clear(self) -> None:
        """When can_unwrap_local returns True (valid passphrase) but bootstrap
        fails with a network error, the keychain and flag must NOT be cleared."""
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True, is_configured=False)
        sync.can_unwrap_local = MagicMock(return_value=True)
        sync.clear_local_keypair_cache = MagicMock()
        auth = _make_auth_service()
        mem_cfg = _make_memory_config(sync_remember_device=True)
        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            memory_config=mem_cfg,
            # Simulate a network error AFTER can_unwrap_local returned True
            bootstrap_side_effect=IOError("connection refused"),
        )

        kr = _make_fake_keyring(
            backend_module="keyring.backends.SecretService", pw="valid-pw"
        )
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            await _run_reactivate(stub)

        # Bootstrap was called once (silent path)
        stub.bootstrap_memory_cloud.assert_called_once()
        # Keychain must NOT be cleared (passphrase was valid)
        kr.delete_password.assert_not_called()
        # Local cache must NOT be cleared
        sync.clear_local_keypair_cache.assert_not_called()
        # Config update must NOT have cleared the flag
        for call_args in stub.config_manager.update.call_args_list:
            kw = call_args.kwargs
            mem = kw.get("memory") or (call_args.args[0] if call_args.args else None)
            if mem is not None:
                # If config was updated, the flag must NOT be False
                flag = getattr(mem, "sync_remember_device", True)
                assert flag is not False, (
                    "sync_remember_device must not be reset on a network error "
                    f"after valid passphrase; got memory={mem!r}"
                )

    @pytest.mark.asyncio
    async def test_valid_passphrase_does_not_fall_to_prompt(self) -> None:
        """When can_unwrap_local returns True and bootstrap succeeds, the modal
        prompt must NOT run (return early after success)."""
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True)
        sync.can_unwrap_local = MagicMock(return_value=True)
        auth = _make_auth_service()
        mem_cfg = _make_memory_config(sync_remember_device=True)
        stub = _make_stub(sync_service=sync, auth_service=auth, memory_config=mem_cfg)

        kr = _make_fake_keyring(
            backend_module="keyring.backends.SecretService", pw="valid-pw"
        )
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            await _run_reactivate(stub)

        # Exactly one call — the silent bootstrap; no second call for the prompt
        stub.bootstrap_memory_cloud.assert_called_once()


# ---------------------------------------------------------------------------
# Remember TTL — silent unlock refuses an expired passphrase
# ---------------------------------------------------------------------------


class TestRememberExpiry:
    @staticmethod
    def _iso(delta_days: int) -> str:
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) + timedelta(days=delta_days)).isoformat()

    def _stub(self, expires_at: str) -> SimpleNamespace:
        mem = MemoryConfig(
            sync_remember_device=True, sync_remember_expires_at=expires_at
        )
        return _make_stub(
            sync_service=_make_sync_service(enrolled_locally=True),
            auth_service=_make_auth_service(),
            memory_config=mem,
        )

    def test_expired_timestamp_is_expired(self) -> None:
        stub = self._stub(self._iso(-1))
        cfg = stub.config_manager.get()
        assert ServonautApp._remember_passphrase_expired(stub, cfg) is True

    def test_future_timestamp_is_not_expired(self) -> None:
        stub = self._stub(self._iso(10))
        cfg = stub.config_manager.get()
        assert ServonautApp._remember_passphrase_expired(stub, cfg) is False

    def test_empty_timestamp_is_not_expired_legacy(self) -> None:
        """Legacy enrolment (no expiry recorded) is treated as not-expired."""
        stub = self._stub("")
        cfg = stub.config_manager.get()
        assert ServonautApp._remember_passphrase_expired(stub, cfg) is False

    def test_malformed_timestamp_fails_open(self) -> None:
        stub = self._stub("not-a-timestamp")
        cfg = stub.config_manager.get()
        assert ServonautApp._remember_passphrase_expired(stub, cfg) is False

    @pytest.mark.asyncio
    async def test_silent_unlock_clears_keychain_when_expired(self) -> None:
        """An expired remembered passphrase is cleared and NOT used to bootstrap.

        Even though ``can_unwrap_local`` would succeed, the expiry check runs
        first so no silent bootstrap happens and the keychain entry is purged.
        """
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True)
        sync.can_unwrap_local = MagicMock(return_value=True)
        stub = self._stub(self._iso(-1))
        stub.memory_sync_service = sync
        # rebind helpers to the new sync service-bearing stub fields
        kr = _make_fake_keyring(
            backend_module="keyring.backends.SecretService", pw="old-pw"
        )
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            await _run_reactivate(stub)

        kr.delete_password.assert_called_once()
        stub.bootstrap_memory_cloud.assert_not_called()
        sync.can_unwrap_local.assert_not_called()
        stub.config_manager.update.assert_called()


# ---------------------------------------------------------------------------
# Remember TTL — _prompt_memory_passphrase stamps an expiry when remembering
# ---------------------------------------------------------------------------


class TestPromptStampsExpiry:
    @pytest.mark.asyncio
    async def test_remember_stores_passphrase_and_stamps_expiry(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        from servonaut.screens.memory_keys import PassphraseResult

        cfg = AppConfig(memory=MemoryConfig())
        cm = MagicMock()
        cm.get = MagicMock(return_value=cfg)
        cm.update = MagicMock()
        stub = SimpleNamespace(
            config_manager=cm,
            notify=MagicMock(),
            push_screen_wait=AsyncMock(
                return_value=PassphraseResult(passphrase="pw", remember=True)
            ),
        )
        kr = _make_fake_keyring(backend_module="keyring.backends.SecretService")
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            pw = await ServonautApp._prompt_memory_passphrase(stub)  # type: ignore[arg-type]

        assert pw == "pw"
        kr.set_password.assert_called_once()
        stamped = any(
            getattr(c.kwargs.get("memory"), "sync_remember_expires_at", "")
            for c in cm.update.call_args_list
            if c.kwargs.get("memory") is not None
        )
        assert stamped, "expected sync_remember_expires_at to be stamped on remember"

    @pytest.mark.asyncio
    async def test_remember_without_keychain_warns_and_does_not_persist(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        from servonaut.screens.memory_keys import PassphraseResult

        cfg = AppConfig(memory=MemoryConfig())
        cm = MagicMock()
        cm.get = MagicMock(return_value=cfg)
        cm.update = MagicMock()
        stub = SimpleNamespace(
            config_manager=cm,
            notify=MagicMock(),
            push_screen_wait=AsyncMock(
                return_value=PassphraseResult(passphrase="pw", remember=True)
            ),
        )
        with patch.object(ps, "_HAS_KEYRING", False), patch.object(ps, "_keyring", None):
            pw = await ServonautApp._prompt_memory_passphrase(stub)  # type: ignore[arg-type]

        assert pw == "pw"
        # No keychain → warn the user, do not flip the remember flag.
        stub.notify.assert_called()
        cm.update.assert_not_called()


# ---------------------------------------------------------------------------
# M4: stale sync_remember_device flag self-correction
# ---------------------------------------------------------------------------


class TestM4StaleFlagSelfCorrection:
    @pytest.mark.asyncio
    async def test_flag_cleared_when_keychain_unavailable(self) -> None:
        """When sync_remember_device=True but keychain is unavailable,
        the flag must be reset to False."""
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        mem_cfg = _make_memory_config(sync_remember_device=True)
        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            memory_config=mem_cfg,
            bootstrap_side_effect=RuntimeError("cancelled"),
        )

        with patch.object(ps, "_HAS_KEYRING", False), patch.object(ps, "_keyring", None):
            await _run_reactivate(stub)

        # Config must have been updated to clear the flag
        stub.config_manager.update.assert_called()

    @pytest.mark.asyncio
    async def test_flag_cleared_when_no_passphrase_stored(self) -> None:
        """When sync_remember_device=True and keychain is available but
        no passphrase is stored, the flag must be reset to False."""
        import servonaut.services.memory.passphrase_store as ps

        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        mem_cfg = _make_memory_config(sync_remember_device=True)
        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            memory_config=mem_cfg,
            bootstrap_side_effect=RuntimeError("cancelled"),
        )

        # Keychain available but empty (get_passphrase returns None)
        kr = _make_fake_keyring(backend_module="keyring.backends.SecretService", pw=None)
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            await _run_reactivate(stub)

        stub.config_manager.update.assert_called()


# ---------------------------------------------------------------------------
# M10: keyring_available allowlist
# ---------------------------------------------------------------------------


class TestKeychainAllowlist:
    def _check_available(self, backend_module: str) -> bool:
        import servonaut.services.memory.passphrase_store as ps
        kr = _make_fake_keyring(backend_module=backend_module)
        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            return ps.keyring_available()

    def test_secretservice_is_accepted(self) -> None:
        assert self._check_available("keyring.backends.SecretService") is True

    def test_secretservice_lowercase_is_accepted(self) -> None:
        assert self._check_available("keyring.backends.secretservice") is True

    def test_kwallet_is_accepted(self) -> None:
        assert self._check_available("keyring.backends.kwallet") is True

    def test_macos_is_accepted(self) -> None:
        assert self._check_available("keyring.backends.macOS") is True

    def test_windows_is_accepted(self) -> None:
        assert self._check_available("keyring.backends.Windows") is True

    def test_chainer_is_accepted(self) -> None:
        assert self._check_available("keyring.backends.chainer") is True

    def test_fail_backend_is_rejected(self) -> None:
        assert self._check_available("keyring.backends.fail") is False

    def test_null_backend_is_rejected(self) -> None:
        assert self._check_available("keyring.backends.null") is False

    def test_unknown_backend_is_rejected(self) -> None:
        assert self._check_available("some.unknown.backend") is False

    def test_empty_module_is_rejected(self) -> None:
        assert self._check_available("") is False


# ---------------------------------------------------------------------------
# M11: session skip — don't re-prompt after user cancels
# ---------------------------------------------------------------------------


class TestSessionSkipAfterCancel:
    @pytest.mark.asyncio
    async def test_no_reprompt_after_cancel_within_session(self) -> None:
        """If the user cancelled the modal in this session
        (_memory_sync_prompt_skipped=True), the prompt must not run again."""
        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        stub = _make_stub(sync_service=sync, auth_service=auth)
        # Simulate that the user already cancelled in this session
        stub._memory_sync_prompt_skipped = True

        await _run_prompt(stub)

        # bootstrap must NOT have been called
        stub.bootstrap_memory_cloud.assert_not_called()

    @pytest.mark.asyncio
    async def test_cancel_sets_skip_flag(self) -> None:
        """A RuntimeError from bootstrap (user cancel) must set
        _memory_sync_prompt_skipped=True on the stub."""
        sync = _make_sync_service(enrolled_locally=True)
        auth = _make_auth_service()
        stub = _make_stub(
            sync_service=sync,
            auth_service=auth,
            bootstrap_side_effect=RuntimeError("cancelled"),
        )
        assert not getattr(stub, "_memory_sync_prompt_skipped", False)

        await _run_prompt(stub)

        assert getattr(stub, "_memory_sync_prompt_skipped", False) is True


# ---------------------------------------------------------------------------
# MAJOR-2: logout clears cache + keychain + flag
# ---------------------------------------------------------------------------


class TestLogoutClearsMemorySyncState:
    def _make_app_stub(self, *, has_sync: bool = True) -> Any:
        """Build a minimal stub for on_user_logout."""
        from servonaut.config.schema import AppConfig, MemoryConfig
        import dataclasses as _dc

        memory_cfg = MemoryConfig(sync_remember_device=True)
        cfg = AppConfig(memory=memory_cfg)
        cm = MagicMock()
        cm.get = MagicMock(return_value=cfg)
        cm.update = MagicMock()

        sync = MagicMock()
        sync.lock = MagicMock()
        sync.clear_local_keypair_cache = MagicMock()

        stub = SimpleNamespace(
            config_sync_service=MagicMock(),
            config_manager=cm,
            memory_sync_service=sync if has_sync else None,
        )
        return stub

    def test_logout_clears_local_keypair_cache(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        stub = self._make_app_stub()
        kr = _make_fake_keyring(backend_module="keyring.backends.SecretService")
        with patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr):
            ServonautApp.on_user_logout(stub)  # type: ignore[arg-type]
        stub.memory_sync_service.clear_local_keypair_cache.assert_called_once()

    def test_logout_locks_in_memory_key(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        stub = self._make_app_stub()
        kr = _make_fake_keyring(backend_module="keyring.backends.SecretService")
        with patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr):
            ServonautApp.on_user_logout(stub)  # type: ignore[arg-type]
        stub.memory_sync_service.lock.assert_called_once()

    def test_logout_clears_keychain_passphrase(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        stub = self._make_app_stub()
        kr = _make_fake_keyring(backend_module="keyring.backends.SecretService")
        with patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr):
            ServonautApp.on_user_logout(stub)  # type: ignore[arg-type]
        kr.delete_password.assert_called_once()

    def test_logout_resets_remember_flag(self) -> None:
        import servonaut.services.memory.passphrase_store as ps
        stub = self._make_app_stub()
        kr = _make_fake_keyring(backend_module="keyring.backends.SecretService")
        with patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr):
            ServonautApp.on_user_logout(stub)  # type: ignore[arg-type]
        stub.config_manager.update.assert_called()

    def test_logout_noop_when_no_sync_service(self) -> None:
        """Logout must not crash when memory_sync_service is None."""
        import servonaut.services.memory.passphrase_store as ps
        stub = self._make_app_stub(has_sync=False)
        kr = _make_fake_keyring(backend_module="keyring.backends.SecretService")
        with patch.object(ps, "_HAS_KEYRING", True), patch.object(ps, "_keyring", kr):
            ServonautApp.on_user_logout(stub)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# MAJOR-3: _do_rotate with remember=True sets sync_remember_device=True
# ---------------------------------------------------------------------------


class TestRotateWithRemember:
    """Duck-type _do_rotate to verify MAJOR-3: when the user rotates their
    keypair and ticks "remember this device", config.memory.sync_remember_device
    is set to True in addition to storing the passphrase in the keychain.
    """

    def _make_screen_stub(self, *, remember: bool) -> SimpleNamespace:
        """Build a minimal duck-typed screen stub for ``_do_rotate``.

        ``_do_rotate`` reads: self.app.memory_sync_service, self.app.push_screen_wait,
        self.app.config_manager, self.app.notify, self._set_busy, self._clear_busy,
        self._show_setup_error, and self._render_state.
        """
        from servonaut.config.schema import AppConfig, MemoryConfig
        from servonaut.screens.memory_keys import PassphraseResult

        memory_cfg = MemoryConfig(sync_remember_device=False)
        cfg = AppConfig(memory=memory_cfg)
        cm = MagicMock()
        cm.get = MagicMock(return_value=cfg)
        cm.update = MagicMock()

        sync = MagicMock()
        sync.is_configured = True
        sync.rotate_keypair = AsyncMock()

        old_result = PassphraseResult(passphrase="old-pw", remember=False)
        new_result = PassphraseResult(passphrase="new-pw", remember=remember)

        app_stub = SimpleNamespace(
            memory_sync_service=sync,
            config_manager=cm,
            notify=MagicMock(),
            # push_screen_wait is called twice: first for old_result, then new_result
            push_screen_wait=AsyncMock(side_effect=[old_result, new_result]),
        )

        stub = SimpleNamespace(
            app=app_stub,
            _set_busy=MagicMock(),
            _clear_busy=MagicMock(),
            _show_setup_error=MagicMock(),
            _render_state=MagicMock(),
        )
        return stub

    @pytest.mark.asyncio
    async def test_rotate_with_remember_sets_config_flag(self) -> None:
        """MAJOR-3: rotate + remember=True must set sync_remember_device=True."""
        import servonaut.services.memory.passphrase_store as ps
        from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

        stub = self._make_screen_stub(remember=True)
        kr = _make_fake_keyring(backend_module="keyring.backends.SecretService")

        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            await MemorySyncSetupScreen._do_rotate(stub)  # type: ignore[arg-type]

        stub.app.config_manager.update.assert_called()
        # Find the call where sync_remember_device was set to True
        updated_to_true = any(
            getattr(
                c.kwargs.get("memory") or (c.args[0] if c.args else None),
                "sync_remember_device",
                None,
            ) is True
            for c in stub.app.config_manager.update.call_args_list
        )
        assert updated_to_true, (
            "Expected config_manager.update to set sync_remember_device=True on "
            f"rotate+remember. Calls: {stub.app.config_manager.update.call_args_list}"
        )

    @pytest.mark.asyncio
    async def test_rotate_without_remember_does_not_set_flag(self) -> None:
        """rotate + remember=False must NOT set sync_remember_device=True."""
        import servonaut.services.memory.passphrase_store as ps
        from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

        stub = self._make_screen_stub(remember=False)
        kr = _make_fake_keyring(backend_module="keyring.backends.SecretService")

        with (
            patch.object(ps, "_HAS_KEYRING", True),
            patch.object(ps, "_keyring", kr),
        ):
            await MemorySyncSetupScreen._do_rotate(stub)  # type: ignore[arg-type]

        # Either update was not called or it set flag to False (never True)
        for c in stub.app.config_manager.update.call_args_list:
            mem = c.kwargs.get("memory") or (c.args[0] if c.args else None)
            if mem is not None:
                flag = getattr(mem, "sync_remember_device", False)
                assert flag is not True, (
                    f"sync_remember_device must not be True when remember=False; "
                    f"got {flag!r}"
                )
