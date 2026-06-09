"""Tests for MemorySyncService — bootstrap flows, per-rejection state machine, queue."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from servonaut.services.api_client import (
    APIError,
    BatchTooLargeError,
    FeatureDisabledError,
    FeatureNotAvailableError,
    ForbiddenEntitlementError,
    NotFoundError,
    QuotaExceededError,
    RateLimitedError,
    ValidationFailedError,
)
from servonaut.services.memory.interfaces import (
    RESERVED_INSTANCE_IDS,
    BackendMaintenance,
    BetaWaitlist,
    MemorySyncStatus,
    MissingSelfWrap,
    ModuleResult,
    NoActiveKeypair,
    QuotaExceeded,
    ReservedInstanceIdError,
    SyncBatchResult,
    SyncEnvelope,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.memory.sync_service import MemorySyncService
from servonaut.services.memory.rate_limiter import RateLimiter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_api_client(
    get_return=None,
    post_return=None,
    get_side_effect=None,
    post_side_effect=None,
    patch_return=None,
    delete_return=None,
):
    """Build a minimal mock APIClient."""
    client = MagicMock()
    client.get = AsyncMock(return_value=get_return or {})
    client.post = AsyncMock(return_value=post_return or {})
    client.patch = AsyncMock(return_value=patch_return or {})
    client.delete = AsyncMock(return_value=delete_return or {})
    if get_side_effect is not None:
        client.get.side_effect = get_side_effect
    if post_side_effect is not None:
        client.post.side_effect = post_side_effect
    return client


def _make_crypto():
    """Return a minimal crypto stub."""
    crypto = MagicMock()
    return crypto


def _make_memory_service():
    ms = MagicMock()
    ms.is_memory_disabled.return_value = False
    ms.list_all.return_value = [
        {"instance_id": "web-01", "name": "web-01", "provider": "custom"},
    ]
    return ms


def _make_auth_service(user_id=42):
    auth = MagicMock()
    auth.fetch_user_id = AsyncMock(return_value=user_id)
    auth.user_id = user_id
    return auth


def _make_config_manager():
    cfg = MagicMock()
    inner = MagicMock()
    inner.connection_rules = []
    inner.memory = MagicMock()
    inner.memory.per_server_overrides = {}
    cfg.get.return_value = inner
    cfg.save = MagicMock()
    return cfg


def _make_service(
    api_client=None,
    crypto=None,
    memory_service=None,
    config_manager=None,
    auth_service=None,
    tmp_path=None,
    configured: bool = True,
) -> MemorySyncService:
    """Build a MemorySyncService for tests.

    ``configured`` defaults to True so existing tests that call
    ``enqueue_module`` keep working — the new lazy-setup gate (``is_configured``)
    treats unset key material as "user hasn't opted in yet" and short-circuits
    the queue. Tests that want to exercise the unconfigured path should pass
    ``configured=False`` explicitly.
    """
    svc = MemorySyncService(
        api_client=api_client or _make_api_client(),
        crypto=crypto or _make_crypto(),
        memory_service=memory_service or _make_memory_service(),
        config_manager=config_manager or _make_config_manager(),
        auth_service=auth_service or _make_auth_service(),
        rate_limiter=RateLimiter(),
    )
    if tmp_path:
        svc._queue_path = tmp_path / "memory" / "sync_queue.jsonl"
    if configured:
        svc._self_pubkey = b"\x00" * 32
        svc._self_privkey = b"\x01" * 32
        # is_configured now also requires user_id — without it drain_now
        # would early-return on missing self-wrap key. Pin to a stable
        # int so tests don't depend on the auth_service mock.
        svc._self_user_id = 42
    return svc


def _make_module_result(module="os", instance_id="web-01") -> ModuleResult:
    return ModuleResult(
        module=module,
        instance_id=instance_id,
        observed={"cpu_count": 4, "ram_gb": 8},
        declared={},
        sudo_used=False,
        truncated=False,
        partial=False,
        probed_at="2026-04-25T12:00:00+00:00",
        ttl_seconds=86400,
        raw_output="",
    )


# ---------------------------------------------------------------------------
# Bootstrap tests
# ---------------------------------------------------------------------------

class TestBootstrap:
    """spec §5 bootstrap flows."""

    @pytest.mark.asyncio
    async def test_bootstrap_503_raises_backend_maintenance(self, tmp_path):
        """GET /memory/settings 503 → BackendMaintenance."""
        api = _make_api_client(get_side_effect=FeatureDisabledError(
            code="feature_disabled", message="maintenance", status=503
        ))
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        with pytest.raises(BackendMaintenance):
            await svc.bootstrap(passphrase_provider=AsyncMock(return_value="password1234ABCD!!"))

    @pytest.mark.asyncio
    async def test_bootstrap_403_feature_not_available_raises_beta_waitlist(self, tmp_path):
        """GET /memory/settings 403 feature_not_available → BetaWaitlist."""
        api = _make_api_client(get_side_effect=FeatureNotAvailableError(
            code="feature_not_available", message="beta", status=403
        ))
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        with pytest.raises(BetaWaitlist):
            await svc.bootstrap(passphrase_provider=AsyncMock(return_value="password1234ABCD!!"))

    @pytest.mark.asyncio
    async def test_bootstrap_403_forbidden_entitlement_raises_upsell_required(self, tmp_path):
        """GET /memory/settings 403 forbidden_entitlement → UpsellRequired."""
        api = _make_api_client(get_side_effect=ForbiddenEntitlementError(
            code="forbidden_entitlement", message="upgrade", status=403
        ))
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        with pytest.raises(UpsellRequired):
            await svc.bootstrap(passphrase_provider=AsyncMock(return_value="password1234ABCD!!"))

    @pytest.mark.asyncio
    async def test_bootstrap_404_keys_prompts_passphrase_and_enrolls(self, tmp_path):
        """GET /memory/keys/me 404 → passphrase prompted → POST /memory/keys."""
        passphrase = "strong-passphrase-ABC123!!"

        # settings GET: 200
        # keys/me GET: 404
        # keys POST: 201
        # instances POST: 200
        get_calls: List[str] = []

        async def get_side(path, **kwargs):
            get_calls.append(path)
            if "/keys/me" in path:
                raise NotFoundError(code="not_found", message="no key", status=404)
            return {}

        post_calls: List[str] = []

        async def post_side(path, *, json=None, **kwargs):
            post_calls.append(path)
            if "/instances" in path:
                return {"instance_id": "web-01"}
            # /keys POST
            return {"id": "uuid", "fingerprint": "a" * 64, "created_at": "2026-01-01T00:00:00+00:00"}

        api = _make_api_client()
        api.get.side_effect = get_side
        api.post.side_effect = post_side

        svc = _make_service(api_client=api, tmp_path=tmp_path)
        passphrase_provider = AsyncMock(return_value=passphrase)

        with patch("servonaut.services.memory.sync_service.generate_keypair") as gk, \
             patch("servonaut.services.memory.sync_service.wrap_private_key") as wk:
            from servonaut.services.memory.crypto import KeyPair, WrappedPrivateKey
            import base64
            fake_kp = KeyPair(
                public_key=b"\x01" * 32,
                private_key=b"\x02" * 32,
                fingerprint="a" * 64,
            )
            gk.return_value = fake_kp

            fake_wrapped = MagicMock()
            fake_wrapped.to_json.return_value = '{"kdf":"argon2id","pw_score":4,"salt":"AA==","nonce":"AA==","ct":"AA==","ops_limit":1,"mem_limit":1}'
            wk.return_value = fake_wrapped

            await svc.bootstrap(passphrase_provider=passphrase_provider)

        # Check that POST /api/v1/memory/keys (enrollment) was called
        assert any(p == "/api/v1/memory/keys" for p in post_calls), \
            f"Expected POST /api/v1/memory/keys in {post_calls}"
        assert passphrase_provider.called

    @pytest.mark.asyncio
    async def test_bootstrap_happy_path_sets_state_idle(self, tmp_path):
        """Happy path: bootstrap succeeds and state becomes idle."""
        async def get_side(path, **kwargs):
            if "/keys/me" in path:
                return {
                    "public_key": __import__("base64").b64encode(b"\x01" * 32).decode(),
                    "wrapped_private_key": '{"kdf":"argon2id","pw_score":4,"salt":"AAAA","nonce":"AAAA","ct":"AAAA","ops_limit":1,"mem_limit":1}',
                    "fingerprint": "a" * 64,
                }
            return {}

        api = _make_api_client()
        api.get.side_effect = get_side
        api.post.return_value = {"instance_id": "web-01"}

        svc = _make_service(api_client=api, tmp_path=tmp_path)

        with patch("servonaut.services.memory.sync_service.unwrap_private_key") as uwk:
            uwk.return_value = b"\x02" * 32
            await svc.bootstrap(passphrase_provider=AsyncMock(return_value="test-pass-ABC123!!"))

        assert svc.status.state == "idle"


# ---------------------------------------------------------------------------
# Reserved instance_id tests
# ---------------------------------------------------------------------------

class TestReservedInstanceIds:
    """All 11 reserved IDs must be rejected by upsert_instance."""

    @pytest.mark.parametrize("reserved_id", sorted(RESERVED_INSTANCE_IDS))
    @pytest.mark.asyncio
    async def test_reserved_id_raises(self, reserved_id, tmp_path):
        svc = _make_service(tmp_path=tmp_path)
        with pytest.raises(ReservedInstanceIdError):
            await svc.upsert_instance({"id": reserved_id, "name": reserved_id, "provider": "custom"})

    @pytest.mark.asyncio
    async def test_invalid_pattern_raises(self, tmp_path):
        """Instance IDs with invalid chars should be rejected."""
        svc = _make_service(tmp_path=tmp_path)
        with pytest.raises(ReservedInstanceIdError):
            await svc.upsert_instance({"id": "has space!", "name": "bad"})


# ---------------------------------------------------------------------------
# Enqueue + JSONL persistence
# ---------------------------------------------------------------------------

class TestEnqueue:
    def test_enqueue_appends_to_pending(self, tmp_path):
        svc = _make_service(tmp_path=tmp_path)
        result = _make_module_result()
        svc.enqueue_module({"id": "web-01", "name": "web-01", "provider": "custom"}, "os", result)
        assert len(svc._pending) == 1

    def test_enqueue_caps_at_queue_cap(self, tmp_path):
        from servonaut.services.memory.sync_service import _QUEUE_CAP
        svc = _make_service(tmp_path=tmp_path)
        result = _make_module_result()
        # Fill to cap
        for i in range(_QUEUE_CAP):
            svc._pending.append(SyncEnvelope(
                instance_id="x", module="os", probed_at="", ttl_seconds=86400,
                truncated=False, partial=False, sudo_used=False,
                memory_disabled=False, safe_metrics=None, plaintext_payload={},
            ))
        # One more should be silently dropped
        svc.enqueue_module({"id": "y", "name": "y"}, "os", result)
        assert len(svc._pending) == _QUEUE_CAP

    def test_enqueue_writes_jsonl(self, tmp_path):
        svc = _make_service(tmp_path=tmp_path)
        result = _make_module_result()
        svc.enqueue_module({"id": "web-01", "name": "web-01"}, "os", result)
        assert svc._queue_path.exists()
        lines = svc._queue_path.read_text().strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["module"] == "os"
        assert data["instance_id"] == "web-01"


# ---------------------------------------------------------------------------
# Per-rejection state machine
# ---------------------------------------------------------------------------

class TestRejectionStateMachine:

    def _make_batch_response(self, reason: str, index: int = 0) -> Dict[str, Any]:
        return {
            "accepted": [],
            "rejected": [{"index": index, "reason": reason, "message": "test"}],
            "quota": None,
        }

    @pytest.mark.asyncio
    async def test_duplicate_hash_drops_silently(self, tmp_path):
        """duplicate_hash: logs debug, drops — loop continues (state=idle)."""
        api = _make_api_client(post_return=self._make_batch_response("duplicate_hash"))
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        svc._self_pubkey = b"\x01" * 32
        svc._self_user_id = 42
        svc._self_privkey = b"\x02" * 32
        env = SyncEnvelope("web-01", "os", "", 86400, False, False, False, False, None, {})
        svc._pending.append(env)

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=lambda: {
                "iv": "AAAAAAAAAAAAAAAA", "tag": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA==", "encryption": "aes-256-gcm",
                "salt": None, "dek_wraps": [],
            })
            result = await svc.drain_now()

        assert result.rejected[0].reason == "duplicate_hash"
        assert svc.status.state == "idle"
        assert svc._halted_reason is None

    @pytest.mark.asyncio
    async def test_bad_crypto_drops_silently(self, tmp_path):
        """bad_crypto: logs error, drops — loop continues."""
        api = _make_api_client(post_return=self._make_batch_response("bad_crypto"))
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        svc._self_pubkey = b"\x01" * 32
        svc._self_user_id = 42
        svc._self_privkey = b"\x02" * 32
        env = SyncEnvelope("web-01", "os", "", 86400, False, False, False, False, None, {})
        svc._pending.append(env)

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=lambda: {
                "iv": "AAAAAAAAAAAAAAAA", "tag": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA==", "encryption": "aes-256-gcm",
                "salt": None, "dek_wraps": [],
            })
            result = await svc.drain_now()

        assert result.rejected[0].reason == "bad_crypto"
        assert svc._halted_reason is None

    @pytest.mark.asyncio
    async def test_missing_self_wrap_raises(self, tmp_path):
        """missing_self_wrap: raises MissingSelfWrap (our crypto bug)."""
        api = _make_api_client(post_return=self._make_batch_response("missing_self_wrap"))
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        svc._self_pubkey = b"\x01" * 32
        svc._self_user_id = 42
        svc._self_privkey = b"\x02" * 32
        env = SyncEnvelope("web-01", "os", "", 86400, False, False, False, False, None, {})
        svc._pending.append(env)

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=lambda: {
                "iv": "AAAAAAAAAAAAAAAA", "tag": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA==", "encryption": "aes-256-gcm",
                "salt": None, "dek_wraps": [],
            })
            with pytest.raises(MissingSelfWrap):
                await svc.drain_now()

    @pytest.mark.asyncio
    async def test_no_active_keypair_halts(self, tmp_path):
        """no_active_keypair: halted_reason set, state=halted."""
        api = _make_api_client(post_return=self._make_batch_response("no_active_keypair"))
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        svc._self_pubkey = b"\x01" * 32
        svc._self_user_id = 42
        svc._self_privkey = b"\x02" * 32
        env = SyncEnvelope("web-01", "os", "", 86400, False, False, False, False, None, {})
        svc._pending.append(env)

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=lambda: {
                "iv": "AAAAAAAAAAAAAAAA", "tag": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA==", "encryption": "aes-256-gcm",
                "salt": None, "dek_wraps": [],
            })
            await svc.drain_now()

        assert svc._halted_reason == "no_active_keypair"
        assert svc.status.state == "halted"

    @pytest.mark.asyncio
    async def test_memory_disabled_persists_opt_out(self, tmp_path):
        """memory_disabled: persist opt-out to config."""
        api = _make_api_client(post_return=self._make_batch_response("memory_disabled"))
        config_manager = _make_config_manager()
        svc = _make_service(api_client=api, config_manager=config_manager, tmp_path=tmp_path)
        svc._self_pubkey = b"\x01" * 32
        svc._self_user_id = 42
        svc._self_privkey = b"\x02" * 32
        env = SyncEnvelope("web-01", "os", "", 86400, False, False, False, False, None, {})
        svc._pending.append(env)

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=lambda: {
                "iv": "AAAAAAAAAAAAAAAA", "tag": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA==", "encryption": "aes-256-gcm",
                "salt": None, "dek_wraps": [],
            })
            await svc.drain_now()

        # Should have tried to save
        assert config_manager.save.called
        assert svc._halted_reason is None  # Not halted

    @pytest.mark.asyncio
    async def test_quota_exceeded_halts_with_backoff(self, tmp_path):
        """quota_exceeded: halted_reason set."""
        api = _make_api_client(post_return=self._make_batch_response("quota_exceeded"))
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        svc._self_pubkey = b"\x01" * 32
        svc._self_user_id = 42
        svc._self_privkey = b"\x02" * 32
        env = SyncEnvelope("web-01", "os", "", 86400, False, False, False, False, None, {})
        svc._pending.append(env)

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=lambda: {
                "iv": "AAAAAAAAAAAAAAAA", "tag": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA==", "encryption": "aes-256-gcm",
                "salt": None, "dek_wraps": [],
            })
            await svc.drain_now()

        assert svc._halted_reason == "quota_exceeded"
        assert svc.status.state == "halted"


# ---------------------------------------------------------------------------
# unknown_instance auto-register + re-queue path. Without this, the CLI loops
# forever logging "unknown reason 'unknown_instance'" while the user's
# unsynced envelopes accumulate and never reach the backend.
# ---------------------------------------------------------------------------


class TestUnknownInstance:

    @staticmethod
    def _enc_to_dict():
        return {
            "iv": "AAAAAAAAAAAAAAAA",
            "tag": "AAAAAAAAAAAAAAAA",
            "ciphertext": "AA==",
            "encryption": "aes-256-gcm",
            "salt": None,
            "dek_wraps": [],
        }

    @pytest.mark.asyncio
    async def test_unknown_instance_auto_registers_and_requeues(self, tmp_path):
        """unknown_instance: POST /memory/instances + envelope back in queue."""
        post_paths: List[str] = []

        async def post_side(path, *, json=None, **kwargs):
            post_paths.append(path)
            if path.endswith("/memory/sync"):
                return {
                    "accepted": [],
                    "rejected": [{
                        "index": 0,
                        "reason": "unknown_instance",
                        "message": "Instance must be registered via POST /api/v1/memory/instances before syncing",
                    }],
                    "quota": None,
                }
            if path.endswith("/memory/instances"):
                return {"instance_id": "web-01"}
            return {}

        api = _make_api_client()
        api.post.side_effect = post_side
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        env = SyncEnvelope(
            "web-01", "os", "", 86400, False, False, False, False, None, {}
        )
        svc._pending.append(env)

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=self._enc_to_dict)
            await svc.drain_now()

        # /memory/instances was POSTed for recovery
        assert any(p.endswith("/memory/instances") for p in post_paths), \
            f"Expected /memory/instances POST, got: {post_paths}"
        # Envelope was re-queued for next cycle
        assert len(svc._pending) == 1
        assert svc._pending[0].instance_id == "web-01"
        # Marked as registered in session cache so a second envelope skips the POST
        assert "web-01" in svc._registered_instance_ids

    @pytest.mark.asyncio
    async def test_unknown_instance_skips_redundant_register(self, tmp_path):
        """Multiple unknown_instance rejections for the same id POST once."""
        post_paths: List[str] = []

        async def post_side(path, *, json=None, **kwargs):
            post_paths.append(path)
            if path.endswith("/memory/sync"):
                return {
                    "accepted": [],
                    "rejected": [
                        {"index": 0, "reason": "unknown_instance", "message": "x"},
                        {"index": 1, "reason": "unknown_instance", "message": "x"},
                    ],
                    "quota": None,
                }
            if path.endswith("/memory/instances"):
                return {"instance_id": "web-01"}
            return {}

        api = _make_api_client()
        api.post.side_effect = post_side
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        for module in ("os", "services"):
            svc._pending.append(SyncEnvelope(
                "web-01", module, "", 86400, False, False, False, False, None, {},
            ))

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=self._enc_to_dict)
            await svc.drain_now()

        instance_posts = [p for p in post_paths if p.endswith("/memory/instances")]
        assert len(instance_posts) == 1, (
            f"Expected exactly one /memory/instances POST per session, got: {instance_posts}"
        )
        # Both envelopes are re-queued for the next drain.
        assert len(svc._pending) == 2

    @pytest.mark.asyncio
    async def test_unknown_instance_register_failure_drops_envelope(self, tmp_path):
        """If POST /memory/instances itself fails, log + drop (don't crash)."""
        async def post_side(path, *, json=None, **kwargs):
            if path.endswith("/memory/sync"):
                return {
                    "accepted": [],
                    "rejected": [{"index": 0, "reason": "unknown_instance", "message": "x"}],
                    "quota": None,
                }
            if path.endswith("/memory/instances"):
                raise QuotaExceededError(
                    code="quota_exceeded",
                    message="memory_instances_max",
                    status=429,
                    details={"limit": "memory_instances_max"},
                )
            return {}

        api = _make_api_client()
        api.post.side_effect = post_side
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        svc._pending.append(SyncEnvelope(
            "web-01", "os", "", 86400, False, False, False, False, None, {},
        ))

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=self._enc_to_dict)
            # MUST NOT raise — sync run continues for other envelopes.
            await svc.drain_now()

        # Envelope dropped, instance NOT marked registered (so a future probe
        # will retry the registration path naturally).
        assert len(svc._pending) == 0
        assert "web-01" not in svc._registered_instance_ids


# ---------------------------------------------------------------------------
# Verbatim logging for unknown rejection codes — guards against the
# "unknown reason 'unknown_instance'" regression where the server's real
# reason got swallowed by an opaque fallback.
# ---------------------------------------------------------------------------


class TestUnknownReasonLogging:

    @pytest.mark.asyncio
    async def test_new_reason_code_is_logged_verbatim(self, tmp_path, caplog):
        api = _make_api_client(post_return={
            "accepted": [],
            "rejected": [{
                "index": 0,
                "reason": "newfangled_reason",
                "message": "from server",
            }],
            "quota": None,
        })
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        svc._pending.append(SyncEnvelope(
            "web-01", "os", "", 86400, False, False, False, False, None, {},
        ))

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=lambda: {
                "iv": "AAAAAAAAAAAAAAAA", "tag": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA==", "encryption": "aes-256-gcm",
                "salt": None, "dek_wraps": [],
            })
            with caplog.at_level("WARNING", logger="servonaut.services.memory.sync_service"):
                await svc.drain_now()

        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any("newfangled_reason" in m for m in warnings), warnings
        assert any("web-01" in m for m in warnings), warnings
        # The opaque "unknown reason" string must NOT appear — that was the
        # exact bug staging logs surfaced as "unknown reason 'unknown_instance'".
        assert not any("unknown reason" in m for m in warnings), warnings


# ---------------------------------------------------------------------------
# Batch splitting on 413
# ---------------------------------------------------------------------------

class TestBatchSplitting:

    @pytest.mark.asyncio
    async def test_batch_too_large_splits_and_requeues(self, tmp_path):
        """413 BatchTooLargeError: batch split in half and re-queued."""
        api = _make_api_client()
        api.post.side_effect = BatchTooLargeError(
            code="batch_too_large", message="too large", status=413
        )
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        svc._self_pubkey = b"\x01" * 32
        svc._self_user_id = 42
        svc._self_privkey = b"\x02" * 32

        # Add 4 envelopes
        for i in range(4):
            svc._pending.append(SyncEnvelope(
                f"inst-{i}", "os", "", 86400, False, False, False, False, None, {}
            ))

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=lambda: {
                "iv": "AAAAAAAAAAAAAAAA", "tag": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA==", "encryption": "aes-256-gcm",
                "salt": None, "dek_wraps": [],
            })
            result = await svc.drain_now()

        # All 4 should be re-queued
        assert len(svc._pending) == 4
        assert result.accepted == []


# ---------------------------------------------------------------------------
# Quota persistence
# ---------------------------------------------------------------------------

class TestQuotaPersistence:

    @pytest.mark.asyncio
    async def test_quota_persisted_to_status(self, tmp_path):
        """Quota from sync response is stored in status.quota."""
        quota_data = {
            "envelopes_used": 100,
            "envelopes_soft_cap": 50000,
            "envelopes_hard_cap": 75000,
            "retention_days": 30,
        }
        api = _make_api_client(post_return={
            "accepted": [{"id": "uuid", "module": "os"}],
            "rejected": [],
            "quota": quota_data,
        })
        svc = _make_service(api_client=api, tmp_path=tmp_path)
        svc._self_pubkey = b"\x01" * 32
        svc._self_user_id = 42
        svc._self_privkey = b"\x02" * 32
        env = SyncEnvelope("web-01", "os", "", 86400, False, False, False, False, None, {})
        svc._pending.append(env)

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=lambda: {
                "iv": "AAAAAAAAAAAAAAAA", "tag": "AAAAAAAAAAAAAAAA",
                "ciphertext": "AA==", "encryption": "aes-256-gcm",
                "salt": None, "dek_wraps": [],
            })
            result = await svc.drain_now()

        assert result.quota is not None
        assert result.quota.envelopes_used == 100
        assert svc.status.quota is not None
        assert svc.status.quota.envelopes_used == 100


# ---------------------------------------------------------------------------
# Integration: enqueue from MemoryService._persist_result
# ---------------------------------------------------------------------------

class TestMemoryServiceIntegration:

    def test_persist_result_calls_enqueue_module(self, tmp_path):
        """MemoryService._persist_result calls sync_service.enqueue_module when wired."""
        from servonaut.services.memory.service import MemoryService
        from servonaut.services.memory.store import MemoryStore

        store = MagicMock()
        store.save_module = MagicMock()

        ms = MemoryService(store=store, config=None)
        sync_svc = MagicMock()
        ms.set_sync_service(sync_svc)

        result = _make_module_result(module="os", instance_id="web-01")
        instance = {"id": "web-01", "name": "web-01", "provider": "custom"}
        ms._persist_result(result, "web-01", "custom", instance=instance)

        sync_svc.enqueue_module.assert_called_once_with(instance, "os", result)

    def test_persist_result_without_sync_service_does_not_raise(self, tmp_path):
        """_persist_result works normally when no sync service wired."""
        from servonaut.services.memory.service import MemoryService

        store = MagicMock()
        ms = MemoryService(store=store, config=None)

        result = _make_module_result()
        ms._persist_result(result, "web-01", "custom")  # Must not raise

        store.save_module.assert_called_once()

    def test_enqueue_module_exception_does_not_propagate(self, tmp_path):
        """If enqueue_module raises, _persist_result logs + continues."""
        from servonaut.services.memory.service import MemoryService

        store = MagicMock()
        ms = MemoryService(store=store, config=None)
        sync_svc = MagicMock()
        sync_svc.enqueue_module.side_effect = RuntimeError("queue full")
        ms.set_sync_service(sync_svc)

        result = _make_module_result()
        # Must not raise even though sync raises
        ms._persist_result(result, "web-01", "custom")
        store.save_module.assert_called_once()


# ---------------------------------------------------------------------------
# backfill_from_local_store — bridges the "probed before keypair enrolment"
# gap. Without this, Sync Now would post 0 envelopes for users whose entire
# local memory cache predates their Memory Sync setup.
# ---------------------------------------------------------------------------


class TestBackfillFromLocalStore:

    def _memory_service_with_cache(self, instances):
        """Build a fake MemoryService whose list_all + get_all_modules
        return the supplied {instance_id: {module: data}} mapping."""
        ms = MagicMock()
        ms.is_memory_disabled.return_value = False
        ms.list_all.return_value = [
            {"instance_id": iid, "name": iid, "provider": "custom"}
            for iid in instances
        ]
        ms.get_all_modules.side_effect = lambda iid, provider: instances.get(iid, {})
        # No annotations present for these fixtures — prevent backfill from
        # creating phantom annotation envelopes from a truthy MagicMock return.
        ms.read_annotations.return_value = ""
        ms.get_annotations_meta.return_value = {}
        return ms

    def test_backfill_enqueues_every_cached_module(self, tmp_path):
        cache = {
            "web-01": {
                "os": {"observed": {"cpu_count": 4}, "probed_at": "2026-04-25T12:00:00Z"},
                "services": {"observed": {}, "probed_at": "2026-04-25T12:00:00Z"},
            },
            "db-02": {
                "os": {"observed": {}, "probed_at": "2026-04-25T13:00:00Z"},
            },
        }
        ms = self._memory_service_with_cache(cache)
        svc = _make_service(memory_service=ms, tmp_path=tmp_path)

        n = svc.backfill_from_local_store()
        assert n == 3
        assert len(svc._pending) == 3
        queued = {(env.instance_id, env.module) for env in svc._pending}
        assert queued == {("web-01", "os"), ("web-01", "services"), ("db-02", "os")}

    def test_backfill_is_noop_when_unconfigured(self, tmp_path):
        cache = {"web-01": {"os": {"observed": {}, "probed_at": "x"}}}
        ms = self._memory_service_with_cache(cache)
        svc = _make_service(memory_service=ms, tmp_path=tmp_path, configured=False)
        assert svc.backfill_from_local_store() == 0
        assert len(svc._pending) == 0

    def test_backfill_skips_ai_summary_module(self, tmp_path):
        cache = {
            "web-01": {
                "os": {"observed": {}, "probed_at": "x"},
                # ai_summary is server-generated; the CLI must never push it.
                "ai_summary": {"observed": {}, "probed_at": "x"},
            },
        }
        ms = self._memory_service_with_cache(cache)
        svc = _make_service(memory_service=ms, tmp_path=tmp_path)
        assert svc.backfill_from_local_store() == 1
        modules = {env.module for env in svc._pending}
        assert modules == {"os"}

    def test_backfill_skips_already_pending_pairs(self, tmp_path):
        cache = {"web-01": {"os": {"observed": {}, "probed_at": "x"}}}
        ms = self._memory_service_with_cache(cache)
        svc = _make_service(memory_service=ms, tmp_path=tmp_path)
        # First call enqueues, second is a no-op (idempotent within session).
        assert svc.backfill_from_local_store() == 1
        assert svc.backfill_from_local_store() == 0
        assert len(svc._pending) == 1

    def test_backfill_skips_memory_disabled_instance(self, tmp_path):
        cache = {"web-01": {"os": {"observed": {}, "probed_at": "x"}}}
        ms = self._memory_service_with_cache(cache)
        ms.is_memory_disabled.return_value = True
        svc = _make_service(memory_service=ms, tmp_path=tmp_path)
        assert svc.backfill_from_local_store() == 0
        assert len(svc._pending) == 0


# ---------------------------------------------------------------------------
# is_configured gate + drain user_id recovery — covers the silent
# "drain_now: no active keypair" production bug where pubkey was set but
# user_id was None, so drain_now early-returned with empty result and
# Sync Now reported "Nothing to sync" while the queue stayed full.
# ---------------------------------------------------------------------------


class TestIsConfiguredGate:

    def test_pubkey_and_privkey_alone_not_enough(self, tmp_path):
        svc = _make_service(tmp_path=tmp_path, configured=False)
        svc._self_pubkey = b"\x00" * 32
        svc._self_privkey = b"\x01" * 32
        # user_id deliberately missing — must NOT report configured
        assert svc.is_configured is False

    def test_all_three_required(self, tmp_path):
        svc = _make_service(tmp_path=tmp_path, configured=False)
        svc._self_pubkey = b"\x00" * 32
        svc._self_privkey = b"\x01" * 32
        svc._self_user_id = 7
        assert svc.is_configured is True


class TestDrainUserIdRecovery:

    @pytest.mark.asyncio
    async def test_drain_retries_fetch_user_id_when_none(self, tmp_path):
        """drain_now should call fetch_user_id once if user_id is missing,
        rather than silently no-op'ing forever."""
        auth = _make_auth_service(user_id=None)
        # First call returns None (existing state), second returns 42
        auth.fetch_user_id = AsyncMock(side_effect=[42])
        api = _make_api_client()
        svc = _make_service(api_client=api, auth_service=auth, tmp_path=tmp_path)
        # Force user_id back to None to simulate the broken bootstrap state
        svc._self_user_id = None
        # Queue something so the early-return doesn't trip on empty queue
        svc._pending.append(SyncEnvelope(
            instance_id="web-01", module="os", probed_at="x",
            ttl_seconds=60, truncated=False, partial=False, sudo_used=False,
            memory_disabled=False, safe_metrics=None, plaintext_payload={},
        ))
        await svc.drain_now()
        # Recovery attempt happened
        assert auth.fetch_user_id.await_count == 1
        assert svc._self_user_id == 42

    @pytest.mark.asyncio
    async def test_drain_surfaces_user_id_error_on_status(self, tmp_path):
        """When fetch_user_id keeps returning None, drain_now must set
        last_error so the screen can show a real diagnostic instead of
        the misleading 'nothing to sync' message."""
        auth = _make_auth_service(user_id=None)
        auth.fetch_user_id = AsyncMock(return_value=None)
        api = _make_api_client()
        svc = _make_service(api_client=api, auth_service=auth, tmp_path=tmp_path)
        svc._self_user_id = None
        svc._pending.append(SyncEnvelope(
            instance_id="web-01", module="os", probed_at="x",
            ttl_seconds=60, truncated=False, partial=False, sudo_used=False,
            memory_disabled=False, safe_metrics=None, plaintext_payload={},
        ))
        await svc.drain_now()
        assert svc._last_error is not None
        assert "user_id" in svc._last_error
        # Pending stays — we did NOT throw away the work
        assert len(svc._pending) == 1


# ---------------------------------------------------------------------------
# Status subscribe
# ---------------------------------------------------------------------------

class TestSubscribe:

    def test_status_subscriber_receives_updates(self, tmp_path):
        svc = _make_service(tmp_path=tmp_path)
        received: List[MemorySyncStatus] = []
        svc.subscribe(received.append)

        result = _make_module_result()
        svc.enqueue_module({"id": "x", "name": "x"}, "os", result)

        assert len(received) >= 1
        assert isinstance(received[-1], MemorySyncStatus)
