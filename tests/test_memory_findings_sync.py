"""Tests for findings-sync surface in MemorySyncService.

Covers:
1. test_gate_off_enqueue_noop       — findings_sync_enabled=False → enqueue_findings is a no-op.
2. test_gate_off_no_post_on_drain   — gate off → no POST on drain after attempted enqueue.
3. test_gate_on_enqueue_one_envelope — gate on → exactly one envelope with module=="findings".
4. test_no_plaintext_findings_on_wire — sentinel absent from encrypted POST body.
5. test_pull_findings_merges        — pull_findings calls merge_findings + set_findings_meta.
6. test_optout_enqueue_noop         — is_memory_disabled=True → enqueue no-op.
7. test_optout_pull_returns_opt_out — is_memory_disabled=True → pull returns "opt_out".
8. test_backfill_enqueues_findings_once — backfill enqueues findings once when gate on (idempotent).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.memory.interfaces import DecryptedEnvelope
from servonaut.services.memory.sync_service import MemorySyncService
from servonaut.services.memory.rate_limiter import RateLimiter

# ---------------------------------------------------------------------------
# Check for crypto deps — some tests require PyNaCl + cryptography
# ---------------------------------------------------------------------------
try:
    from servonaut.services.memory.crypto import generate_keypair, KeyPair
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ---------------------------------------------------------------------------
# Local helpers (mirror test_memory_annotations_sync.py patterns)
# ---------------------------------------------------------------------------

def _make_api_client(post_return=None, post_side_effect=None):
    """Build a minimal AsyncMock API client."""
    client = MagicMock()
    client.get = AsyncMock(return_value={})
    client.post = AsyncMock(return_value=post_return or {})
    client.patch = AsyncMock(return_value={})
    client.delete = AsyncMock(return_value={})
    if post_side_effect is not None:
        client.post.side_effect = post_side_effect
    return client


def _make_memory_service_mock(
    instances: Optional[List[Dict[str, Any]]] = None,
    disabled: bool = False,
    findings_map: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> MagicMock:
    """Return a fully-stubbed MemoryService mock."""
    ms = MagicMock()
    ms.is_memory_disabled.return_value = disabled
    ms.list_all.return_value = instances or []
    findings_map = findings_map or {}
    ms.list_findings.side_effect = (
        lambda iid, provider="custom", include_superseded=False: findings_map.get(iid, [])
    )
    ms.merge_findings = MagicMock(
        return_value={"created": 0, "updated": 0, "skipped": 0, "active_after": 0}
    )
    ms.set_findings_meta = MagicMock()
    ms.get_all_modules.return_value = {}
    ms.read_annotations.return_value = ""
    ms.get_annotations_meta.return_value = {}
    return ms


def _make_service(
    api_client=None,
    memory_service=None,
    tmp_path: Optional[Path] = None,
    configured: bool = True,
    findings_sync_enabled: bool = False,
) -> MemorySyncService:
    """Build a MemorySyncService wired for findings tests."""
    if memory_service is None:
        memory_service = _make_memory_service_mock()

    config_manager = MagicMock()
    inner = MagicMock()
    inner.connection_rules = []
    inner.memory = MagicMock()
    inner.memory.per_server_overrides = {}
    inner.memory.findings_sync_enabled = findings_sync_enabled
    config_manager.get.return_value = inner
    config_manager.save = MagicMock()

    auth = MagicMock()
    auth.fetch_user_id = AsyncMock(return_value=42)
    auth.user_id = 42

    svc = MemorySyncService(
        api_client=api_client or _make_api_client(),
        crypto=MagicMock(),
        memory_service=memory_service,
        config_manager=config_manager,
        auth_service=auth,
        rate_limiter=RateLimiter(),
    )
    if tmp_path is not None:
        svc._queue_path = tmp_path / "memory" / "sync_queue.jsonl"
    if configured:
        svc._self_pubkey = b"\x00" * 32
        svc._self_privkey = b"\x01" * 32
        svc._self_user_id = 42
    return svc


_SAMPLE_FINDINGS = [
    {"id": "f_abc1234567890abc", "title": "Open port 22", "severity": "low"},
    {"id": "f_def4567890defabc", "title": "Outdated nginx", "severity": "medium"},
]


def _enc_stub_to_dict():
    """Stub encrypt_envelope return value dict (not real crypto)."""
    return {
        "iv": "AAAAAAAAAAAAAAAA",
        "tag": "AAAAAAAAAAAAAAAA",
        "ciphertext": "AA==",
        "encryption": "aes-256-gcm",
        "salt": None,
        "dek_wraps": [],
    }


def _post_accept_all(path, *, json=None, **kwargs):
    """Async side-effect that accepts every envelope in the batch."""
    envelopes = (json or {}).get("envelopes", [])
    accepted = [{"id": f"uuid-{i}", "module": "findings"} for i, _ in enumerate(envelopes)]
    return {"accepted": accepted, "rejected": [], "quota": None}


# ---------------------------------------------------------------------------
# 1. Gate OFF → enqueue_findings is a no-op
# ---------------------------------------------------------------------------

class TestGateOffEnqueueNoop:

    def test_gate_off_enqueue_noop(self, tmp_path: Path):
        """When findings_sync_enabled=False, enqueue_findings must not add any envelope."""
        ms = _make_memory_service_mock(disabled=False)
        svc = _make_service(memory_service=ms, tmp_path=tmp_path, findings_sync_enabled=False)
        instance = {"id": "web-1", "name": "web-1", "provider": "custom"}

        depth_before = len(svc._pending)
        svc.enqueue_findings(instance, _SAMPLE_FINDINGS)
        assert len(svc._pending) == depth_before, (
            "enqueue_findings must be a no-op when findings_sync_enabled=False"
        )


# ---------------------------------------------------------------------------
# 2. Gate OFF → no POST on drain after attempted enqueue
# ---------------------------------------------------------------------------

class TestGateOffNoPostOnDrain:

    @pytest.mark.asyncio
    async def test_gate_off_no_post_on_drain(self, tmp_path: Path):
        """Gate off: nothing enqueued, so drain produces zero POSTs."""
        api = _make_api_client()
        ms = _make_memory_service_mock(disabled=False)
        svc = _make_service(
            api_client=api, memory_service=ms, tmp_path=tmp_path,
            findings_sync_enabled=False,
        )
        instance = {"id": "web-1", "name": "web-1", "provider": "custom"}

        svc.enqueue_findings(instance, _SAMPLE_FINDINGS)
        assert len(svc._pending) == 0

        with patch("servonaut.services.memory.sync_service.encrypt_envelope") as mock_enc:
            mock_enc.return_value = MagicMock(to_dict=_enc_stub_to_dict)
            result = await svc.drain_now()

        api.post.assert_not_called()
        assert result.accepted == []


# ---------------------------------------------------------------------------
# 3. Gate ON → exactly one envelope with module=="findings"
# ---------------------------------------------------------------------------

class TestGateOnEnqueueOneEnvelope:

    def test_gate_on_enqueue_one_envelope(self, tmp_path: Path):
        """When findings_sync_enabled=True, exactly one findings envelope is enqueued
        with the correct module name and payload."""
        ms = _make_memory_service_mock(disabled=False)
        svc = _make_service(memory_service=ms, tmp_path=tmp_path, findings_sync_enabled=True)
        instance = {"id": "web-1", "name": "web-1", "provider": "custom"}

        svc.enqueue_findings(instance, _SAMPLE_FINDINGS)

        assert len(svc._pending) == 1
        env = svc._pending[0]
        assert env.module == "findings"
        assert env.instance_id == "web-1"
        assert env.plaintext_payload == {"findings": _SAMPLE_FINDINGS}
        assert env.ttl_seconds == 86400
        assert not env.truncated
        assert not env.partial
        assert not env.sudo_used
        assert env.safe_metrics is None


# ---------------------------------------------------------------------------
# 4. No plaintext findings on wire (real encryption)
# ---------------------------------------------------------------------------

class TestNoPlaintextFindingsOnWire:

    @pytest.mark.asyncio
    async def test_no_plaintext_findings_on_wire(self, tmp_path: Path):
        """Sentinel string must NOT appear in POST body JSON after AES-256-GCM encryption."""
        if not _HAS_CRYPTO:
            pytest.skip("PyNaCl / cryptography not installed; skipping real-crypto test")

        sentinel = "SENTINEL-FIND-XYZZY"
        instance = {"id": "web-1", "name": "web-1", "provider": "custom"}
        records = [{"id": "f_abc1234567890abc", "detail": sentinel}]

        kp: KeyPair = generate_keypair()

        captured_bodies: List[dict] = []

        async def capture_post(path, *, json=None, **kwargs):
            if json is not None:
                captured_bodies.append(json)
            envelopes = (json or {}).get("envelopes", [])
            return {
                "accepted": [{"id": f"u{i}", "module": "findings"} for i in range(len(envelopes))],
                "rejected": [],
                "quota": None,
            }

        from servonaut.services.api_client import APIClient
        api = MagicMock(spec=APIClient)
        api.get = AsyncMock(return_value={})
        api.post = AsyncMock(side_effect=capture_post)
        api.patch = AsyncMock(return_value={})

        ms = _make_memory_service_mock(disabled=False)
        svc = _make_service(api_client=api, memory_service=ms, tmp_path=tmp_path,
                            findings_sync_enabled=True)

        # Wire real key material
        svc._self_pubkey = kp.public_key
        svc._self_privkey = kp.private_key
        svc._self_user_id = 99

        svc.enqueue_findings(instance, records)
        assert len(svc._pending) == 1

        result = await svc.drain_now()

        assert len(result.accepted) == 1, f"Expected drain accepted, got: {result}"
        assert len(captured_bodies) == 1, "Expected exactly one POST body"

        wire_json = json.dumps(captured_bodies[0])
        assert sentinel not in wire_json, (
            f"Sentinel plaintext found in wire JSON — encryption failed!\n"
            f"Wire snippet: {wire_json[:300]}"
        )


# ---------------------------------------------------------------------------
# 5. pull_findings merges into MemoryService and calls set_findings_meta
# ---------------------------------------------------------------------------

class TestPullFindingsMerges:

    def _make_decrypted(
        self,
        findings: List[Dict[str, Any]],
        probed_at: str = "2026-06-01T00:00:00+00:00",
        instance_id: str = "web-1",
    ) -> DecryptedEnvelope:
        return DecryptedEnvelope(
            id="uuid-findings-1",
            instance_id=instance_id,
            module="findings",
            snapshot_version=1,
            probed_at=probed_at,
            ttl_seconds=86400,
            truncated=False,
            partial=False,
            sudo_used=False,
            safe_metrics=None,
            plaintext={"findings": findings},
            created_at=probed_at,
        )

    @pytest.mark.asyncio
    async def test_pull_findings_calls_merge_and_meta(self, tmp_path: Path):
        """pull_findings calls merge_findings with the server list and
        set_findings_meta with the probed_at timestamp and active_after count."""
        incoming = [
            {"id": "f_aaa1234567890abc", "title": "Open port", "severity": "low"},
        ]
        ms = _make_memory_service_mock(disabled=False)
        ms.merge_findings.return_value = {
            "created": 1, "updated": 0, "skipped": 0, "active_after": 1
        }

        svc = _make_service(memory_service=ms, tmp_path=tmp_path, findings_sync_enabled=False)

        server_envelope = self._make_decrypted(incoming, probed_at="2026-06-05T00:00:00+00:00")
        retrieval_svc = MagicMock()
        retrieval_svc.get_module = AsyncMock(return_value=server_envelope)
        svc.set_retrieval_service(retrieval_svc)

        outcome = await svc.pull_findings("web-1", instance_name="web-1")

        assert outcome == "updated", f"Expected 'updated', got {outcome!r}"
        ms.merge_findings.assert_called_once_with("web-1", incoming, "custom")
        ms.set_findings_meta.assert_called_once_with(
            "web-1",
            findings_synced_at="2026-06-05T00:00:00+00:00",
            findings_count=1,
        )

    @pytest.mark.asyncio
    async def test_pull_findings_unchanged_when_no_new(self, tmp_path: Path):
        """pull_findings returns 'unchanged' when merge_findings reports zero created/updated."""
        ms = _make_memory_service_mock(disabled=False)
        ms.merge_findings.return_value = {
            "created": 0, "updated": 0, "skipped": 0, "active_after": 3
        }

        svc = _make_service(memory_service=ms, tmp_path=tmp_path)

        incoming = [{"id": "f_bbb1234567890abc", "title": "Same old finding"}]
        server_envelope = self._make_decrypted(incoming)
        retrieval_svc = MagicMock()
        retrieval_svc.get_module = AsyncMock(return_value=server_envelope)
        svc.set_retrieval_service(retrieval_svc)

        outcome = await svc.pull_findings("web-1")
        assert outcome == "unchanged", f"Expected 'unchanged', got {outcome!r}"

    @pytest.mark.asyncio
    async def test_pull_findings_not_found_on_backend_error(self, tmp_path: Path):
        """pull_findings returns 'not_found' when the retrieval service raises."""
        from servonaut.services.memory.interfaces import MemoryBackendError

        ms = _make_memory_service_mock(disabled=False)
        svc = _make_service(memory_service=ms, tmp_path=tmp_path)

        retrieval_svc = MagicMock()
        retrieval_svc.get_module = AsyncMock(side_effect=MemoryBackendError("gone"))
        svc.set_retrieval_service(retrieval_svc)

        outcome = await svc.pull_findings("web-1")
        assert outcome == "not_found"


# ---------------------------------------------------------------------------
# 6. Opt-out → enqueue is a no-op
# ---------------------------------------------------------------------------

class TestOptoutEnqueueNoop:

    def test_optout_skips_enqueue(self, tmp_path: Path):
        """When is_memory_disabled returns True, enqueue_findings is a no-op."""
        ms = _make_memory_service_mock(disabled=True)
        svc = _make_service(memory_service=ms, tmp_path=tmp_path, findings_sync_enabled=True)
        instance = {"id": "web-1", "name": "web-1", "provider": "custom"}

        svc.enqueue_findings(instance, _SAMPLE_FINDINGS)
        assert len(svc._pending) == 0, (
            "enqueue_findings must be a no-op when memory is disabled"
        )


# ---------------------------------------------------------------------------
# 7. Opt-out → pull returns "opt_out"
# ---------------------------------------------------------------------------

class TestOptoutPullReturnsOptOut:

    @pytest.mark.asyncio
    async def test_optout_pull_returns_opt_out(self, tmp_path: Path):
        """When is_memory_disabled returns True, pull_findings returns 'opt_out'
        without calling the retrieval service."""
        ms = _make_memory_service_mock(disabled=True)
        svc = _make_service(memory_service=ms, tmp_path=tmp_path)

        retrieval_svc = MagicMock()
        retrieval_svc.get_module = AsyncMock()
        svc.set_retrieval_service(retrieval_svc)

        outcome = await svc.pull_findings("web-1", instance_name="web-1")
        assert outcome == "opt_out", f"Expected 'opt_out', got {outcome!r}"
        retrieval_svc.get_module.assert_not_called()


# ---------------------------------------------------------------------------
# 8. backfill enqueues findings once when gate ON (idempotent)
# ---------------------------------------------------------------------------

class TestBackfillEnqueuesFindings:

    def test_backfill_enqueues_findings_when_gate_on(self, tmp_path: Path):
        """backfill_from_local_store enqueues one findings envelope per instance
        when gate on and local findings exist.  Second call is a no-op (idempotent)."""
        instances = [
            {"instance_id": "web-1", "name": "web-1", "provider": "custom"},
        ]
        findings_for_web1 = [
            {"id": "f_abc1234567890abc", "title": "Open port 22"},
        ]
        ms = MagicMock()
        ms.is_memory_disabled.return_value = False
        ms.list_all.return_value = instances
        ms.get_all_modules.return_value = {}
        ms.read_annotations.return_value = ""
        ms.get_annotations_meta.return_value = {}
        ms.list_findings.side_effect = (
            lambda iid, provider="custom", include_superseded=False: (
                findings_for_web1 if iid == "web-1" else []
            )
        )

        svc = _make_service(memory_service=ms, tmp_path=tmp_path, findings_sync_enabled=True)

        count_1 = svc.backfill_from_local_store()
        assert count_1 == 1, f"Expected 1 findings envelope enqueued, got {count_1}"
        modules_enqueued = {(e.instance_id, e.module) for e in svc._pending}
        assert ("web-1", "findings") in modules_enqueued

        # Second call: already pending, must not add duplicates.
        count_2 = svc.backfill_from_local_store()
        assert count_2 == 0, f"Expected 0 on second call (idempotent), got {count_2}"
        assert len(svc._pending) == 1

    def test_backfill_findings_noop_when_gate_off(self, tmp_path: Path):
        """When findings_sync_enabled=False, backfill skips findings even when they exist."""
        instances = [
            {"instance_id": "web-1", "name": "web-1", "provider": "custom"},
        ]
        findings_for_web1 = [
            {"id": "f_abc1234567890abc", "title": "Open port 22"},
        ]
        ms = MagicMock()
        ms.is_memory_disabled.return_value = False
        ms.list_all.return_value = instances
        ms.get_all_modules.return_value = {}
        ms.read_annotations.return_value = ""
        ms.get_annotations_meta.return_value = {}
        ms.list_findings.side_effect = (
            lambda iid, provider="custom", include_superseded=False: (
                findings_for_web1 if iid == "web-1" else []
            )
        )

        svc = _make_service(memory_service=ms, tmp_path=tmp_path, findings_sync_enabled=False)

        count = svc.backfill_from_local_store()
        assert count == 0, f"Expected 0 (gate off), got {count}"
        pending_modules = {e.module for e in svc._pending}
        assert "findings" not in pending_modules

    def test_backfill_findings_noop_when_empty(self, tmp_path: Path):
        """backfill skips findings envelope when list_findings returns empty list."""
        instances = [
            {"instance_id": "web-1", "name": "web-1", "provider": "custom"},
        ]
        ms = MagicMock()
        ms.is_memory_disabled.return_value = False
        ms.list_all.return_value = instances
        ms.get_all_modules.return_value = {}
        ms.read_annotations.return_value = ""
        ms.get_annotations_meta.return_value = {}
        ms.list_findings.return_value = []

        svc = _make_service(memory_service=ms, tmp_path=tmp_path, findings_sync_enabled=True)

        count = svc.backfill_from_local_store()
        assert count == 0, f"Expected 0 (no findings on disk), got {count}"
