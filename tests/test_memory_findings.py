"""Tests for finding storage CRUD in MemoryStore, trust_notices, and MemoryService.

Instance IDs use neutral fixtures only (web-1, app-2 — no real names or IPs).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import (
    MemoryStore,
    _validate_finding_id,
)
from servonaut.services.memory import trust_notices


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(finding_id: str, created_at: str = "", **extra: Any) -> Dict[str, Any]:
    """Return a minimal finding record fixture."""
    record: Dict[str, Any] = {"id": finding_id, "title": f"Finding {finding_id}"}
    if created_at:
        record["created_at"] = created_at
    record.update(extra)
    return record


# ---------------------------------------------------------------------------
# TestStore
# ---------------------------------------------------------------------------


class TestStore:
    """Unit tests for MemoryStore finding storage CRUD."""

    # ------------------------------------------------------------------
    # save_finding / get_finding round-trip
    # ------------------------------------------------------------------

    def test_save_finding_writes_file_under_findings_subdir(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        record = _make_finding("f_abcdef1234567890")
        path = store.save_finding("web-1", record)

        assert path.exists()
        # Must be inside a "findings" subdirectory, not loose in the instance dir.
        assert path.parent.name == "findings"
        assert path.name == "f_abcdef1234567890.json"

    def test_save_finding_file_has_restricted_permissions(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        record = _make_finding("f_abcdef1234567890")
        path = store.save_finding("web-1", record)

        mode = oct(path.stat().st_mode & 0o777)
        assert mode == oct(0o600), f"expected 0o600, got {mode}"

    def test_get_finding_round_trips(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        record = _make_finding("f_abcdef1234567890", title="Missing redis key")
        store.save_finding("web-1", record)

        loaded = store.get_finding("web-1", "f_abcdef1234567890")
        assert loaded is not None
        assert loaded["title"] == "Missing redis key"

    def test_get_finding_returns_none_for_missing(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        result = store.get_finding("web-1", "f_abcdef1234567890")
        assert result is None

    def test_get_finding_returns_none_on_corrupt_json(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        record = _make_finding("f_abcdef1234567890")
        path = store.save_finding("web-1", record)
        # Corrupt the file.
        path.write_text("{ not valid json }", encoding="utf-8")

        result = store.get_finding("web-1", "f_abcdef1234567890")
        assert result is None

    # ------------------------------------------------------------------
    # list_findings — superseded filtering + ordering
    # ------------------------------------------------------------------

    def test_list_findings_excludes_superseded_by_default(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        store.save_finding("web-1", _make_finding(
            "f_aaaaaaaaaaaaaaaa", created_at="2026-06-01T00:00:00Z"
        ))
        store.save_finding("web-1", _make_finding(
            "f_bbbbbbbbbbbbbbbb",
            created_at="2026-06-02T00:00:00Z",
            superseded_by="f_aaaaaaaaaaaaaaaa",
        ))

        results = store.list_findings("web-1")
        ids = [r["id"] for r in results]
        assert "f_aaaaaaaaaaaaaaaa" in ids
        assert "f_bbbbbbbbbbbbbbbb" not in ids

    def test_list_findings_includes_superseded_with_flag(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        store.save_finding("web-1", _make_finding(
            "f_aaaaaaaaaaaaaaaa", created_at="2026-06-01T00:00:00Z"
        ))
        store.save_finding("web-1", _make_finding(
            "f_bbbbbbbbbbbbbbbb",
            created_at="2026-06-02T00:00:00Z",
            superseded_by="f_aaaaaaaaaaaaaaaa",
        ))

        results = store.list_findings("web-1", include_superseded=True)
        ids = [r["id"] for r in results]
        assert "f_aaaaaaaaaaaaaaaa" in ids
        assert "f_bbbbbbbbbbbbbbbb" in ids

    def test_list_findings_sorted_newest_first(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        store.save_finding("web-1", _make_finding(
            "f_aaaaaaaaaaaaaaaa", created_at="2026-06-01T00:00:00Z"
        ))
        store.save_finding("web-1", _make_finding(
            "f_cccccccccccccccc", created_at="2026-06-03T00:00:00Z"
        ))
        store.save_finding("web-1", _make_finding(
            "f_bbbbbbbbbbbbbbbb", created_at="2026-06-02T00:00:00Z"
        ))

        results = store.list_findings("web-1")
        assert results[0]["id"] == "f_cccccccccccccccc"
        assert results[1]["id"] == "f_bbbbbbbbbbbbbbbb"
        assert results[2]["id"] == "f_aaaaaaaaaaaaaaaa"

    def test_list_findings_returns_empty_for_no_findings_dir(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        results = store.list_findings("web-1")
        assert results == []

    def test_list_findings_skips_malformed_files(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        record = _make_finding("f_aaaaaaaaaaaaaaaa", created_at="2026-06-01T00:00:00Z")
        store.save_finding("web-1", record)

        # Plant a corrupt file directly.
        findings_dir = tmp_path / "custom" / "web-1" / "findings"
        corrupt = findings_dir / "f_zzzzzzzzzzzzzzzz.json"
        corrupt.write_text("not json", encoding="utf-8")

        results = store.list_findings("web-1")
        assert len(results) == 1
        assert results[0]["id"] == "f_aaaaaaaaaaaaaaaa"

    # ------------------------------------------------------------------
    # delete_finding
    # ------------------------------------------------------------------

    def test_delete_finding_returns_true_on_success(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        store.save_finding("web-1", _make_finding("f_abcdef1234567890"))
        result = store.delete_finding("web-1", "f_abcdef1234567890")
        assert result is True

    def test_delete_finding_removes_file(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        store.save_finding("web-1", _make_finding("f_abcdef1234567890"))
        store.delete_finding("web-1", "f_abcdef1234567890")
        assert store.get_finding("web-1", "f_abcdef1234567890") is None

    def test_delete_finding_returns_false_when_absent(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        result = store.delete_finding("web-1", "f_abcdef1234567890")
        assert result is False

    # ------------------------------------------------------------------
    # get_findings_meta / set_findings_meta
    # ------------------------------------------------------------------

    def test_get_findings_meta_defaults(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        meta = store.get_findings_meta("web-1")
        assert meta["findings_count"] == 0
        assert meta["findings_synced_at"] == ""

    def test_set_findings_meta_partial_update_preserves_other_keys(
        self, tmp_path: Path
    ) -> None:
        store = MemoryStore(root=tmp_path)
        # Seed an index entry with unrelated data.
        store.update_index("web-1", name="web-1", provider="custom", modules=["os"])
        # Set only findings_count.
        store.set_findings_meta("web-1", findings_count=3)
        # findings_synced_at should still be default.
        meta = store.get_findings_meta("web-1")
        assert meta["findings_count"] == 3
        assert meta["findings_synced_at"] == ""
        # Other index keys must survive.
        entry = store.get_index_entry("web-1")
        assert entry is not None
        assert "name" in entry

    def test_set_findings_meta_updates_synced_at(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        store.set_findings_meta("web-1", findings_synced_at="2026-06-10T12:00:00Z")
        meta = store.get_findings_meta("web-1")
        assert meta["findings_synced_at"] == "2026-06-10T12:00:00Z"
        assert meta["findings_count"] == 0  # not touched

    def test_set_findings_meta_creates_entry_if_absent(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        store.set_findings_meta("app-2", findings_count=7)
        meta = store.get_findings_meta("app-2")
        assert meta["findings_count"] == 7

    def test_set_findings_meta_both_kwargs(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        store.set_findings_meta(
            "web-1",
            findings_count=5,
            findings_synced_at="2026-06-10T00:00:00Z",
        )
        meta = store.get_findings_meta("web-1")
        assert meta["findings_count"] == 5
        assert meta["findings_synced_at"] == "2026-06-10T00:00:00Z"

    # ------------------------------------------------------------------
    # _validate_finding_id
    # ------------------------------------------------------------------

    def test_validate_finding_id_accepts_valid_ids(self) -> None:
        # Must not raise.
        _validate_finding_id("f_abcdef1234567890")           # exactly 16 hex chars
        _validate_finding_id("f_" + "a" * 32)                # max 32 alphanumeric
        _validate_finding_id("f_abc123def456789012345678901234")  # 32 chars exactly

    def test_validate_finding_id_rejects_no_f_prefix(self) -> None:
        with pytest.raises(ValueError, match="Invalid finding ID"):
            _validate_finding_id("abcdef1234567890")

    def test_validate_finding_id_rejects_too_short(self) -> None:
        with pytest.raises(ValueError, match="Invalid finding ID"):
            _validate_finding_id("f_abc")  # only 3 chars after f_

    def test_validate_finding_id_rejects_path_traversal(self) -> None:
        # Path-traversal attempts must not match the whitelist.
        with pytest.raises(ValueError, match="Invalid finding ID"):
            _validate_finding_id("f_../x" + "a" * 16)

    def test_validate_finding_id_rejects_uppercase(self) -> None:
        with pytest.raises(ValueError, match="Invalid finding ID"):
            _validate_finding_id("f_ABCDEF1234567890")

    def test_validate_finding_id_rejects_empty(self) -> None:
        with pytest.raises(ValueError, match="Invalid finding ID"):
            _validate_finding_id("")

    def test_validate_finding_id_rejects_too_long(self) -> None:
        with pytest.raises(ValueError, match="Invalid finding ID"):
            _validate_finding_id("f_" + "a" * 33)  # 33 chars after f_ = too long

    # ------------------------------------------------------------------
    # _validate_instance_id guards findings methods
    # ------------------------------------------------------------------

    def test_save_finding_rejects_path_traversal_instance_id(
        self, tmp_path: Path
    ) -> None:
        store = MemoryStore(root=tmp_path)
        with pytest.raises(ValueError):
            store.save_finding("../evil", _make_finding("f_abcdef1234567890"))

    def test_get_finding_rejects_empty_instance_id(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        with pytest.raises(ValueError):
            store.get_finding("", "f_abcdef1234567890")

    def test_list_findings_rejects_path_traversal_instance_id(
        self, tmp_path: Path
    ) -> None:
        store = MemoryStore(root=tmp_path)
        with pytest.raises(ValueError):
            store.list_findings("../../etc")

    def test_delete_finding_rejects_bad_instance_id(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        with pytest.raises(ValueError):
            store.delete_finding("../evil", "f_abcdef1234567890")

    def test_get_findings_meta_rejects_path_traversal(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        with pytest.raises(ValueError):
            store.get_findings_meta("../evil")

    def test_set_findings_meta_rejects_path_traversal(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        with pytest.raises(ValueError):
            store.set_findings_meta("../evil", findings_count=1)

    # ------------------------------------------------------------------
    # clear() removes the findings dir
    # ------------------------------------------------------------------

    def test_clear_removes_findings_directory(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        store.save_finding("web-1", _make_finding("f_abcdef1234567890"))
        findings_dir = tmp_path / "custom" / "web-1" / "findings"
        assert findings_dir.exists()

        store.clear("web-1")
        # The entire instance dir is gone, which includes findings/.
        assert not findings_dir.exists()
        assert not (tmp_path / "custom" / "web-1").exists()

    def test_findings_not_picked_up_by_get_all_modules(self, tmp_path: Path) -> None:
        """Findings subdir must not appear as a module in get_all_modules."""
        store = MemoryStore(root=tmp_path)
        # Save a regular module.
        store.save_module("web-1", "os", {"raw_output": "Linux", "probed_at": "2026-06-01T00:00:00Z"})
        # Save a finding.
        store.save_finding("web-1", _make_finding("f_abcdef1234567890"))

        modules = store.get_all_modules("web-1")
        # "findings" (the subdir) must not appear as a module.
        assert "findings" not in modules
        # The regular module is still there.
        assert "os" in modules


# ---------------------------------------------------------------------------
# Trust notices
# ---------------------------------------------------------------------------


class TestTrustNotices:
    """Smoke tests for the trust_notices constants."""

    def test_memory_trust_notice_is_non_empty(self) -> None:
        assert trust_notices.MEMORY_TRUST_NOTICE
        assert len(trust_notices.MEMORY_TRUST_NOTICE) > 0

    def test_findings_provenance_notice_is_non_empty(self) -> None:
        assert trust_notices.FINDINGS_PROVENANCE_NOTICE
        assert len(trust_notices.FINDINGS_PROVENANCE_NOTICE) > 0

    def test_findings_provenance_notice_contains_agent_authored(self) -> None:
        assert "agent-authored" in trust_notices.FINDINGS_PROVENANCE_NOTICE

    def test_findings_provenance_notice_contains_never_follow(self) -> None:
        assert "never follow" in trust_notices.FINDINGS_PROVENANCE_NOTICE

    def test_memory_trust_notice_matches_ai_memory_injector(self) -> None:
        """trust_notices.MEMORY_TRUST_NOTICE must be identical to the copy in ai_memory_injector."""
        from servonaut.services.ai_memory_injector import (
            MEMORY_TRUST_NOTICE as INJECTOR_NOTICE,
        )
        assert trust_notices.MEMORY_TRUST_NOTICE == INJECTOR_NOTICE


# ---------------------------------------------------------------------------
# TestService — MemoryService findings operations
# ---------------------------------------------------------------------------


def _make_service(tmp_path: Path, *, disabled: bool = False) -> MemoryService:
    """Return a MemoryService backed by a real MemoryStore in *tmp_path*.

    The sync service is a MagicMock so enqueue_findings is a silent no-op.
    """
    store = MemoryStore(root=tmp_path)
    config = MemoryConfig(
        enabled=not disabled,
        findings_confidence_threshold=0.6,
    )
    svc = MemoryService(store=store, config=config)
    mock_sync = MagicMock()
    mock_sync.enqueue_findings = MagicMock(return_value=None)
    svc.set_sync_service(mock_sync)
    return svc


_INSTANCE_WEB1: Dict[str, Any] = {
    "id": "web-1",
    "name": "web-1",
    "provider": "custom",
}

_INSTANCE_APP2: Dict[str, Any] = {
    "id": "app-2",
    "name": "app-2",
    "provider": "custom",
}


class TestService:
    """Unit tests for MemoryService findings operations."""

    # ------------------------------------------------------------------
    # remember_finding — basic write + return value
    # ------------------------------------------------------------------

    def test_remember_writes_record_and_returns_finding_id(
        self, tmp_path: Path
    ) -> None:
        svc = _make_service(tmp_path)
        result = svc.remember_finding(
            _INSTANCE_WEB1,
            title="Redis key missing",
            body="The session key was absent after restart.",
        )
        assert "finding_id" in result
        fid = result["finding_id"]
        assert fid.startswith("f_")
        assert result["instance_id"] == "web-1"
        assert result["title"] == "Redis key missing"
        # Record must be readable from the store.
        record = svc.get_finding("web-1", fid)
        assert record is not None
        assert record["title"] == "Redis key missing"

    def test_remember_returns_auto_inject_true_at_threshold(
        self, tmp_path: Path
    ) -> None:
        svc = _make_service(tmp_path)
        result = svc.remember_finding(
            _INSTANCE_WEB1,
            title="High confidence finding",
            body="Body text.",
            confidence=0.6,  # exactly at threshold
        )
        assert result["auto_inject"] is True

    def test_remember_returns_auto_inject_false_below_threshold(
        self, tmp_path: Path
    ) -> None:
        svc = _make_service(tmp_path)
        result = svc.remember_finding(
            _INSTANCE_WEB1,
            title="Low confidence finding",
            body="Speculative.",
            confidence=0.3,
        )
        assert result["auto_inject"] is False

    def test_remember_clamps_confidence_above_one(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        result = svc.remember_finding(
            _INSTANCE_WEB1, title="High", body="x", confidence=1.5
        )
        fid = result["finding_id"]
        record = svc.get_finding("web-1", fid)
        assert record is not None
        assert record["confidence"] == 1.0

    def test_remember_clamps_confidence_below_zero(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        result = svc.remember_finding(
            _INSTANCE_WEB1, title="Zero", body="x", confidence=-1.0
        )
        fid = result["finding_id"]
        record = svc.get_finding("web-1", fid)
        assert record is not None
        assert record["confidence"] == 0.0

    def test_remember_raises_on_empty_title(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        with pytest.raises(ValueError, match="title must not be empty"):
            svc.remember_finding(_INSTANCE_WEB1, title="   ", body="x")

    # ------------------------------------------------------------------
    # Opt-out gate
    # ------------------------------------------------------------------

    def test_remember_refuses_when_memory_disabled(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path, disabled=True)
        result = svc.remember_finding(
            _INSTANCE_WEB1, title="Finding", body="Body"
        )
        assert result == {"refused": True, "reason": "memory_disabled"}

    def test_recall_returns_empty_when_memory_disabled(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path, disabled=True)
        assert svc.recall_findings("web-1") == []

    def test_recall_honors_name_keyed_optout(self, tmp_path: Path) -> None:
        """A server opted out BY NAME (id != name) must not leak finding bodies
        through recall — the opt-out check must use both id AND name."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig(
            enabled=True,
            findings_confidence_threshold=0.6,
            # Override keyed by NAME, not the cloud id.
            per_server_overrides={"prod-web": {"memory_disabled": True}},
        )
        svc = MemoryService(store=store, config=config)
        mock_sync = MagicMock()
        mock_sync.enqueue_findings = MagicMock(return_value=None)
        svc.set_sync_service(mock_sync)
        # Seed a finding directly on disk (bypassing the disabled remember path).
        store.save_finding(
            "i-secret123",
            {
                "id": "f_" + "a" * 20,
                "instance_id": "i-secret123",
                "title": "secret",
                "body": "SENSITIVE BODY",
                "tags": [],
                "confidence": 0.9,
                "source": "agent",
                "created_at": "2026-06-10T00:00:00+00:00",
                "updated_at": "2026-06-10T00:00:00+00:00",
                "superseded_by": None,
            },
            "custom",
        )
        # id-only would miss the name override and leak; with the name it's empty.
        assert svc.recall_findings("i-secret123", instance_name="prod-web") == []

    # ------------------------------------------------------------------
    # recall_findings — lexical ranking
    # ------------------------------------------------------------------

    def test_recall_lexical_ranks_title_match_above_body_only(
        self, tmp_path: Path
    ) -> None:
        svc = _make_service(tmp_path)
        # title_match: word "redis" in title
        r1 = svc.remember_finding(
            _INSTANCE_WEB1,
            title="Redis connection failure",
            body="Some unrelated body text.",
            confidence=0.9,
        )
        # body_match: word "redis" only in body
        svc.remember_finding(
            _INSTANCE_WEB1,
            title="General error",
            body="Redis was unreachable during probe.",
            confidence=0.9,
        )
        hits = svc.recall_findings("web-1", query="redis")
        assert len(hits) == 2
        # Title-match must outrank body-only match.
        assert hits[0]["id"] == r1["finding_id"] or hits[0]["title"] == "Redis connection failure"

    def test_recall_tag_and_filter(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        svc.remember_finding(
            _INSTANCE_WEB1, title="Tagged AB", body="x",
            tags=["alpha", "beta"],
        )
        svc.remember_finding(
            _INSTANCE_WEB1, title="Tagged A only", body="x",
            tags=["alpha"],
        )
        # Filter requires BOTH alpha AND beta.
        hits = svc.recall_findings("web-1", tags=["alpha", "beta"])
        assert len(hits) == 1
        assert hits[0]["title"] == "Tagged AB"

    # ------------------------------------------------------------------
    # Supersede
    # ------------------------------------------------------------------

    def test_supersede_marks_old_finding_and_excludes_from_active_recall(
        self, tmp_path: Path
    ) -> None:
        svc = _make_service(tmp_path)
        r1 = svc.remember_finding(
            _INSTANCE_WEB1, title="Old finding", body="Original observation."
        )
        old_id = r1["finding_id"]

        r2 = svc.remember_finding(
            _INSTANCE_WEB1,
            title="Updated finding",
            body="Revised observation.",
            supersede_id=old_id,
        )
        new_id = r2["finding_id"]
        assert r2["superseded"] == old_id

        # Old finding must have superseded_by set.
        old_record = svc.get_finding("web-1", old_id)
        assert old_record is not None
        assert old_record["superseded_by"] == new_id

        # Active recall must not include the superseded finding.
        hits = svc.recall_findings("web-1")
        hit_ids = [h["id"] for h in hits]
        assert old_id not in hit_ids
        assert new_id in hit_ids

    # ------------------------------------------------------------------
    # Secret warning
    # ------------------------------------------------------------------

    def test_secret_warning_populated_but_record_still_saved(
        self, tmp_path: Path
    ) -> None:
        # A fake AWS access key pattern to trigger the scanner.
        fake_body = "Key is AKIAIOSFODNN7EXAMPLE stored in config."
        svc = _make_service(tmp_path)
        result = svc.remember_finding(
            _INSTANCE_WEB1, title="Credentials leak", body=fake_body
        )
        # Warning must be non-empty.
        assert result["secret_warning"]
        assert "aws-access-key" in result["secret_warning"]
        # Record must still be saved.
        assert svc.get_finding("web-1", result["finding_id"]) is not None

    # ------------------------------------------------------------------
    # Soft-cap pruning
    # ------------------------------------------------------------------

    def test_soft_cap_prunes_superseded_before_low_confidence(
        self, tmp_path: Path
    ) -> None:
        """With cap=2: save 2 superseded + 1 low-conf → superseded pruned first."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig(
            enabled=True,
            findings_confidence_threshold=0.6,
        )
        svc = MemoryService(store=store, config=config)
        # Override soft cap to 2 for this test.
        svc._FINDINGS_SOFT_CAP = 2

        # Save 2 superseded findings directly via store.
        sup1 = {
            "id": "f_superseded111111111111111",
            "instance_id": "web-1",
            "title": "Old1",
            "body": "",
            "tags": [],
            "confidence": 0.9,
            "source": "agent",
            "created_at": "2026-06-01T00:00:00+00:00",
            "updated_at": "2026-06-01T00:00:00+00:00",
            "superseded_by": "f_something111111111111111",
        }
        sup2 = {
            "id": "f_superseded222222222222222",
            "instance_id": "web-1",
            "title": "Old2",
            "body": "",
            "tags": [],
            "confidence": 0.9,
            "source": "agent",
            "created_at": "2026-06-02T00:00:00+00:00",
            "updated_at": "2026-06-02T00:00:00+00:00",
            "superseded_by": "f_something222222222222222",
        }
        store.save_finding("web-1", sup1)
        store.save_finding("web-1", sup2)

        # Now remember a new finding — this pushes total to 3, cap is 2.
        result = svc.remember_finding(
            _INSTANCE_WEB1,
            title="New active finding",
            body="body",
            confidence=0.1,  # low confidence — but superseded pruned first
        )
        pruned = result["pruned"]
        # At least one superseded finding must have been pruned.
        assert len(pruned) >= 1
        assert sup1["id"] in pruned or sup2["id"] in pruned

    # ------------------------------------------------------------------
    # merge_findings — last-writer-wins + monotonic supersede
    # ------------------------------------------------------------------

    def test_merge_creates_new_finding(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        incoming = [
            {
                "id": "f_merge111111111111111111111",
                "instance_id": "web-1",
                "title": "Merged finding",
                "body": "From server.",
                "tags": [],
                "confidence": 0.8,
                "source": "agent",
                "created_at": "2026-06-01T10:00:00+00:00",
                "updated_at": "2026-06-01T10:00:00+00:00",
                "superseded_by": None,
            }
        ]
        stats = svc.merge_findings("web-1", incoming)
        assert stats["created"] == 1
        assert stats["updated"] == 0
        assert stats["skipped"] == 0

    def test_merge_last_writer_wins_incoming_newer(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        fid = "f_lww1111111111111111111111111"
        # Save an older local version.
        store = svc._store
        store.save_finding("web-1", {
            "id": fid,
            "title": "Old local",
            "body": "old",
            "tags": [],
            "confidence": 0.5,
            "source": "agent",
            "created_at": "2026-06-01T00:00:00+00:00",
            "updated_at": "2026-06-01T00:00:00+00:00",
            "superseded_by": None,
        })
        incoming = [{
            "id": fid,
            "title": "Newer remote",
            "body": "newer",
            "tags": [],
            "confidence": 0.7,
            "source": "agent",
            "created_at": "2026-06-01T00:00:00+00:00",
            "updated_at": "2026-06-02T00:00:00+00:00",  # newer updated_at
            "superseded_by": None,
        }]
        stats = svc.merge_findings("web-1", incoming)
        assert stats["updated"] == 1
        saved = svc.get_finding("web-1", fid)
        assert saved is not None
        assert saved["title"] == "Newer remote"

    def test_merge_local_wins_on_tie(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        fid = "f_tie11111111111111111111111111"
        store = svc._store
        store.save_finding("web-1", {
            "id": fid,
            "title": "Local title",
            "body": "local",
            "tags": [],
            "confidence": 0.5,
            "source": "agent",
            "created_at": "2026-06-01T00:00:00+00:00",
            "updated_at": "2026-06-01T00:00:00+00:00",
            "superseded_by": None,
        })
        incoming = [{
            "id": fid,
            "title": "Remote title",
            "body": "remote",
            "tags": [],
            "confidence": 0.7,
            "source": "agent",
            "created_at": "2026-06-01T00:00:00+00:00",
            "updated_at": "2026-06-01T00:00:00+00:00",  # same timestamp
            "superseded_by": None,
        }]
        stats = svc.merge_findings("web-1", incoming)
        assert stats["skipped"] == 1
        saved = svc.get_finding("web-1", fid)
        assert saved is not None
        assert saved["title"] == "Local title"

    def test_merge_monotonic_supersede_incoming_sets_local_lacks(
        self, tmp_path: Path
    ) -> None:
        """Incoming has superseded_by set; local does not — merged record adopts it."""
        svc = _make_service(tmp_path)
        fid = "f_mono1111111111111111111111111"
        other_id = "f_other111111111111111111111111"
        store = svc._store
        store.save_finding("web-1", {
            "id": fid,
            "title": "Local no supersede",
            "body": "",
            "tags": [],
            "confidence": 0.5,
            "source": "agent",
            "created_at": "2026-06-01T00:00:00+00:00",
            "updated_at": "2026-06-01T00:00:00+00:00",
            "superseded_by": None,
        })
        # Incoming is older — local wins on time, but incoming carries superseded_by.
        incoming = [{
            "id": fid,
            "title": "Remote superseded",
            "body": "",
            "tags": [],
            "confidence": 0.5,
            "source": "agent",
            "created_at": "2026-05-31T00:00:00+00:00",
            "updated_at": "2026-05-31T00:00:00+00:00",
            "superseded_by": other_id,
        }]
        svc.merge_findings("web-1", incoming)
        saved = svc.get_finding("web-1", fid)
        assert saved is not None
        # Monotonic: superseded_by from incoming must survive even though local won.
        assert saved["superseded_by"] == other_id

    def test_merge_skips_invalid_id(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        stats = svc.merge_findings("web-1", [{"id": "BAD_ID", "title": "x"}])
        assert stats["skipped"] == 1
        assert stats["created"] == 0
