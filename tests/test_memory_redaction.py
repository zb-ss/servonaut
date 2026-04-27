"""Tests for the redaction seam in MemoryStore.

Verifies that:
- A custom redactor supplied at MemoryStore construction time is applied to
  raw_output before the data is written to disk.
- The noop_redactor (default) leaves text unchanged.
- MemoryService default-constructs MemoryStore with noop_redactor wired.

This is the seam test that ensures T9 can plug in a real redaction
implementation by replacing noop_redactor without touching any other call sites.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.store import MemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_data(raw_output: str) -> dict:
    return {
        "module": "os",
        "instance_id": "i-redact-test",
        "probed_at": "2026-04-20T00:00:00+00:00",
        "ttl_seconds": 86400,
        "sudo_used": False,
        "truncated": False,
        "partial": False,
        "observed": {"pretty_name": "Ubuntu 22.04"},
        "declared": {},
        "raw_output": raw_output,
    }


def _read_raw_output(store: MemoryStore, instance_id: str, module: str) -> str:
    data = store.get_module(instance_id, module, provider="custom")
    assert data is not None, "Module data not found in store"
    return data["raw_output"]


# ---------------------------------------------------------------------------
# noop_redactor
# ---------------------------------------------------------------------------

class TestNoopRedactor:
    def test_returns_text_unchanged(self) -> None:
        assert noop_redactor("hello world") == "hello world"

    def test_returns_empty_unchanged(self) -> None:
        assert noop_redactor("") == ""

    def test_returns_sensitive_text_unchanged(self) -> None:
        # noop_redactor intentionally does NOT redact — that is T9's job.
        text = "AWS_KEY_XYZ=AKIAIOSFODNN7EXAMPLE"
        assert noop_redactor(text) == text


# ---------------------------------------------------------------------------
# MemoryStore redaction seam
# ---------------------------------------------------------------------------

class TestMemoryStoreRedactionSeam:
    """Verify the redactor callable is applied to raw_output on write."""

    def test_custom_redactor_applied_on_save(self, tmp_path: Path) -> None:
        """A redactor that replaces 'AWS_KEY_XYZ' with '<redacted>' must fire."""
        sentinel = "AWS_KEY_XYZ"

        def _redactor(text: str) -> str:
            return text.replace(sentinel, "<redacted>")

        store = MemoryStore(root=tmp_path, redactor=_redactor)
        data = _make_data(f"some output {sentinel} more output")
        store.save_module("i-redact-test", "os", data, provider="custom")

        on_disk = _read_raw_output(store, "i-redact-test", "os")
        assert sentinel not in on_disk, (
            f"Redaction did not fire: sentinel '{sentinel}' still present on disk."
        )
        assert "<redacted>" in on_disk

    def test_no_redactor_leaves_output_unchanged(self, tmp_path: Path) -> None:
        """When no redactor is supplied (None), raw_output is written verbatim."""
        store = MemoryStore(root=tmp_path, redactor=None)
        raw = "plain output with nothing sensitive"
        data = _make_data(raw)
        store.save_module("i-noop-test", "os", data, provider="custom")

        on_disk = _read_raw_output(store, "i-noop-test", "os")
        assert on_disk == raw

    def test_noop_redactor_leaves_output_unchanged(self, tmp_path: Path) -> None:
        """noop_redactor must leave raw_output byte-identical to the original."""
        store = MemoryStore(root=tmp_path, redactor=noop_redactor)
        raw = "token=super_secret_value and more text"
        data = _make_data(raw)
        store.save_module("i-noop-redact", "os", data, provider="custom")

        on_disk = _read_raw_output(store, "i-noop-redact", "os")
        assert on_disk == raw

    def test_caller_dict_not_mutated(self, tmp_path: Path) -> None:
        """save_module must not mutate the caller's dict (uses a shallow copy)."""
        sentinel = "ORIGINAL_VALUE"

        def _redactor(text: str) -> str:
            return text.replace(sentinel, "<redacted>")

        store = MemoryStore(root=tmp_path, redactor=_redactor)
        data = _make_data(sentinel)
        original_raw = data["raw_output"]
        store.save_module("i-mutate-test", "os", data, provider="custom")

        # The caller's dict must be untouched.
        assert data["raw_output"] == original_raw, (
            "save_module mutated the caller's dict — must use a copy."
        )


# ---------------------------------------------------------------------------
# MemoryService default-constructs store with noop_redactor
# ---------------------------------------------------------------------------

class TestMemoryServiceDefaultRedactor:
    """MemoryService with no store argument must wire noop_redactor by default."""

    def test_service_default_store_has_redactor(self) -> None:
        """MemoryService() without an explicit store must inject noop_redactor."""
        from servonaut.config.schema import MemoryConfig
        from servonaut.services.memory.service import MemoryService

        config = MemoryConfig()
        # Construct with no store — service must default-construct one.
        service = MemoryService(config=config)
        # The internal store must have a redactor wired.
        assert service._store._redactor is not None, (
            "MemoryService default store has no redactor — noop_redactor must be injected."
        )

    def test_service_explicit_store_respected(self, tmp_path: Path) -> None:
        """When an explicit store is passed, MemoryService uses it as-is."""
        from servonaut.config.schema import MemoryConfig
        from servonaut.services.memory.service import MemoryService

        explicit_store = MemoryStore(root=tmp_path, redactor=None)
        config = MemoryConfig()
        service = MemoryService(store=explicit_store, config=config)
        assert service._store is explicit_store
