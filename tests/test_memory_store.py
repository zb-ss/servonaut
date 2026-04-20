"""Unit tests for MemoryStore (T1 storage layer)."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.store import (
    MemoryStore,
    _migrate_index,
    _validate_instance_id,
    _validate_module_name,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path: Path) -> MemoryStore:
    """MemoryStore with an isolated temp directory."""
    return MemoryStore(root=tmp_path)


@pytest.fixture
def default_config() -> MemoryConfig:
    """MemoryConfig with no overrides."""
    return MemoryConfig()


@pytest.fixture
def sample_module_data() -> dict:
    return {
        "module": "runtimes",
        "instance_id": "i-abc",
        "probed_at": datetime.now(tz=timezone.utc).isoformat(),
        "ttl_seconds": 604800,
        "sudo_used": False,
        "truncated": False,
        "partial": False,
        "observed": {"node": "v20.11.0", "python": "Python 3.11.2"},
        "declared": {},
        "raw_output": "node -v → v20.11.0",
    }


# ---------------------------------------------------------------------------
# Round-trip: write a module, read it back
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_save_and_get_returns_same_data(
        self, store: MemoryStore, sample_module_data: dict
    ) -> None:
        store.save_module("i-abc", "runtimes", sample_module_data, provider="aws")
        result = store.get_module("i-abc", "runtimes", provider="aws")
        assert result == sample_module_data

    def test_get_returns_none_when_missing(self, store: MemoryStore) -> None:
        assert store.get_module("i-missing", "os", provider="aws") is None

    def test_get_all_modules_returns_all(
        self, store: MemoryStore, sample_module_data: dict
    ) -> None:
        os_data = {**sample_module_data, "module": "os"}
        store.save_module("i-abc", "runtimes", sample_module_data, provider="aws")
        store.save_module("i-abc", "os", os_data, provider="aws")
        all_modules = store.get_all_modules("i-abc", provider="aws")
        assert set(all_modules.keys()) == {"runtimes", "os"}
        assert all_modules["runtimes"] == sample_module_data
        assert all_modules["os"] == os_data

    def test_get_all_modules_empty_when_no_data(self, store: MemoryStore) -> None:
        result = store.get_all_modules("i-absent", provider="aws")
        assert result == {}


# ---------------------------------------------------------------------------
# Atomic write: interruption must not corrupt the original
# ---------------------------------------------------------------------------

class TestAtomicWrite:
    def test_original_file_untouched_on_replace_failure(
        self, store: MemoryStore, sample_module_data: dict, tmp_path: Path
    ) -> None:
        # Write original data successfully.
        store.save_module("i-abc", "runtimes", sample_module_data, provider="aws")
        module_path = (
            tmp_path / "aws" / "i-abc" / "runtimes.json"
        )
        assert module_path.exists()

        new_data = {**sample_module_data, "observed": {"node": "v99.0.0"}}

        # Simulate os.replace raising mid-write.
        with patch("servonaut.services.memory.store.os.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError, match="disk full"):
                store.save_module("i-abc", "runtimes", new_data, provider="aws")

        # Original file must still contain the original data.
        with open(module_path) as fh:
            on_disk = json.load(fh)
        assert on_disk == sample_module_data

    def test_tmp_file_cleaned_up_on_write_failure(
        self, store: MemoryStore, sample_module_data: dict, tmp_path: Path
    ) -> None:
        # Patch fdopen so the write itself fails.
        original_open = os.fdopen

        def patched_fdopen(fd, mode):
            os.close(fd)  # release the fd so we don't leak it
            raise OSError("simulated write error")

        with patch("servonaut.services.memory.store.os.fdopen", side_effect=patched_fdopen):
            with pytest.raises(OSError):
                store.save_module("i-abc", "runtimes", sample_module_data, provider="aws")

        # No .tmp file should linger.
        tmp_files = list(tmp_path.rglob("*.tmp"))
        assert tmp_files == [], f"Stale tmp files found: {tmp_files}"


# ---------------------------------------------------------------------------
# File mode must be 0o600
# ---------------------------------------------------------------------------

class TestFileMode:
    def test_module_json_has_0600_mode(
        self, store: MemoryStore, sample_module_data: dict, tmp_path: Path
    ) -> None:
        store.save_module("i-abc", "runtimes", sample_module_data, provider="aws")
        path = tmp_path / "aws" / "i-abc" / "runtimes.json"
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_index_json_has_0600_mode(
        self, store: MemoryStore, tmp_path: Path
    ) -> None:
        store.update_index(
            instance_id="i-abc",
            name="web-prod",
            provider="AWS",
            modules=["os"],
        )
        index_path = tmp_path / "index.json"
        mode = stat.S_IMODE(os.stat(index_path).st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


# ---------------------------------------------------------------------------
# Index integrity
# ---------------------------------------------------------------------------

class TestIndex:
    def test_update_and_reload_index(self, store: MemoryStore) -> None:
        store.update_index("i-001", "web-1", "AWS", ["os", "runtimes"])
        store.update_index("i-002", "db-1", "AWS", ["os"])
        store.update_index("i-003", "cache-1", "custom", ["os", "services"])

        instances = store.list_instances()
        assert set(instances) == {"i-001", "i-002", "i-003"}

    def test_index_entry_contents(self, store: MemoryStore) -> None:
        store.update_index("i-abc", "web-prod", "AWS", ["os", "runtimes"])
        entry = store.get_index_entry("i-abc")
        assert entry is not None
        assert entry["name"] == "web-prod"
        assert entry["provider"] == "AWS"
        assert "os" in entry["modules"]
        assert "runtimes" in entry["modules"]
        assert "first_scan" in entry
        assert "last_scan" in entry

    def test_index_modules_accumulate_across_updates(self, store: MemoryStore) -> None:
        store.update_index("i-abc", "web", "AWS", ["os"])
        store.update_index("i-abc", "web", "AWS", ["runtimes"])
        entry = store.get_index_entry("i-abc")
        assert set(entry["modules"]) == {"os", "runtimes"}

    def test_first_scan_preserved_on_update(self, store: MemoryStore) -> None:
        store.update_index("i-abc", "web", "AWS", ["os"])
        first = store.get_index_entry("i-abc")["first_scan"]
        store.update_index("i-abc", "web", "AWS", ["runtimes"])
        second = store.get_index_entry("i-abc")["first_scan"]
        assert first == second


# ---------------------------------------------------------------------------
# Index migration
# ---------------------------------------------------------------------------

class TestIndexMigration:
    def test_version_1_unchanged(self) -> None:
        data = {"version": 1, "instances": {"i-abc": {"name": "web"}}}
        result = _migrate_index(data, from_version=1)
        assert result == data

    def test_version_0_upgraded_to_1(self) -> None:
        # Pre-versioned index: raw dict of instance entries, no "version" key.
        data = {"i-abc": {"name": "web"}, "i-def": {"name": "db"}}
        result = _migrate_index(data, from_version=0)
        assert result["version"] == 1
        assert "i-abc" in result["instances"]
        assert "i-def" in result["instances"]

    def test_unknown_version_raises(self) -> None:
        data = {"version": 99, "instances": {}}
        with pytest.raises(ValueError, match="Unknown index version"):
            _migrate_index(data, from_version=99)

    def test_store_loads_legacy_index(self, store: MemoryStore, tmp_path: Path) -> None:
        # Write a version-0 (pre-versioned) index directly to disk.
        index_path = tmp_path / "index.json"
        legacy = {"i-legacy": {"name": "old-server"}}
        with open(index_path, "w") as fh:
            json.dump(legacy, fh)

        instances = store.list_instances()
        assert "i-legacy" in instances


# ---------------------------------------------------------------------------
# TTL / is_stale
# ---------------------------------------------------------------------------

class TestTTL:
    def test_fresh_module_not_stale(
        self,
        store: MemoryStore,
        sample_module_data: dict,
        default_config: MemoryConfig,
    ) -> None:
        store.save_module("i-abc", "runtimes", sample_module_data, provider="aws")
        assert not store.is_stale(
            "i-abc", "runtimes", default_config, provider="aws", module_default_ttl=604800
        )

    def test_old_module_is_stale(
        self, store: MemoryStore, default_config: MemoryConfig, tmp_path: Path
    ) -> None:
        old_dt = datetime.now(tz=timezone.utc) - timedelta(days=30)
        old_data = {
            "module": "runtimes",
            "instance_id": "i-abc",
            "probed_at": old_dt.isoformat(),
            "ttl_seconds": 604800,
            "observed": {},
        }
        store.save_module("i-abc", "runtimes", old_data, provider="aws")
        assert store.is_stale(
            "i-abc", "runtimes", default_config, provider="aws", module_default_ttl=604800
        )

    def test_missing_module_is_stale(
        self, store: MemoryStore, default_config: MemoryConfig
    ) -> None:
        assert store.is_stale(
            "i-absent", "runtimes", default_config, provider="aws"
        )

    def test_config_ttl_override_respected(
        self, store: MemoryStore, sample_module_data: dict
    ) -> None:
        # Override TTL to 1 second; a just-probed module should be stale.
        config = MemoryConfig(default_ttl_overrides={"runtimes": 1})
        data = {
            **sample_module_data,
            "probed_at": (datetime.now(tz=timezone.utc) - timedelta(seconds=2)).isoformat(),
        }
        store.save_module("i-abc", "runtimes", data, provider="aws")
        assert store.is_stale(
            "i-abc", "runtimes", config, provider="aws", module_default_ttl=604800
        )

    def test_module_with_missing_probed_at_is_stale(
        self, store: MemoryStore, default_config: MemoryConfig
    ) -> None:
        data = {"module": "os", "instance_id": "i-abc", "probed_at": ""}
        store.save_module("i-abc", "os", data, provider="aws")
        assert store.is_stale("i-abc", "os", default_config, provider="aws")


# ---------------------------------------------------------------------------
# Instance-id sanitisation
# ---------------------------------------------------------------------------

class TestInstanceIdSanitisation:
    @pytest.mark.parametrize("bad_id", [
        "../evil",
        "etc/passwd",
        "foo/bar",
        "..\\evil",
        "foo\\bar",
        "..",
        "",
    ])
    def test_rejects_unsafe_ids(self, store: MemoryStore, bad_id: str) -> None:
        with pytest.raises(ValueError):
            store.save_module(bad_id, "os", {}, provider="aws")

    @pytest.mark.parametrize("bad_id", [
        "../evil",
        "",
        "a/b",
    ])
    def test_validate_raises_directly(self, bad_id: str) -> None:
        with pytest.raises(ValueError):
            _validate_instance_id(bad_id)

    @pytest.mark.parametrize("good_id", [
        "i-0123456789abcdef",
        "my-vps",
        "vps-123abc",
        "web-prod-1",
    ])
    def test_accepts_valid_ids(
        self, store: MemoryStore, good_id: str, sample_module_data: dict
    ) -> None:
        data = {**sample_module_data, "instance_id": good_id}
        # Should not raise.
        store.save_module(good_id, "os", data, provider="custom")


# ---------------------------------------------------------------------------
# Module-name sanitisation (path traversal prevention)
# ---------------------------------------------------------------------------

class TestModuleNameSanitisation:
    """Module names are whitelisted to ^[a-z][a-z0-9_]{0,30}$.

    Anything outside the whitelist must raise ``ValueError`` from save_module,
    get_module, and clear (with a modules list).
    """

    @pytest.mark.parametrize("bad_name", [
        "os.json/../../evil",  # path traversal via dot-extension
        "../evil",             # classic path traversal
        "os;rm -rf",           # shell injection
        "OS",                  # uppercase not allowed
        "",                    # empty string
        "a" * 100,             # too long (> 31 chars)
        ".hidden",             # leading dot
        "0starts_digit",       # must start with letter
        "has space",           # whitespace
        "has-hyphen",          # hyphens not allowed (only [a-z0-9_])
    ])
    def test_save_rejects_bad_module_names(
        self, store: MemoryStore, bad_name: str
    ) -> None:
        with pytest.raises(ValueError, match="Invalid module name"):
            store.save_module("i-abc", bad_name, {}, provider="aws")

    @pytest.mark.parametrize("bad_name", [
        "os.json/../../evil",
        "../evil",
        "OS",
        "",
        "a" * 100,
    ])
    def test_get_rejects_bad_module_names(
        self, store: MemoryStore, bad_name: str
    ) -> None:
        with pytest.raises(ValueError, match="Invalid module name"):
            store.get_module("i-abc", bad_name, provider="aws")

    @pytest.mark.parametrize("bad_name", [
        "os.json/../../evil",
        "../evil",
        "OS",
        "",
    ])
    def test_clear_rejects_bad_module_names(
        self, store: MemoryStore, bad_name: str
    ) -> None:
        with pytest.raises(ValueError, match="Invalid module name"):
            store.clear("i-abc", modules=[bad_name], provider="aws")

    @pytest.mark.parametrize("good_name", [
        "os",
        "runtimes",
        "web_stack",
        "services",
        "logs",
        "a",               # single char
        "abc123",          # alphanumeric
        "module_name_30x", # max-ish length
    ])
    def test_accepts_valid_module_names(
        self, store: MemoryStore, sample_module_data: dict, good_name: str
    ) -> None:
        # Must not raise.
        store.save_module("i-abc", good_name, sample_module_data, provider="aws")

    @pytest.mark.parametrize("bad_name", [
        "os.json/../../evil",
        "../evil",
        "OS",
        "",
        "a" * 100,
    ])
    def test_validate_module_name_raises_directly(self, bad_name: str) -> None:
        with pytest.raises(ValueError, match="Invalid module name"):
            _validate_module_name(bad_name)

    @pytest.mark.parametrize("good_name", ["os", "runtimes", "web_stack"])
    def test_validate_module_name_accepts_good_names(self, good_name: str) -> None:
        # Must not raise.
        _validate_module_name(good_name)


# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------

class TestClear:
    def test_per_module_clear_removes_one_file(
        self,
        store: MemoryStore,
        sample_module_data: dict,
        tmp_path: Path,
    ) -> None:
        os_data = {**sample_module_data, "module": "os"}
        store.save_module("i-abc", "runtimes", sample_module_data, provider="aws")
        store.save_module("i-abc", "os", os_data, provider="aws")

        store.clear("i-abc", modules=["runtimes"], provider="aws")

        assert store.get_module("i-abc", "runtimes", provider="aws") is None
        assert store.get_module("i-abc", "os", provider="aws") is not None

    def test_full_clear_removes_instance_directory(
        self, store: MemoryStore, sample_module_data: dict, tmp_path: Path
    ) -> None:
        store.save_module("i-abc", "runtimes", sample_module_data, provider="aws")
        store.save_module("i-abc", "os", sample_module_data, provider="aws")

        instance_dir = tmp_path / "aws" / "i-abc"
        assert instance_dir.exists()

        store.clear("i-abc", modules=None, provider="aws")

        assert not instance_dir.exists()

    def test_clear_nonexistent_instance_does_not_raise(
        self, store: MemoryStore
    ) -> None:
        # Should silently succeed.
        store.clear("i-does-not-exist", modules=None, provider="aws")
