"""Tests for servonaut.utils.ephemeral_key."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.utils.ephemeral_key import (
    cleanup_stale_bw_keys,
    ephemeral_ssh_key,
    persistent_bw_ssh_key,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "AAAA...fake...key...body==\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)

SAMPLE_KEY_NO_NEWLINE = SAMPLE_KEY.rstrip("\n")


@pytest.fixture(autouse=True)
def redirect_runtime_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect Path.home() into tmp_path so tests don't touch ~/.servonaut."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_file_contains_key_body(self) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY) as path:
            content = Path(path).read_text()
        assert content == SAMPLE_KEY

    def test_file_permissions_are_0600(self) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY) as path:
            mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600

    def test_directory_permissions_are_0700_or_stricter(self, tmp_path: Path) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY) as path:
            parent = Path(path).parent
            dir_mode = os.stat(parent).st_mode & 0o777
        assert dir_mode <= 0o700, f"Expected <= 0700, got {oct(dir_mode)}"

    def test_directory_is_under_servonaut_tmp(self, tmp_path: Path) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY) as path:
            parent = Path(path).parent
        assert parent == tmp_path / ".servonaut" / "tmp"

    def test_file_deleted_after_normal_exit(self) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY) as path:
            pass
        assert not Path(path).exists()

    def test_containing_directory_persists_after_exit(self, tmp_path: Path) -> None:
        """The runtime dir is NOT removed — other servonaut processes may use it."""
        with ephemeral_ssh_key(SAMPLE_KEY) as path:
            parent = Path(path).parent
        assert parent.exists()

    def test_tmpfile_name_carries_default_prefix(self) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY) as path:
            name = Path(path).name
        assert name.startswith("servonaut-ssh-")

    def test_tmpfile_name_carries_custom_prefix(self) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY, prefix="bw-key-") as path:
            name = Path(path).name
        assert name.startswith("bw-key-")


class TestNewlineHandling:
    def test_trailing_newline_appended_when_missing(self) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY_NO_NEWLINE) as path:
            content = Path(path).read_text()
        assert content.endswith("\n")

    def test_trailing_newline_not_doubled_when_present(self) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY) as path:
            content = Path(path).read_text()
        assert not content.endswith("\n\n")

    def test_body_content_preserved_with_newline_appended(self) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY_NO_NEWLINE) as path:
            content = Path(path).read_text()
        assert content == SAMPLE_KEY_NO_NEWLINE + "\n"


class TestCleanupOnException:
    def test_file_deleted_even_on_exception(self) -> None:
        captured_path: list[str] = []
        with pytest.raises(RuntimeError, match="boom"):
            with ephemeral_ssh_key(SAMPLE_KEY) as path:
                captured_path.append(path)
                raise RuntimeError("boom")
        assert captured_path, "with-block body should have executed"
        assert not Path(captured_path[0]).exists()

    def test_exception_propagates_unchanged(self) -> None:
        with pytest.raises(ValueError, match="test-signal"):
            with ephemeral_ssh_key(SAMPLE_KEY):
                raise ValueError("test-signal")


class TestConcurrency:
    def test_two_concurrent_managers_yield_different_paths(self) -> None:
        with ephemeral_ssh_key(SAMPLE_KEY, prefix="key-a-") as path_a:
            with ephemeral_ssh_key(SAMPLE_KEY, prefix="key-b-") as path_b:
                assert path_a != path_b
                assert Path(path_a).exists()
                assert Path(path_b).exists()


class TestZeroWipe:
    def test_file_overwritten_with_zeros_before_unlink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Capture file contents just before unlink to verify zero-wipe."""
        captured_bytes: list[bytes] = []
        original_unlink = os.unlink

        def spy_unlink(p: str) -> None:
            # Read file bytes (if still present) before delegating to real unlink.
            try:
                with open(p, "rb") as fh:
                    captured_bytes.append(fh.read())
            except OSError:
                pass
            original_unlink(p)

        monkeypatch.setattr(os, "unlink", spy_unlink)

        with ephemeral_ssh_key(SAMPLE_KEY) as path:
            key_size = len(SAMPLE_KEY)

        assert captured_bytes, "spy_unlink was never called"
        wiped = captured_bytes[0]
        wiped_preview = repr(wiped[:40])
        assert wiped == b"\x00" * key_size, (
            f"Expected all-zero bytes of length {key_size}, got {wiped_preview}..."
        )


# ---------------------------------------------------------------------------
# persistent_bw_ssh_key tests
# ---------------------------------------------------------------------------


class TestPersistentBwSshKey:
    def test_file_written_with_0600_perms(self, tmp_path: Path) -> None:
        path = persistent_bw_ssh_key(SAMPLE_KEY)
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600

    def test_file_contains_key_body(self, tmp_path: Path) -> None:
        path = persistent_bw_ssh_key(SAMPLE_KEY)
        content = Path(path).read_text()
        assert content == SAMPLE_KEY

    def test_file_under_servonaut_tmp(self, tmp_path: Path) -> None:
        path = persistent_bw_ssh_key(SAMPLE_KEY)
        parent = Path(path).parent
        assert parent == tmp_path / ".servonaut" / "tmp"

    def test_dir_permissions_0700(self, tmp_path: Path) -> None:
        persistent_bw_ssh_key(SAMPLE_KEY)
        runtime_dir = tmp_path / ".servonaut" / "tmp"
        mode = os.stat(runtime_dir).st_mode & 0o777
        assert mode == 0o700

    def test_atexit_callback_registered(self, tmp_path: Path) -> None:
        """atexit.register must be called once per persistent_bw_ssh_key call."""
        with patch("atexit.register") as mock_register:
            persistent_bw_ssh_key(SAMPLE_KEY)
        mock_register.assert_called_once()

    def test_file_has_bw_prefix(self, tmp_path: Path) -> None:
        path = persistent_bw_ssh_key(SAMPLE_KEY)
        assert Path(path).name.startswith("bw-")

    def test_custom_prefix_used(self, tmp_path: Path) -> None:
        path = persistent_bw_ssh_key(SAMPLE_KEY, prefix="myprefix-")
        assert Path(path).name.startswith("myprefix-")

    def test_trailing_newline_appended(self, tmp_path: Path) -> None:
        path = persistent_bw_ssh_key(SAMPLE_KEY_NO_NEWLINE)
        content = Path(path).read_text()
        assert content.endswith("\n")

    def test_two_calls_produce_different_files(self, tmp_path: Path) -> None:
        path1 = persistent_bw_ssh_key(SAMPLE_KEY)
        path2 = persistent_bw_ssh_key(SAMPLE_KEY)
        assert path1 != path2


# ---------------------------------------------------------------------------
# cleanup_stale_bw_keys tests
# ---------------------------------------------------------------------------


class TestCleanupStaleBwKeys:
    def test_silent_when_tmp_dir_missing(self, tmp_path: Path) -> None:
        """cleanup_stale_bw_keys must not raise when the tmp dir doesn't exist."""
        # tmp_path is home; ~/.servonaut/tmp does NOT exist yet
        cleanup_stale_bw_keys(max_age_seconds=3600)  # should not raise

    def test_removes_old_bw_key(self, tmp_path: Path) -> None:
        """Files older than max_age_seconds with bw- prefix are deleted."""
        path = persistent_bw_ssh_key(SAMPLE_KEY)
        # Back-date the file by 2 days
        old_ts = time.time() - 172800
        os.utime(path, (old_ts, old_ts))

        cleanup_stale_bw_keys(max_age_seconds=86400)

        assert not Path(path).exists()

    def test_leaves_recent_bw_key(self, tmp_path: Path) -> None:
        """Recent files (within max_age_seconds) are left alone."""
        path = persistent_bw_ssh_key(SAMPLE_KEY)
        # File is freshly created — well within 24 h
        cleanup_stale_bw_keys(max_age_seconds=86400)
        assert Path(path).exists()

    def test_does_not_touch_non_bw_files(self, tmp_path: Path) -> None:
        """Files without the bw- prefix are not removed even when stale."""
        runtime_dir = tmp_path / ".servonaut" / "tmp"
        os.makedirs(str(runtime_dir), mode=0o700, exist_ok=True)
        other_file = runtime_dir / "servonaut-ssh-somefile"
        other_file.write_text("not a bw key")
        # Back-date
        old_ts = time.time() - 172800
        os.utime(str(other_file), (old_ts, old_ts))

        cleanup_stale_bw_keys(max_age_seconds=86400)

        assert other_file.exists()
