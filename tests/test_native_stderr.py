"""Tests for the fd-level stderr redirect that protects the TUI."""

from __future__ import annotations

import os

from servonaut.utils.native_stderr import redirect_native_stderr


class TestRedirectNativeStderr:

    def test_fd_level_writes_land_in_the_log(self, tmp_path):
        """C-library output (fd 2, not sys.stderr) must reach the file."""
        log = tmp_path / "native_stderr.log"
        with redirect_native_stderr(log) as engaged:
            assert engaged == log
            os.write(2, b"native library noise\n")
        assert b"native library noise" in log.read_bytes()

    def test_stderr_is_restored_afterwards(self, tmp_path):
        log = tmp_path / "native_stderr.log"
        before = os.dup(2)
        try:
            with redirect_native_stderr(log):
                pass
            # Writes after the context must NOT land in the log.
            os.write(2, b"back on the terminal\n")
            assert b"back on the terminal" not in log.read_bytes()
        finally:
            # Repair fd 2 in case the assertion above interrupted state.
            os.dup2(before, 2)
            os.close(before)

    def test_restored_even_when_the_body_raises(self, tmp_path):
        log = tmp_path / "native_stderr.log"
        marker = b"post-crash traceback\n"
        try:
            with redirect_native_stderr(log):
                raise RuntimeError("app crashed")
        except RuntimeError:
            pass
        os.write(2, marker)
        assert marker not in log.read_bytes()

    def test_unwritable_path_degrades_to_no_redirect(self, tmp_path):
        """A failed redirect must never take the app down."""
        blocked = tmp_path / "not-a-dir"
        blocked.write_text("file where a directory is needed")
        with redirect_native_stderr(blocked / "native.log") as engaged:
            assert engaged is None

    def test_appends_across_runs(self, tmp_path):
        log = tmp_path / "native_stderr.log"
        for line in (b"first run\n", b"second run\n"):
            with redirect_native_stderr(log):
                os.write(2, line)
        content = log.read_bytes()
        assert b"first run" in content and b"second run" in content
