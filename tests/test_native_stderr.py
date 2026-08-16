"""Tests for the fd-level stderr redirect that protects the TUI."""

from __future__ import annotations

import os
import sys

from servonaut.utils.native_stderr import redirect_native_stderr


class TestRedirectNativeStderr:

    def test_fd_level_writes_land_in_the_log(self, tmp_path):
        """C-library output (fd 2, not sys.stderr) must reach the file."""
        log = tmp_path / "native_stderr.log"
        with redirect_native_stderr(log) as engaged:
            assert engaged == log
            os.write(2, b"native library noise\n")
        assert b"native library noise" in log.read_bytes()

    def test_python_stderr_keeps_the_terminal_native_gets_the_log(self, tmp_path):
        """The load-bearing split: Textual renders the interface through the
        Python stderr object, so that must keep reaching the terminal while
        raw fd-2 writers go to the log. Regression guard for the redirect
        that sent the whole interface into the log file."""
        log = tmp_path / "native_stderr.log"
        read_end, write_end = os.pipe()
        saved = os.dup(2)
        try:
            os.dup2(write_end, 2)  # a fake terminal we can read back
            os.close(write_end)
            with redirect_native_stderr(log):
                sys.stderr.write("interface frame\n")
                sys.stderr.flush()
                os.write(2, b"native library noise\n")
            os.dup2(saved, 2)
            terminal = os.read(read_end, 4096)
        finally:
            os.dup2(saved, 2)
            os.close(saved)
            os.close(read_end)
        assert b"interface frame" in terminal
        assert b"native library noise" not in terminal
        content = log.read_bytes()
        assert b"native library noise" in content
        assert b"interface frame" not in content

    def test_stderr_objects_are_restored(self, tmp_path):
        log = tmp_path / "native_stderr.log"
        before, before_dunder = sys.stderr, sys.__stderr__
        with redirect_native_stderr(log):
            assert sys.stderr is not before
            assert sys.__stderr__ is not before_dunder
        assert sys.stderr is before
        assert sys.__stderr__ is before_dunder

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
