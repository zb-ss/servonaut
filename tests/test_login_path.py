"""Tests for the macOS login-shell PATH merge."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from servonaut.utils import login_path
from servonaut.utils.login_path import (
    merge_login_path,
    merged_path,
    probe_login_shell_path,
    well_known_bin_dirs,
)

LAUNCHD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def _env(path: str = LAUNCHD_PATH, **extra: str) -> dict[str, str]:
    return {"PATH": path, "SHELL": "/bin/sh", **extra}


@pytest.fixture
def no_extra_dirs(monkeypatch):
    monkeypatch.setattr(login_path, "well_known_bin_dirs", lambda home=None: ())


class TestWellKnownDirs:
    def test_order_and_home(self, tmp_path):
        assert well_known_bin_dirs(tmp_path) == (
            Path("/opt/homebrew/bin"),
            Path("/opt/homebrew/sbin"),
            Path("/usr/local/bin"),
            tmp_path / ".local" / "bin",
        )


class TestProbeSuccess:
    def test_login_entries_first_originals_kept_no_duplicates(self, no_extra_dirs):
        env = _env()
        changed = merge_login_path(
            environ=env,
            platform="darwin",
            probe=lambda s, t, e: "/opt/homebrew/bin:/usr/bin:/custom/bin",
        )
        assert changed is True
        parts = env["PATH"].split(":")
        assert parts[:3] == ["/opt/homebrew/bin", "/usr/bin", "/custom/bin"]
        assert {"/bin", "/usr/sbin", "/sbin"} <= set(parts)
        assert len(parts) == len(set(parts))


class TestPreferCurrent:
    """The MCP server keeps its client's PATH first and appends the rest."""

    def test_inherited_entries_stay_first(self, no_extra_dirs):
        env = _env("/client/bin:/usr/bin:/bin")
        changed = merge_login_path(
            environ=env,
            platform="darwin",
            probe=lambda s, t, e: "/opt/homebrew/bin:/usr/bin:/custom/bin",
            prefer_current=True,
        )
        assert changed is True
        assert env["PATH"].split(":") == [
            "/client/bin", "/usr/bin", "/bin", "/opt/homebrew/bin", "/custom/bin",
        ]

    def test_well_known_dirs_are_appended(self, tmp_path, monkeypatch):
        extra = tmp_path / "brew"
        extra.mkdir()
        monkeypatch.setattr(login_path, "well_known_bin_dirs", lambda home=None: (extra,))
        env = _env("/client/bin")
        merge_login_path(
            environ=env, platform="darwin", probe=lambda s, t, e: "/login/bin",
            prefer_current=True,
        )
        assert env["PATH"].split(":") == ["/client/bin", "/login/bin", str(extra)]

    def test_default_keeps_login_first(self, no_extra_dirs):
        env = _env("/client/bin")
        merge_login_path(environ=env, platform="darwin", probe=lambda s, t, e: "/login/bin")
        assert env["PATH"].split(":") == ["/login/bin", "/client/bin"]

    def test_merged_path_prefer_current(self):
        assert merged_path("/a:/b", "/b:/c", (), prefer_current=True) == "/a:/b:/c"


class TestFallback:
    def _dirs(self, tmp_path, monkeypatch):
        existing = tmp_path / "exists"
        existing.mkdir()
        missing = tmp_path / "missing"
        monkeypatch.setattr(
            login_path, "well_known_bin_dirs", lambda home=None: (existing, missing)
        )
        return existing

    def test_probe_none_appends_existing_dirs(self, tmp_path, monkeypatch):
        existing = self._dirs(tmp_path, monkeypatch)
        env = _env()
        merge_login_path(environ=env, platform="darwin", probe=lambda s, t, e: None)
        assert env["PATH"] == f"{LAUNCHD_PATH}:{existing}"

    def test_probe_raising_is_swallowed(self, tmp_path, monkeypatch):
        existing = self._dirs(tmp_path, monkeypatch)

        def boom(s, t, e):
            raise RuntimeError("boom")

        env = _env()
        assert merge_login_path(environ=env, platform="darwin", probe=boom) is True
        assert env["PATH"] == f"{LAUNCHD_PATH}:{existing}"

    def test_nothing_to_add_returns_false(self, no_extra_dirs):
        env = _env()
        assert (
            merge_login_path(environ=env, platform="darwin", probe=lambda s, t, e: None)
            is False
        )
        assert env["PATH"] == LAUNCHD_PATH


class TestMergedPath:
    def test_dedup_keeps_first(self):
        assert merged_path("/a:/b:/a", "/b:/c", ()) == "/b:/c:/a"

    def test_drops_empty_and_relative(self):
        assert merged_path("/a::rel/bin:.", "/b:bin", ()) == "/b:/a"


class TestGuards:
    def test_non_darwin_noop(self):
        def fail(s, t, e):
            pytest.fail("probe must not run")

        env = _env()
        assert merge_login_path(environ=env, platform="linux", probe=fail) is False
        assert env["PATH"] == LAUNCHD_PATH

    @pytest.mark.parametrize("value", ["0", "-1"])
    def test_non_positive_timeout_skips_probe(self, value, no_extra_dirs):
        def fail(s, t, e):
            pytest.fail("probe must not run")

        env = _env(SERVONAUT_LOGIN_PATH_TIMEOUT_SECONDS=value)
        merge_login_path(environ=env, platform="darwin", probe=fail)

    def test_invalid_timeout_uses_default(self, no_extra_dirs):
        seen: list[float] = []

        def spy(s, t, e):
            seen.append(t)
            return None

        env = _env(SERVONAUT_LOGIN_PATH_TIMEOUT_SECONDS="abc")
        merge_login_path(environ=env, platform="darwin", probe=spy)
        assert seen == [login_path._DEFAULT_PROBE_TIMEOUT_SECONDS]

    def test_unusable_shell_skips_probe(self, no_extra_dirs):
        def fail(s, t, e):
            pytest.fail("probe must not run")

        env = _env()
        env["SHELL"] = "/nonexistent/shell"
        merge_login_path(environ=env, platform="darwin", probe=fail)


@pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX shell")
class TestRealProbe:
    def test_reads_path_between_markers(self, tmp_path):
        shell = tmp_path / "fakeshell"
        shell.write_text(
            "#!/bin/sh\n"
            "echo 'rc noise before'\n"
            'PATH=/fake/bin:/usr/bin /bin/sh -c "$2"\n'
            "echo 'rc noise after'\n"
        )
        shell.chmod(0o755)
        result = probe_login_shell_path(str(shell), 5.0, dict(os.environ))
        assert result == "/fake/bin:/usr/bin"

    def test_timeout_returns_none_quickly(self, tmp_path):
        shell = tmp_path / "slowshell"
        shell.write_text("#!/bin/sh\nsleep 30\n")
        shell.chmod(0o755)
        start = time.monotonic()
        result = probe_login_shell_path(str(shell), 0.3, dict(os.environ))
        assert result is None
        assert time.monotonic() - start < 3

    def test_timeout_after_printing_the_path_still_answers(self, tmp_path):
        shell = tmp_path / "hangingshell"
        shell.write_text(
            "#!/bin/sh\n"
            'PATH=/fake/bin:/usr/bin /bin/sh -c "$2"\n'
            "sleep 30\n"
        )
        shell.chmod(0o755)
        start = time.monotonic()
        result = probe_login_shell_path(str(shell), 0.5, dict(os.environ))
        assert result == "/fake/bin:/usr/bin"
        assert time.monotonic() - start < 3

    def test_timeout_with_one_marker_returns_none(self, tmp_path):
        shell = tmp_path / "halfshell"
        shell.write_text(
            "#!/bin/sh\n"
            "printf '%s' __SERVONAUT_PATH_\n"
            "sleep 30\n"
        )
        shell.chmod(0o755)
        assert probe_login_shell_path(str(shell), 0.3, dict(os.environ)) is None


class TestTimeoutOutput:
    """The bytes a timed-out probe already wrote are searched for the PATH."""

    def _popen(self, monkeypatch, *, after_kill):
        import subprocess

        captured = {}

        class FakeProc:
            pid = 999_999

            def __init__(self, args, **kwargs):
                captured["script"] = args[2]
                self._calls = 0

            def communicate(self, timeout=None):
                self._calls += 1
                marker = captured["script"].split("'")[3]
                printed = f"noise{marker}/fake/bin{marker}".encode()
                if self._calls == 1:
                    raise subprocess.TimeoutExpired("sh", timeout, output=printed)
                if after_kill == "raise":
                    raise subprocess.TimeoutExpired("sh", timeout)
                return printed, None

        monkeypatch.setattr(login_path.subprocess, "Popen", FakeProc)
        monkeypatch.setattr(login_path.os, "killpg", lambda *a: None)

    def test_post_kill_output_is_used(self, monkeypatch):
        self._popen(monkeypatch, after_kill="return")
        assert probe_login_shell_path("/bin/sh", 0.1, {}) == "/fake/bin"

    def test_exception_output_is_used_when_the_drain_times_out(self, monkeypatch):
        self._popen(monkeypatch, after_kill="raise")
        assert probe_login_shell_path("/bin/sh", 0.1, {}) == "/fake/bin"
