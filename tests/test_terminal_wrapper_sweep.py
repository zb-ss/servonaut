"""Tests for SSH wrapper script creation + stale-file sweep.

``TerminalService._create_wrapper_script`` drops bash wrappers into
``~/.servonaut/logs/`` so terminal emulators stay open on SSH failure.
Without a sweep those files accumulated forever — one per SSH launch.
These tests pin the new sweep behaviour so a future refactor can't
quietly regress it.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.services import terminal_service as ts_mod
from servonaut.services.terminal_service import TerminalService


@pytest.fixture
def wrapper_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the module-level wrapper directory to a tmp path."""
    monkeypatch.setattr(ts_mod, "_WRAPPER_DIR", tmp_path)
    return tmp_path


def test_sweep_removes_files_older_than_ttl(wrapper_dir: Path) -> None:
    """Files whose mtime is older than _WRAPPER_TTL_SECONDS are unlinked."""
    stale = wrapper_dir / "servonaut_old.sh"
    stale.write_text("# stale")
    # Rewind mtime two days so the sweep is guaranteed to match.
    two_days_ago = time.time() - (2 * 24 * 60 * 60)
    os.utime(stale, (two_days_ago, two_days_ago))

    fresh = wrapper_dir / "servonaut_new.sh"
    fresh.write_text("# fresh")

    TerminalService._sweep_stale_wrappers()

    assert not stale.exists(), "stale wrapper should be swept"
    assert fresh.exists(), "fresh wrapper must survive the sweep"


def test_sweep_removes_only_stale_owned_wrapper_suffixes(wrapper_dir: Path) -> None:
    """The Windows wrappers are swept too, without touching other log files."""
    old_time = time.time() - (2 * 24 * 60 * 60)
    for suffix in (".ps1", ".cmd"):
        wrapper = wrapper_dir / f"servonaut_old{suffix}"
        wrapper.write_text("stale")
        os.utime(wrapper, (old_time, old_time))

    unrelated = wrapper_dir / "other.cmd"
    unrelated.write_text("keep")
    os.utime(unrelated, (old_time, old_time))

    TerminalService._sweep_stale_wrappers()

    assert not (wrapper_dir / "servonaut_old.ps1").exists()
    assert not (wrapper_dir / "servonaut_old.cmd").exists()
    assert unrelated.exists()


def test_sweep_ignores_non_servonaut_files(wrapper_dir: Path) -> None:
    """Unrelated files in the logs directory are never touched."""
    other = wrapper_dir / "servonaut.log"
    other.write_text("application log")
    # Age it past the TTL so we'd unlink it if the glob were too loose.
    two_days_ago = time.time() - (2 * 24 * 60 * 60)
    os.utime(other, (two_days_ago, two_days_ago))

    TerminalService._sweep_stale_wrappers()

    assert other.exists(), "servonaut.log must not match the sweep glob"


@pytest.mark.skipif(os.name == "nt", reason="POSIX wrapper mode and permissions")
def test_create_wrapper_triggers_sweep(wrapper_dir: Path) -> None:
    """_create_wrapper_script sweeps before writing the new wrapper."""
    svc = TerminalService()
    with patch.object(
        TerminalService, "_sweep_stale_wrappers", wraps=TerminalService._sweep_stale_wrappers
    ) as sweep_mock:
        path = svc._create_wrapper_script(["ssh", "user@host"])
        sweep_mock.assert_called_once()

    wrapper = Path(path)
    assert wrapper.exists(), "new wrapper script must be written"
    assert wrapper.stat().st_mode & 0o777 == 0o700
    assert "ssh user@host" in wrapper.read_text()


@pytest.mark.skipif(os.name == "nt", reason="requires a POSIX shell")
def test_posix_wrapper_executes_a_literal_argv(wrapper_dir: Path, tmp_path: Path) -> None:
    """A generated POSIX wrapper actually preserves shell-sensitive argv."""
    output = tmp_path / "captured.txt"
    payload = "spaces & | < > $dollar 'quote' \\"
    command = [
        sys.executable,
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text(repr(sys.argv[2]))",
        str(output),
        payload,
    ]

    wrapper = TerminalService()._create_posix_wrapper(command)
    result = subprocess.run(["bash", wrapper], check=False, capture_output=True, text=True)

    assert result.returncode == 0
    assert output.read_text() == repr(payload)


def test_sweep_missing_directory_is_noop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No directory, no error — the sweep bails cleanly."""
    missing = tmp_path / "does_not_exist"
    monkeypatch.setattr(ts_mod, "_WRAPPER_DIR", missing)
    TerminalService._sweep_stale_wrappers()  # must not raise
