"""Tests for the resilient UpdateService upgrade path.

The key guarantee: run_upgrade NEVER reports success unless the installed
version actually advanced, and it refuses (with guidance) on source/local
installs that can't be release-upgraded in place.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from servonaut.runtime import DistributionKind, RuntimeEvidence, resolve_runtime
from servonaut.services.update_service import UpdateService


def _svc(current="2.16.3", latest="2.17.0", kind=DistributionKind.PIP):
    executable = Path(sys.executable)
    runtime = resolve_runtime(RuntimeEvidence(
        executable=executable,
        executable_root=executable.parent,
        resource_root=Path("/resources"),
        home=Path("/home/user"),
        is_frozen=kind in {DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP},
        package_version=current,
        package_is_installed=kind is not DistributionKind.SOURCE,
        source_install_path="file:///project" if kind is DistributionKind.SOURCE else None,
        path_console=None,
        pipx_executable=Path("/usr/bin/pipx") if kind is DistributionKind.PIPX else None,
        pipx_contains_servonaut=kind is DistributionKind.PIPX,
        marker=(
            {"schema_version": 1, "distribution": kind.value, "product_version": current,
             "channel": "stable", "packaging_revision": 1, "console_helper": "servonaut-cli"}
            if kind is DistributionKind.PACKAGED_DESKTOP else None
        ),
    ))
    service = UpdateService(runtime)
    service._latest = latest
    return service


def _fake_proc(returncode=0, out=b"ok"):
    p = MagicMock()
    p.returncode = returncode
    p.communicate = AsyncMock(return_value=(out, b""))
    return p


# --- version compare ---------------------------------------------------------

def test_is_newer():
    assert UpdateService._is_newer("2.17.0", "2.16.3")
    assert not UpdateService._is_newer("2.16.3", "2.17.0")
    assert not UpdateService._is_newer("2.17.0", "2.17.0")


# --- upgrade command targets the right environment ---------------------------

def test_get_upgrade_command_pip_uses_sys_executable(monkeypatch):
    s = _svc()
    assert s.get_upgrade_command() == [
        sys.executable, "-m", "pip", "install", "--upgrade", "servonaut"]


def test_get_upgrade_command_pipx_uses_full_path(monkeypatch):
    s = _svc(kind=DistributionKind.PIPX)
    assert s.get_upgrade_command() == [
        str(Path("/usr/bin/pipx")), "upgrade", "servonaut"
    ]


def test_source_missing_upgrade_command_has_no_side_effects():
    service = _svc(kind=DistributionKind.SOURCE)

    assert service.get_upgrade_command() is None
    assert service.update_status is None


def test_frozen_missing_upgrade_command_has_no_side_effects():
    service = _svc(kind=DistributionKind.FROZEN_CLI)

    assert service.get_upgrade_command() is None
    assert service.update_status is None
    assert service.check_for_update() is None
    assert "signed build" in service.update_status


# --- source/local installs are not silently "upgraded" -----------------------

def test_source_install_blocks_upgrade(monkeypatch):
    s = _svc(kind=DistributionKind.SOURCE)
    called = MagicMock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", called)
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is False
    assert "source installation" in msg
    called.assert_not_called()  # never ran a subprocess


def test_source_install_path_detects_a_local_directory(monkeypatch):
    s = _svc()

    class _Dist:
        def read_text(self, name):
            return '{"dir_info": {}, "url": "file:///home/user/servonaut"}'

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: _Dist())
    assert s.source_install_path() == "file:///home/user/servonaut"


def test_source_install_path_ignores_a_local_wheel_archive(monkeypatch):
    s = _svc()

    class _Dist:
        def read_text(self, name):
            return (
                '{"url": "file:///tmp/servonaut.whl", '
                '"archive_info": {"hash": "sha256=abc"}}'
            )

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: _Dist())
    assert s.source_install_path() is None


def test_source_install_path_detects_editable(monkeypatch):
    s = _svc()

    class _Dist:
        def read_text(self, name):
            return '{"url": "file:///x", "dir_info": {"editable": true}}'

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: _Dist())
    assert s.source_install_path() == "file:///x"


def test_source_install_path_none_for_pypi(monkeypatch):
    s = _svc()

    class _Dist:
        def read_text(self, name):
            return None  # PyPI wheels have no direct_url.json

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: _Dist())
    assert s.source_install_path() is None


# --- run_upgrade verifies the version actually changed ------------------------

def _wire_pypi_upgrade(monkeypatch, s, before, after, returncode=0, out=b"ok"):
    monkeypatch.setattr(s, "source_install_path", lambda: None)
    monkeypatch.setattr(s, "detect_install_method", lambda: "pipx")
    monkeypatch.setattr(s, "get_upgrade_command",
                        lambda: ["pipx", "upgrade", "servonaut"])
    monkeypatch.setattr(s, "installed_version_external",
                        MagicMock(side_effect=[before, after]))
    monkeypatch.setattr(asyncio, "create_subprocess_exec",
                        AsyncMock(return_value=_fake_proc(returncode, out)))


def test_run_upgrade_success_when_version_advances(monkeypatch):
    s = _svc()
    _wire_pypi_upgrade(monkeypatch, s, "2.16.3", "2.17.0")
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is True and "2.16.3" in msg and "2.17.0" in msg


def test_run_upgrade_honest_when_version_unchanged(monkeypatch):
    # The original bug: exit 0 but nothing actually upgraded.
    s = _svc()
    _wire_pypi_upgrade(monkeypatch, s, "2.16.3", "2.16.3")
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is False
    assert "still v2.16.3" in msg and "expected v2.17.0" in msg


def test_run_upgrade_already_latest(monkeypatch):
    s = _svc(current="2.17.0", latest="2.17.0")
    _wire_pypi_upgrade(monkeypatch, s, "2.17.0", "2.17.0")
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is True and "latest" in msg.lower()


def test_run_upgrade_command_failure(monkeypatch):
    s = _svc()
    monkeypatch.setattr(s, "source_install_path", lambda: None)
    monkeypatch.setattr(s, "detect_install_method", lambda: "pipx")
    monkeypatch.setattr(s, "get_upgrade_command",
                        lambda: ["pipx", "upgrade", "servonaut"])
    monkeypatch.setattr(s, "installed_version_external", lambda: "2.16.3")
    monkeypatch.setattr(asyncio, "create_subprocess_exec",
                        AsyncMock(return_value=_fake_proc(1, b"boom")))
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is False and "failed" in msg.lower() and "boom" in msg


def test_run_upgrade_missing_command(monkeypatch):
    s = _svc()
    monkeypatch.setattr(s, "source_install_path", lambda: None)
    monkeypatch.setattr(s, "detect_install_method", lambda: "pipx")
    monkeypatch.setattr(s, "get_upgrade_command",
                        lambda: ["pipx", "upgrade", "servonaut"])
    monkeypatch.setattr(s, "installed_version_external", lambda: "2.16.3")
    monkeypatch.setattr(asyncio, "create_subprocess_exec",
                        AsyncMock(side_effect=OSError("no pipx")))
    ok, msg = asyncio.run(s.run_upgrade())
    assert ok is False and "Could not run" in msg
