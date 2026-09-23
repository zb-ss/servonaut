"""Unit tests for VoiceRuntimeManager and companion runtime provisioning.

Verifies:
- Requirements canonicalization and deterministic hashing
- Manifest serialization, validation, and schema version checking
- Inter-process file locking, contention, and timeout handling
- Runtime state inspection (NOT_INSTALLED, INSTALLING, CORRUPTED, UPDATE_AVAILABLE, READY)
- Virtualenv provisioning lifecycle, .pth linking, and progress reporting
- Failure handling (pip failure, timeout, smoke test failure)
- get_worker_cmd resolution and readiness gating
- Repair and uninstallation
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from servonaut.desktop.voice.requirements import (
    VOICE_RUNTIME_VERSION,
    compute_requirements_hash,
    get_default_requirements,
)
from servonaut.desktop.voice.runtime import (
    DEFAULT_RUNTIME_ROOT,
    VoiceRuntimeError,
    VoiceRuntimeLock,
    VoiceRuntimeLockError,
    VoiceRuntimeManifest,
    VoiceRuntimeManager,
    VoiceRuntimeState,
    VoiceRuntimeStatus,
)


class TestVoiceRequirements:
    def test_requirements_hash_is_deterministic(self) -> None:
        reqs1 = ["sounddevice>=0.4.6", "numpy>=1.24.0", "scipy>=1.10.0"]
        reqs2 = ["numpy>=1.24.0", "scipy>=1.10.0", "sounddevice>=0.4.6"]
        h1 = compute_requirements_hash(reqs1)
        h2 = compute_requirements_hash(reqs2)
        assert h1 == h2
        assert len(h1) == 64

    def test_requirements_hash_ignores_comments_and_whitespace(self) -> None:
        reqs1 = ["numpy>=1.24.0", "  sounddevice>=0.4.6  ", "# comment line", ""]
        reqs2 = ["numpy>=1.24.0", "sounddevice>=0.4.6"]
        assert compute_requirements_hash(reqs1) == compute_requirements_hash(reqs2)

    def test_requirements_hash_changes_on_version_difference(self) -> None:
        reqs1 = ["numpy>=1.24.0"]
        reqs2 = ["numpy>=1.25.0"]
        assert compute_requirements_hash(reqs1) != compute_requirements_hash(reqs2)

    def test_get_default_requirements(self) -> None:
        reqs = get_default_requirements()
        assert any("numpy" in r for r in reqs)
        assert any("sounddevice" in r for r in reqs)


class TestVoiceRuntimeManifest:
    def test_manifest_roundtrip(self) -> None:
        m = VoiceRuntimeManifest(
            schema_version=1,
            runtime_version="1.0.0",
            servonaut_version="0.59.0",
            created_at="2026-09-23T00:00:00Z",
            python_version="3.12.0",
            platform="linux",
            architecture="x86_64",
            requirements_sha256="abc123def456",
            status="ready",
        )
        data = m.to_dict()
        assert data["schema_version"] == 1
        assert data["runtime_version"] == "1.0.0"

        restored = VoiceRuntimeManifest.from_dict(data)
        assert restored == m

    def test_manifest_invalid_schema_version(self) -> None:
        data = {
            "schema_version": 999,
            "runtime_version": "1.0.0",
        }
        with pytest.raises(VoiceRuntimeError, match="Unsupported manifest schema_version"):
            VoiceRuntimeManifest.from_dict(data)

    def test_manifest_default_status(self) -> None:
        data = {
            "schema_version": 1,
            "runtime_version": "1.0.0",
            "servonaut_version": "0.59.0",
            "created_at": "2026-09-23T00:00:00Z",
            "python_version": "3.12.0",
            "platform": "linux",
            "architecture": "x86_64",
            "requirements_sha256": "abc123def456",
        }
        m = VoiceRuntimeManifest.from_dict(data)
        assert m.status == "ready"


class TestVoiceRuntimeLock:
    def test_lock_acquire_and_release(self, tmp_path: Path) -> None:
        lock_file = tmp_path / ".runtime.lock"
        lock = VoiceRuntimeLock(lock_file, timeout=1.0)
        assert not lock.is_locked()

        lock.acquire()
        assert lock.is_locked()

        lock.release()
        assert not lock.is_locked()

    def test_lock_context_manager(self, tmp_path: Path) -> None:
        lock_file = tmp_path / ".runtime.lock"
        lock = VoiceRuntimeLock(lock_file, timeout=1.0)
        assert not lock.is_locked()

        with lock:
            assert lock.is_locked()

        assert not lock.is_locked()

    def test_lock_contention_timeout(self, tmp_path: Path) -> None:
        lock_file = tmp_path / ".runtime.lock"
        lock1 = VoiceRuntimeLock(lock_file, timeout=2.0)
        lock2 = VoiceRuntimeLock(lock_file, timeout=0.2)

        lock1.acquire()
        try:
            with pytest.raises(VoiceRuntimeLockError, match="Failed to acquire voice runtime lock"):
                lock2.acquire()
        finally:
            lock1.release()

        # After lock1 releases, lock2 can acquire
        lock2.acquire()
        lock2.release()


class TestVoiceRuntimeManagerStatus:
    def test_status_not_installed_when_empty(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        status = mgr.status()
        assert status.state is VoiceRuntimeState.NOT_INSTALLED
        assert not status.is_ready
        assert "not installed" in status.message

    def test_status_installing_when_locked(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        lock = VoiceRuntimeLock(mgr.lock_path, timeout=1.0)
        lock.acquire()
        try:
            status = mgr.status()
            assert status.state is VoiceRuntimeState.INSTALLING
            assert not status.is_ready
            assert "in progress" in status.message
        finally:
            lock.release()

    def test_status_corrupted_missing_manifest(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        # Create dummy python executable
        mgr.python_executable.parent.mkdir(parents=True, exist_ok=True)
        mgr.python_executable.write_text("#!/bin/sh\nexit 0\n")
        mgr.python_executable.chmod(0o755)

        status = mgr.status()
        assert status.state is VoiceRuntimeState.CORRUPTED
        assert not status.is_ready
        assert "manifest.json is missing" in status.message

    def test_status_corrupted_invalid_manifest(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        mgr.python_executable.parent.mkdir(parents=True, exist_ok=True)
        mgr.python_executable.write_text("#!/bin/sh\nexit 0\n")
        mgr.python_executable.chmod(0o755)
        mgr.manifest_path.write_text("invalid json{{{{", encoding="utf-8")

        status = mgr.status()
        assert status.state is VoiceRuntimeState.CORRUPTED
        assert "Failed to read or parse" in status.message

    def test_status_corrupted_python_fails_exec(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        mgr.python_executable.parent.mkdir(parents=True, exist_ok=True)
        mgr.python_executable.write_text("#!/bin/sh\nexit 1\n")
        mgr.python_executable.chmod(0o755)

        manifest = VoiceRuntimeManifest(
            schema_version=1,
            runtime_version=VOICE_RUNTIME_VERSION,
            servonaut_version="0.59.0",
            created_at="2026-09-23T00:00:00Z",
            python_version="3.12.0",
            platform=sys.platform,
            architecture="x86_64",
            requirements_sha256=compute_requirements_hash(get_default_requirements()),
        )
        mgr.manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="exec error")
            status = mgr.status()
            assert status.state is VoiceRuntimeState.CORRUPTED
            assert "returned code 1" in status.message

    def test_status_update_available_when_requirements_mismatch(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        mgr.python_executable.parent.mkdir(parents=True, exist_ok=True)
        mgr.python_executable.write_text("#!/bin/sh\nexit 0\n")
        mgr.python_executable.chmod(0o755)

        manifest = VoiceRuntimeManifest(
            schema_version=1,
            runtime_version=VOICE_RUNTIME_VERSION,
            servonaut_version="0.59.0",
            created_at="2026-09-23T00:00:00Z",
            python_version="3.12.0",
            platform=sys.platform,
            architecture="x86_64",
            requirements_sha256="old_hash_12345",
        )
        mgr.manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Python 3.12.0\n")
            status = mgr.status()
            assert status.state is VoiceRuntimeState.UPDATE_AVAILABLE
            assert not status.is_ready
            assert "details" in status.details or "installed_hash" in status.details

    def test_status_corrupted_smoke_check_failure(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        mgr.python_executable.parent.mkdir(parents=True, exist_ok=True)
        mgr.python_executable.write_text("#!/bin/sh\nexit 0\n")
        mgr.python_executable.chmod(0o755)

        req_hash = compute_requirements_hash(get_default_requirements())
        manifest = VoiceRuntimeManifest(
            schema_version=1,
            runtime_version=VOICE_RUNTIME_VERSION,
            servonaut_version="0.59.0",
            created_at="2026-09-23T00:00:00Z",
            python_version="3.12.0",
            platform=sys.platform,
            architecture="x86_64",
            requirements_sha256=req_hash,
        )
        mgr.manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")

        def fake_run(cmd, *args, **kwargs):
            if "--version" in cmd:
                return MagicMock(returncode=0, stdout="Python 3.12.0\n")
            if "-c" in cmd and "servonaut.desktop.voice.worker" in cmd[2]:
                return MagicMock(returncode=1, stderr="ImportError: missing numpy")
            return MagicMock(returncode=0)

        with patch("subprocess.run", side_effect=fake_run):
            status = mgr.status()
            assert status.state is VoiceRuntimeState.CORRUPTED
            assert "Companion smoke test failed" in status.message

    def test_status_ready_success(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        mgr.python_executable.parent.mkdir(parents=True, exist_ok=True)
        mgr.python_executable.write_text("#!/bin/sh\nexit 0\n")
        mgr.python_executable.chmod(0o755)

        req_hash = compute_requirements_hash(get_default_requirements())
        manifest = VoiceRuntimeManifest(
            schema_version=1,
            runtime_version=VOICE_RUNTIME_VERSION,
            servonaut_version="0.59.0",
            created_at="2026-09-23T00:00:00Z",
            python_version="3.12.0",
            platform=sys.platform,
            architecture="x86_64",
            requirements_sha256=req_hash,
        )
        mgr.manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Python 3.12.0\n")
            status = mgr.status()
            assert status.state is VoiceRuntimeState.READY
            assert status.is_ready
            assert mgr.is_ready()


class TestVoiceRuntimeManagerWorkerCmd:
    def test_get_worker_cmd_raises_when_not_ready(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        with pytest.raises(VoiceRuntimeError, match="Cannot launch VoiceWorker"):
            mgr.get_worker_cmd()

    def test_get_worker_cmd_returns_argv_when_ready(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        with patch.object(mgr, "status") as mock_status:
            mock_status.return_value = VoiceRuntimeStatus(
                state=VoiceRuntimeState.READY,
                runtime_dir=tmp_path,
                python_executable=mgr.python_executable,
            )
            cmd = mgr.get_worker_cmd()
            assert cmd == [str(mgr.python_executable), "-m", "servonaut.desktop.voice.worker"]


class TestVoiceRuntimeManagerProvisioning:
    def test_provision_progress_and_success(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)

        phases: list[tuple[str, float, str]] = []

        def callback(phase: str, pct: float, msg: str) -> None:
            phases.append((phase, pct, msg))

        # Mock venv.EnvBuilder to avoid slow real pip download during tests
        def mock_builder_create(target_dir):
            python_path = mgr.python_executable
            python_path.parent.mkdir(parents=True, exist_ok=True)
            python_path.write_text("#!/bin/sh\nexit 0\n")
            python_path.chmod(0o755)
            # Create site-packages
            sp = mgr.venv_dir / ("Lib" if os.name == "nt" else "lib") / "python3.12" / "site-packages"
            sp.mkdir(parents=True, exist_ok=True)

        def mock_run(cmd, *args, **kwargs):
            if "--version" in cmd:
                return MagicMock(returncode=0, stdout="Python 3.12.0\n")
            if "pip" in cmd:
                return MagicMock(returncode=0, stdout="Successfully installed")
            if "worker" in str(cmd):
                return MagicMock(returncode=0, stdout="OK\n")
            return MagicMock(returncode=0)

        with (
            patch("venv.EnvBuilder.create", side_effect=mock_builder_create),
            patch("subprocess.run", side_effect=mock_run),
        ):
            status = mgr.provision(progress_callback=callback)
            assert status.state is VoiceRuntimeState.READY
            assert mgr.manifest_path.exists()

            # Check that phases were reported
            reported_phases = [p[0] for p in phases]
            assert "init" in reported_phases
            assert "venv" in reported_phases
            assert "link" in reported_phases
            assert "pip" in reported_phases
            assert "verify" in reported_phases
            assert "manifest" in reported_phases
            assert "done" in reported_phases

            # Verify .pth file created
            sp_dirs = list(mgr.venv_dir.rglob("site-packages"))
            assert len(sp_dirs) > 0
            pth_file = sp_dirs[0] / "servonaut_companion.pth"
            assert pth_file.exists()

    def test_provision_pip_failure(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)

        def mock_builder_create(target_dir):
            python_path = mgr.python_executable
            python_path.parent.mkdir(parents=True, exist_ok=True)
            python_path.write_text("#!/bin/sh\nexit 0\n")
            python_path.chmod(0o755)

        def mock_run(cmd, *args, **kwargs):
            if "pip" in cmd:
                return MagicMock(returncode=1, stderr="ERROR: Could not find a version")
            return MagicMock(returncode=0)

        with (
            patch("venv.EnvBuilder.create", side_effect=mock_builder_create),
            patch("subprocess.run", side_effect=mock_run),
        ):
            with pytest.raises(VoiceRuntimeError, match="Package installation failed"):
                mgr.provision()

    def test_provision_pip_timeout(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)

        def mock_builder_create(target_dir):
            python_path = mgr.python_executable
            python_path.parent.mkdir(parents=True, exist_ok=True)
            python_path.write_text("#!/bin/sh\nexit 0\n")
            python_path.chmod(0o755)

        with (
            patch("venv.EnvBuilder.create", side_effect=mock_builder_create),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="pip", timeout=5.0)),
        ):
            with pytest.raises(VoiceRuntimeError, match="Package installation timed out"):
                mgr.provision()

    def test_provision_smoke_test_failure(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)

        def mock_builder_create(target_dir):
            python_path = mgr.python_executable
            python_path.parent.mkdir(parents=True, exist_ok=True)
            python_path.write_text("#!/bin/sh\nexit 0\n")
            python_path.chmod(0o755)

        def mock_run(cmd, *args, **kwargs):
            if "pip" in cmd:
                return MagicMock(returncode=0)
            if "worker" in str(cmd):
                return MagicMock(returncode=1, stderr="Segfault on import sounddevice")
            return MagicMock(returncode=0)

        with (
            patch("venv.EnvBuilder.create", side_effect=mock_builder_create),
            patch("subprocess.run", side_effect=mock_run),
        ):
            with pytest.raises(VoiceRuntimeError, match="Integrity check failed"):
                mgr.provision()

    def test_repair_calls_provision_with_force(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        with patch.object(mgr, "provision") as mock_prov:
            mock_prov.return_value = VoiceRuntimeStatus(
                state=VoiceRuntimeState.READY,
                runtime_dir=tmp_path,
            )
            mgr.repair()
            mock_prov.assert_called_once_with(progress_callback=None, force=True)

    def test_uninstall(self, tmp_path: Path) -> None:
        mgr = VoiceRuntimeManager(runtime_dir=tmp_path)
        mgr.venv_dir.mkdir(parents=True, exist_ok=True)
        mgr.manifest_path.write_text("{}", encoding="utf-8")
        mgr.models_dir.mkdir(parents=True, exist_ok=True)

        mgr.uninstall(remove_models=False)
        assert not mgr.venv_dir.exists()
        assert not mgr.manifest_path.exists()
        assert mgr.models_dir.exists()

        # Uninstall with remove_models=True
        mgr.uninstall(remove_models=True)
        assert not mgr.models_dir.exists()
