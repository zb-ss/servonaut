"""Managed Voice Runtime environment provisioner and lifecycle controller.

Maintains an isolated Python virtual environment under ~/.servonaut/runtimes/voice/
for the companion voice worker daemon. Ensures zero native voice dependencies
in the base distribution, coordinates atomic provisioning, performs integrity
smoke checks, and manages runtime repair and uninstallation.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
from typing import Any, Callable, Dict, Final, List, Mapping, Optional, Sequence
import venv

from servonaut import __version__
from servonaut.desktop.voice.requirements import (
    VOICE_RUNTIME_VERSION,
    compute_requirements_hash,
    get_default_requirements,
)
from servonaut.services.relay_lock import (
    _acquire_exclusive_nonblocking,
    _release,
)

logger = logging.getLogger(__name__)

DEFAULT_RUNTIME_ROOT: Final[Path] = Path.home() / ".servonaut" / "runtimes" / "voice"
_LOCK_FILENAME: Final[str] = ".runtime.lock"
_MANIFEST_FILENAME: Final[str] = "manifest.json"
_MANIFEST_SCHEMA_VERSION: Final[int] = 1


class VoiceRuntimeState(str, Enum):
    """Lifecycle state of the companion voice virtualenv."""

    NOT_INSTALLED = "not_installed"
    INSTALLING = "installing"
    READY = "ready"
    UPDATE_AVAILABLE = "update_available"
    CORRUPTED = "corrupted"
    UNSUPPORTED = "unsupported"


class VoiceRuntimeError(Exception):
    """Base exception for voice runtime provisioning and management failures."""


class VoiceRuntimeLockError(VoiceRuntimeError):
    """Raised when runtime directory lock cannot be acquired."""


@dataclass(frozen=True, slots=True)
class VoiceRuntimeManifest:
    """Persistent metadata certifying the provisioned companion runtime."""

    schema_version: int
    runtime_version: str
    servonaut_version: str
    created_at: str
    python_version: str
    platform: str
    architecture: str
    requirements_sha256: str
    status: str = "ready"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "runtime_version": self.runtime_version,
            "servonaut_version": self.servonaut_version,
            "created_at": self.created_at,
            "python_version": self.python_version,
            "platform": self.platform,
            "architecture": self.architecture,
            "requirements_sha256": self.requirements_sha256,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VoiceRuntimeManifest:
        schema_version = int(data.get("schema_version", 1))
        if schema_version != _MANIFEST_SCHEMA_VERSION:
            raise VoiceRuntimeError(f"Unsupported manifest schema_version: {schema_version}")
        return cls(
            schema_version=schema_version,
            runtime_version=str(data.get("runtime_version", "")),
            servonaut_version=str(data.get("servonaut_version", "")),
            created_at=str(data.get("created_at", "")),
            python_version=str(data.get("python_version", "")),
            platform=str(data.get("platform", "")),
            architecture=str(data.get("architecture", "")),
            requirements_sha256=str(data.get("requirements_sha256", "")),
            status=str(data.get("status", "ready")),
        )


@dataclass(frozen=True, slots=True)
class VoiceRuntimeStatus:
    """Result of an inspection of the companion runtime directory."""

    state: VoiceRuntimeState
    runtime_dir: Path
    python_executable: Optional[Path] = None
    manifest: Optional[VoiceRuntimeManifest] = None
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_ready(self) -> bool:
        """Whether the runtime is ready to launch the voice companion daemon."""
        return self.state is VoiceRuntimeState.READY


class VoiceRuntimeLock:
    """Inter-process advisory file lock for runtime provisioning."""

    def __init__(self, lock_path: Path, timeout: float = 10.0) -> None:
        self.lock_path = lock_path
        self.timeout = max(0.0, float(timeout))
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        """Acquire exclusive lock on the runtime lockfile."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(str(self.lock_path), flags, 0o600)

        deadline = time.time() + self.timeout
        acquired = False
        while time.time() <= deadline:
            if _acquire_exclusive_nonblocking(fd):
                acquired = True
                break
            time.sleep(0.1)

        if not acquired:
            os.close(fd)
            raise VoiceRuntimeLockError(
                f"Failed to acquire voice runtime lock at '{self.lock_path}' after {self.timeout}s"
            )

        self._fd = fd

    def release(self) -> None:
        """Release the held lock file descriptor."""
        if self._fd is not None:
            fd = self._fd
            self._fd = None
            try:
                _release(fd)
            finally:
                with contextlib.suppress(OSError):
                    os.close(fd)

    def is_locked(self) -> bool:
        """Probe if another process currently holds the lock without blocking."""
        if not self.lock_path.exists():
            return False
        flags = os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            fd = os.open(str(self.lock_path), flags, 0o600)
        except OSError:
            return False

        try:
            if _acquire_exclusive_nonblocking(fd):
                _release(fd)
                return False
            return True
        finally:
            with contextlib.suppress(OSError):
                os.close(fd)

    def __enter__(self) -> VoiceRuntimeLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()


class VoiceRuntimeManager:
    """Manages provisioning and lifecycle of the companion voice environment.

    Ensures that the voice runtime virtualenv is created, dependencies are installed,
    and integrity is verified before the VoiceWorker daemon is launched.
    """

    def __init__(
        self,
        runtime_dir: Optional[Path] = None,
        *,
        base_python: Optional[Path] = None,
    ) -> None:
        self._runtime_dir = (runtime_dir or DEFAULT_RUNTIME_ROOT).resolve()
        self._base_python = (base_python or Path(sys.executable)).resolve()

    @property
    def runtime_dir(self) -> Path:
        """Root directory for the voice companion runtime."""
        return self._runtime_dir

    @property
    def venv_dir(self) -> Path:
        """Path to the isolated virtualenv directory."""
        return self._runtime_dir / "venv"

    @property
    def models_dir(self) -> Path:
        """Directory reserved for local model asset cache."""
        return self._runtime_dir / "models"

    @property
    def manifest_path(self) -> Path:
        """Path to the metadata manifest file."""
        return self._runtime_dir / _MANIFEST_FILENAME

    @property
    def lock_path(self) -> Path:
        """Path to the inter-process lock file."""
        return self._runtime_dir / _LOCK_FILENAME

    @property
    def python_executable(self) -> Path:
        """Path to the Python interpreter inside the companion venv."""
        if os.name == "nt":
            return self.venv_dir / "Scripts" / "python.exe"
        return self.venv_dir / "bin" / "python"

    def status(self) -> VoiceRuntimeStatus:
        """Perform a pure, non-destructive inspection of the runtime status."""
        lock = VoiceRuntimeLock(self.lock_path)
        if lock.is_locked():
            return VoiceRuntimeStatus(
                state=VoiceRuntimeState.INSTALLING,
                runtime_dir=self._runtime_dir,
                message="Runtime provisioning or update is currently in progress",
            )

        if not self.venv_dir.exists() or not self.python_executable.exists():
            return VoiceRuntimeStatus(
                state=VoiceRuntimeState.NOT_INSTALLED,
                runtime_dir=self._runtime_dir,
                message="Companion virtualenv is not installed",
            )

        if not self.manifest_path.exists():
            return VoiceRuntimeStatus(
                state=VoiceRuntimeState.CORRUPTED,
                runtime_dir=self._runtime_dir,
                python_executable=self.python_executable,
                message="Runtime manifest.json is missing",
            )

        # Read and validate manifest
        manifest: Optional[VoiceRuntimeManifest] = None
        try:
            with self.manifest_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            manifest = VoiceRuntimeManifest.from_dict(data)
        except Exception as e:
            return VoiceRuntimeStatus(
                state=VoiceRuntimeState.CORRUPTED,
                runtime_dir=self._runtime_dir,
                python_executable=self.python_executable,
                message=f"Failed to read or parse runtime manifest: {e}",
            )

        # Check interpreter executability
        try:
            res = subprocess.run(
                [str(self.python_executable), "--version"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if res.returncode != 0:
                return VoiceRuntimeStatus(
                    state=VoiceRuntimeState.CORRUPTED,
                    runtime_dir=self._runtime_dir,
                    python_executable=self.python_executable,
                    manifest=manifest,
                    message=f"Companion Python interpreter returned code {res.returncode}",
                )
        except Exception as e:
            return VoiceRuntimeStatus(
                state=VoiceRuntimeState.CORRUPTED,
                runtime_dir=self._runtime_dir,
                python_executable=self.python_executable,
                manifest=manifest,
                message=f"Companion Python interpreter could not be executed: {e}",
            )

        # Check requirements hash
        expected_hash = compute_requirements_hash(get_default_requirements())
        if manifest.requirements_sha256 != expected_hash:
            return VoiceRuntimeStatus(
                state=VoiceRuntimeState.UPDATE_AVAILABLE,
                runtime_dir=self._runtime_dir,
                python_executable=self.python_executable,
                manifest=manifest,
                message="Newer requirements or engine updates are available",
                details={
                    "installed_hash": manifest.requirements_sha256,
                    "expected_hash": expected_hash,
                },
            )

        # Smoke check: can companion python import the worker module?
        try:
            smoke = subprocess.run(
                [
                    str(self.python_executable),
                    "-c",
                    "import servonaut.desktop.voice.worker",
                ],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            if smoke.returncode != 0:
                return VoiceRuntimeStatus(
                    state=VoiceRuntimeState.CORRUPTED,
                    runtime_dir=self._runtime_dir,
                    python_executable=self.python_executable,
                    manifest=manifest,
                    message=f"Companion smoke test failed: {smoke.stderr.strip()}",
                )
        except Exception as e:
            return VoiceRuntimeStatus(
                state=VoiceRuntimeState.CORRUPTED,
                runtime_dir=self._runtime_dir,
                python_executable=self.python_executable,
                manifest=manifest,
                message=f"Companion smoke test probe execution failed: {e}",
            )

        return VoiceRuntimeStatus(
            state=VoiceRuntimeState.READY,
            runtime_dir=self._runtime_dir,
            python_executable=self.python_executable,
            manifest=manifest,
            message="Companion voice runtime is installed and verified",
        )

    def is_ready(self) -> bool:
        """Whether the runtime is currently READY."""
        return self.status().is_ready

    def get_worker_cmd(self) -> list[str]:
        """Return the command argv to launch the companion VoiceWorker.

        Raises:
            VoiceRuntimeError: If runtime is not in READY state.
        """
        st = self.status()
        if not st.is_ready:
            raise VoiceRuntimeError(
                f"Cannot launch VoiceWorker: runtime is in state '{st.state.value}' ({st.message})"
            )
        return [
            str(self.python_executable),
            "-m",
            "servonaut.desktop.voice.worker",
            "--models-root",
            str(self.models_dir),
        ]

    def provision(
        self,
        *,
        progress_callback: Optional[Callable[[str, float, str], None]] = None,
        force: bool = False,
        requirements: Optional[Sequence[str]] = None,
        timeout: float = 120.0,
    ) -> VoiceRuntimeStatus:
        """Provision or update the companion virtualenv and verify baseline packages.

        Args:
            progress_callback: Optional callable receiving (phase, percentage, message).
            force: If True, clears existing virtualenv completely before provisioning.
            requirements: Optional custom package requirements (defaults to CORE_VOICE_REQUIREMENTS).
            timeout: Subprocess timeout in seconds for pip operations.

        Returns:
            The resulting VoiceRuntimeStatus after provisioning.

        Raises:
            VoiceRuntimeLockError: If concurrency lock cannot be acquired.
            VoiceRuntimeError: If provisioning or verification fails.
        """
        def report(phase: str, pct: float, msg: str) -> None:
            if progress_callback:
                try:
                    progress_callback(phase, pct, msg)
                except Exception:
                    pass

        self._runtime_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)

        req_list = list(requirements) if requirements is not None else get_default_requirements()
        req_hash = compute_requirements_hash(req_list)

        with VoiceRuntimeLock(self.lock_path, timeout=10.0):
            report("init", 0.05, "Initializing runtime directory...")

            # 1. Check Python version compatibility
            if sys.version_info < (3, 10):
                raise VoiceRuntimeError(
                    f"Python 3.10+ required for voice companion; current: {platform.python_version()}"
                )

            # 2. Build or clear venv
            report("venv", 0.20, "Creating companion virtualenv...")
            need_clear = force or (self.venv_dir.exists() and not self.python_executable.exists())
            try:
                builder = venv.EnvBuilder(
                    with_pip=True,
                    clear=need_clear,
                    symlinks=(os.name != "nt"),
                )
                builder.create(str(self.venv_dir))
            except Exception as e:
                raise VoiceRuntimeError(f"Failed to create companion virtualenv: {e}") from e

            if not self.python_executable.exists():
                raise VoiceRuntimeError(
                    f"Virtualenv created but Python interpreter missing at '{self.python_executable}'"
                )

            # 3. Configure servonaut package accessibility via .pth link
            report("link", 0.40, "Configuring companion site-packages...")
            self._link_servonaut_to_venv()

            # 4. Install requirements into companion venv
            if req_list:
                report("pip", 0.60, f"Installing {len(req_list)} companion packages...")
                cmd = [
                    str(self.python_executable),
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-input",
                    *req_list,
                ]
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                try:
                    res = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=False,
                        env=env,
                    )
                    if res.returncode != 0:
                        raise VoiceRuntimeError(
                            f"Package installation failed (code {res.returncode}): {res.stderr.strip()}"
                        )
                except subprocess.TimeoutExpired:
                    raise VoiceRuntimeError(
                        f"Package installation timed out after {timeout} seconds"
                    ) from None
                except Exception as e:
                    if isinstance(e, VoiceRuntimeError):
                        raise
                    raise VoiceRuntimeError(f"Failed to execute pip install: {e}") from e

            # 5. Verify companion environment with smoke test
            report("verify", 0.85, "Verifying companion worker integrity...")
            smoke = subprocess.run(
                [
                    str(self.python_executable),
                    "-c",
                    "import servonaut.desktop.voice.worker; print('OK')",
                ],
                capture_output=True,
                text=True,
                timeout=15.0,
                check=False,
            )
            if smoke.returncode != 0 or "OK" not in smoke.stdout:
                raise VoiceRuntimeError(
                    f"Integrity check failed: {smoke.stderr.strip() or smoke.stdout.strip()}"
                )

            # 6. Write atomic manifest.json
            report("manifest", 0.95, "Finalizing manifest...")
            now_iso = datetime.now(timezone.utc).isoformat()
            manifest = VoiceRuntimeManifest(
                schema_version=_MANIFEST_SCHEMA_VERSION,
                runtime_version=VOICE_RUNTIME_VERSION,
                servonaut_version=__version__,
                created_at=now_iso,
                python_version=platform.python_version(),
                platform=sys.platform,
                architecture=platform.machine(),
                requirements_sha256=req_hash,
                status="ready",
            )
            temp_manifest = self._runtime_dir / f"{_MANIFEST_FILENAME}.tmp.{os.getpid()}"
            with temp_manifest.open("w", encoding="utf-8") as f:
                json.dump(manifest.to_dict(), f, indent=2)
                f.write("\n")
            temp_manifest.replace(self.manifest_path)

            report("done", 1.0, "Companion voice runtime is ready.")

        return self.status()

    def repair(
        self,
        *,
        progress_callback: Optional[Callable[[str, float, str], None]] = None,
    ) -> VoiceRuntimeStatus:
        """Force re-provisioning of the companion environment."""
        return self.provision(progress_callback=progress_callback, force=True)

    def uninstall(self, *, remove_models: bool = False) -> None:
        """Remove the companion virtualenv and manifest.

        Args:
            remove_models: If True, also clears the models/ cache directory.
        """
        with VoiceRuntimeLock(self.lock_path, timeout=5.0):
            if self.venv_dir.exists():
                shutil.rmtree(self.venv_dir, ignore_errors=True)
            if self.manifest_path.exists():
                with contextlib.suppress(OSError):
                    self.manifest_path.unlink()
            if remove_models and self.models_dir.exists():
                shutil.rmtree(self.models_dir, ignore_errors=True)

    def _link_servonaut_to_venv(self) -> None:
        """Install a .pth file into the companion venv site-packages.

        This allows the companion Python interpreter to import `servonaut`
        directly from the active installation location without needing to rebuild
        or wheel-install the parent package into the companion venv.
        """
        site_packages_dirs: list[Path] = []
        lib_dir = self.venv_dir / ("Lib" if os.name == "nt" else "lib")
        if lib_dir.exists():
            for child in lib_dir.iterdir():
                if child.name.casefold() == "site-packages":
                    site_packages_dirs.append(child)
                elif child.is_dir() and (child / "site-packages").exists():
                    site_packages_dirs.append(child / "site-packages")

        if not site_packages_dirs:
            logger.warning("Could not find site-packages directory in %s", self.venv_dir)
            return

        # Locate the root folder containing the servonaut package
        servonaut_pkg_dir = Path(__file__).resolve().parent.parent.parent.parent
        link_content = f"{servonaut_pkg_dir}\n"

        for sp in site_packages_dirs:
            pth_file = sp / "servonaut_companion.pth"
            try:
                pth_file.write_text(link_content, encoding="utf-8")
            except OSError as e:
                logger.debug("Failed to write %s: %s", pth_file, e)
