"""Managed voice runtime for packaged desktop builds.

A packaged desktop build carries no voice packages of its own. Instead it ships
a pinned ``uv`` executable, the matching Servonaut wheel and a hash-locked
requirements file (see :mod:`servonaut.desktop.voice.packaged_manifest`). This
module uses them to build an isolated runtime under
``<data root>/runtimes/voice``::

    python/                    uv-managed Python installations
    cache/                     uv download cache, emptied after each install
    staging/<token>/           an install in progress (inputs/ and venv/)
    releases/<release>/venv    finished runtimes
    releases/<release>/.in-use held (shared) by every worker running it
    current.json               the active release, replaced atomically
    lock                       held while installing, repairing or removing

Every install happens in a fresh staging directory. The previous release stays
active until the new one has passed its smoke test and ``current.json`` points
at it, so a failed, cancelled or interrupted install never leaves voice
unusable. The release that was active before an install, and any release a
worker still runs from, survive the cleanup that follows. Model weights live
outside this tree and survive runtime removal unless removal is requested
explicitly.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import io
import json
import logging
import os
import queue
import re
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Final, Optional, TypeVar, Union

from servonaut.desktop.process_tree import (
    OwnedProcessTree,
    ProcessTreeError,
    spawn_desktop_child,
)
from servonaut.desktop.voice.packaged_manifest import (
    PACKAGED_MANIFEST_FILENAME,
    PACKAGED_VOICE_DIRNAME,
    BundledFile,
    PackagedVoiceManifest,
    PackagedVoiceManifestError,
    ProvisionTimeouts,
    load_packaged_manifest,
)
from servonaut.desktop.voice.protocol import (
    VOICE_PROTOCOL_VERSION,
    HandshakeRequest,
    HandshakeResponsePayload,
    VoiceMessage,
    VoiceProtocolError,
    VoiceResponse,
    read_voice_frame,
    write_voice_frame,
)
from servonaut.desktop.voice.release_lock import (
    IN_USE_FILENAME,
    LockTimeoutError,
    can_lock,
    open_and_lock,
    unlock,
)
from servonaut.runtime import DistributionKind, RuntimeLayout

logger = logging.getLogger(__name__)

# Location of the runtime under the default data root, for callers without a
# runtime layout.
DEFAULT_RUNTIME_ROOT: Final[Path] = Path.home() / ".servonaut" / "runtimes" / "voice"

_RUNTIMES_DIRNAME: Final = "runtimes"
_VOICE_RUNTIME_DIRNAME: Final = "voice"
_MODELS_DIRNAME: Final = "voice_models"
# Hugging Face cache inside the models root. The batch engine downloads its
# weights through the hub library on first use; pointing the hub here keeps
# every voice model under one root, and keeps the user's own hub cache and
# hub token out of the worker.
_HF_HOME_DIRNAME: Final = "huggingface"
_HF_HUB_DIRNAME: Final = "hub"
# The model cache's lock file inside the models root.
_MODELS_LOCK_FILENAME: Final = ".models.lock"
_CURRENT_FILENAME: Final = "current.json"
_LOCK_FILENAME: Final = "lock"
_PYTHON_DIRNAME: Final = "python"
_PYTHON_INSTALL_PREFIX: Final = "cpython-"
_CACHE_DIRNAME: Final = "cache"
_STAGING_DIRNAME: Final = "staging"
_INPUTS_DIRNAME: Final = "inputs"
_RELEASES_DIRNAME: Final = "releases"
_VENV_DIRNAME: Final = "venv"

_CURRENT_SCHEMA_VERSION: Final = 1
# current.json is a handful of scalar fields written by this module; the bound
# stops a damaged file from consuming unbounded memory.
_MAX_CURRENT_BYTES: Final = 64 * 1024
_RELEASE_NAME_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_O_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)

_LAUNCHER_MODULE: Final = "servonaut.desktop.voice.release_lock"
# Native stacks the voice worker imports. Importing sounddevice loads PortAudio,
# so this also proves the native audio library is present.
_ENGINE_MODULES: Final = ("numpy", "sounddevice", "faster_whisper", "sherpa_onnx")

# Process-control mechanics, not policy: how often a running step is checked,
# how long a killed step may take to exit, how long an operation waits out a
# concurrent status probe, and how much output is kept for error messages. The
# provisioning time limits themselves come from the packaged manifest.
_POLL_INTERVAL_SECONDS: Final = 0.1
_TERMINATE_GRACE_SECONDS: Final = 1.0
_TREE_EXIT_TIMEOUT_SECONDS: Final = 5.0
_READER_JOIN_SECONDS: Final = 1.0
_LOCK_RETRY_SECONDS: Final = 1.5
_OUTPUT_TAIL_BYTES: Final = 8192
_READ_CHUNK_BYTES: Final = 4096
_HASH_CHUNK_BYTES: Final = 1024 * 1024
# Windows reports a file that a just-exited process or a scanner still holds
# as a permission error for a moment; those operations are retried briefly.
_RETRY_PERMISSION_ERRORS: bool = os.name == "nt"
_PERMISSION_RETRY_ATTEMPTS: Final = 10
_PERMISSION_RETRY_DELAY_SECONDS: float = 0.3

# Variables every child inherits. Everything else, including PYTHONPATH,
# VIRTUAL_ENV, loader variables, cloud credentials and any uv or pip
# configuration, is dropped.
_BASE_ENV: Final = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "HOMEDRIVE",
        "HOMEPATH",
        "USERNAME",
    }
)
# Provisioning downloads packages, so it also gets proxy and certificate
# settings for installs behind a corporate proxy.
_NETWORK_ENV: Final = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    }
)
# The worker plays and records audio, so it needs to find the sound server.
_AUDIO_ENV: Final = frozenset(
    {
        "XDG_RUNTIME_DIR",
        "PULSE_SERVER",
        "PULSE_SINK",
        "PULSE_SOURCE",
        "PIPEWIRE_RUNTIME_DIR",
        "PIPEWIRE_REMOTE",
    }
)

ProgressCallback = Callable[[str, int, int], None]
"""Receives ``(label, completed_steps, total_steps)`` as provisioning advances."""

_STEP_LABELS: Final = (
    "Checking the bundled voice files",
    "Downloading Python",
    "Creating the voice environment",
    "Downloading voice packages",
    "Installing the voice worker",
    "Testing the voice runtime",
    "Activating the voice runtime",
    "Removing older voice runtimes",
)
_SMOKE_STEP: Final = _STEP_LABELS[5]
_DONE_LABEL: Final = "Voice runtime installed"

_Frame = Union[VoiceMessage, Exception, None]
_T = TypeVar("_T")


class VoiceRuntimeState(str, Enum):
    """Lifecycle state of the managed voice runtime."""

    NOT_INSTALLED = "not_installed"
    INSTALLING = "installing"
    READY = "ready"
    UPDATE_AVAILABLE = "update_available"
    BROKEN = "broken"


class VoiceRuntimeError(Exception):
    """Base exception for managed voice runtime failures."""


class VoiceRuntimeLockError(VoiceRuntimeError):
    """Raised when another operation, download or running worker blocks this one."""


class VoiceRuntimeUnavailableError(VoiceRuntimeError):
    """Raised when this build carries no usable voice runtime inputs."""


class VoiceRuntimeNotReadyError(VoiceRuntimeError):
    """Raised when the worker is requested from a runtime that cannot run it."""


class VoiceRuntimeIntegrityError(VoiceRuntimeError):
    """Raised when a bundled input is missing or does not match its checksum."""


class VoiceRuntimeCancelledError(VoiceRuntimeError):
    """Raised when provisioning is cancelled by the caller."""


class VoiceRuntimeStepError(VoiceRuntimeError):
    """Raised when a provisioning step fails; carries the step's output."""

    def __init__(self, step: str, message: str, output: str = "") -> None:
        super().__init__(message)
        self.step = step
        self.output = output


class VoiceRuntimeCommandError(VoiceRuntimeStepError):
    """Raised when a provisioning command exits unsuccessfully."""

    def __init__(self, step: str, returncode: int, output: str) -> None:
        super().__init__(
            step,
            f"{step} failed (exit code {returncode}){_last_line_suffix(output)}",
            output,
        )
        self.returncode = returncode


class VoiceRuntimeTimeoutError(VoiceRuntimeStepError):
    """Raised when a step exceeds its time limit or stops making progress."""


class VoiceRuntimeSmokeError(VoiceRuntimeStepError):
    """Raised when a runtime cannot load its engines or complete a handshake."""


@dataclass(frozen=True)
class VoiceRuntimeManifest:
    """The active release recorded in ``current.json``."""

    runtime_id: str
    release: str
    python_version: str
    lock_sha256: str
    wheel_sha256: str
    product_version: str
    protocol_version: int
    created_at: str

    def to_json(self) -> bytes:
        """Serialize for an atomic write to ``current.json``."""
        document = {"schema_version": _CURRENT_SCHEMA_VERSION, **dataclasses.asdict(self)}
        return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> VoiceRuntimeManifest:
        """Parse ``current.json`` strictly.

        Raises:
            VoiceRuntimeError: If the document does not match the schema.
        """
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise VoiceRuntimeError(f"current.json is not valid JSON: {error}") from None
        fields = {field.name for field in dataclasses.fields(cls)}
        if not isinstance(document, dict) or set(document) != {"schema_version", *fields}:
            raise VoiceRuntimeError("current.json does not match the expected fields.")
        schema_version = document.pop("schema_version")
        if type(schema_version) is not int or schema_version != _CURRENT_SCHEMA_VERSION:
            raise VoiceRuntimeError("current.json has an unsupported schema version.")
        record = cls(**document)
        record._validate()
        return record

    def _validate(self) -> None:
        text_fields = (
            self.runtime_id,
            self.release,
            self.python_version,
            self.lock_sha256,
            self.wheel_sha256,
            self.product_version,
            self.created_at,
        )
        if not all(type(value) is str and value for value in text_fields):
            raise VoiceRuntimeError("current.json has an empty or non-text field.")
        if type(self.protocol_version) is not int:
            raise VoiceRuntimeError("current.json has a non-integer protocol version.")
        if _RELEASE_NAME_PATTERN.fullmatch(self.release) is None:
            raise VoiceRuntimeError("current.json names an invalid release directory.")
        for digest in (self.lock_sha256, self.wheel_sha256):
            if _SHA256_PATTERN.fullmatch(digest) is None:
                raise VoiceRuntimeError("current.json has a malformed checksum.")


@dataclass(frozen=True)
class VoiceRuntimeStatus:
    """A cheap, side-effect-free snapshot of the managed runtime."""

    state: VoiceRuntimeState
    message: str
    expected_runtime_id: str
    installed: Optional[VoiceRuntimeManifest] = None
    python_executable: Optional[Path] = None

    @property
    def is_ready(self) -> bool:
        """Whether the runtime is installed at the version this build expects."""
        return self.state is VoiceRuntimeState.READY

    @property
    def is_usable(self) -> bool:
        """Whether the voice worker can be launched from the installed runtime."""
        return self.state in (VoiceRuntimeState.READY, VoiceRuntimeState.UPDATE_AVAILABLE)


class VoiceRuntimeLock:
    """Inter-process exclusive lock for runtime and model directories.

    :meth:`is_locked` probes with a shared lock, so concurrent probes never
    see each other as a holder.
    """

    def __init__(self, lock_path: Path, timeout: float = 10.0) -> None:
        self.lock_path = lock_path
        self.timeout = max(0.0, float(timeout))
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        """Acquire the exclusive lock, polling until ``timeout`` elapses.

        Raises:
            VoiceRuntimeLockError: If another holder keeps the lock.
            OSError: If the lock file cannot be created or locked.
        """
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._fd = open_and_lock(self.lock_path, exclusive=True, timeout=self.timeout)
        except LockTimeoutError:
            raise VoiceRuntimeLockError(
                f"Failed to acquire voice runtime lock at '{self.lock_path}' "
                f"after {self.timeout}s"
            ) from None

    def release(self) -> None:
        """Release the held lock file descriptor."""
        if self._fd is None:
            return
        fd = self._fd
        self._fd = None
        try:
            with contextlib.suppress(OSError):
                unlock(fd)
        finally:
            os.close(fd)

    def is_locked(self) -> bool:
        """Whether an exclusive holder has the lock; never blocks or creates it.

        Raises:
            OSError: If the lock file exists but cannot be probed.
        """
        return not can_lock(self.lock_path, exclusive=False)

    def __enter__(self) -> VoiceRuntimeLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()


def compute_runtime_id(
    *,
    product_version: str,
    protocol_version: int,
    target: str,
    python_version: str,
    lock_sha256: str,
    wheel_sha256: str,
) -> str:
    """Identify a runtime by every input that changes what it contains."""
    identity = json.dumps(
        [product_version, protocol_version, target, python_version, lock_sha256, wheel_sha256],
        separators=(",", ":"),
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    readable = re.sub(r"[^A-Za-z0-9.]+", "_", product_version)[:32]
    return f"v{readable}-{digest}"


class VoiceRuntimeManager:
    """Installs, verifies, repairs and removes the managed voice runtime.

    ``status``, ``get_worker_cmd`` and ``worker_env`` never start a process and
    are safe on a UI thread. ``verify``, ``provision``, ``repair`` and
    ``remove`` block, so callers run them off the event loop.
    """

    def __init__(
        self,
        *,
        runtime_dir: Path,
        bundle_dir: Path,
        manifest: PackagedVoiceManifest,
        models_root: Path,
        product_version: str,
    ) -> None:
        self._paths = _RuntimePaths(runtime_dir)
        self._bundle_dir = bundle_dir
        self._manifest = manifest
        self._models_root = models_root
        self._product_version = product_version
        self._expected_runtime_id = compute_runtime_id(
            product_version=product_version,
            protocol_version=VOICE_PROTOCOL_VERSION,
            target=manifest.target,
            python_version=manifest.python_version,
            lock_sha256=manifest.requirements.sha256,
            wheel_sha256=manifest.wheel.sha256,
        )
        self._verification_lock = threading.Lock()
        self._verification: Optional[tuple[str, Optional[str]]] = None

    @classmethod
    def for_runtime(cls, runtime_layout: RuntimeLayout) -> Optional[VoiceRuntimeManager]:
        """Build the manager for a packaged desktop build.

        Returns ``None`` for every other distribution, which keeps voice
        in-process.

        Raises:
            VoiceRuntimeUnavailableError: If the build's voice manifest is
                missing or invalid.
        """
        if runtime_layout.kind is not DistributionKind.PACKAGED_DESKTOP:
            return None
        bundle_dir = runtime_layout.resource_root / PACKAGED_VOICE_DIRNAME
        try:
            manifest = load_packaged_manifest(bundle_dir / PACKAGED_MANIFEST_FILENAME)
        except PackagedVoiceManifestError as error:
            raise VoiceRuntimeUnavailableError(
                f"This build cannot install voice: {error}"
            ) from error
        return cls(
            runtime_dir=runtime_layout.data_root / _RUNTIMES_DIRNAME / _VOICE_RUNTIME_DIRNAME,
            bundle_dir=bundle_dir,
            manifest=manifest,
            models_root=runtime_layout.data_root / _MODELS_DIRNAME,
            product_version=runtime_layout.product_version,
        )

    @property
    def runtime_dir(self) -> Path:
        """Root directory of the managed runtime."""
        return self._paths.root

    @property
    def models_root(self) -> Path:
        """Directory holding voice model weights, outside the runtime tree."""
        return self._models_root

    @property
    def whisper_cache_root(self) -> Path:
        """Hub cache the worker's batch engine downloads its weights into."""
        return self._models_root / _HF_HOME_DIRNAME / _HF_HUB_DIRNAME

    @property
    def packaged_manifest(self) -> PackagedVoiceManifest:
        """The validated manifest bundled with this build."""
        return self._manifest

    @property
    def expected_runtime_id(self) -> str:
        """Runtime id this build installs."""
        return self._expected_runtime_id

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def status(self) -> VoiceRuntimeStatus:
        """Inspect the runtime from its files alone; never starts a process."""
        return self._evaluate(check_lock=True)

    def verify(self, cancel: Optional[threading.Event] = None) -> VoiceRuntimeStatus:
        """Smoke-test the installed runtime and remember the result.

        A failure, including a worker that cannot start, reports another
        version, or does not answer in time, turns later ``status`` results
        into BROKEN until a successful ``verify``, ``provision`` or
        ``repair``. A runtime that is not installed, busy or unreadable is
        returned as-is without a test.

        Raises:
            VoiceRuntimeCancelledError: If ``cancel`` is set.
        """
        status, record = self._inspect(check_lock=True)
        if record is None or not status.is_usable:
            return status
        release_dir = self._paths.release(record.release)
        runner = self._runner(cancel, watch=(release_dir,))
        target = _SmokeTarget(release_dir, record.runtime_id, record.product_version)
        try:
            _smoke_test(runner, target, models_root=self._models_root, env=self.worker_env())
        except VoiceRuntimeStepError as error:
            self._remember_verification(record.release, str(error))
        else:
            self._remember_verification(record.release, None)
        return self.status()

    def get_worker_cmd(self) -> list[str]:
        """Return the argv that launches the voice worker.

        The command holds the release's in-use lock for as long as the worker
        runs, which keeps that release from being pruned or removed.

        Raises:
            VoiceRuntimeNotReadyError: Unless the runtime is READY or
                UPDATE_AVAILABLE.
        """
        status = self.status()
        if not status.is_usable or status.installed is None:
            raise VoiceRuntimeNotReadyError(status.message)
        return _worker_argv(
            self._paths.release(status.installed.release),
            self._models_root,
            status.installed.runtime_id,
        )

    def worker_env(self) -> dict[str, str]:
        """The complete environment for the voice worker: basics and audio only.

        Credentials, loader variables, proxy and certificate overrides and
        Python path settings from the parent are never passed on. The hub
        cache is pinned under the models root (see :attr:`whisper_cache_root`).
        """
        env = _inherited_env(_BASE_ENV | _AUDIO_ENV)
        env.update(
            {
                "PYTHONUNBUFFERED": "1",
                "PYTHONIOENCODING": "utf-8",
                "HF_HOME": str(self.whisper_cache_root.parent),
                "HF_HUB_CACHE": str(self.whisper_cache_root),
            }
        )
        return env

    # ------------------------------------------------------------------
    # Transactions
    # ------------------------------------------------------------------

    def provision(
        self,
        progress: Optional[ProgressCallback] = None,
        cancel: Optional[threading.Event] = None,
    ) -> VoiceRuntimeStatus:
        """Install the runtime this build expects, unless it is already READY.

        Blocks until the install finishes. Setting ``cancel`` before the new
        release is activated stops the running step and removes the staging
        directory; the previous release, if any, stays active. Once the new
        release is active, cancelling has no effect. Restart the voice worker
        afterwards so it runs from the new release.

        Raises:
            VoiceRuntimeLockError: If another runtime operation is running.
            VoiceRuntimeIntegrityError: If a bundled input fails its checksum.
            VoiceRuntimeCommandError: If an install command fails.
            VoiceRuntimeTimeoutError: If a step times out or stalls.
            VoiceRuntimeSmokeError: If the new runtime fails its smoke test.
            VoiceRuntimeCancelledError: If ``cancel`` is set.
            VoiceRuntimeError: If the runtime directory cannot be written.
        """
        return self._install(progress, cancel, reuse_ready=True)

    def repair(
        self,
        progress: Optional[ProgressCallback] = None,
        cancel: Optional[threading.Event] = None,
    ) -> VoiceRuntimeStatus:
        """Build a fresh runtime even when one is READY.

        The working release is replaced only after the new one passes its
        smoke test. Raises the same errors as :meth:`provision`.
        """
        return self._install(progress, cancel, reuse_ready=False)

    def remove(self, *, remove_models: bool = False) -> VoiceRuntimeStatus:
        """Delete the runtime; models are kept unless ``remove_models`` is set.

        Nothing is deleted while a voice worker still runs from any release,
        or, with ``remove_models``, while a model download holds the model
        cache lock.

        Raises:
            VoiceRuntimeLockError: If another runtime operation, a running
                worker or a model download blocks the removal.
            VoiceRuntimeError: If some files could not be deleted. The runtime
                already reads as NOT_INSTALLED by then.
        """
        failures: list[str] = []
        with self._exclusive_lock():
            self._refuse_while_in_use()
            with self._models_lock(remove_models):
                # current.json goes first so a partial removal reads as not installed.
                _remove_entry(self._paths.current, failures)
                for entry in _children(self._paths.root):
                    if entry.name != _LOCK_FILENAME:
                        _remove_entry(entry, failures)
                if remove_models:
                    self._remove_models(failures)
            self._remember_verification(None, None)
        if failures:
            raise VoiceRuntimeError(
                "Some voice runtime files could not be removed: " + "; ".join(failures)
            )
        return self.status()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _install(
        self,
        progress: Optional[ProgressCallback],
        cancel: Optional[threading.Event],
        *,
        reuse_ready: bool,
    ) -> VoiceRuntimeStatus:
        with self._exclusive_lock():
            if reuse_ready and self._evaluate(check_lock=False).is_ready:
                return self._evaluate(check_lock=False)
            previous = self._current_release()
            self._sweep_staging()
            try:
                staging = self._paths.new_staging()
            except OSError as error:
                raise VoiceRuntimeError(
                    f"The voice runtime directory is not writable: {error}"
                ) from error
            transaction = _Provisioning(
                paths=self._paths,
                bundle_dir=self._bundle_dir,
                manifest=self._manifest,
                target=_SmokeTarget(staging, self._expected_runtime_id, self._product_version),
                models_root=self._models_root,
                previous_release=previous,
                worker_env=self.worker_env(),
                runner=self._runner(
                    cancel, watch=(self._paths.python, self._paths.cache, staging)
                ),
                progress=progress,
            )
            try:
                record = transaction.run()
            finally:
                _remove_entry(staging, [])
            self._remember_verification(record.release, None)
        return self.status()

    def _evaluate(self, *, check_lock: bool) -> VoiceRuntimeStatus:
        status, record = self._inspect(check_lock=check_lock)
        if record is None or not status.is_usable:
            return status
        failure = self._verification_failure(record)
        if failure is None:
            return status
        return self._status(VoiceRuntimeState.BROKEN, failure, record)

    def _inspect(
        self, *, check_lock: bool
    ) -> tuple[VoiceRuntimeStatus, Optional[VoiceRuntimeManifest]]:
        try:
            locked = check_lock and VoiceRuntimeLock(self._paths.lock).is_locked()
        except OSError as error:
            message = f"The voice runtime lock cannot be checked: {error}"
            return self._status(VoiceRuntimeState.BROKEN, message), None
        if locked:
            message = "A voice runtime operation is in progress."
            return self._status(VoiceRuntimeState.INSTALLING, message), None
        try:
            record = self._read_current()
        except VoiceRuntimeError as error:
            message = f"The voice runtime record is damaged: {error}"
            return self._status(VoiceRuntimeState.BROKEN, message), None
        if record is None:
            message = "The voice runtime is not installed."
            return self._status(VoiceRuntimeState.NOT_INSTALLED, message), None
        return self._classify(record), record

    def _classify(self, record: VoiceRuntimeManifest) -> VoiceRuntimeStatus:
        if not self._release_python(record).is_file():
            return self._status(
                VoiceRuntimeState.BROKEN, "Voice runtime files are missing.", record
            )
        if record.protocol_version != VOICE_PROTOCOL_VERSION:
            return self._status(
                VoiceRuntimeState.BROKEN,
                "The installed voice runtime belongs to another Servonaut version; repair it.",
                record,
            )
        if record.runtime_id != self._expected_runtime_id:
            return self._status(
                VoiceRuntimeState.UPDATE_AVAILABLE, "A voice runtime update is available.", record
            )
        return self._status(VoiceRuntimeState.READY, "The voice runtime is ready.", record)

    def _status(
        self,
        state: VoiceRuntimeState,
        message: str,
        record: Optional[VoiceRuntimeManifest] = None,
    ) -> VoiceRuntimeStatus:
        return VoiceRuntimeStatus(
            state=state,
            message=message,
            expected_runtime_id=self._expected_runtime_id,
            installed=record,
            python_executable=None if record is None else self._release_python(record),
        )

    def _release_python(self, record: VoiceRuntimeManifest) -> Path:
        return _venv_python(self._paths.release(record.release) / _VENV_DIRNAME)

    def _read_current(self) -> Optional[VoiceRuntimeManifest]:
        """Read current.json as a regular file, never through a symlink."""
        path = self._paths.current
        if not _O_NOFOLLOW and path.is_symlink():
            raise VoiceRuntimeError("current.json must not be a symbolic link.")
        try:
            fd = os.open(str(path), os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise VoiceRuntimeError(
                f"current.json cannot be read: {error.strerror or error}"
            ) from error
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise VoiceRuntimeError("current.json is not a regular file.")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                raw = handle.read(_MAX_CURRENT_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > _MAX_CURRENT_BYTES:
            raise VoiceRuntimeError("current.json is too large.")
        return VoiceRuntimeManifest.from_json(raw)

    def _current_release(self) -> Optional[str]:
        """The active release's directory name, if the record is readable."""
        try:
            record = self._read_current()
        except VoiceRuntimeError:
            return None
        return None if record is None else record.release

    def _verification_failure(self, record: VoiceRuntimeManifest) -> Optional[str]:
        with self._verification_lock:
            if self._verification is None or self._verification[0] != record.release:
                return None
            return self._verification[1]

    def _remember_verification(self, release: Optional[str], failure: Optional[str]) -> None:
        with self._verification_lock:
            self._verification = None if release is None else (release, failure)

    def _runner(
        self, cancel: Optional[threading.Event], *, watch: Sequence[Path]
    ) -> _StepRunner:
        return _StepRunner(
            cwd=self._paths.root,
            timeouts=self._manifest.timeouts,
            cancel=cancel,
            watch=watch,
        )

    @contextlib.contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        # A short retry absorbs status probes, which hold a shared lock briefly.
        lock = VoiceRuntimeLock(self._paths.lock, timeout=_LOCK_RETRY_SECONDS)
        try:
            lock.acquire()
        except VoiceRuntimeLockError:
            raise VoiceRuntimeLockError(
                "Another voice runtime operation is already in progress."
            ) from None
        except OSError as error:
            raise VoiceRuntimeError(
                f"The voice runtime directory is not writable: {error}"
            ) from error
        try:
            yield
        finally:
            lock.release()

    @contextlib.contextmanager
    def _models_lock(self, required: bool) -> Iterator[None]:
        """Hold the model cache lock so no download runs during removal."""
        if not required or not self._models_root.is_dir():
            yield
            return
        lock = VoiceRuntimeLock(self._models_root / _MODELS_LOCK_FILENAME, timeout=0.0)
        try:
            lock.acquire()
        except VoiceRuntimeLockError:
            raise VoiceRuntimeLockError(
                "A voice model download is in progress; try again when it finishes."
            ) from None
        except OSError as error:
            raise VoiceRuntimeError(f"The voice models cannot be locked: {error}") from error
        try:
            yield
        finally:
            lock.release()

    def _remove_models(self, failures: list[str]) -> None:
        """Delete model weights but keep the held lock file; links are only unlinked."""
        if self._models_root.is_symlink():
            _remove_entry(self._models_root, failures)
            return
        for entry in _children(self._models_root):
            if entry.name != _MODELS_LOCK_FILENAME:
                _remove_entry(entry, failures)

    def _refuse_while_in_use(self) -> None:
        for release_dir in _children(self._paths.releases):
            try:
                in_use = not can_lock(release_dir / IN_USE_FILENAME, exclusive=True)
            except OSError as error:
                raise VoiceRuntimeError(
                    f"Cannot tell whether voice is still running: {error}"
                ) from error
            if in_use:
                raise VoiceRuntimeLockError(
                    "Voice is still running from this runtime; stop it before removing."
                )

    def _sweep_staging(self) -> None:
        """Delete staging left by an interrupted install; the lock is held."""
        failures: list[str] = []
        for entry in _children(self._paths.staging):
            _remove_entry(entry, failures)
        for failure in failures:
            logger.warning("Could not remove stale voice runtime staging: %s", failure)


@dataclass(frozen=True)
class _RuntimePaths:
    root: Path

    @property
    def python(self) -> Path:
        return self.root / _PYTHON_DIRNAME

    @property
    def cache(self) -> Path:
        return self.root / _CACHE_DIRNAME

    @property
    def staging(self) -> Path:
        return self.root / _STAGING_DIRNAME

    @property
    def releases(self) -> Path:
        return self.root / _RELEASES_DIRNAME

    @property
    def current(self) -> Path:
        return self.root / _CURRENT_FILENAME

    @property
    def lock(self) -> Path:
        return self.root / _LOCK_FILENAME

    def release(self, name: str) -> Path:
        return self.releases / name

    def new_staging(self) -> Path:
        self.staging.mkdir(parents=True, exist_ok=True)
        path = self.staging / secrets.token_hex(8)
        path.mkdir()
        return path


@dataclass(frozen=True)
class _SmokeTarget:
    """A runtime directory (staging or release) and what its worker must report."""

    directory: Path
    runtime_id: str
    product_version: str

    @property
    def python(self) -> Path:
        return _venv_python(self.directory / _VENV_DIRNAME)


def _inherited_env(names: frozenset[str]) -> dict[str, str]:
    return {name: value for name, value in os.environ.items() if name in names}


def _provisioning_env(paths: _RuntimePaths) -> dict[str, str]:
    """Environment for uv: inherited basics and network settings plus uv pins."""
    env = _inherited_env(_BASE_ENV | _NETWORK_ENV)
    env.update(
        {
            "UV_PYTHON_INSTALL_DIR": str(paths.python),
            "UV_CACHE_DIR": str(paths.cache),
            "UV_NO_CONFIG": "1",
            "UV_PYTHON_PREFERENCE": "only-managed",
            "UV_PYTHON_DOWNLOADS": "automatic",
            # Keep the managed interpreter private: no links in the user's
            # bin directory and no Windows registry entries.
            "UV_PYTHON_INSTALL_BIN": "0",
            "UV_PYTHON_INSTALL_REGISTRY": "0",
        }
    )
    return env


class _Provisioning:
    """One install transaction: build in staging, smoke-test, then promote."""

    def __init__(
        self,
        *,
        paths: _RuntimePaths,
        bundle_dir: Path,
        manifest: PackagedVoiceManifest,
        target: _SmokeTarget,
        models_root: Path,
        previous_release: Optional[str],
        worker_env: dict[str, str],
        runner: _StepRunner,
        progress: Optional[ProgressCallback],
    ) -> None:
        self._paths = paths
        self._bundle_dir = bundle_dir
        self._manifest = manifest
        self._target = target
        self._models_root = models_root
        self._previous_release = previous_release
        self._worker_env = worker_env
        self._uv_env = _provisioning_env(paths)
        self._runner = runner
        self._progress = progress

    def run(self) -> VoiceRuntimeManifest:
        staging = self._target.directory
        inputs = staging / _INPUTS_DIRNAME
        venv_python = str(self._target.python)
        python_version = self._manifest.python_version

        self._begin(0)
        _verify_sha256(self._bundle_dir / self._manifest.uv.filename, self._manifest.uv.sha256)
        requirements = self._stage_input(self._manifest.requirements, inputs)
        wheel = self._stage_input(self._manifest.wheel, inputs)
        self._begin(1)
        self._uv(1, "python", "install", python_version)
        self._begin(2)
        self._uv(2, "venv", "--python", python_version, str(staging / _VENV_DIRNAME))
        self._begin(3)
        _verify_sha256(requirements, self._manifest.requirements.sha256)
        self._uv(
            3, "pip", "install", "--python", venv_python,
            "--require-hashes", "--only-binary", ":all:", "--no-deps",
            "-r", str(requirements),
        )
        self._begin(4)
        _verify_sha256(wheel, self._manifest.wheel.sha256)
        self._uv(
            4, "pip", "install", "--python", venv_python,
            "--no-deps", "--no-index", str(wheel),
        )
        _remove_entry(inputs, [])
        self._begin(5)
        _smoke_test(self._runner, self._target, models_root=self._models_root, env=self._worker_env)
        self._begin(6)
        record = self._promote(staging)
        # The new release is active: nothing below may cancel or fail the install.
        self._report(_STEP_LABELS[7], 7)
        self._clean_up(record)
        self._report(_DONE_LABEL, len(_STEP_LABELS))
        return record

    def _begin(self, index: int) -> None:
        self._runner.check_cancelled(_STEP_LABELS[index])
        self._report(_STEP_LABELS[index], index)

    def _report(self, label: str, completed: int) -> None:
        if self._progress is not None:
            self._progress(label, completed, len(_STEP_LABELS))

    def _uv(self, index: int, *args: str) -> None:
        uv = self._bundle_dir / self._manifest.uv.filename
        _verify_sha256(uv, self._manifest.uv.sha256)
        self._runner.run(_STEP_LABELS[index], [str(uv), *args], env=self._uv_env)

    def _stage_input(self, bundled: BundledFile, inputs: Path) -> Path:
        """Copy a verified bundled file into staging and verify the copy."""
        source = self._bundle_dir / bundled.filename
        _verify_sha256(source, bundled.sha256)
        copy = inputs / bundled.filename
        try:
            inputs.mkdir(exist_ok=True)
            shutil.copyfile(source, copy)
        except OSError as error:
            raise VoiceRuntimeError(
                f"The bundled file {bundled.filename} could not be staged: {error}"
            ) from error
        _verify_sha256(copy, bundled.sha256)
        return copy

    def _promote(self, staging: Path) -> VoiceRuntimeManifest:
        release = self._release_name()
        target = self._paths.release(release)
        try:
            self._paths.releases.mkdir(parents=True, exist_ok=True)
            _with_permission_retry(lambda: staging.rename(target))
        except OSError as error:
            raise VoiceRuntimeError(
                f"The voice runtime could not be activated: {error}"
            ) from error
        # The release must be on disk before current.json can point at it.
        _flush_filesystems()
        record = VoiceRuntimeManifest(
            runtime_id=self._target.runtime_id,
            release=release,
            python_version=self._manifest.python_version,
            lock_sha256=self._manifest.requirements.sha256,
            wheel_sha256=self._manifest.wheel.sha256,
            product_version=self._target.product_version,
            protocol_version=VOICE_PROTOCOL_VERSION,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        try:
            _write_atomic(self._paths.current, record.to_json())
        except OSError as error:
            # current.json still names the previous release, so the new one
            # is unreferenced and safe to discard.
            _remove_entry(target, [])
            raise VoiceRuntimeError(
                f"The voice runtime could not be activated: {error}"
            ) from error
        return record

    def _release_name(self) -> str:
        # Repairing the same runtime id must not overwrite the working
        # release, so it gets a distinct directory until the old one is pruned.
        runtime_id = self._target.runtime_id
        if not self._paths.release(runtime_id).exists():
            return runtime_id
        return f"{runtime_id}-{secrets.token_hex(4)}"

    def _clean_up(self, record: VoiceRuntimeManifest) -> None:
        """Drop what the active and previous releases no longer need."""
        keep = {record.release}
        if self._previous_release is not None:
            keep.add(self._previous_release)
        retained = _prune_releases(self._paths, keep=keep)
        _prune_python_installs(self._paths, retained)
        failures: list[str] = []
        _remove_entry(self._paths.cache, failures)
        for failure in failures:
            logger.warning("Could not empty the voice runtime download cache: %s", failure)


class _OutputTail:
    """Thread-safe bounded tail of a child's output plus its last activity time."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data = bytearray()
        self.last_activity = time.monotonic()

    def append(self, chunk: bytes) -> None:
        with self._lock:
            self._data += chunk
            del self._data[:-_OUTPUT_TAIL_BYTES]
            self.last_activity = time.monotonic()

    def text(self) -> str:
        with self._lock:
            return self._data.decode("utf-8", errors="replace").strip()


class _PipeReader:
    """Reads one child pipe on a daemon thread from a private descriptor.

    Owning a duplicate descriptor means closing the process tree's own stream
    can never race a blocked read.
    """

    def __init__(self, stream: BinaryIO, consume: Callable[[BinaryIO], None]) -> None:
        self._file: BinaryIO = io.open(os.dup(stream.fileno()), "rb", buffering=0)
        self._consume = consume
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self) -> None:
        self._thread.join(_READER_JOIN_SECONDS)

    def _run(self) -> None:
        try:
            self._consume(self._file)
        finally:
            with contextlib.suppress(OSError):
                self._file.close()


class _RunningStep:
    """A spawned step: its owned process tree and pipe readers."""

    def __init__(self, argv: Sequence[str], *, env: dict[str, str], cwd: Path) -> None:
        self.tree: OwnedProcessTree = spawn_desktop_child(argv, env=env, cwd=cwd)
        self.stdout = _OutputTail()
        self.stderr = _OutputTail()
        self._readers: list[_PipeReader] = []
        self._closed = False
        try:
            self.add_reader(self.tree.process.stderr, lambda file: _drain(file, self.stderr))
        except OSError:
            self.tree.close()
            raise

    def add_reader(self, stream: Optional[BinaryIO], consume: Callable[[BinaryIO], None]) -> None:
        if stream is None:
            return
        reader = _PipeReader(stream, consume)
        self._readers.append(reader)
        reader.start()

    def wait(self, timeout: float) -> Optional[int]:
        try:
            return self.tree.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def close(self) -> None:
        """Kill whatever is left of the tree, wait until it is gone, collect readers."""
        if self._closed:
            return
        self._closed = True
        self.tree.terminate(grace_seconds=_TERMINATE_GRACE_SECONDS)
        # Files the step touched stay open until every process has exited,
        # which on Windows would block renaming or deleting them.
        if not self.tree.kill_all(_TREE_EXIT_TIMEOUT_SECONDS):
            logger.warning("Processes of a voice runtime step outlived their tree")
        self.tree.close()
        for reader in self._readers:
            reader.join()

    def output(self) -> str:
        return "\n".join(part for part in (self.stdout.text(), self.stderr.text()) if part)


def _drain(file: BinaryIO, tail: _OutputTail) -> None:
    while chunk := file.read(_READ_CHUNK_BYTES):
        tail.append(chunk)


class _ActivityWatch:
    """Detects a stalled step: no output and no file changes for a window.

    uv prints little when its output is not a terminal, so a long download is
    recognised by files growing under the watched directories. A stall is
    therefore reported between one and two windows after the last activity.
    """

    def __init__(self, paths: Sequence[Path], outputs: Sequence[_OutputTail]) -> None:
        self._paths = paths
        self._outputs = outputs
        self._last_activity = time.monotonic()
        self._fingerprint = _fingerprint(paths)

    def stalled(self, now: float, window: float) -> bool:
        latest_output = max(output.last_activity for output in self._outputs)
        self._last_activity = max(self._last_activity, latest_output)
        if now - self._last_activity < window:
            return False
        fingerprint = _fingerprint(self._paths)
        if fingerprint == self._fingerprint:
            return True
        self._fingerprint = fingerprint
        self._last_activity = now
        return False


def _fingerprint(paths: Sequence[Path]) -> tuple[int, int]:
    """Count entries and bytes under ``paths`` without following links."""
    entries = 0
    size = 0
    pending = [str(path) for path in paths]
    while pending:
        try:
            scanner = os.scandir(pending.pop())
        except OSError:
            continue
        with scanner:
            for entry in scanner:
                entries += 1
                try:
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(entry.path)
                    else:
                        size += entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
    return entries, size


class _StepRunner:
    """Runs provisioning children inside owned process trees with limits.

    Each child is bounded by the per-command limit, the overall provisioning
    budget, the stall window and the caller's cancel event. On any of these
    the whole process tree is killed.
    """

    def __init__(
        self,
        *,
        cwd: Path,
        timeouts: ProvisionTimeouts,
        cancel: Optional[threading.Event],
        watch: Sequence[Path],
    ) -> None:
        self._cwd = cwd
        self._timeouts = timeouts
        self._cancel = cancel
        self._watch = tuple(watch)
        self._deadline = time.monotonic() + timeouts.provision_seconds

    def check_cancelled(self, step: str) -> None:
        if self._cancel is not None and self._cancel.is_set():
            raise VoiceRuntimeCancelledError(f"Cancelled during: {step}.")

    def run(self, step: str, argv: Sequence[str], *, env: dict[str, str]) -> None:
        """Run a command to completion; raise unless it exits with status 0."""
        running = self._spawn(step, argv, env)
        try:
            _close_quietly(running.tree.stdin)
            running.add_reader(running.tree.stdout, lambda file: _drain(file, running.stdout))
            watch = _ActivityWatch(self._watch, (running.stdout, running.stderr))
            returncode = self._wait_for_exit(step, running, watch)
        finally:
            running.close()
        if returncode != 0:
            logger.warning("Voice runtime step %r failed:\n%s", step, running.output())
            raise VoiceRuntimeCommandError(step, returncode, running.output())

    def handshake(
        self,
        step: str,
        argv: Sequence[str],
        request: HandshakeRequest,
        *,
        env: dict[str, str],
    ) -> VoiceResponse:
        """Start the worker, send ``request`` and return the matching response."""
        running = self._spawn(step, argv, env)
        frames: queue.Queue[_Frame] = queue.Queue()
        try:
            running.add_reader(running.tree.stdout, lambda file: _read_frames(file, frames))
            self._send(step, running, request)
            return self._await_response(step, running, frames, request.id)
        finally:
            _close_quietly(running.tree.stdin)
            running.close()

    def _spawn(self, step: str, argv: Sequence[str], env: dict[str, str]) -> _RunningStep:
        self.check_cancelled(step)
        try:
            return _RunningStep(argv, env=env, cwd=self._cwd)
        except (OSError, ProcessTreeError) as error:
            raise VoiceRuntimeStepError(step, f"{step} could not start: {error}") from error

    def _wait_for_exit(self, step: str, running: _RunningStep, watch: _ActivityWatch) -> int:
        limit = self._command_deadline()
        while True:
            returncode = running.wait(_POLL_INTERVAL_SECONDS)
            if returncode is not None:
                return returncode
            self._check_limits(step, limit, running, watch)

    def _send(self, step: str, running: _RunningStep, request: HandshakeRequest) -> None:
        stdin = running.tree.stdin
        try:
            if stdin is None:
                raise BrokenPipeError("the voice worker has no input stream")
            write_voice_frame(stdin, request)
        except OSError as error:
            running.close()
            output = running.stderr.text()
            raise VoiceRuntimeSmokeError(
                step,
                f"The voice worker exited before the handshake{_last_line_suffix(output)}",
                output,
            ) from error

    def _await_response(
        self,
        step: str,
        running: _RunningStep,
        frames: queue.Queue[_Frame],
        request_id: str,
    ) -> VoiceResponse:
        limit = self._command_deadline()
        # A worker that neither answers nor logs is stalled, whatever the
        # command limit allows.
        watch = _ActivityWatch(self._watch, (running.stderr,))
        while True:
            self._check_limits(step, limit, running, watch)
            try:
                frame = frames.get(timeout=_POLL_INTERVAL_SECONDS)
            except queue.Empty:
                continue
            if isinstance(frame, VoiceResponse) and frame.ref_id == request_id:
                return frame
            if frame is None or isinstance(frame, Exception):
                running.close()
                output = running.stderr.text()
                reason = "stopped" if frame is None else f"sent an unreadable reply ({frame})"
                raise VoiceRuntimeSmokeError(
                    step,
                    f"The voice worker {reason} before answering the handshake"
                    f"{_last_line_suffix(output)}",
                    output,
                )

    def _command_deadline(self) -> float:
        return min(time.monotonic() + self._timeouts.uv_command_seconds, self._deadline)

    def _check_limits(
        self, step: str, limit: float, running: _RunningStep, watch: _ActivityWatch
    ) -> None:
        self.check_cancelled(step)
        now = time.monotonic()
        if now >= limit:
            budget = (
                f"the {self._timeouts.provision_seconds}-second installation limit"
                if limit >= self._deadline
                else f"its {self._timeouts.uv_command_seconds}-second limit"
            )
            raise VoiceRuntimeTimeoutError(
                step, f"{step} did not finish within {budget}.", running.output()
            )
        if watch.stalled(now, self._timeouts.stall_seconds):
            raise VoiceRuntimeTimeoutError(
                step,
                f"{step} stopped making progress for {self._timeouts.stall_seconds} seconds.",
                running.output(),
            )


def _read_frames(file: BinaryIO, frames: queue.Queue[_Frame]) -> None:
    reader = io.BufferedReader(file)  # type: ignore[arg-type]
    while True:
        try:
            frame = read_voice_frame(reader)
        except (VoiceProtocolError, OSError, ValueError) as error:
            frames.put(error)
            return
        frames.put(frame)
        if frame is None:
            return


def _smoke_test(
    runner: _StepRunner,
    target: _SmokeTarget,
    *,
    models_root: Path,
    env: dict[str, str],
) -> None:
    """Prove a runtime loads its native engines and speaks the worker protocol."""
    imports = "import " + ", ".join(_ENGINE_MODULES)
    try:
        runner.run(_SMOKE_STEP, [str(target.python), "-I", "-c", imports], env=env)
    except VoiceRuntimeCommandError as error:
        raise VoiceRuntimeSmokeError(
            _SMOKE_STEP,
            f"The voice engines could not be loaded{_last_line_suffix(error.output)}",
            error.output,
        ) from error
    request = HandshakeRequest(id=secrets.token_hex(8), client_version=target.product_version)
    argv = _worker_argv(target.directory, models_root, target.runtime_id)
    response = runner.handshake(_SMOKE_STEP, argv, request, env=env)
    _check_handshake(response, target)


def _check_handshake(response: VoiceResponse, target: _SmokeTarget) -> None:
    if not response.ok:
        reason = response.error.message if response.error is not None else "no reason given"
        raise VoiceRuntimeSmokeError(
            _SMOKE_STEP, f"The voice worker rejected the handshake: {reason}"
        )
    try:
        payload = HandshakeResponsePayload.from_dict(response.payload)
    except VoiceProtocolError as error:
        raise VoiceRuntimeSmokeError(
            _SMOKE_STEP, f"The voice worker sent an invalid handshake: {error}"
        ) from error
    if payload.protocol_version != VOICE_PROTOCOL_VERSION:
        raise VoiceRuntimeSmokeError(
            _SMOKE_STEP,
            f"The voice worker speaks protocol {payload.protocol_version}, "
            f"expected {VOICE_PROTOCOL_VERSION}.",
        )
    if payload.worker_version != target.product_version:
        raise VoiceRuntimeSmokeError(
            _SMOKE_STEP,
            f"The voice worker is version {payload.worker_version}, "
            f"expected {target.product_version}.",
        )
    if payload.manifest_id != target.runtime_id:
        raise VoiceRuntimeSmokeError(
            _SMOKE_STEP, "The voice worker reported a different runtime id."
        )


def _worker_argv(release_dir: Path, models_root: Path, runtime_id: str) -> list[str]:
    """Launch the worker through the release lock so the release stays in use."""
    return [
        str(_venv_python(release_dir / _VENV_DIRNAME)),
        "-I",
        "-m",
        _LAUNCHER_MODULE,
        "--hold",
        str(release_dir / IN_USE_FILENAME),
        "--",
        "--models-root",
        str(models_root),
        "--manifest-id",
        runtime_id,
    ]


def _venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _verify_sha256(path: Path, expected: str) -> None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(_HASH_CHUNK_BYTES):
                digest.update(chunk)
    except OSError as error:
        raise VoiceRuntimeIntegrityError(
            f"The bundled file {path.name} cannot be read: {error.strerror or error}"
        ) from error
    if digest.hexdigest() != expected:
        raise VoiceRuntimeIntegrityError(
            f"The bundled file {path.name} does not match its recorded checksum."
        )


def _prune_releases(paths: _RuntimePaths, *, keep: set[str]) -> list[str]:
    """Delete releases outside ``keep`` that no worker uses; return the rest."""
    retained: list[str] = []
    failures: list[str] = []
    for entry in _children(paths.releases):
        if entry.name in keep or _release_in_use(entry):
            retained.append(entry.name)
        else:
            _remove_entry(entry, failures)
    for failure in failures:
        logger.warning("Could not remove an older voice runtime: %s", failure)
    return retained


def _release_in_use(release_dir: Path) -> bool:
    """Whether a worker holds the release; unknown counts as in use."""
    try:
        return not can_lock(release_dir / IN_USE_FILENAME, exclusive=True)
    except OSError as error:
        logger.warning("Keeping voice runtime %s: %s", release_dir.name, error)
        return True


def _prune_python_installs(paths: _RuntimePaths, releases: Sequence[str]) -> None:
    """Delete managed interpreters that none of ``releases`` runs on.

    When the interpreter of any release cannot be determined, every
    interpreter is kept.
    """
    keep: set[str] = set()
    for release in releases:
        used = _python_installs_used_by(paths, release)
        if used is None:
            return
        keep |= used
    failures: list[str] = []
    for entry in _children(paths.python):
        if entry.name.startswith(_PYTHON_INSTALL_PREFIX) and entry.name not in keep:
            _remove_entry(entry, failures)
    for failure in failures:
        logger.warning("Could not remove an unused voice Python: %s", failure)


def _python_installs_used_by(paths: _RuntimePaths, release: str) -> Optional[set[str]]:
    """Names under ``python/`` that a release's venv points at, if known."""
    config = paths.release(release) / _VENV_DIRNAME / "pyvenv.cfg"
    try:
        home = _pyvenv_home(config.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return None
    if home is None:
        return None
    try:
        resolved = ((Path(home), paths.python), (Path(home).resolve(), paths.python.resolve()))
    except (OSError, RuntimeError):
        return None
    names: set[str] = set()
    for candidate, root in resolved:
        with contextlib.suppress(ValueError, IndexError):
            names.add(candidate.relative_to(root).parts[0])
    return names or None


def _pyvenv_home(config: str) -> Optional[str]:
    for line in config.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "home":
            return value.strip()
    return None


def _children(directory: Path) -> list[Path]:
    try:
        return list(directory.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return []


def _remove_entry(path: Path, failures: list[str]) -> None:
    """Delete ``path``; a symlink is unlinked, never followed."""
    try:
        if path.is_symlink() or not path.is_dir():
            path.unlink(missing_ok=True)
        else:
            _with_permission_retry(lambda: shutil.rmtree(path))
    except FileNotFoundError:
        return
    except OSError as error:
        failures.append(f"{path.name}: {error.strerror or error}")


def _with_permission_retry(action: Callable[[], _T]) -> _T:
    """Run ``action``, retrying briefly while Windows reports a file in use."""
    attempts = _PERMISSION_RETRY_ATTEMPTS if _RETRY_PERMISSION_ERRORS else 1
    attempt = 1
    while True:
        try:
            return action()
        except PermissionError:
            if attempt >= attempts:
                raise
        attempt += 1
        time.sleep(_PERMISSION_RETRY_DELAY_SECONDS)


def _write_atomic(path: Path, data: bytes) -> None:
    temporary = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            _fsync_file(handle.fileno())
        _with_permission_retry(lambda: os.replace(temporary, path))
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)


def _fsync_file(fd: int) -> None:
    if sys.platform == "darwin":
        import fcntl

        # fsync on macOS does not reach the storage device; F_FULLFSYNC does,
        # on the file systems that support it.
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass
    os.fsync(fd)


def _flush_filesystems() -> None:
    """Write every pending file to disk where the platform offers it."""
    if hasattr(os, "sync"):
        os.sync()


def _fsync_directory(directory: Path) -> None:
    """Persist renames in ``directory``; best effort, and a no-op on Windows."""
    if os.name == "nt":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError as error:
        logger.debug("Could not open %s to persist a rename: %s", directory, error)
        return
    try:
        os.fsync(fd)
    except OSError as error:
        logger.debug("Could not persist a rename in %s: %s", directory, error)
    finally:
        os.close(fd)


def _close_quietly(stream: Optional[BinaryIO]) -> None:
    if stream is not None and not stream.closed:
        with contextlib.suppress(OSError):
            stream.close()


def _last_line_suffix(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return f": {lines[-1]}" if lines else "."
