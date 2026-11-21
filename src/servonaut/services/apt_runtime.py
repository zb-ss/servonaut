"""Running Debian payload generations and leases for in-generation children."""

from __future__ import annotations

import json
import logging
import math
import os
import re
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from servonaut.debian_layout import (
    GENERATION, GENERATIONS, HELPER_ROOT, INSTALL_ROOT, LEASE, MARKER, MAX_STATUS_BYTES,
    PACKAGE_NAME, PAYLOAD, RESTART_GENERATION_ENV, ROLES, STATUS, acquire_shared_lease, invocation_role,
)
from servonaut.runtime import (
    RuntimeLayout, RuntimeMarkerError, _ValidatedMarker, _read_build_marker, _validate_marker,
)

_DEB_PRODUCT_VERSION = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)(rc[0-9]+)?")
APT_RUNTIME_POLL_ENV = "SERVONAUT_APT_RUNTIME_POLL_SECONDS"
_DEFAULT_RUNTIME_POLL_SECONDS = 30.0
_DPKG_STATUS_FILE = Path("/var/lib/dpkg/status")
APT_RESTART_EXIT_CODE = 75


@dataclass(frozen=True)
class AptBuildIdentity:
    product_version: str
    build_revision: str | None
    packaging_revision: int
    executable_id: tuple[int, int]


@dataclass(frozen=True)
class DpkgPackageState:
    status: str
    version: str = ""


class AptChange(Enum):
    UNCHANGED = "unchanged"
    DEFERRED = "deferred"
    RESTART_REQUIRED = "restart-required"
    REMOVED = "removed"


@dataclass(frozen=True)
class AptUpgradeState:
    change: AptChange
    installed: AptBuildIdentity | None = None
    allocated_bytes: int = 0
    unconsolidated_bytes: int = 0

    @property
    def restart_version(self) -> str | None:
        return self.installed.product_version if self.change is AptChange.RESTART_REQUIRED and self.installed else None


def restart_instruction(running_version: str, installed_version: str) -> str:
    if installed_version == running_version:
        return "Restart to use the updated build"
    return f"Restart to use version {installed_version}"


def package_update_notice(running_version: str, installed_version: str, *, managed_by_apt: bool) -> str:
    source = " by apt" if managed_by_apt else ""
    return f"Servonaut was updated{source}. {restart_instruction(running_version, installed_version)}."


def apt_runtime_poll_seconds() -> float:
    try:
        seconds = float(os.environ.get(APT_RUNTIME_POLL_ENV, ""))
    except ValueError:
        return _DEFAULT_RUNTIME_POLL_SECONDS
    return max(5.0, min(seconds, 600.0)) if math.isfinite(seconds) else _DEFAULT_RUNTIME_POLL_SECONDS


class AptRuntimeMonitor:
    """Track an immutable running build without repeating package ownership queries."""

    def __init__(self, runtime: RuntimeLayout, running: AptBuildIdentity) -> None:
        self.runtime = runtime
        self.running = running
        self._owned = False
        self._lock = threading.Lock()
        self._cached_state: AptUpgradeState | None = None
        self._cached_stamp: tuple | None = None
        self._checked_at = 0.0

    @classmethod
    def for_runtime(cls, runtime: RuntimeLayout) -> AptRuntimeMonitor | None:
        running = capture_running_apt_build(runtime)
        return cls(runtime, running) if running is not None else None

    def check(self, *, force: bool = False) -> AptUpgradeState | None:
        """Return a state once dpkg has confirmed ownership of this install."""
        from servonaut.updates.apt import read_apt_runtime_package

        def read_dpkg(package: str) -> DpkgPackageState | None:
            state = read_apt_runtime_package(self.runtime, package, verify_ownership=not self._owned)
            if state is not None:
                self._owned = True
            return state

        with self._lock:
            executable = self.runtime.executable
            stamp = _runtime_stamp(executable)
            recent = time.monotonic() - self._checked_at < apt_runtime_poll_seconds()
            confirmed = self._cached_state is not None and self._cached_state.change is not AptChange.DEFERRED
            if not force and stamp is not None and stamp == self._cached_stamp and (recent or confirmed):
                return self._cached_state
            state = inspect_apt_upgrade(self.runtime.executable, self.running, read_dpkg)
            self._cached_stamp = stamp if stamp == _runtime_stamp(executable) else None
            self._cached_state = state if self._owned else None
            self._checked_at = time.monotonic()
            return self._cached_state


@dataclass(frozen=True)
class _InstalledSnapshot:
    build: AptBuildIdentity
    identities: tuple[tuple[int, int, int, int], ...]
    allocated_bytes: int = 0
    unconsolidated_bytes: int = 0


def _package_root(executable: Path) -> Path | None:
    if sys.platform != "linux" or executable.name not in ROLES:
        return None
    directory = generation_directory(executable)
    root = directory.parent.parent if directory is not None else executable.parent.resolve()
    return root if root.parent == INSTALL_ROOT.resolve() and PACKAGE_NAME.fullmatch(root.name) else None


def _root_regular(path: Path) -> os.stat_result:
    entry = path.lstat()
    if not stat.S_ISREG(entry.st_mode) or entry.st_uid != 0 or entry.st_mode & 0o022:
        raise ValueError("Invalid installed Servonaut package file.")
    return entry


def _root_directory(path: Path) -> None:
    entry = path.lstat()
    if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != 0 or entry.st_mode & 0o022:
        raise ValueError("Invalid installed Servonaut package directory.")


def stable_apt_launcher(executable: Path, role: str) -> Path | None:
    """Return the persistent launcher for a role in a concrete generation."""
    generation = generation_directory(executable)
    if generation is None or role not in ROLES:
        return None
    return INSTALL_ROOT / generation.parent.parent.name / role


def validate_stable_apt_launcher(launcher: Path) -> Path:
    """Require the root-owned alias to point to the installed package helper."""
    root = launcher.parent
    _root_directory(root.resolve())
    helper = HELPER_ROOT / root.name / "apt-generation"
    _root_directory(helper.parent)
    if launcher.readlink() != helper or launcher.lstat().st_uid != 0:
        raise ValueError("Invalid Servonaut stable launcher.")
    _root_regular(helper)
    return helper


def dpkg_generation_paths(executable: Path) -> tuple[Path, Path] | None:
    """Return the dpkg-owned paths representing a retained executable's role."""
    generation = generation_directory(executable)
    if generation is None:
        return None
    root = INSTALL_ROOT / generation.parent.parent.name
    validate_stable_apt_launcher(root / executable.name)
    _root_directory(root / PAYLOAD)
    binary, marker = root / PAYLOAD / executable.name, root / MARKER
    _root_regular(binary)
    _root_regular(marker)
    # Keep the original spelling for dpkg-query's file database, including
    # installations with a separate /opt target behind a symbolic link.
    return binary, marker


def exec_apt_restart(executable: Path, args: list[str]) -> None:
    """Replace a stopped application with the currently installed role."""
    from servonaut.utils.process_cleanup import cleanup_process_resources

    root = _package_root(executable)
    if root is None:
        raise ValueError("Servonaut cannot find its installed Debian launcher.")
    launcher = INSTALL_ROOT / root.name / executable.name
    env = os.environ.copy()
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    original_library_path = env.pop("LD_LIBRARY_PATH_ORIG", None)
    if original_library_path is None:
        env.pop("LD_LIBRARY_PATH", None)
    else:
        env["LD_LIBRARY_PATH"] = original_library_path
    if launcher.is_symlink():
        validate_stable_apt_launcher(launcher)
        env[RESTART_GENERATION_ENV] = "1"
    else:
        _root_directory(root)
        _root_regular(launcher)
        env.pop(RESTART_GENERATION_ENV, None)
    generation = generation_directory(executable)
    if generation is not None:
        _release_lease_on_exec(generation / LEASE)
        if Path.cwd().is_relative_to(generation):
            os.chdir(root)
    cleanup_process_resources()
    logging.shutdown()
    os.execve(launcher, [str(launcher), *args], env)


def _release_lease_on_exec(lease: Path) -> None:
    """Do not carry the old generation's lease into the replacement process."""
    original = lease.stat()
    for entry in Path("/proc/self/fd").iterdir():
        descriptor = int(entry.name)
        if descriptor < 3:
            continue
        try:
            if os.path.samestat(os.fstat(descriptor), original):
                os.set_inheritable(descriptor, False)
        except OSError:
            continue  # another thread closed the descriptor

def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _runtime_stamp(executable: Path) -> tuple | None:
    """Use cheap path metadata until dpkg or the installed generation changes."""
    root = _package_root(executable)
    if root is None:
        return None
    observations = []
    for path in (_DPKG_STATUS_FILE, root / MARKER, root / executable.name,
                 root / PAYLOAD / executable.name, root / GENERATIONS / STATUS):
        try:
            observations.append(_file_identity(path.lstat()))
        except FileNotFoundError:
            observations.append(None)
        except OSError:
            return None
    return tuple(observations)


def capture_running_apt_build(runtime: RuntimeLayout) -> AptBuildIdentity | None:
    """Capture launch facts once for a runtime whose package ownership was proven."""
    if not runtime.is_frozen or runtime.packaging_revision is None or _package_root(runtime.executable) is None:
        return None
    try:
        image = Path("/proc/self/exe").stat()
        if not os.path.samestat(image, _root_regular(runtime.executable)):
            return None
    except (OSError, ValueError):
        return None
    return AptBuildIdentity(
        runtime.product_version, runtime.build_revision, runtime.packaging_revision,
        (image.st_dev, image.st_ino),
    )


def _matches_dpkg_version(build: AptBuildIdentity, version: str) -> bool:
    match = _DEB_PRODUCT_VERSION.fullmatch(build.product_version)
    if not match:
        return False
    release, rc = match.groups()
    upstream = f"{release}~{rc}" if rc else release
    return version == f"{upstream}-{build.packaging_revision}" or (
        build.packaging_revision == 1 and version == upstream
    )


def _generation_status(root: Path) -> dict:
    path = root / GENERATIONS / STATUS
    _root_regular(path)
    with path.open("rb") as handle:
        data = handle.read(MAX_STATUS_BYTES + 1)
    if len(data) > MAX_STATUS_BYTES:
        raise ValueError("Invalid Servonaut generation status size.")
    status = json.loads(data)
    if not isinstance(status, dict) or status.get("schema_version") != 1:
        raise ValueError("Invalid Servonaut generation status schema.")
    name = status.get("current")
    if not isinstance(name, str) or not GENERATION.fullmatch(name):
        raise ValueError("Invalid current Servonaut generation.")
    for field in ("allocated_bytes", "unconsolidated_bytes"):
        value = status.get(field)
        if type(value) is not int or value < 0:
            raise ValueError("Invalid Servonaut generation storage totals.")
    return status


def _installed_snapshot(root: Path, role: str) -> _InstalledSnapshot:
    _root_directory(root)
    canonical_marker = root / MARKER
    stable_role = root / role
    observed = [_file_identity(_root_regular(canonical_marker))]
    marker = _read_build_marker(root)
    build = _validate_marker(marker, root)
    if build is None:
        raise ValueError("Servonaut package marker is missing.")
    if not stable_role.is_symlink():
        binary = _root_regular(stable_role)
        observed.append(_file_identity(binary))
        return _snapshot(build, binary, observed, allocated=0, unshared=0)

    helper = validate_stable_apt_launcher(stable_role)
    _root_directory(root / PAYLOAD)
    _root_directory(root / GENERATIONS)
    status = _generation_status(root)
    generation = root / GENERATIONS / status["current"]
    _root_directory(generation)
    staged = _root_regular(root / PAYLOAD / role)
    for path in (helper, generation / MARKER):
        observed.append(_file_identity(_root_regular(path)))
    if marker != _read_build_marker(generation):
        raise ValueError("Servonaut staged and active markers differ.")
    binary = _root_regular(generation / role)
    unshared = status["unconsolidated_bytes"]
    if unshared == 0 and not os.path.samestat(staged, binary):
        raise ValueError("Servonaut staged and active executables differ.")
    observed.extend((_file_identity(staged), _file_identity(binary)))
    return _snapshot(build, binary, observed, allocated=status["allocated_bytes"], unshared=unshared)


def _snapshot(
    build: _ValidatedMarker,
    binary: os.stat_result,
    observed: list[tuple[int, int, int, int]],
    *,
    allocated: int,
    unshared: int,
) -> _InstalledSnapshot:
    identity = AptBuildIdentity(
        build.product_version, build.build_revision, build.packaging_revision,
        (binary.st_dev, binary.st_ino),
    )
    return _InstalledSnapshot(identity, tuple(observed), allocated, unshared)


def inspect_apt_upgrade(
    executable: Path,
    running: AptBuildIdentity,
    read_dpkg: Callable[[str], DpkgPackageState | None],
) -> AptUpgradeState:
    """Compare two bounded reads around dpkg's configured state off the UI thread."""
    root = _package_root(executable)
    deferred = AptUpgradeState(AptChange.DEFERRED)
    if root is None:
        return deferred
    before = read_dpkg(root.name)
    if before is None:
        return deferred
    if before.status in {"not-installed", "config-files"}:
        marker = root / MARKER
        if not marker.exists() and read_dpkg(root.name) == before and not marker.exists():
            return AptUpgradeState(AptChange.REMOVED)
        return deferred
    if before.status != "installed":
        return deferred
    try:
        first = _installed_snapshot(root, executable.name)
        second = _installed_snapshot(root, executable.name)
    except (OSError, RuntimeMarkerError, ValueError, RecursionError):
        return deferred
    if first != second or not _matches_dpkg_version(second.build, before.version):
        return deferred
    if read_dpkg(root.name) != before:
        return deferred
    change = AptChange.UNCHANGED if running == second.build else AptChange.RESTART_REQUIRED
    return AptUpgradeState(change, second.build, second.allocated_bytes, second.unconsolidated_bytes)


def generation_directory(executable: Path) -> Path | None:
    """Recognize the concrete executable path used by a Debian launcher."""
    if sys.platform != "linux" or executable.name not in ROLES:
        return None
    directory = executable.parent.resolve()
    store = directory.parent
    package = store.parent
    if (
        package.parent == INSTALL_ROOT.resolve()
        and PACKAGE_NAME.fullmatch(package.name)
        and store.name == GENERATIONS
        and GENERATION.fullmatch(directory.name)
    ):
        return directory
    return None


def pin_apt_command(command: str) -> str:
    """Keep launches made by a running Debian process in that process's payload."""
    generation = generation_directory(Path(sys.executable))
    if generation is None:
        return command
    root = generation.parent.parent
    helper = HELPER_ROOT / root.name / "apt-generation"
    role = invocation_role(Path(command), root, helper.resolve())
    return str(generation / role) if role is not None else command


@contextmanager
def inherited_apt_lease(command: str) -> Iterator[tuple[int, ...]]:
    """Hold a shared generation lease through exec of a sibling payload role."""
    generation = generation_directory(Path(sys.executable))
    if generation is None or generation_directory(Path(command)) != generation:
        yield ()
        return

    lease = os.open(generation / LEASE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(lease)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise OSError("The installed Servonaut generation lease is invalid.")
        yield (lease,) if acquire_shared_lease(lease) else ()
    finally:
        # The child's descriptor refers to the same open file description.
        # Closing our copy leaves the child's lease active until it exits.
        os.close(lease)
