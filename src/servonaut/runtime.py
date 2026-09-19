"""Distribution-aware runtime layout and launch-command construction.

The resolver in this module is intentionally pure.  ``RuntimeEvidence`` is
collected at the process boundary and can therefore be supplied directly by
tests or by a caller that has already made its own discovery decisions.
"""

from __future__ import annotations

import importlib.metadata
import json
import math
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Final

from servonaut import __version__

_MARKER_FILENAME: Final = "servonaut-runtime.json"
_MARKER_SCHEMA_VERSION: Final = 1
# Build markers are a fixed, build-time schema with a handful of scalar fields.
# This protocol bound prevents an untrusted sibling file from consuming
# unbounded startup memory; it is deliberately not deployment configuration.
_MAX_MARKER_BYTES: Final = 256 * 1024
_PIPX_INSPECTION_TIMEOUT_ENV: Final = "SERVONAUT_PIPX_INSPECTION_TIMEOUT_SECONDS"
_DEFAULT_PIPX_INSPECTION_TIMEOUT_SECONDS: Final = 5.0
_MARKER_FIELDS: Final = frozenset(
    {
        "schema_version",
        "distribution",
        "product_version",
        "build_revision",
        "console_helper",
        "desktop_child",
    }
)


class DistributionKind(Enum):
    """The way the current Servonaut process was installed or packaged."""

    SOURCE = "source"
    PIP = "pip"
    PIPX = "pipx"
    FROZEN_CLI = "frozen-cli"
    PACKAGED_DESKTOP = "packaged-desktop"


class PackageManagementKind(Enum):
    """How (or whether) this distribution may manage Python packages."""

    PIP = "pip"
    PIPX = "pipx"
    MANAGED_RUNTIME = "managed-runtime"
    UNSUPPORTED = "unsupported"


class RuntimeCapabilityError(RuntimeError):
    """The detected distribution cannot perform the requested operation."""


class RuntimeMarkerError(RuntimeError):
    """A present build marker is invalid or unsafe."""


class DesktopProcessRole(str, Enum):
    """The operating role of a process in a packaged desktop distribution."""

    GUI = "gui"
    CHILD = "child"
    CONSOLE = "console"


@dataclass(frozen=True, slots=True)
class DesktopLaunchRoles:
    """Validated executable roles for a packaged desktop launch."""

    current: Path
    child: Path
    console: Path


@dataclass(frozen=True)
class RuntimeEvidence:
    """Facts collected at the runtime boundary before pure resolution."""

    executable: Path
    executable_root: Path
    resource_root: Path
    home: Path
    is_frozen: bool
    package_version: str
    package_is_installed: bool
    source_install_path: str | None
    path_console: Path | None
    pipx_executable: Path | None
    pipx_contains_servonaut: bool
    marker: Mapping[str, object] | None

    def __post_init__(self) -> None:
        """Freeze marker contents as well as the dataclass field binding."""
        if self.marker is not None:
            object.__setattr__(self, "marker", MappingProxyType(dict(self.marker)))


@dataclass(frozen=True)
class PackageManagementCapability:
    """Immutable package-management policy and fresh command builders."""

    kind: PackageManagementKind
    argv_prefix: tuple[str, ...]
    allows_automatic_mutation: bool

    def __post_init__(self) -> None:
        """Defensively freeze an argv prefix supplied by an external caller."""
        object.__setattr__(self, "argv_prefix", tuple(self.argv_prefix))

    def dependency_install_argv(self, packages: Sequence[str]) -> list[str]:
        """Build a package-install argv without mutating shared state."""
        package_args = _validate_package_names(packages)
        if self.kind is PackageManagementKind.PIP:
            return [*self.argv_prefix, "install", *package_args]
        if self.kind is PackageManagementKind.PIPX:
            return [*self.argv_prefix, "inject", "servonaut", *package_args]
        raise RuntimeCapabilityError(
            "This Servonaut distribution cannot install Python dependencies."
        )

    def self_update_argv(self, package: str = "servonaut") -> list[str]:
        """Build a self-update argv when this distribution permits one."""
        if not isinstance(package, str) or not package:
            raise ValueError("package must be a non-empty string")
        if self.kind is PackageManagementKind.PIP:
            if not self.allows_automatic_mutation:
                raise RuntimeCapabilityError(
                    "Source installations cannot self-update; update from the source checkout."
                )
            return [*self.argv_prefix, "install", "--upgrade", package]
        if self.kind is PackageManagementKind.PIPX:
            return [*self.argv_prefix, "upgrade", package]
        if self.kind is PackageManagementKind.UNSUPPORTED:
            raise RuntimeCapabilityError(
                "Frozen Servonaut distributions cannot update themselves with pip."
            )
        raise RuntimeCapabilityError(
            "This Servonaut distribution does not support self-updates."
        )


@dataclass(frozen=True)
class RuntimeLayout:
    """Resolved immutable layout and command builders for this process."""

    kind: DistributionKind
    product_version: str
    build_revision: str | None
    resource_root: Path
    executable_root: Path
    data_root: Path
    executable: Path
    python_executable: Path | None
    path_console: Path | None
    console_helper: Path | None
    desktop_child: Path | None
    package_management: PackageManagementCapability
    is_frozen: bool

    def current_app_argv(self, *args: str) -> list[str]:
        """Return a fresh argv that launches the current command surface."""
        command_args = _validate_launch_args(args)
        if self.kind in {
            DistributionKind.SOURCE,
            DistributionKind.PIP,
            DistributionKind.PIPX,
        }:
            return [str(self._python()), "-m", "servonaut.main", *command_args]
        if self.kind is DistributionKind.FROZEN_CLI:
            return [str(self.executable), *command_args]
        return [str(self._console_helper()), *command_args]

    def mcp_argv(self) -> list[str]:
        """Return a fresh argv for the console-safe MCP server command."""
        if self.kind in {
            DistributionKind.SOURCE,
            DistributionKind.PIP,
            DistributionKind.PIPX,
        }:
            if self.path_console is not None:
                return [str(self.path_console), "--mcp"]
            return [str(self._python()), "-m", "servonaut.main", "--mcp"]
        if self.kind is DistributionKind.FROZEN_CLI:
            return [str(self.executable), "--mcp"]
        return [str(self._console_helper()), "--mcp"]

    def desktop_child_argv(self, *args: str) -> list[str]:
        """Return a fresh argv for the separately packaged desktop child."""
        if self.desktop_child is None:
            raise RuntimeCapabilityError(
                "This Servonaut distribution has no desktop child helper."
            )
        return [str(self.desktop_child), *_validate_launch_args(args)]

    def _python(self) -> Path:
        if self.python_executable is None:
            raise RuntimeCapabilityError(
                "This frozen Servonaut distribution has no Python interpreter command."
            )
        return self.python_executable

    def _console_helper(self) -> Path:
        if self.console_helper is None:
            raise RuntimeCapabilityError(
                "This desktop distribution has no console helper."
            )
        return self.console_helper


def resolve_runtime(evidence: RuntimeEvidence) -> RuntimeLayout:
    """Resolve an immutable layout from evidence without any I/O.

    Do not add calls which inspect a path, environment, metadata, or process to
    this function.  Callers that need those facts must provide them through
    ``RuntimeEvidence`` or use ``collect_runtime_evidence``.
    """
    marker = _validate_marker(evidence.marker, evidence.executable_root)
    if marker is not None:
        return _layout_from_marker(evidence, marker)

    if evidence.is_frozen:
        return _frozen_cli_layout(evidence)
    if evidence.source_install_path is not None or not evidence.package_is_installed:
        return _managed_layout(evidence, DistributionKind.SOURCE)
    if evidence.pipx_contains_servonaut:
        return _managed_layout(evidence, DistributionKind.PIPX)
    return _managed_layout(evidence, DistributionKind.PIP)


def detect_runtime() -> RuntimeLayout:
    """Collect process facts and resolve the current runtime layout."""
    return resolve_runtime(collect_runtime_evidence())


def collect_runtime_evidence() -> RuntimeEvidence:
    """Collect best-effort process and installation facts at the I/O boundary."""
    executable = Path(sys.executable)
    executable_root = executable.parent
    is_frozen = bool(getattr(sys, "frozen", False))
    bundle_root = getattr(sys, "_MEIPASS", None)
    resource_root = (
        Path(bundle_root) if bundle_root is not None else Path(__file__).parent
    )
    package_version, package_is_installed, source_install_path = _package_evidence()
    marker = _read_build_marker(executable_root)
    has_packaged_marker = (
        marker is not None and _validate_marker(marker, executable_root) is not None
    )
    path_console = _current_interpreter_console(_path_command("servonaut"), executable)
    needs_pipx_classification = (
        package_is_installed
        and source_install_path is None
        and not is_frozen
        and not has_packaged_marker
    )
    pipx_executable = _path_command("pipx") if needs_pipx_classification else None
    pipx_contains_servonaut = (
        _pipx_owns_current_runtime(pipx_executable, executable)
        if needs_pipx_classification
        else False
    )

    return RuntimeEvidence(
        executable=executable,
        executable_root=executable_root,
        resource_root=resource_root,
        home=Path.home(),
        is_frozen=is_frozen,
        package_version=package_version,
        package_is_installed=package_is_installed,
        source_install_path=source_install_path,
        path_console=path_console,
        pipx_executable=pipx_executable,
        pipx_contains_servonaut=pipx_contains_servonaut,
        marker=marker,
    )


def validate_launch_argv(
    argv: Sequence[str],
    *,
    platform_name: str | None = None,
    executable_root: Path | None = None,
    runtime: RuntimeLayout | None = None,
) -> list[str]:
    """Validate an argv at an external launch/configuration boundary.

    The resolver deliberately does not call this helper.  It performs the
    filesystem and executability checks immediately before a process launch or
    an MCP configuration write, returning a new list on success. Supplying a
    runtime derives the executable root and applies its console-launch role
    policy; ``executable_root`` remains available to validate callers that do
    not hold a layout.
    """
    values = _validate_launch_args(argv)
    if not values:
        raise RuntimeCapabilityError("Launch command is empty.")
    command = Path(values[0])
    if not command.is_absolute():
        raise RuntimeCapabilityError("Launch command must be an absolute path.")
    if not command.is_file():
        raise RuntimeCapabilityError("Launch command must be an existing regular file.")
    selected_platform = os.name if platform_name is None else platform_name
    if selected_platform == "nt":
        if runtime is not None and runtime.is_frozen:
            if command.suffix.casefold() != ".exe":
                raise RuntimeCapabilityError(
                    "Frozen launch commands must be native Windows .exe files."
                )
        elif not _has_windows_executable_suffix(command):
            raise RuntimeCapabilityError(
                "Launch command must have an executable Windows file extension."
            )
    # Windows determines whether a file is launchable by its registered suffix;
    # POSIX execute bits do not carry that meaning there.
    if selected_platform != "nt" and not os.access(command, os.X_OK):
        raise RuntimeCapabilityError("Launch command is not executable.")
    confinement_root = executable_root
    if runtime is not None and runtime.is_frozen:
        confinement_root = runtime.executable_root
    if confinement_root is not None:
        _validate_command_confinement(command, confinement_root)
    if runtime is not None:
        _validate_console_launch_role(command, runtime)
    return list(values)


def _validate_command_confinement(command: Path, executable_root: Path) -> None:
    """Require a packaged command's resolved target to remain under its root."""
    try:
        resolved_command = command.resolve()
        resolved_root = executable_root.resolve()
        resolved_command.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise RuntimeCapabilityError(
            "Launch command must resolve inside the executable root."
        ) from error


def _validate_console_launch_role(command: Path, runtime: RuntimeLayout) -> None:
    """Require packaged console commands to identify the marked console helper."""
    if runtime.kind is not DistributionKind.PACKAGED_DESKTOP:
        return
    desktop_child = getattr(runtime, "desktop_child", None)
    if desktop_child is not None and _paths_identify_same_file(command, desktop_child):
        raise RuntimeCapabilityError(
            "A console launch command must not identify the desktop child helper."
        )
    is_console_executable = runtime.executable.stem.casefold() == "servonaut-cli" or (
        getattr(runtime, "executable_root", None) is not None
        and runtime.executable.parent != runtime.executable_root
        and getattr(runtime, "console_helper", None) is not None
        and _paths_identify_same_file(runtime.executable, runtime.console_helper)
        and runtime.console_helper.stem.casefold() != "servonaut-desktop"
    )
    if not is_console_executable and _paths_identify_same_file(
        command, runtime.executable
    ):
        raise RuntimeCapabilityError(
            "A console launch command must not identify the GUI executable."
        )
    console_helper = getattr(runtime, "console_helper", None)
    if console_helper is None or not _paths_identify_same_file(command, console_helper):
        raise RuntimeCapabilityError(
            "A console launch command must identify the console helper."
        )


def _paths_identify_same_file(first: Path, second: Path) -> bool:
    """Compare existing launch targets, including symlinks and hard links."""
    try:
        return first.samefile(second)
    except OSError:
        try:
            return first.resolve() == second.resolve()
        except (OSError, RuntimeError):
            return False


def _validate_desktop_executable_file(
    path: Path, executable_root: Path, selected_platform: str
) -> None:
    """Ensure a desktop executable is absolute, regular, non-symlink, confined, and executable."""
    if not path.is_absolute():
        raise RuntimeCapabilityError("Desktop executable must be an absolute path.")
    try:
        if path.is_symlink():
            raise RuntimeCapabilityError("Desktop executable must not be a symlink.")
        if path.is_dir():
            raise RuntimeCapabilityError("Desktop executable must not be a directory.")
        if not path.is_file():
            raise RuntimeCapabilityError(
                "Desktop executable must be an existing regular file."
            )
    except OSError as error:
        raise RuntimeCapabilityError(
            "Desktop executable must be an existing regular file."
        ) from error

    try:
        resolved_path = path.resolve()
        resolved_root = executable_root.resolve()
        resolved_path.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise RuntimeCapabilityError(
            "Desktop executable must resolve inside the executable root."
        ) from error

    if selected_platform == "nt":
        if path.suffix.casefold() != ".exe":
            raise RuntimeCapabilityError(
                "Frozen launch commands must be native Windows .exe files."
            )
    elif not os.access(path, os.X_OK):
        raise RuntimeCapabilityError("Launch command is not executable.")


def validate_desktop_process_role(
    runtime: RuntimeLayout,
    expected_role: DesktopProcessRole,
    *,
    current_executable: Path,
    platform_name: str | None = None,
) -> DesktopLaunchRoles:
    """Validate executable roles immediately before a desktop process launch.

    Derives roles from the shared build marker without assuming the current
    process is GUI. Normalizes errors to fixed messages without exposing paths.
    """
    if runtime.kind is not DistributionKind.PACKAGED_DESKTOP:
        raise RuntimeCapabilityError(
            "Desktop process roles require a packaged desktop distribution."
        )
    if not runtime.is_frozen:
        raise RuntimeCapabilityError(
            "Desktop process roles require a frozen distribution."
        )
    if runtime.desktop_child is None or runtime.console_helper is None:
        raise RuntimeCapabilityError(
            "Desktop process roles require marked child and console helpers."
        )

    if not _paths_identify_same_file(current_executable, runtime.executable):
        raise RuntimeCapabilityError(
            "Current executable does not match the runtime executable."
        )

    selected_platform = os.name if platform_name is None else platform_name
    for path in (current_executable, runtime.desktop_child, runtime.console_helper):
        _validate_desktop_executable_file(
            path, runtime.executable_root, selected_platform
        )

    if _paths_identify_same_file(runtime.desktop_child, runtime.console_helper):
        raise RuntimeCapabilityError(
            "Desktop child and console helper must be distinct files."
        )

    is_child = _paths_identify_same_file(current_executable, runtime.desktop_child)
    is_console = _paths_identify_same_file(current_executable, runtime.console_helper)

    if is_child and is_console:
        raise RuntimeCapabilityError(
            "Desktop child and console helper must be distinct files."
        )

    if is_child:
        derived_role = DesktopProcessRole.CHILD
    elif is_console:
        derived_role = DesktopProcessRole.CONSOLE
    else:
        derived_role = DesktopProcessRole.GUI

    if derived_role != expected_role:
        raise RuntimeCapabilityError(
            "Desktop process role does not match expected role."
        )

    return DesktopLaunchRoles(
        current=current_executable,
        child=runtime.desktop_child,
        console=runtime.console_helper,
    )


def validate_desktop_child_argv(
    argv: Sequence[str],
    *,
    runtime: RuntimeLayout,
    launcher_executable: Path,
    platform_name: str | None = None,
) -> tuple[str, ...]:
    """Validate a desktop child argv immediately before process creation.

    Verifies the calling launcher's GUI role and requires argv to be the
    exact marker-selected child path with valid arguments.
    """
    validate_desktop_process_role(
        runtime,
        DesktopProcessRole.GUI,
        current_executable=launcher_executable,
        platform_name=platform_name,
    )
    values = _validate_launch_args(argv)
    if not values:
        raise RuntimeCapabilityError("Launch command is empty.")
    if runtime.desktop_child is None:
        raise RuntimeCapabilityError(
            "Desktop process roles require marked child and console helpers."
        )
    if values[0] != str(runtime.desktop_child):
        raise RuntimeCapabilityError(
            "Desktop child command must use the marked child path."
        )
    return tuple(values)


def _managed_layout(evidence: RuntimeEvidence, kind: DistributionKind) -> RuntimeLayout:
    capability = _package_capability(
        kind, evidence.executable, evidence.pipx_executable
    )
    return RuntimeLayout(
        kind=kind,
        product_version=evidence.package_version,
        build_revision=None,
        resource_root=evidence.resource_root,
        executable_root=evidence.executable_root,
        data_root=evidence.home / ".servonaut",
        executable=evidence.executable,
        python_executable=evidence.executable,
        path_console=evidence.path_console,
        console_helper=None,
        desktop_child=None,
        package_management=capability,
        is_frozen=False,
    )


def _frozen_cli_layout(evidence: RuntimeEvidence) -> RuntimeLayout:
    return RuntimeLayout(
        kind=DistributionKind.FROZEN_CLI,
        product_version=evidence.package_version,
        build_revision=None,
        resource_root=evidence.resource_root,
        executable_root=evidence.executable_root,
        data_root=evidence.home / ".servonaut",
        executable=evidence.executable,
        python_executable=None,
        path_console=evidence.path_console,
        console_helper=evidence.executable,
        desktop_child=None,
        package_management=_unsupported_capability(),
        is_frozen=True,
    )


def _layout_from_marker(
    evidence: RuntimeEvidence, marker: _ValidatedMarker
) -> RuntimeLayout:
    kind = marker.kind
    console_helper = marker.console_helper
    if kind is DistributionKind.FROZEN_CLI and console_helper is None:
        console_helper = evidence.executable
    if kind is DistributionKind.PACKAGED_DESKTOP and console_helper is None:
        raise RuntimeMarkerError("A packaged-desktop marker requires console_helper.")
    if marker.desktop_child is not None and marker.desktop_child == console_helper:
        raise RuntimeMarkerError(
            "A desktop child helper must not be used as the console helper."
        )
    return RuntimeLayout(
        kind=kind,
        product_version=marker.product_version,
        build_revision=marker.build_revision,
        resource_root=evidence.resource_root,
        executable_root=evidence.executable_root,
        data_root=evidence.home / ".servonaut",
        executable=evidence.executable,
        python_executable=None,
        path_console=evidence.path_console,
        console_helper=console_helper,
        desktop_child=marker.desktop_child,
        package_management=_unsupported_capability(),
        is_frozen=True,
    )


def _package_capability(
    kind: DistributionKind,
    executable: Path,
    pipx_executable: Path | None,
) -> PackageManagementCapability:
    if kind is DistributionKind.PIP:
        return PackageManagementCapability(
            PackageManagementKind.PIP,
            (str(executable), "-m", "pip"),
            True,
        )
    if kind is DistributionKind.PIPX:
        if pipx_executable is None:
            raise RuntimeCapabilityError("The pipx executable is unavailable.")
        return PackageManagementCapability(
            PackageManagementKind.PIPX,
            (str(pipx_executable),),
            True,
        )
    if kind is DistributionKind.SOURCE:
        return PackageManagementCapability(
            PackageManagementKind.PIP,
            (str(executable), "-m", "pip"),
            False,
        )
    return _unsupported_capability()


def _unsupported_capability() -> PackageManagementCapability:
    return PackageManagementCapability(
        PackageManagementKind.UNSUPPORTED,
        (),
        False,
    )


@dataclass(frozen=True)
class _ValidatedMarker:
    kind: DistributionKind
    product_version: str
    build_revision: str | None
    console_helper: Path | None
    desktop_child: Path | None


def _validate_marker(
    marker: Mapping[str, object] | None, executable_root: Path
) -> _ValidatedMarker | None:
    if marker is None:
        return None
    if not isinstance(marker, Mapping):
        raise RuntimeMarkerError("Build marker must be a JSON object.")
    unknown_fields = set(marker).difference(_MARKER_FIELDS)
    if unknown_fields:
        raise RuntimeMarkerError("Build marker contains unsupported fields.")
    schema_version = marker.get("schema_version")
    if type(schema_version) is not int or schema_version != _MARKER_SCHEMA_VERSION:
        raise RuntimeMarkerError("Build marker has an unsupported schema_version.")
    distribution = marker.get("distribution")
    try:
        kind = DistributionKind(distribution)
    except (TypeError, ValueError) as error:
        raise RuntimeMarkerError("Build marker has an invalid distribution.") from error
    if kind not in {DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP}:
        raise RuntimeMarkerError("Build marker distribution is not a packaged runtime.")
    product_version = marker.get("product_version")
    if not isinstance(product_version, str) or not product_version.strip():
        raise RuntimeMarkerError("Build marker requires a non-empty product_version.")
    build_revision = _optional_identity(marker, "build_revision")
    console_helper = _marker_helper(marker, "console_helper", executable_root)
    desktop_child = _marker_helper(marker, "desktop_child", executable_root)
    return _ValidatedMarker(
        kind=kind,
        product_version=product_version,
        build_revision=build_revision,
        console_helper=console_helper,
        desktop_child=desktop_child,
    )


def _optional_identity(marker: Mapping[str, object], field: str) -> str | None:
    value = marker.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RuntimeMarkerError(
            f"Build marker field {field} must be a non-empty string."
        )
    return value


def _marker_helper(
    marker: Mapping[str, object], field: str, executable_root: Path
) -> Path | None:
    value = marker.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeMarkerError(
            f"Build marker field {field} must be null or a path string."
        )
    segments = _safe_relative_segments(value)
    return executable_root.joinpath(*segments)


def _safe_relative_segments(value: str) -> tuple[str, ...]:
    """Validate one marker helper path under POSIX and Windows semantics.

    This is string-only validation.  In particular it intentionally does not
    call ``Path.resolve`` or inspect a filesystem, keeping resolver tests
    deterministic on hosts that differ from the packaged target platform.
    """
    if not value or "\x00" in value:
        raise RuntimeMarkerError("Build marker helper path must be non-empty and safe.")
    posix_path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or windows_path.root
    ):
        raise RuntimeMarkerError("Build marker helper path must be relative.")
    segments = tuple(value.replace("\\", "/").split("/"))
    if any(
        segment in {"", ".", ".."}
        or ":" in segment
        or _is_unsafe_windows_segment(segment)
        for segment in segments
    ):
        raise RuntimeMarkerError("Build marker helper path contains an unsafe segment.")
    return segments


def _is_unsafe_windows_segment(segment: str) -> bool:
    """Reject Windows-normalised aliases before a marker can name one."""
    if segment.endswith((".", " ")):
        return True
    device_name = segment.split(".", 1)[0].casefold()
    return device_name in {
        "con",
        "conin$",
        "conout$",
        "prn",
        "aux",
        "nul",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
        "com¹",
        "com²",
        "com³",
        "lpt¹",
        "lpt²",
        "lpt³",
    }


def _validate_package_names(packages: Sequence[str]) -> list[str]:
    values = list(packages)
    if not values or any(
        not isinstance(package, str) or not package for package in values
    ):
        raise ValueError("packages must contain one or more non-empty strings")
    return values


def _validate_launch_args(args: Sequence[str]) -> list[str]:
    values = list(args)
    if any(not isinstance(arg, str) for arg in values):
        raise TypeError("launch arguments must be strings")
    return values


def _has_windows_executable_suffix(command: Path) -> bool:
    extensions = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    allowed = {extension.lower() for extension in extensions.split(";") if extension}
    return command.suffix.lower() in allowed


def _read_build_marker(executable_root: Path) -> Mapping[str, object] | None:
    marker_path = executable_root / _MARKER_FILENAME
    try:
        with marker_path.open("rb") as marker_file:
            raw_marker_bytes = marker_file.read(_MAX_MARKER_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeMarkerError("Build marker could not be read.") from error
    if len(raw_marker_bytes) > _MAX_MARKER_BYTES:
        raise RuntimeMarkerError("Build marker exceeds the supported size.")
    try:
        raw_marker = raw_marker_bytes.decode("utf-8")
    except UnicodeError as error:
        raise RuntimeMarkerError("Build marker could not be read.") from error
    try:
        marker = json.loads(raw_marker)
    except (json.JSONDecodeError, RecursionError) as error:
        raise RuntimeMarkerError("Build marker contains invalid JSON.") from error
    if not isinstance(marker, dict):
        raise RuntimeMarkerError("Build marker must contain a JSON object.")
    return marker


def _package_evidence() -> tuple[str, bool, str | None]:
    try:
        distribution = importlib.metadata.distribution("servonaut")
    except importlib.metadata.PackageNotFoundError:
        return __version__, False, None
    package_version = distribution.version
    return package_version, True, _source_install_path(distribution)


def _source_install_path(distribution: importlib.metadata.Distribution) -> str | None:
    try:
        raw_direct_url = distribution.read_text("direct_url.json")
        direct_url = json.loads(raw_direct_url) if raw_direct_url else None
    except (OSError, TypeError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(direct_url, dict):
        return None
    url = direct_url.get("url")
    dir_info = direct_url.get("dir_info")
    if isinstance(direct_url.get("archive_info"), dict):
        return None
    editable = isinstance(dir_info, dict) and bool(dir_info.get("editable"))
    local_directory = (
        isinstance(dir_info, dict) and isinstance(url, str) and url.startswith("file:")
    )
    if editable or local_directory:
        return url if isinstance(url, str) else "editable"
    return None


def _path_command(name: str) -> Path | None:
    command = shutil.which(name)
    if command is None:
        return None
    return Path(os.path.abspath(command))


def _current_interpreter_console(
    path_console: Path | None, executable: Path
) -> Path | None:
    """Keep only a PATH script that belongs to this interpreter environment.

    A PATH result is later persisted in MCP configuration, so an unrelated
    wrapper must not displace the always-correct ``python -m`` fallback.
    Returning the canonical entrypoint also avoids retaining a mutable PATH
    symlink after it has been proven equivalent at collection time.
    """
    if path_console is None:
        return None
    expected_entrypoint = _interpreter_console_entrypoint(executable)
    try:
        if path_console.resolve() != expected_entrypoint.resolve():
            return None
    except (OSError, RuntimeError):
        return None
    return expected_entrypoint.resolve()


def _interpreter_console_entrypoint(executable: Path) -> Path:
    """Return this interpreter environment's console-script entrypoint."""
    suffix = ".exe" if os.name == "nt" else ""
    return executable.parent / f"servonaut{suffix}"


def _pipx_owns_current_runtime(pipx_executable: Path | None, executable: Path) -> bool:
    """Confirm both pipx membership and that *this* Python is its venv.

    A different `servonaut` pipx venv on PATH must not reclassify a source or
    normal pip process.  The executable containment check is intentionally
    collected here, outside the pure resolver.
    """
    if pipx_executable is None:
        return False
    venv_directory = _containing_venv_directory(executable)
    if venv_directory is None:
        return False
    try:
        environment_result = subprocess.run(
            [str(pipx_executable), "environment", "--value", "PIPX_LOCAL_VENVS"],
            capture_output=True,
            check=False,
            text=True,
            timeout=_pipx_inspection_timeout_seconds(),
        )
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return False
    if environment_result.returncode != 0:
        return False
    local_venvs = environment_result.stdout.strip()
    if not local_venvs:
        return False
    try:
        expected_venv = _canonical_directory(Path(local_venvs) / "servonaut")
        current_venv = _canonical_directory(venv_directory)
    except (OSError, RuntimeError):
        return False
    if current_venv != expected_venv:
        return False
    try:
        list_result = subprocess.run(
            [str(pipx_executable), "list", "--json"],
            capture_output=True,
            check=False,
            text=True,
            timeout=_pipx_inspection_timeout_seconds(),
        )
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return False
    if list_result.returncode != 0:
        return False
    try:
        payload = json.loads(list_result.stdout)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    venvs = payload.get("venvs")
    return isinstance(venvs, dict) and "servonaut" in venvs


def _containing_venv_directory(executable: Path) -> Path | None:
    """Return the venv directory containing a POSIX or Windows interpreter.

    Deliberately do not resolve ``executable``: virtual-environment Python is
    commonly a symlink to a base interpreter outside the venv.
    """
    if executable.parent.name.casefold() not in {"bin", "scripts"}:
        return None
    return executable.parent.parent


def _canonical_directory(path: Path) -> Path:
    """Canonicalise a containing directory during impure pipx discovery."""
    return path.resolve()


def _pipx_inspection_timeout_seconds() -> float:
    """Return a bounded, deployment-configurable pipx discovery timeout.

    Runtime collection runs during startup.  A missing or malformed override
    must not leave startup unbounded or make a package-manager probe fatal.
    """
    raw_value = os.environ.get(_PIPX_INSPECTION_TIMEOUT_ENV)
    if raw_value is None:
        return _DEFAULT_PIPX_INSPECTION_TIMEOUT_SECONDS
    try:
        timeout = float(raw_value)
    except ValueError:
        return _DEFAULT_PIPX_INSPECTION_TIMEOUT_SECONDS
    if not math.isfinite(timeout) or timeout <= 0:
        return _DEFAULT_PIPX_INSPECTION_TIMEOUT_SECONDS
    return timeout
