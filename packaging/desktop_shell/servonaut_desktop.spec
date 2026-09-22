"""PyInstaller desktop-onedir definition for an installed Servonaut wheel.

Builds three executable roles into a single onedir payload:
1. servonaut-desktop: GUI launcher (windowed subsystem, pywebview main thread)
2. servonaut-desktop-child: Private child server (console subsystem, authenticated loopback host)
3. servonaut: Packaged console helper (console subsystem, CLI/MCP)
"""

from __future__ import annotations

import errno
import importlib.metadata
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

from PyInstaller.utils.hooks import copy_metadata

try:
    from PyInstaller.exceptions import (
        ImportErrorWhenRunningHook as _HookImportError,
        PythonLibraryNotFoundError as _PythonLibraryNotFoundError,
    )
    from PyInstaller.isolated._parent import (
        SubprocessDiedError as _IsolatedChildDiedError,
    )
except ImportError:
    _HookImportError = None
    _IsolatedChildDiedError = None
    _PythonLibraryNotFoundError = None

try:
    from PyInstaller.compat import pywintypes as _pywintypes
except ImportError:
    _PyWinTypesError = None
else:
    _candidate_pywin_error = getattr(_pywintypes, "error", None)
    _PyWinTypesError = (
        _candidate_pywin_error if isinstance(_candidate_pywin_error, type) else None
    )

_ENVIRONMENT_KEYS = frozenset(
    {
        "SERVONAUT_DESKTOP_GUI_ENTRY_SCRIPT",
        "SERVONAUT_DESKTOP_CHILD_ENTRY_SCRIPT",
        "SERVONAUT_DESKTOP_CLI_ENTRY_SCRIPT",
        "SERVONAUT_DESKTOP_ISOLATED_SITE_PACKAGES",
        "SERVONAUT_DESKTOP_PROFILE_PATH",
        "SERVONAUT_DESKTOP_OUTPUT_DIR",
        "SERVONAUT_DESKTOP_BUILD_METADATA_DIR",
        "SERVONAUT_DESKTOP_FRONTEND_DIR",
        "SERVONAUT_DESKTOP_REQUIRE_ARTIFACT_SELFTEST",
    }
)
_PROFILE_KEYS = frozenset(
    {
        "schema_version",
        "target_name",
        "target_platform",
        "target_architecture",
        "python_version",
        "payload_name",
        "product_version",
        "excluded_modules",
        "hook_directory",
        "require_artifact_selftest",
    }
)
_TARGETS = {
    "windows-x64": ("win32", "x86_64"),
    "macos-x64": ("darwin", "x86_64"),
    "macos-arm64": ("darwin", "arm64"),
    "linux-x64-ubuntu-22.04": ("linux", "x86_64"),
}
_FIXED_EXCLUDES = (
    "readline",
    "faster_whisper",
    "ctranslate2",
    "sherpa_onnx",
    "sounddevice",
    "numpy",
)
_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)$")
_TARGET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_RUNTIME_METADATA_DISTRIBUTIONS = (
    "servonaut",
    "mcp",
    "ovh",
    "hcloud",
    "boto3",
    "botocore",
    "cryptography",
    "PyNaCl",
    "bcrypt",
    "keyring",
    "certifi",
    "pywebview",
    "aiohttp",
    "textual",
    "textual_serve",
)
_DIAGNOSTIC_EXIT_BASE = 64
_DIAGNOSTIC_PHASE_PREFLIGHT = 0
_DIAGNOSTIC_PHASE_RUNTIME_METADATA = 1
_DIAGNOSTIC_PHASE_ANALYSIS = 2
_DIAGNOSTIC_PHASE_DATA_FILTERING = 3
_DIAGNOSTIC_PHASE_PYZ = 4
_DIAGNOSTIC_PHASE_EXE = 5
_DIAGNOSTIC_PHASE_COLLECT = 6
_DIAGNOSTIC_CATEGORY_OTHER = 0
_DIAGNOSTIC_CATEGORY_ISOLATED_CHILD = 1
_DIAGNOSTIC_CATEGORY_HOOK_IMPORT = 2
_DIAGNOSTIC_CATEGORY_PYTHON_LIBRARY = 3
_DIAGNOSTIC_CATEGORY_FILESYSTEM_MISSING = 4
_DIAGNOSTIC_CATEGORY_FILESYSTEM_ACCESS = 5
_DIAGNOSTIC_CATEGORY_FILESYSTEM_CAPACITY = 6
_DIAGNOSTIC_CATEGORY_RECURSION = 7
_DIAGNOSTIC_CATEGORY_MEMORY = 8
_DIAGNOSTIC_ACCESS_ERRNOS = frozenset({errno.EACCES})
_DIAGNOSTIC_CAPACITY_ERRNOS = frozenset(
    value
    for value in (errno.ENOSPC, getattr(errno, "EDQUOT", None))
    if type(value) is int
)
_DIAGNOSTIC_ACCESS_WINERRORS = frozenset({5, 32, 110})


def _fail(message: str) -> None:
    raise RuntimeError(f"Invalid desktop build environment: {message}")


def _diagnostic_category(error: BaseException) -> int:
    current: BaseException | None = error
    seen: list[BaseException] = []
    category = _DIAGNOSTIC_CATEGORY_OTHER
    for index in range(4):
        if current is None or any(current is previous for previous in seen):
            return _DIAGNOSTIC_CATEGORY_OTHER
        seen.append(current)
        current_category = _diagnostic_category_for_error(current)
        if category == _DIAGNOSTIC_CATEGORY_OTHER and current_category != 0:
            category = current_category
        explicit_cause = BaseException.__cause__.__get__(current)
        if explicit_cause is None:
            return category
        if not isinstance(explicit_cause, BaseException):
            return _DIAGNOSTIC_CATEGORY_OTHER
        if index == 3:
            return _DIAGNOSTIC_CATEGORY_OTHER
        current = explicit_cause
    return _DIAGNOSTIC_CATEGORY_OTHER


def _diagnostic_category_for_error(error: BaseException) -> int:
    if _IsolatedChildDiedError is not None and type(error) is _IsolatedChildDiedError:
        return _DIAGNOSTIC_CATEGORY_ISOLATED_CHILD
    if _HookImportError is not None and type(error) is _HookImportError:
        return _DIAGNOSTIC_CATEGORY_HOOK_IMPORT
    if (
        _PythonLibraryNotFoundError is not None
        and type(error) is _PythonLibraryNotFoundError
    ):
        return _DIAGNOSTIC_CATEGORY_PYTHON_LIBRARY
    if type(error) is FileNotFoundError:
        return _DIAGNOSTIC_CATEGORY_FILESYSTEM_MISSING
    if type(error) is PermissionError:
        return _DIAGNOSTIC_CATEGORY_FILESYSTEM_ACCESS
    if type(error) is OSError:
        error_number = error.errno
        if type(error_number) is int:
            if error_number in _DIAGNOSTIC_ACCESS_ERRNOS or (
                sys.platform == "win32" and error_number == errno.EINVAL
            ):
                return _DIAGNOSTIC_CATEGORY_FILESYSTEM_ACCESS
            if error_number in _DIAGNOSTIC_CAPACITY_ERRNOS:
                return _DIAGNOSTIC_CATEGORY_FILESYSTEM_CAPACITY
        winerror = getattr(error, "winerror", None)
        if type(winerror) is int and winerror in _DIAGNOSTIC_ACCESS_WINERRORS:
            return _DIAGNOSTIC_CATEGORY_FILESYSTEM_ACCESS
    if _PyWinTypesError is not None and isinstance(error, _PyWinTypesError):
        args = getattr(error, "args", None)
        if (
            isinstance(args, tuple)
            and len(args) >= 1
            and type(args[0]) is int
            and args[0] in _DIAGNOSTIC_ACCESS_WINERRORS
        ):
            return _DIAGNOSTIC_CATEGORY_FILESYSTEM_ACCESS
    if type(error) is RecursionError:
        return _DIAGNOSTIC_CATEGORY_RECURSION
    if type(error) is MemoryError:
        return _DIAGNOSTIC_CATEGORY_MEMORY
    return _DIAGNOSTIC_CATEGORY_OTHER


def _run_diagnostic_phase(phase: int, callback: object) -> object:
    try:
        return callback()
    except BaseException as error:
        category = _diagnostic_category(error)
        code = _DIAGNOSTIC_EXIT_BASE + (phase * 16) + category
        raise SystemExit(code) from error


def _resolved_environment_path(name: str) -> Path:
    raw = os.environ.get(name)
    if raw is None or not raw:
        _fail(f"missing required environment variable: {name}")
    try:
        path = Path(raw).resolve(strict=True)
    except OSError as exc:
        _fail(f"unresolvable path in {name}: {exc}")
    return path


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _require_profile_string(profile: dict[str, object], key: str) -> str:
    value = profile.get(key)
    if not isinstance(value, str) or not value.strip():
        _fail(f"profile {key} must be a non-empty string")
    return value.strip()


def _validate_environment() -> tuple[
    Path,
    Path,
    Path,
    Path,
    Path,
    Path | None,
    list[Path],
    dict[str, object],
    str,
    list[str],
    list[str],
]:
    missing_keys = _ENVIRONMENT_KEYS.difference(os.environ)
    if missing_keys:
        _fail(f"missing environment keys: {sorted(missing_keys)}")

    gui_entry = _resolved_environment_path("SERVONAUT_DESKTOP_GUI_ENTRY_SCRIPT")
    child_entry = _resolved_environment_path("SERVONAUT_DESKTOP_CHILD_ENTRY_SCRIPT")
    cli_entry = _resolved_environment_path("SERVONAUT_DESKTOP_CLI_ENTRY_SCRIPT")
    site_packages = _resolved_environment_path(
        "SERVONAUT_DESKTOP_ISOLATED_SITE_PACKAGES"
    )
    profile_path = _resolved_environment_path("SERVONAUT_DESKTOP_PROFILE_PATH")
    output_dir = _resolved_environment_path("SERVONAUT_DESKTOP_OUTPUT_DIR")
    metadata_dir = _resolved_environment_path("SERVONAUT_DESKTOP_BUILD_METADATA_DIR")
    frontend_dir = _resolved_environment_path("SERVONAUT_DESKTOP_FRONTEND_DIR")
    selftest_value = os.environ.get("SERVONAUT_DESKTOP_REQUIRE_ARTIFACT_SELFTEST")

    if selftest_value not in {"0", "1"}:
        _fail("SERVONAUT_DESKTOP_REQUIRE_ARTIFACT_SELFTEST must be '0' or '1'")

    for entry_file, label in (
        (gui_entry, "GUI entry"),
        (child_entry, "Child entry"),
        (cli_entry, "CLI entry"),
    ):
        if not entry_file.is_file():
            _fail(f"{label} is not a regular file")
        if not entry_file.name.endswith(".py"):
            _fail(f"{label} must have a .py extension")

    if not site_packages.is_dir():
        _fail("site-packages must be an existing directory")
    if not profile_path.is_file():
        _fail("profile path must be a regular file")
    if not output_dir.is_dir():
        _fail("output directory must be an existing directory")
    if not metadata_dir.is_dir():
        _fail("build metadata directory must be an existing directory")
    if not frontend_dir.is_dir():
        _fail("frontend directory must be an existing directory")

    raw_profile = json.loads(profile_path.read_text(encoding="utf-8"))
    if not isinstance(raw_profile, dict):
        _fail("profile must be a JSON object")
    missing_profile_keys = _PROFILE_KEYS.difference(raw_profile)
    if missing_profile_keys:
        _fail(f"profile is missing keys: {sorted(missing_profile_keys)}")
    if raw_profile["schema_version"] != 1:
        _fail("profile schema_version must be 1")

    target_name = _require_profile_string(raw_profile, "target_name")
    if target_name not in _TARGETS:
        _fail(f"profile target_name {target_name!r} is unsupported")
    platform, architecture = _TARGETS[target_name]
    if (
        raw_profile["target_platform"] != platform
        or raw_profile["target_architecture"] != architecture
    ):
        _fail("profile target does not match its platform and architecture")
    if raw_profile["python_version"] != "3.12":
        _fail("profile python_version must be 3.12")
    if raw_profile["payload_name"] != "servonaut-desktop":
        _fail("profile payload_name must be servonaut-desktop")

    product_version = _require_profile_string(raw_profile, "product_version")
    if not _VERSION_PATTERN.fullmatch(product_version):
        _fail("profile product_version has an unsupported format")

    excluded_modules = raw_profile["excluded_modules"]
    if (
        not isinstance(excluded_modules, list)
        or any(not isinstance(m, str) or not m for m in excluded_modules)
        or "readline" not in excluded_modules
    ):
        _fail("profile excluded_modules must include readline")

    hook_dir = Path(_require_profile_string(raw_profile, "hook_directory"))
    if not hook_dir.is_dir():
        _fail("profile hook_directory must be an existing directory")

    module_spec = importlib.util.find_spec("servonaut")
    if module_spec is None or module_spec.origin is None:
        _fail("servonaut is not importable from the isolated wheel")
    module_origin = Path(module_spec.origin).resolve()
    if not _is_within(module_origin, site_packages):
        _fail("servonaut import origin is outside isolated site-packages")

    try:
        distribution = importlib.metadata.distribution("servonaut")
        distribution_root = Path(distribution.locate_file("")).resolve()
    except importlib.metadata.PackageNotFoundError as exc:
        _fail(f"servonaut wheel metadata is unavailable: {exc}")
    if not _is_within(distribution_root, site_packages):
        _fail("servonaut wheel metadata is outside isolated site-packages")
    if distribution.version != product_version:
        _fail("profile product_version does not match wheel metadata")

    hidden_imports = [
        "boto3",
        "botocore.credentials",
        "botocore.session",
        "certifi",
        "cryptography.hazmat.bindings._rust",
        "hcloud",
        "keyring.backends",
        "mcp.server.stdio",
        "nacl.bindings",
        "ovh",
        "servonaut.desktop",
        "servonaut.desktop.bridge",
        "servonaut.desktop.child",
        "servonaut.desktop.dialogs",
        "servonaut.desktop.launcher",
        "servonaut.desktop.host",
        "servonaut.desktop.driver",
        "servonaut.desktop.assets",
        "servonaut.desktop.model",
        "servonaut.desktop.control",
        "servonaut.desktop.process_tree",
        "servonaut.desktop.child_process",
        "webview",
        "aiohttp",
        "textual",
        "textual_serve",
    ]
    if selftest_value == "1":
        selftest = site_packages / "servonaut" / "_artifact_selftest.py"
        if not selftest.is_file():
            _fail("required servonaut._artifact_selftest is absent from the wheel")
        hidden_imports.append("servonaut._artifact_selftest")

    excludes = list(dict.fromkeys([*excluded_modules, *_FIXED_EXCLUDES]))

    # Notices
    notice_source_raw = os.environ.get("SERVONAUT_DESKTOP_RUNTIME_NOTICE_SOURCE")
    runtime_notice_source = (
        Path(notice_source_raw).resolve() if notice_source_raw else None
    )
    embedded_raw = os.environ.get("SERVONAUT_DESKTOP_THIRD_PARTY_NOTICES_ROOT")
    embedded_notice_sources = (
        [p.resolve() for p in Path(embedded_raw).iterdir() if p.is_file()]
        if embedded_raw and Path(embedded_raw).is_dir()
        else []
    )

    return (
        gui_entry,
        child_entry,
        cli_entry,
        hook_dir,
        frontend_dir,
        runtime_notice_source,
        embedded_notice_sources,
        raw_profile,
        product_version,
        hidden_imports,
        excludes,
    )


(
    GUI_ENTRY,
    CHILD_ENTRY,
    CLI_ENTRY,
    HOOK_DIRECTORY,
    FRONTEND_DIR,
    RUNTIME_NOTICE_SOURCE,
    EMBEDDED_NOTICE_SOURCES,
    PROFILE,
    PRODUCT_VERSION,
    HIDDEN_IMPORTS,
    EXCLUDES,
) = _run_diagnostic_phase(_DIAGNOSTIC_PHASE_PREFLIGHT, _validate_environment)


def _collect_runtime_metadata() -> list[object]:
    collected: list[object] = []
    for dist_name in _RUNTIME_METADATA_DISTRIBUTIONS:
        try:
            collected.extend(copy_metadata(dist_name))
        except Exception:
            pass
    return collected


RUNTIME_METADATA = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_RUNTIME_METADATA, _collect_runtime_metadata
)

# Collect frontend assets
FRONTEND_DATAS: list[tuple[str, str]] = []
if FRONTEND_DIR and FRONTEND_DIR.is_dir():
    for asset_path in FRONTEND_DIR.rglob("*"):
        if asset_path.is_file():
            rel = asset_path.relative_to(FRONTEND_DIR).as_posix()
            dest_dir = "frontend" if "/" not in rel else f"frontend/{rel.rsplit('/', 1)[0]}"
            FRONTEND_DATAS.append((str(asset_path), dest_dir))

NOTICES_DATAS: list[tuple[str, str]] = []
if RUNTIME_NOTICE_SOURCE and RUNTIME_NOTICE_SOURCE.is_file():
    NOTICES_DATAS.append((str(RUNTIME_NOTICE_SOURCE), "notices"))
for source in EMBEDDED_NOTICE_SOURCES:
    NOTICES_DATAS.append((str(source), "notices"))

ALL_DATAS = [
    *RUNTIME_METADATA,
    *FRONTEND_DATAS,
    *NOTICES_DATAS,
]


def _build_analysis(entry_script: Path) -> object:
    return Analysis(
        [str(entry_script)],
        pathex=[],
        binaries=[],
        datas=ALL_DATAS,
        hiddenimports=HIDDEN_IMPORTS,
        hookspath=[str(HOOK_DIRECTORY)],
        runtime_hooks=[],
        excludes=EXCLUDES,
        noarchive=False,
    )


def _filter_collected_data(analysis: object) -> object:
    return type(analysis.datas)(
        entry
        for entry in analysis.datas
        if not str(entry[0]).replace("\\", "/").endswith(".dist-info/direct_url.json")
    )


# 1. GUI executable analysis
a_gui = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_ANALYSIS,
    lambda: _build_analysis(GUI_ENTRY),
)
a_gui.datas = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_DATA_FILTERING,
    lambda: _filter_collected_data(a_gui),
)

# 2. Child executable analysis
a_child = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_ANALYSIS,
    lambda: _build_analysis(CHILD_ENTRY),
)
a_child.datas = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_DATA_FILTERING,
    lambda: _filter_collected_data(a_child),
)

# 3. Console CLI helper analysis
a_cli = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_ANALYSIS,
    lambda: _build_analysis(CLI_ENTRY),
)
a_cli.datas = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_DATA_FILTERING,
    lambda: _filter_collected_data(a_cli),
)

pyz_gui = _run_diagnostic_phase(_DIAGNOSTIC_PHASE_PYZ, lambda: PYZ(a_gui.pure))
pyz_child = _run_diagnostic_phase(_DIAGNOSTIC_PHASE_PYZ, lambda: PYZ(a_child.pure))
pyz_cli = _run_diagnostic_phase(_DIAGNOSTIC_PHASE_PYZ, lambda: PYZ(a_cli.pure))

exe_gui = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_EXE,
    lambda: EXE(
        pyz_gui,
        a_gui.scripts,
        [],
        exclude_binaries=True,
        name="servonaut-desktop",
        console=False,
    ),
)

exe_child = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_EXE,
    lambda: EXE(
        pyz_child,
        a_child.scripts,
        [],
        exclude_binaries=True,
        name="servonaut-desktop-child",
        console=True,
    ),
)

exe_cli = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_EXE,
    lambda: EXE(
        pyz_cli,
        a_cli.scripts,
        [],
        exclude_binaries=True,
        name="servonaut",
        console=True,
    ),
)

coll = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_COLLECT,
    lambda: COLLECT(
        exe_gui,
        a_gui.binaries,
        a_gui.datas,
        exe_child,
        a_child.binaries,
        a_child.datas,
        exe_cli,
        a_cli.binaries,
        a_cli.datas,
        name="servonaut-desktop",
    ),
)
