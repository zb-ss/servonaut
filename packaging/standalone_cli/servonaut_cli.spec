"""PyInstaller console-onedir definition for an installed Servonaut wheel."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import errno
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
        "SERVONAUT_STANDALONE_ENTRY_SCRIPT",
        "SERVONAUT_STANDALONE_ISOLATED_SITE_PACKAGES",
        "SERVONAUT_STANDALONE_PROFILE_PATH",
        "SERVONAUT_STANDALONE_OUTPUT_DIR",
        "SERVONAUT_STANDALONE_BUILD_METADATA_DIR",
        "SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE",
        "SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT",
        "SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST",
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
    "pywebview",
    "textual_serve",
    "faster_whisper",
    "ctranslate2",
    "sherpa_onnx",
    "sounddevice",
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
)
_EMBEDDED_NOTICE_CONFIG_FIELDS = frozenset({"schema_version", "notices"})
_EMBEDDED_NOTICE_FIELDS = frozenset(
    {
        "distribution",
        "version",
        "source_relative_path",
        "payload_path",
        "sha256_by_target",
    }
)
_EMBEDDED_NOTICE_CONFIG_MAX_BYTES = 1_000_000
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
    raise RuntimeError(f"Invalid standalone build environment: {message}")


def _diagnostic_category(error: BaseException) -> int:
    """Classify only exact, bounded exception identities from a spec phase."""
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
    if _PyWinTypesError is not None and type(error) is _PyWinTypesError:
        winerror = error.winerror
        if type(winerror) is int and winerror in _DIAGNOSTIC_ACCESS_WINERRORS:
            return _DIAGNOSTIC_CATEGORY_FILESYSTEM_ACCESS
    if type(error) is RecursionError:
        return _DIAGNOSTIC_CATEGORY_RECURSION
    if type(error) is MemoryError:
        return _DIAGNOSTIC_CATEGORY_MEMORY
    return _DIAGNOSTIC_CATEGORY_OTHER


def _run_diagnostic_phase(phase: int, action: object) -> object:
    try:
        return action()
    except (Exception, SystemExit) as error:
        category = _diagnostic_category(error)
        raise SystemExit(_DIAGNOSTIC_EXIT_BASE + (phase * 16) + category) from None


def _resolved_environment_path(name: str, *, directory: bool = False) -> Path:
    value = os.environ.get(name)
    if not value:
        _fail(f"missing {name}")
    path = Path(value)
    if not path.is_absolute():
        _fail(f"{name} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        _fail(f"{name} is not resolvable: {exc}")
    if directory and not resolved.is_dir():
        _fail(f"{name} must name a directory")
    if not directory and not resolved.is_file():
        _fail(f"{name} must name a file")
    return resolved


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _runtime_notice_source(metadata_dir: Path) -> Path:
    name = "SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE"
    value = os.environ.get(name)
    if not value:
        _fail(f"missing {name}")
    path = Path(value)
    if not path.is_absolute():
        _fail(f"{name} must be an absolute path")
    expected = metadata_dir / "runtime-notice" / "CPython-LICENSE.txt"
    expected_parent = expected.parent
    try:
        source_status = path.lstat()
        resolved = path.resolve(strict=True)
        parent_status = expected_parent.lstat()
        resolved_parent = expected_parent.resolve(strict=True)
    except OSError as exc:
        _fail(f"{name} is not resolvable: {exc}")
    if (
        path != expected
        or resolved != expected
        or resolved_parent != expected_parent
        or not stat.S_ISDIR(parent_status.st_mode)
        or expected_parent.is_symlink()
        or not stat.S_ISREG(source_status.st_mode)
        or path.is_symlink()
    ):
        _fail(f"{name} must name the staged CPython notice")
    return resolved


def _embedded_notice_sources(metadata_dir: Path) -> list[Path]:
    name = "SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT"
    value = os.environ.get(name)
    if not value:
        _fail(f"missing {name}")
    root = Path(value)
    if not root.is_absolute():
        _fail(f"{name} must be an absolute path")
    try:
        root_status = root.lstat()
        resolved_root = root.resolve(strict=True)
        expected_root = metadata_dir / "third-party-notices"
    except OSError as exc:
        _fail(f"{name} is not resolvable: {exc}")
    if (
        root != expected_root
        or resolved_root != expected_root
        or not stat.S_ISDIR(root_status.st_mode)
        or root.is_symlink()
    ):
        _fail(f"{name} must name the staged embedded-notice directory")

    expected_names = _embedded_notice_names()
    try:
        actual_names = sorted(entry.name for entry in os.scandir(root))
    except OSError as exc:
        _fail(f"{name} could not be inspected: {exc}")
    if actual_names != expected_names:
        _fail(f"{name} must contain exactly the configured notices")
    sources: list[Path] = []
    for filename in expected_names:
        source = root / filename
        try:
            source_status = source.lstat()
            resolved_source = source.resolve(strict=True)
        except OSError as exc:
            _fail(f"{name} contains an unavailable notice: {exc}")
        if (
            resolved_source != source
            or not stat.S_ISREG(source_status.st_mode)
            or source.is_symlink()
            or source_status.st_nlink != 1
        ):
            _fail(f"{name} must contain only single-link regular files")
        sources.append(resolved_source)
    return sources


def _embedded_notice_names() -> list[str]:
    path = Path(SPECPATH).resolve() / "embedded-notices.json"
    try:
        status = path.lstat()
        if (
            not stat.S_ISREG(status.st_mode)
            or path.is_symlink()
            or status.st_size <= 0
            or status.st_size > _EMBEDDED_NOTICE_CONFIG_MAX_BYTES
        ):
            _fail("embedded notice configuration is invalid")
        with path.open("rb") as source:
            encoded = source.read(_EMBEDDED_NOTICE_CONFIG_MAX_BYTES + 1)
        if len(encoded) > _EMBEDDED_NOTICE_CONFIG_MAX_BYTES:
            _fail("embedded notice configuration is invalid")
        raw = json.loads(encoded.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        _fail(f"could not read embedded notice configuration: {exc}")
    if (
        not isinstance(raw, dict)
        or set(raw) != _EMBEDDED_NOTICE_CONFIG_FIELDS
        or type(raw.get("schema_version")) is not int
        or raw["schema_version"] != 1
        or not isinstance(raw.get("notices"), list)
        or len(raw["notices"]) != 5
    ):
        _fail("embedded notice configuration is invalid")
    distributions: list[str] = []
    names: list[str] = []
    for row in raw["notices"]:
        if not isinstance(row, dict) or set(row) != _EMBEDDED_NOTICE_FIELDS:
            _fail("embedded notice configuration is invalid")
        distribution = row.get("distribution")
        payload_value = row.get("payload_path")
        if not isinstance(distribution, str) or not isinstance(payload_value, str):
            _fail("embedded notice configuration is invalid")
        payload_path = Path(payload_value)
        if (
            payload_path.as_posix() != payload_value
            or payload_path.parts[:2] != ("_internal", "notices")
            or len(payload_path.parts) != 3
            or payload_path.name in {"", ".", ".."}
        ):
            _fail("embedded notice configuration is invalid")
        distributions.append(distribution)
        names.append(payload_path.name)
    if (
        distributions != sorted(distributions)
        or len(set(distributions)) != len(distributions)
        or len(set(names)) != len(names)
    ):
        _fail("embedded notice configuration is invalid")
    return sorted(names)


def _venv_root(site_packages: Path) -> Path:
    if site_packages.name != "site-packages":
        _fail("isolated site-packages directory has an unexpected name")
    parent = site_packages.parent
    if parent.name == "Lib":
        return parent.parent
    if parent.name.startswith("python") and parent.parent.name == "lib":
        return parent.parent.parent
    _fail("could not determine the isolated virtual-environment root")


def _load_profile(profile_path: Path) -> dict[str, object]:
    try:
        profile = json.loads(
            profile_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"could not read resolved profile: {exc}")
    if not isinstance(profile, dict) or frozenset(profile) != _PROFILE_KEYS:
        _fail("resolved profile must contain exactly the supported fields")
    return profile


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"resolved profile duplicates key {key!r}")
        result[key] = value
    return result


def _require_profile_string(profile: dict[str, object], name: str) -> str:
    value = profile[name]
    if not isinstance(value, str) or not value:
        _fail(f"profile {name} must be a non-empty string")
    return value


def _validate_environment() -> tuple[
    Path, Path, Path, list[Path], dict[str, object], str, list[str], list[str]
]:
    unknown = {
        name
        for name in os.environ
        if name.startswith("SERVONAUT_STANDALONE_") and name not in _ENVIRONMENT_KEYS
    }
    if unknown:
        _fail(f"unexpected standalone environment variables: {sorted(unknown)}")
    if sys.version_info[:2] != (3, 12):
        _fail("PyInstaller must run under Python 3.12")

    entry_script = _resolved_environment_path("SERVONAUT_STANDALONE_ENTRY_SCRIPT")
    site_packages = _resolved_environment_path(
        "SERVONAUT_STANDALONE_ISOLATED_SITE_PACKAGES", directory=True
    )
    profile_path = _resolved_environment_path("SERVONAUT_STANDALONE_PROFILE_PATH")
    output_dir = _resolved_environment_path(
        "SERVONAUT_STANDALONE_OUTPUT_DIR", directory=True
    )
    metadata_dir = _resolved_environment_path(
        "SERVONAUT_STANDALONE_BUILD_METADATA_DIR", directory=True
    )
    runtime_notice_source = _runtime_notice_source(metadata_dir)
    embedded_notice_sources = _embedded_notice_sources(metadata_dir)
    selftest_value = os.environ.get("SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST")
    if selftest_value not in {"0", "1"}:
        _fail("SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST must be 0 or 1")
    if any(output_dir.iterdir()):
        _fail("SERVONAUT_STANDALONE_OUTPUT_DIR must be empty")
    if metadata_dir.parent != output_dir.parent or _is_within(metadata_dir, output_dir):
        _fail("build metadata directory must be an output-directory sibling")
    if Path(DISTPATH).resolve() != output_dir:
        _fail("PyInstaller DISTPATH must equal SERVONAUT_STANDALONE_OUTPUT_DIR")

    venv_root = _venv_root(site_packages)
    if not _is_within(entry_script, venv_root):
        _fail("entry shim must be inside the isolated virtual environment")
    profile = _load_profile(profile_path)
    if type(profile["schema_version"]) is not int or profile["schema_version"] != 1:
        _fail("profile schema_version must be 1")
    target_name = _require_profile_string(profile, "target_name")
    if not _TARGET_PATTERN.fullmatch(target_name) or target_name not in _TARGETS:
        _fail("profile target_name is unsupported")
    platform, architecture = _TARGETS[target_name]
    if (
        profile["target_platform"] != platform
        or profile["target_architecture"] != architecture
    ):
        _fail("profile target does not match its platform and architecture")
    if profile["python_version"] != "3.12":
        _fail("profile python_version must be 3.12")
    if profile["payload_name"] != "servonaut":
        _fail("profile payload_name must be servonaut")
    product_version = _require_profile_string(profile, "product_version")
    if not _VERSION_PATTERN.fullmatch(product_version):
        _fail("profile product_version has an unsupported format")
    if not isinstance(profile["require_artifact_selftest"], bool):
        _fail("profile require_artifact_selftest must be boolean")
    if profile["require_artifact_selftest"] != (selftest_value == "1"):
        _fail("self-test environment and profile values disagree")
    excluded_modules = profile["excluded_modules"]
    if (
        not isinstance(excluded_modules, list)
        or any(not isinstance(module, str) or not module for module in excluded_modules)
        or len(set(excluded_modules)) != len(excluded_modules)
        or "readline" not in excluded_modules
    ):
        _fail("profile excluded_modules must include readline")
    hook_directory = Path(_require_profile_string(profile, "hook_directory"))
    if not hook_directory.is_absolute() or not hook_directory.is_dir():
        _fail("profile hook_directory must name an existing absolute directory")
    expected_hook_directory = Path(SPECPATH).resolve() / "hooks"
    if hook_directory.resolve() != expected_hook_directory:
        _fail("profile hook_directory must be this spec's hooks directory")

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
    ]
    if selftest_value == "1":
        selftest = site_packages / "servonaut" / "_artifact_selftest.py"
        if not selftest.is_file():
            _fail("required servonaut._artifact_selftest is absent from the wheel")
        hidden_imports.append("servonaut._artifact_selftest")
    excludes = list(dict.fromkeys([*excluded_modules, *_FIXED_EXCLUDES]))
    return (
        entry_script,
        hook_directory,
        runtime_notice_source,
        embedded_notice_sources,
        profile,
        product_version,
        hidden_imports,
        excludes,
    )


(
    ENTRY_SCRIPT,
    HOOK_DIRECTORY,
    RUNTIME_NOTICE_SOURCE,
    EMBEDDED_NOTICE_SOURCES,
    PROFILE,
    PRODUCT_VERSION,
    HIDDEN_IMPORTS,
    EXCLUDES,
) = _run_diagnostic_phase(_DIAGNOSTIC_PHASE_PREFLIGHT, _validate_environment)


# Frozen runtime self-checks use installed-distribution metadata.  Keep the
# complete metadata directories so license files and RECORD stay available.
def _collect_runtime_metadata() -> list[object]:
    return [
        item
        for distribution_name in _RUNTIME_METADATA_DISTRIBUTIONS
        for item in copy_metadata(distribution_name)
    ]


def _build_analysis() -> object:
    return Analysis(
        [str(ENTRY_SCRIPT)],
        pathex=[],
        binaries=[],
        datas=[
            *RUNTIME_METADATA,
            (str(RUNTIME_NOTICE_SOURCE), "notices"),
            *((str(source), "notices") for source in EMBEDDED_NOTICE_SOURCES),
        ],
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


RUNTIME_METADATA = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_RUNTIME_METADATA, _collect_runtime_metadata
)

a = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_ANALYSIS,
    _build_analysis,
)
# ``direct_url.json`` records the wheel's local acquisition path.  Exclude only
# this generated destination from the collected TOC; never mutate installed
# wheel files or unrelated application data.
a.datas = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_DATA_FILTERING,
    lambda: _filter_collected_data(a),
)
pyz = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_PYZ,
    lambda: PYZ(a.pure),
)
exe = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_EXE,
    lambda: EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="servonaut",
        console=True,
    ),
)
coll = _run_diagnostic_phase(
    _DIAGNOSTIC_PHASE_COLLECT,
    lambda: COLLECT(
        exe,
        a.binaries,
        a.datas,
        name="servonaut",
    ),
)
