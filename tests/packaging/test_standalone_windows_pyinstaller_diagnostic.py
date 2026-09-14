"""Native Windows coverage for the closed PyInstaller diagnostic boundary."""

from __future__ import annotations

import ctypes
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

if sys.platform != "win32":
    pytest.skip(
        "requires the native Windows qualification environment", allow_module_level=True
    )

EXE = importlib.import_module("PyInstaller.building.api").EXE
_compat = importlib.import_module("PyInstaller.compat")
_exceptions = importlib.import_module("PyInstaller.exceptions")
_isolated_parent = importlib.import_module("PyInstaller.isolated._parent")
pywintypes = _compat.pywintypes
win32api = _compat.win32api
ImportErrorWhenRunningHook = _exceptions.ImportErrorWhenRunningHook
PythonLibraryNotFoundError = _exceptions.PythonLibraryNotFoundError
SubprocessDiedError = _isolated_parent.SubprocessDiedError


_REPOSITORY_ROOT = Path(__file__).parents[2]
_SPEC_SOURCE = _REPOSITORY_ROOT / "packaging" / "standalone_cli" / "servonaut_cli.spec"
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_OUTCOME_ROOT_VARIABLE = "QUALIFICATION_SETUP_ROOT"
_OUTCOME_SCHEMA_VERSION = 1
_FIXTURE_SETUP_FAILED = "fixture-setup-failed"
_COPIED_SPEC_PREFLIGHT = "copied-spec-preflight"
_COPIED_SPEC_GENERIC_FAILURE = "copied-spec-generic-failure"
_EXPECTED_CLASSIFIER = "expected-classifier"
_OTHER_KNOWN_CLASSIFIER = "other-known-classifier"
_UNEXPECTED_CHILD_EXIT = "unexpected-child-exit"
_DIAGNOSTIC_EXIT_BASE = 64
_DIAGNOSTIC_PHASE_COUNT = 7
_DIAGNOSTIC_CATEGORY_COUNT = 9
_STAGE_EXPECTED_EXIT_CODES = {
    "share-lock": 149,
    "isolated-child": 97,
    "hook-import": 98,
    "python-library": 99,
}
_KNOWN_DIAGNOSTIC_EXIT_CODES = frozenset(
    _DIAGNOSTIC_EXIT_BASE + (phase * 16) + category
    for phase in range(_DIAGNOSTIC_PHASE_COUNT)
    for category in range(_DIAGNOSTIC_CATEGORY_COUNT)
)


def _classify_child_outcome(stage: str, returncode: int) -> str:
    expected = _STAGE_EXPECTED_EXIT_CODES[stage]
    if returncode == expected:
        return _EXPECTED_CLASSIFIER
    if returncode == _DIAGNOSTIC_EXIT_BASE:
        return _COPIED_SPEC_PREFLIGHT
    if returncode == 1:
        return _COPIED_SPEC_GENERIC_FAILURE
    if returncode in _KNOWN_DIAGNOSTIC_EXIT_CODES:
        return _OTHER_KNOWN_CLASSIFIER
    return _UNEXPECTED_CHILD_EXIT


def _write_diagnostic_outcome(stage: str, outcome: str) -> None:
    root_value = os.environ.get(_OUTCOME_ROOT_VARIABLE)
    if not root_value:
        return
    if stage not in _STAGE_EXPECTED_EXIT_CODES:
        raise ValueError("unknown Windows PyInstaller diagnostic stage")
    if outcome not in {
        _FIXTURE_SETUP_FAILED,
        _COPIED_SPEC_PREFLIGHT,
        _COPIED_SPEC_GENERIC_FAILURE,
        _EXPECTED_CLASSIFIER,
        _OTHER_KNOWN_CLASSIFIER,
        _UNEXPECTED_CHILD_EXIT,
    }:
        raise ValueError("unknown Windows PyInstaller diagnostic outcome")
    root = Path(root_value)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RuntimeError("Windows PyInstaller diagnostic root is unavailable")
    destination = root / f"windows-pyinstaller-outcome-{stage}.json"
    with destination.open("x", encoding="utf-8") as record:
        json.dump(
            {
                "schema_version": _OUTCOME_SCHEMA_VERSION,
                "stage": stage,
                "outcome": outcome,
            },
            record,
            separators=(",", ":"),
        )


def _copy_writable_fixture(source: Path, destination: Path) -> Path:
    shutil.copyfile(source, destination)
    destination.chmod(destination.stat().st_mode | stat.S_IWUSR)
    copied = destination.lstat()
    if not stat.S_ISREG(copied.st_mode) or destination.is_symlink():
        raise OSError("copied executable fixture is not a regular file")
    if not copied.st_mode & stat.S_IWUSR:
        raise OSError("copied executable fixture is not owner-writable")
    return destination


def _locked_executable(tmp_path: Path) -> tuple[Path, int]:
    executable = _copy_writable_fixture(
        Path(sys.executable), tmp_path / "locked-python.exe"
    )
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(executable),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        0,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), "could not lock owned executable")
    return executable, int(handle)


def _close_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel32.CloseHandle(ctypes.c_void_p(handle)):
        raise OSError(ctypes.get_last_error(), "could not release owned executable")


def _assert_share_lock_error(executable: Path) -> RuntimeError:
    with pytest.raises(RuntimeError) as raised:
        EXE._retry_operation(
            win32api.BeginUpdateResource,
            str(executable),
            False,
            max_attempts=1,
        )
    error = raised.value
    cause = BaseException.__cause__.__get__(error)
    assert type(cause) is pywintypes.error
    assert type(cause.winerror) is int
    assert cause.winerror == 32
    return error


def _write_copied_spec_environment(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    spec_directory = tmp_path / "spec"
    spec_directory.mkdir()
    spec_path = spec_directory / "servonaut_cli.spec"
    shutil.copy2(_SPEC_SOURCE, spec_path)
    (spec_directory / "hooks").mkdir()
    venv_root = tmp_path / "venv"
    site_packages = venv_root / "Lib" / "site-packages"
    package = site_packages / "servonaut"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("__version__ = '2.26.2'\n", encoding="utf-8")
    metadata = site_packages / "servonaut-2.26.2.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: servonaut\nVersion: 2.26.2\n",
        encoding="utf-8",
    )
    shim = venv_root / "Scripts" / "servonaut_shim.py"
    shim.parent.mkdir()
    shim.write_text("from servonaut.main import main\nmain()\n", encoding="utf-8")
    output_dir = tmp_path / "output" / "dist"
    metadata_dir = tmp_path / "output" / "build-metadata"
    output_dir.mkdir(parents=True)
    metadata_dir.mkdir()
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target_name": "windows-x64",
                "target_platform": "win32",
                "target_architecture": "x86_64",
                "python_version": "3.12",
                "payload_name": "servonaut",
                "product_version": "2.26.2",
                "excluded_modules": ["readline"],
                "hook_directory": str((spec_directory / "hooks").resolve()),
                "require_artifact_selftest": False,
            }
        ),
        encoding="utf-8",
    )
    environment = {
        "SERVONAUT_STANDALONE_ENTRY_SCRIPT": str(shim.resolve()),
        "SERVONAUT_STANDALONE_ISOLATED_SITE_PACKAGES": str(site_packages.resolve()),
        "SERVONAUT_STANDALONE_PROFILE_PATH": str(profile_path.resolve()),
        "SERVONAUT_STANDALONE_OUTPUT_DIR": str(output_dir.resolve()),
        "SERVONAUT_STANDALONE_BUILD_METADATA_DIR": str(metadata_dir.resolve()),
        "SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST": "0",
    }
    script = tmp_path / "run-copied-spec.py"
    script.write_text(
        """
import ctypes
import os
import runpy
import shutil
import stat
import sys
from pathlib import Path
from types import ModuleType

from PyInstaller.building.api import EXE as PyInstallerEXE
from PyInstaller.compat import pywintypes, win32api
from PyInstaller.exceptions import ImportErrorWhenRunningHook, PythonLibraryNotFoundError
from PyInstaller.isolated._parent import SubprocessDiedError

root = Path(os.environ["DIAGNOSTIC_ROOT"])
for name, value in __import__("json").loads(os.environ["DIAGNOSTIC_ENV"]).items():
    os.environ[name] = value
sys.path.insert(0, str(root / "venv" / "Lib" / "site-packages"))

diagnostic_class = os.environ.get("DIAGNOSTIC_CLASS")
locked = None
handle = None
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
if not diagnostic_class:
    locked = root / "child-locked.exe"
    shutil.copyfile(sys.executable, locked)
    locked.chmod(locked.stat().st_mode | stat.S_IWUSR)
    if not locked.stat().st_mode & stat.S_IWUSR:
        raise OSError("copied executable fixture is not owner-writable")
    create_file = kernel32.CreateFileW
    create_file.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
    create_file.restype = ctypes.c_void_p
    handle = create_file(str(locked), 0x80000000, 0x00000001, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        raise SystemExit(201)

class Analysis:
    def __init__(self, *args, **kwargs):
        if diagnostic_class == "isolated-child":
            raise SubprocessDiedError()
        if diagnostic_class == "hook-import":
            raise ImportErrorWhenRunningHook("module", "hook")
        if diagnostic_class == "python-library":
            raise PythonLibraryNotFoundError("library")
        self.scripts = []
        self.binaries = []
        self.datas = []
        self.pure = []

class PYZ:
    def __init__(self, *args, **kwargs):
        pass

class EXE:
    def __init__(self, *args, **kwargs):
        if locked is None:
            raise RuntimeError("share-lock executable fixture is unavailable")
        try:
            PyInstallerEXE._retry_operation(win32api.BeginUpdateResource, str(locked), False, max_attempts=1)
        except RuntimeError as error:
            cause = BaseException.__cause__.__get__(error)
            if type(cause) is not pywintypes.error or type(cause.winerror) is not int or cause.winerror != 32:
                raise SystemExit(202)
            raise

class COLLECT:
    def __init__(self, *args, **kwargs):
        pass

hooks = ModuleType("PyInstaller.utils.hooks")
hooks.copy_metadata = lambda _name: []
sys.modules["PyInstaller.utils.hooks"] = hooks
try:
    runpy.run_path(str(root / "spec" / "servonaut_cli.spec"), init_globals={
        "Analysis": Analysis, "PYZ": PYZ, "EXE": EXE, "COLLECT": COLLECT,
        "DISTPATH": os.environ["SERVONAUT_STANDALONE_OUTPUT_DIR"],
        "SPECPATH": str(root / "spec"),
    })
finally:
    if handle is not None:
        if not kernel32.CloseHandle(ctypes.c_void_p(handle)):
            raise OSError(ctypes.get_last_error(), "could not release owned executable")
        handle = None
    if locked is not None:
        locked.unlink()
""".lstrip(),
        encoding="utf-8",
    )
    environment["DIAGNOSTIC_ROOT"] = str(tmp_path)
    environment["DIAGNOSTIC_ENV"] = json.dumps(environment)
    return script, environment


def test_native_share_lock_is_classified_by_the_copied_spec(tmp_path: Path) -> None:
    stage = "share-lock"
    outcome = _FIXTURE_SETUP_FAILED
    try:
        executable, handle = _locked_executable(tmp_path)
        try:
            _assert_share_lock_error(executable)
        finally:
            _close_handle(handle)
            executable.unlink()

        script, environment = _write_copied_spec_environment(tmp_path)
        returncode = _run_copied_spec_child(tmp_path, script, environment)
        outcome = _classify_child_outcome(stage, returncode)
        assert returncode == _STAGE_EXPECTED_EXIT_CODES[stage]
    finally:
        _write_diagnostic_outcome(stage, outcome)


def _run_copied_spec_child(
    tmp_path: Path,
    script: Path,
    environment: dict[str, str],
    diagnostic_class: str = "",
) -> int:
    system_root = next(
        (
            value
            for name, value in os.environ.items()
            if name.casefold() == "systemroot" and isinstance(value, str) and value
        ),
        None,
    )
    assert system_root is not None
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env={
            "PATH": os.environ["PATH"],
            "SystemRoot": system_root,
            "DIAGNOSTIC_CLASS": diagnostic_class,
            **environment,
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode


@pytest.mark.parametrize(
    ("diagnostic_class", "expected"),
    (
        ("isolated-child", 97),
        ("hook-import", 98),
        ("python-library", 99),
    ),
    ids=("isolated-child", "hook-import", "python-library"),
)
def test_native_pinned_pyinstaller_classes_are_classified_by_copied_spec(
    tmp_path: Path, diagnostic_class: str, expected: int
) -> None:
    stage = diagnostic_class
    outcome = _FIXTURE_SETUP_FAILED
    try:
        script, environment = _write_copied_spec_environment(tmp_path)
        returncode = _run_copied_spec_child(
            tmp_path, script, environment, diagnostic_class
        )
        outcome = _classify_child_outcome(stage, returncode)
        assert returncode == expected
    finally:
        _write_diagnostic_outcome(stage, outcome)
