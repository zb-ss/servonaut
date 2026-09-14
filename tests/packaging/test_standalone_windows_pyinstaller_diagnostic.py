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
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

import pytest

if sys.platform != "win32":
    pytest.skip(
        "requires the native Windows qualification environment", allow_module_level=True
    )

EXE = importlib.import_module("PyInstaller.building.api").EXE
_compat = importlib.import_module("PyInstaller.compat")
_exceptions = importlib.import_module("PyInstaller.exceptions")
_isolated_parent = importlib.import_module("PyInstaller.isolated._parent")
_winresource = importlib.import_module("PyInstaller.utils.win32.winresource")
pywintypes = _compat.pywintypes
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
_OUTCOME_SCHEMA_VERSION = 2
_CHILD_OBSERVER_SCHEMA_VERSION = 1
_CHILD_STDERR_LIMIT_BYTES = 4096
_CHILD_DEADLINE_SECONDS = 20.0
_CHILD_STOP_WAIT_SECONDS = 2.0
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
_CHECKPOINTS = frozenset(
    {
        "outer-before-copy",
        "outer-before-create",
        "outer-before-resource-call",
        "outer-before-cause-type",
        "outer-before-winerror-type",
        "outer-before-winerror-value",
        "outer-before-close",
        "outer-before-unlink",
        "outer-complete",
        "parent-before-copied-environment",
        "parent-before-child-launch",
        "parent-before-process-create",
        "parent-after-child-launch",
        "parent-before-result-classification",
        "child-bootstrap",
        "child-import-pyinstaller-api",
        "child-import-pyinstaller-compat",
        "child-import-pyinstaller-exceptions",
        "child-import-pyinstaller-isolated",
        "child-environment",
        "child-share-copy",
        "child-share-create",
        "child-spec-dispatch",
        "child-spec-analysis",
        "child-spec-exe",
        "child-spec-finished",
        "child-before-close",
        "child-before-unlink",
        "child-complete",
        "child-timeout",
        "child-stderr-overflow",
        "child-observer-invalid",
        "child-interpreter-fatal",
        "child-script-parse",
        "child-startup-no-stderr",
        "child-startup-unclassified",
    }
)
_ERROR_TYPE_PAIRS = (
    (OSError, "os-error"),
    (FileNotFoundError, "file-not-found"),
    (FileExistsError, "file-exists"),
    (PermissionError, "permission-error"),
    (NotADirectoryError, "not-a-directory"),
    (IsADirectoryError, "is-a-directory"),
    (ImportError, "import-error"),
    (ModuleNotFoundError, "module-not-found"),
    (AttributeError, "attribute-error"),
    (TypeError, "type-error"),
    (ValueError, "value-error"),
    (RuntimeError, "runtime-error"),
    (AssertionError, "assertion-error"),
    (SystemExit, "system-exit"),
)
_ERROR_TYPES = frozenset(
    {token for _, token in _ERROR_TYPE_PAIRS} | {"none", "other", "unavailable"}
)
_CHILD_CHECKPOINTS = frozenset(
    checkpoint for checkpoint in _CHECKPOINTS if checkpoint.startswith("child-")
)


def _classify_exception_type(error: BaseException) -> str:
    error_type = type(error)
    for expected_type, token in _ERROR_TYPE_PAIRS:
        if error_type is expected_type:
            return token
    return "other"


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


def _write_diagnostic_outcome(
    stage: str, outcome: str, checkpoint: str, error_type: str
) -> None:
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
    if checkpoint not in _CHECKPOINTS:
        raise ValueError("unknown Windows PyInstaller diagnostic checkpoint")
    if error_type not in _ERROR_TYPES:
        raise ValueError("unknown Windows PyInstaller diagnostic error type")
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
                "checkpoint": checkpoint,
                "error_type": error_type,
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


def _locked_executable(
    tmp_path: Path, set_checkpoint: Callable[[str], None]
) -> tuple[Path, int]:
    set_checkpoint("outer-before-copy")
    executable = _copy_writable_fixture(
        Path(sys.executable), tmp_path / "locked-python.exe"
    )
    set_checkpoint("outer-before-create")
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


def _assert_share_lock_error(
    executable: Path, set_checkpoint: Callable[[str], None]
) -> RuntimeError:
    set_checkpoint("outer-before-resource-call")
    with pytest.raises(RuntimeError) as raised:
        EXE._retry_operation(
            _winresource.remove_all_resources,
            str(executable),
            max_attempts=1,
        )
    error = raised.value
    cause = BaseException.__cause__.__get__(error)
    set_checkpoint("outer-before-cause-type")
    assert type(cause) is pywintypes.error
    set_checkpoint("outer-before-winerror-type")
    assert type(cause.winerror) is int
    set_checkpoint("outer-before-winerror-value")
    assert cause.winerror == 32
    return error


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate child observer key")
        result[key] = value
    return result


def _read_child_observer(path: Path) -> tuple[str, str] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("child observer is not a regular file")
    if metadata.st_size > 512:
        raise ValueError("child observer is too large")
    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object
    )
    if type(value) is not dict or set(value) != {
        "schema_version",
        "checkpoint",
        "error_type",
    }:
        raise ValueError("child observer has the wrong fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("child observer has the wrong schema")
    checkpoint = value["checkpoint"]
    error_type = value["error_type"]
    if type(checkpoint) is not str or checkpoint not in _CHILD_CHECKPOINTS:
        raise ValueError("child observer has an unknown checkpoint")
    if type(error_type) is not str or error_type not in _ERROR_TYPES:
        raise ValueError("child observer has an unknown error type")
    return checkpoint, error_type


def _pump_child_stderr(
    stream: BinaryIO,
    destination: Path,
    overflow: threading.Event,
    pump_errors: list[BaseException],
) -> None:
    try:
        remaining = _CHILD_STDERR_LIMIT_BYTES
        with destination.open("xb") as retained:
            while True:
                chunk = stream.read1(min(65536, remaining + 1))
                if not chunk:
                    return
                if len(chunk) > remaining:
                    retained.write(chunk[:remaining])
                    overflow.set()
                    return
                retained.write(chunk)
                remaining -= len(chunk)
    except BaseException as error:  # noqa: BLE001 - report exact private fixture state.
        pump_errors.append(error)


def _stop_owned_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=_CHILD_STOP_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=_CHILD_STOP_WAIT_SECONDS)


def _startup_checkpoint(stderr: bytes) -> str:
    lines = stderr.splitlines()
    if any(line.startswith(b"Fatal Python error:") for line in lines):
        return "child-interpreter-fatal"
    if any(line.startswith((b"SyntaxError:", b"IndentationError:")) for line in lines):
        return "child-script-parse"
    if not stderr:
        return "child-startup-no-stderr"
    return "child-startup-unclassified"


def _run_observed_child(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    observer_path: Path,
    stderr_path: Path,
    set_checkpoint: Callable[[str], None],
) -> tuple[int, str, str]:
    set_checkpoint("parent-before-process-create")
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if process.stderr is None:
        _stop_owned_child(process)
        raise RuntimeError("child stderr pipe is unavailable")
    overflow = threading.Event()
    pump_errors: list[BaseException] = []
    pump = threading.Thread(
        target=_pump_child_stderr,
        args=(process.stderr, stderr_path, overflow, pump_errors),
        daemon=True,
    )
    pump.start()
    terminal_checkpoint: str | None = None
    deadline = time.monotonic() + _CHILD_DEADLINE_SECONDS
    try:
        while process.poll() is None:
            if overflow.wait(timeout=0.01):
                terminal_checkpoint = "child-stderr-overflow"
                _stop_owned_child(process)
                break
            if time.monotonic() >= deadline:
                terminal_checkpoint = "child-timeout"
                _stop_owned_child(process)
                break
        returncode = process.wait(timeout=_CHILD_STOP_WAIT_SECONDS)
    finally:
        pump.join(timeout=_CHILD_STOP_WAIT_SECONDS)
        if pump.is_alive():
            process.stderr.close()
            pump.join(timeout=_CHILD_STOP_WAIT_SECONDS)
        else:
            process.stderr.close()
        if pump.is_alive():
            raise RuntimeError("child stderr pump did not stop")
    if pump_errors:
        raise pump_errors[0]
    if overflow.is_set():
        terminal_checkpoint = "child-stderr-overflow"
    set_checkpoint("parent-after-child-launch")
    if terminal_checkpoint is not None:
        return returncode, terminal_checkpoint, "unavailable"
    try:
        observation = _read_child_observer(observer_path)
    except (OSError, UnicodeError, ValueError):
        return returncode, "child-observer-invalid", "unavailable"
    if observation is not None:
        return returncode, *observation
    stderr = stderr_path.read_bytes()
    return returncode, _startup_checkpoint(stderr), "unavailable"


def _select_diagnostic_observation(
    *,
    cleanup_failure: tuple[str, str] | None,
    child_observation: tuple[str, str] | None,
    primary_failure: tuple[str, str] | None,
    success_checkpoint: str,
) -> tuple[str, str]:
    if cleanup_failure is not None:
        return cleanup_failure
    if child_observation is not None:
        return child_observation
    if primary_failure is not None:
        return primary_failure
    return success_checkpoint, "none"


def _write_copied_spec_environment(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    canonical_root = tmp_path.resolve(strict=True)
    home_directory = tmp_path / "home"
    home_directory.mkdir(mode=0o700)
    home_metadata = home_directory.lstat()
    canonical_home = home_directory.resolve(strict=True)
    if (
        home_directory.is_symlink()
        or not stat.S_ISDIR(home_metadata.st_mode)
        or canonical_home.parent != canonical_root
    ):
        raise OSError("child home fixture is not a contained physical directory")
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
        "USERPROFILE": str(canonical_home),
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
import json
import os
import sys
observer_path = os.environ["DIAGNOSTIC_OBSERVER"]
observer_temporary_path = observer_path + ".tmp"
error_type_pairs = (
    (OSError, "os-error"),
    (FileNotFoundError, "file-not-found"),
    (FileExistsError, "file-exists"),
    (PermissionError, "permission-error"),
    (NotADirectoryError, "not-a-directory"),
    (IsADirectoryError, "is-a-directory"),
    (ImportError, "import-error"),
    (ModuleNotFoundError, "module-not-found"),
    (AttributeError, "attribute-error"),
    (TypeError, "type-error"),
    (ValueError, "value-error"),
    (RuntimeError, "runtime-error"),
    (AssertionError, "assertion-error"),
    (SystemExit, "system-exit"),
)

def classify_exception_type(error):
    for expected_type, token in error_type_pairs:
        if type(error) is expected_type:
            return token
    return "other"

def write_observer(checkpoint, error_type="none"):
    with open(observer_temporary_path, "w", encoding="utf-8") as record:
        json.dump(
            {
                "schema_version": 1,
                "checkpoint": checkpoint,
                "error_type": error_type,
            },
            record,
            separators=(",", ":"),
        )
    os.replace(observer_temporary_path, observer_path)

state = {"current": "child-bootstrap"}
write_observer(state["current"])
primary_failure = None
locked = None
handle = None
try:
    import ctypes
    import runpy
    import shutil
    import stat
    from pathlib import Path
    from types import ModuleType

    state["current"] = "child-import-pyinstaller-api"
    write_observer(state["current"])
    from PyInstaller.building.api import EXE as PyInstallerEXE

    state["current"] = "child-import-pyinstaller-compat"
    write_observer(state["current"])
    from PyInstaller.compat import pywintypes
    from PyInstaller.utils.win32 import winresource as pyinstaller_winresource

    state["current"] = "child-import-pyinstaller-exceptions"
    write_observer(state["current"])
    from PyInstaller.exceptions import ImportErrorWhenRunningHook, PythonLibraryNotFoundError

    state["current"] = "child-import-pyinstaller-isolated"
    write_observer(state["current"])
    from PyInstaller.isolated._parent import SubprocessDiedError

    state["current"] = "child-environment"
    write_observer(state["current"])
    root = Path(os.environ["DIAGNOSTIC_ROOT"])
    for name, value in json.loads(os.environ["DIAGNOSTIC_ENV"]).items():
        os.environ[name] = value
    sys.path.insert(0, str(root / "venv" / "Lib" / "site-packages"))

    diagnostic_class = os.environ.get("DIAGNOSTIC_CLASS")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not diagnostic_class:
        state["current"] = "child-share-copy"
        write_observer(state["current"])
        locked = root / "child-locked.exe"
        shutil.copyfile(sys.executable, locked)
        locked.chmod(locked.stat().st_mode | stat.S_IWUSR)
        if not locked.stat().st_mode & stat.S_IWUSR:
            raise OSError("copied executable fixture is not owner-writable")
        state["current"] = "child-share-create"
        write_observer(state["current"])
        create_file = kernel32.CreateFileW
        create_file.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
        create_file.restype = ctypes.c_void_p
        handle = create_file(str(locked), 0x80000000, 0x00000001, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            raise SystemExit(201)

    class Analysis:
        def __init__(self, *args, **kwargs):
            state["current"] = "child-spec-analysis"
            write_observer(state["current"])
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
            state["current"] = "child-spec-exe"
            write_observer(state["current"])
            if locked is None:
                raise RuntimeError("share-lock executable fixture is unavailable")
            try:
                PyInstallerEXE._retry_operation(pyinstaller_winresource.remove_all_resources, str(locked), max_attempts=1)
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
    state["current"] = "child-spec-dispatch"
    write_observer(state["current"])
    runpy.run_path(str(root / "spec" / "servonaut_cli.spec"), init_globals={
        "Analysis": Analysis, "PYZ": PYZ, "EXE": EXE, "COLLECT": COLLECT,
        "DISTPATH": os.environ["SERVONAUT_STANDALONE_OUTPUT_DIR"],
        "SPECPATH": str(root / "spec"),
    })
    state["current"] = "child-spec-finished"
    write_observer(state["current"])
except BaseException as error:
    primary_failure = (state["current"], classify_exception_type(error))
    write_observer(*primary_failure)
    raise
finally:
    try:
        if handle is not None:
            state["current"] = "child-before-close"
            write_observer(state["current"])
            if not kernel32.CloseHandle(ctypes.c_void_p(handle)):
                raise OSError(ctypes.get_last_error(), "could not release owned executable")
            handle = None
        if locked is not None:
            state["current"] = "child-before-unlink"
            write_observer(state["current"])
            locked.unlink()
    except BaseException as error:
        write_observer(state["current"], classify_exception_type(error))
        raise
    else:
        if primary_failure is not None:
            write_observer(*primary_failure)
        else:
            state["current"] = "child-complete"
            write_observer(state["current"])
""".lstrip(),
        encoding="utf-8",
    )
    environment["DIAGNOSTIC_ROOT"] = str(tmp_path)
    environment["DIAGNOSTIC_ENV"] = json.dumps(environment)
    return script, environment


def test_native_share_lock_is_classified_by_the_copied_spec(tmp_path: Path) -> None:
    stage = "share-lock"
    outcome = _FIXTURE_SETUP_FAILED
    current_checkpoint = "outer-before-copy"
    primary_failure: tuple[str, str] | None = None
    cleanup_failure: tuple[str, str] | None = None
    child_observation: tuple[str, str] | None = None
    executable: Path | None = None
    handle: int | None = None

    def set_checkpoint(checkpoint: str) -> None:
        nonlocal current_checkpoint
        current_checkpoint = checkpoint

    try:
        try:
            executable, handle = _locked_executable(tmp_path, set_checkpoint)
            _assert_share_lock_error(executable, set_checkpoint)
        except BaseException as error:
            primary_failure = (
                current_checkpoint,
                _classify_exception_type(error),
            )
            raise
        finally:
            try:
                if handle is not None:
                    set_checkpoint("outer-before-close")
                    _close_handle(handle)
                    handle = None
                if executable is not None:
                    set_checkpoint("outer-before-unlink")
                    executable.unlink()
                    executable = None
            except BaseException as error:
                cleanup_failure = (
                    current_checkpoint,
                    _classify_exception_type(error),
                )
                raise

        set_checkpoint("parent-before-copied-environment")
        script, environment = _write_copied_spec_environment(tmp_path)
        returncode, checkpoint, error_type = _run_copied_spec_child(
            tmp_path,
            script,
            environment,
            stage,
            set_checkpoint=set_checkpoint,
        )
        child_observation = checkpoint, error_type
        set_checkpoint("parent-before-result-classification")
        outcome = _classify_child_outcome(stage, returncode)
        assert child_observation == ("child-spec-exe", "system-exit")
        assert returncode == _STAGE_EXPECTED_EXIT_CODES[stage]
    except BaseException as error:
        if primary_failure is None and cleanup_failure is None:
            primary_failure = (
                current_checkpoint,
                _classify_exception_type(error),
            )
        raise
    finally:
        checkpoint, error_type = _select_diagnostic_observation(
            cleanup_failure=cleanup_failure,
            child_observation=child_observation,
            primary_failure=primary_failure,
            success_checkpoint="outer-complete",
        )
        _write_diagnostic_outcome(stage, outcome, checkpoint, error_type)


def _run_copied_spec_child(
    tmp_path: Path,
    script: Path,
    environment: dict[str, str],
    stage: str,
    diagnostic_class: str = "",
    *,
    set_checkpoint: Callable[[str], None],
) -> tuple[int, str, str]:
    set_checkpoint("parent-before-child-launch")
    system_root = next(
        (
            value
            for name, value in os.environ.items()
            if name.casefold() == "systemroot" and isinstance(value, str) and value
        ),
        None,
    )
    assert system_root is not None
    outcome_root = Path(os.environ[_OUTCOME_ROOT_VARIABLE])
    observer_path = outcome_root / f"windows-pyinstaller-child-{stage}.json"
    stderr_path = outcome_root / f"windows-pyinstaller-child-{stage}.stderr"
    child_environment = {
        "PATH": os.environ["PATH"],
        "SystemRoot": system_root,
        "DIAGNOSTIC_CLASS": diagnostic_class,
        "DIAGNOSTIC_OBSERVER": str(observer_path),
        **environment,
    }
    return _run_observed_child(
        [sys.executable, str(script)],
        cwd=tmp_path,
        environment=child_environment,
        observer_path=observer_path,
        stderr_path=stderr_path,
        set_checkpoint=set_checkpoint,
    )


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
    current_checkpoint = "parent-before-copied-environment"
    primary_failure: tuple[str, str] | None = None
    child_observation: tuple[str, str] | None = None

    def set_checkpoint(checkpoint: str) -> None:
        nonlocal current_checkpoint
        current_checkpoint = checkpoint

    try:
        set_checkpoint("parent-before-copied-environment")
        script, environment = _write_copied_spec_environment(tmp_path)
        returncode, checkpoint, error_type = _run_copied_spec_child(
            tmp_path,
            script,
            environment,
            stage,
            diagnostic_class,
            set_checkpoint=set_checkpoint,
        )
        child_observation = checkpoint, error_type
        set_checkpoint("parent-before-result-classification")
        outcome = _classify_child_outcome(stage, returncode)
        assert child_observation == ("child-spec-analysis", "system-exit")
        assert returncode == expected
    except BaseException as error:
        primary_failure = current_checkpoint, _classify_exception_type(error)
        raise
    finally:
        checkpoint, error_type = _select_diagnostic_observation(
            cleanup_failure=None,
            child_observation=child_observation,
            primary_failure=primary_failure,
            success_checkpoint="outer-complete",
        )
        _write_diagnostic_outcome(stage, outcome, checkpoint, error_type)
