"""Prepare locked wheel-build tools and build one verified Servonaut wheel."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from typing import BinaryIO, NoReturn

_LOCK_RELATIVE_PATH = Path(
    "packaging/standalone_cli/requirements/wheel-build-tools.txt"
)
_DIRECT_RELATIVE_PATH = _LOCK_RELATIVE_PATH.with_suffix(".in")
_POLICY_RELATIVE_PATH = Path("packaging/standalone_cli/wheel-tools-policy.json")
_HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s*\\)?$")
_PIN_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9._+!-]*)"
    r"(?:\s*;\s*(.+?))?\s*\\?$"
)
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PYTHON_VERSION_RE = re.compile(r"^([0-9]+)\.([0-9]+)$")
_POLICY_KEYS = frozenset({"schema_version", "python_version", "limits"})
_LIMIT_BOUNDS = {
    "command_timeout_seconds": (1, 3600),
    "process_cleanup_timeout_seconds": (1, 60),
    "max_lock_bytes": (1024, 1024 * 1024),
    "max_report_bytes": (1024, 1024 * 1024),
    "max_metadata_bytes": (1024, 16 * 1024 * 1024),
    "max_wheel_bytes": (1024 * 1024, 1024 * 1024 * 1024),
    "max_stdout_bytes": (1024, 64 * 1024 * 1024),
    "max_stderr_bytes": (1024, 64 * 1024 * 1024),
}
_LIMIT_KEYS = frozenset(_LIMIT_BOUNDS)
_DIRECT_TOOL_NAMES = frozenset({"build", "hatchling"})
_POLICY_SIZE_CEILING = 64 * 1024
_POLL_INTERVAL_SECONDS = 0.05
_DirectoryIdentity = tuple[int, int]


class WheelToolError(RuntimeError):
    """Raised when locked wheel-tool preparation violates its contract."""


@dataclass(frozen=True)
class WheelToolRequest:
    """Explicit native inputs for one isolated wheel preparation."""

    selected_python: Path
    checkout: Path
    work_parent: Path
    lock: Path
    policy: Path
    github_output: Path | None = None


@dataclass(frozen=True)
class WheelToolResult:
    """Only the bounded values passed to later standalone build steps."""

    python_path: Path
    wheel_path: Path
    wheel_sha256: str
    tool_lock_sha256: str


@dataclass(frozen=True)
class _OwnedRoot:
    path: Path
    identity: _DirectoryIdentity


@dataclass(frozen=True)
class _LockPin:
    name: str
    version: str
    marker: str | None
    hashes: frozenset[str]


@dataclass(frozen=True)
class WheelToolLimits:
    """Policy-owned process and file bounds."""

    command_timeout_seconds: int
    process_cleanup_timeout_seconds: int
    max_lock_bytes: int
    max_report_bytes: int
    max_metadata_bytes: int
    max_wheel_bytes: int
    max_stdout_bytes: int
    max_stderr_bytes: int


@dataclass(frozen=True)
class WheelToolPolicy:
    """Strict checked-in policy for native wheel preparation."""

    python_major: int
    python_minor: int
    limits: WheelToolLimits


@dataclass(frozen=True)
class _StageResult:
    stdout: bytes


@dataclass
class _PumpState:
    exceeded: bool = False
    failure: BaseException | None = None


_StageRunner = Callable[
    [Sequence[str], Mapping[str, str], Path, Path, str, bool, WheelToolLimits],
    _StageResult,
]


def _fail(message: str) -> NoReturn:
    raise WheelToolError(message)


def sanitized_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Remove inherited Python, pip, and standalone-build controls."""
    inherited = os.environ if source is None else source
    environment = {
        key: value
        for key, value in inherited.items()
        if not key.casefold().startswith(("python", "pip_", "servonaut_standalone_"))
    }
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def venv_python(venv_root: Path, platform_name: str | None = None) -> Path:
    """Return the lexical venv interpreter path without following its POSIX link."""
    current_platform = os.name if platform_name is None else platform_name
    relative = (
        Path("Scripts/python.exe") if current_platform == "nt" else Path("bin/python")
    )
    candidate = (venv_root / relative).absolute()
    if not candidate.is_file():
        _fail("private wheel-tool venv did not provide an interpreter")
    return candidate


def prepare_wheel_tools(
    request: WheelToolRequest, *, run_stage: _StageRunner | None = None
) -> WheelToolResult:
    """Create a private tool venv and build exactly one verified wheel."""
    selected_python, checkout, work_parent, lock, policy_path = _validate_request(
        request
    )
    policy = load_wheel_tool_policy(policy_path)
    direct_path = _canonical_file(
        checkout / _DIRECT_RELATIVE_PATH,
        "wheel-tool direct requirements",
    )
    direct = _validate_direct_requirements(direct_path, policy.limits.max_lock_bytes)
    pins = _validate_lock(lock, direct, policy.limits.max_lock_bytes)
    owned = _create_owned_root(work_parent)
    runner = _run_stage if run_stage is None else run_stage
    completed = False
    try:
        environment = sanitized_environment()
        logs = owned.path / "logs"
        logs.mkdir(mode=0o700)
        _verify_selected_python(
            selected_python, policy, environment, owned.path, logs, runner
        )
        venv_root = owned.path / "wheel-tool-venv"
        runner(
            [str(selected_python), "-I", "-m", "venv", str(venv_root)],
            environment,
            owned.path,
            logs,
            "create-venv",
            False,
            policy.limits,
        )
        python = venv_python(venv_root)
        _verify_venv_prefix(
            python,
            venv_root,
            policy,
            environment,
            owned.path,
            logs,
            runner,
        )
        runner(
            [
                str(python),
                "-m",
                "pip",
                "--isolated",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--no-cache-dir",
                "--only-binary=:all:",
                "--require-hashes",
                "-r",
                str(lock),
            ],
            environment,
            owned.path,
            logs,
            "install-tools",
            False,
            policy.limits,
        )
        _verify_installed_tools(
            python,
            venv_root,
            pins,
            environment,
            owned.path,
            logs,
            runner,
            policy.limits,
        )
        wheel_dir = owned.path / "wheel"
        wheel_dir.mkdir(mode=0o700)
        report = owned.path / "wheel-report.json"
        runner(
            [
                str(python),
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                str(wheel_dir),
                "--report",
                str(report),
                str(checkout),
            ],
            environment,
            owned.path,
            logs,
            "build-wheel",
            False,
            policy.limits,
        )
        project_version = _read_project_version(
            checkout / "pyproject.toml", policy.limits.max_metadata_bytes
        )
        wheel, wheel_hash = _validate_build_report(
            report, wheel_dir, project_version, policy.limits
        )
        result = WheelToolResult(python, wheel, wheel_hash, _sha256_file(lock))
        if request.github_output is not None:
            _write_github_outputs(request.github_output, result)
        completed = True
        return result
    except (OSError, subprocess.SubprocessError) as error:
        raise WheelToolError("wheel tool preparation failed") from error
    finally:
        if not completed:
            _remove_owned_root(owned)


def _validate_request(
    request: WheelToolRequest,
) -> tuple[Path, Path, Path, Path, Path]:
    if not isinstance(request, WheelToolRequest):
        raise TypeError("request must be a WheelToolRequest")
    checkout = _canonical_directory(request.checkout, "checkout")
    work_parent = _canonical_directory(request.work_parent, "work parent")
    lock = _canonical_file(request.lock, "wheel-tool lock")
    if lock != (checkout / _LOCK_RELATIVE_PATH).resolve(strict=True):
        _fail("wheel-tool lock does not match the checked-in path")
    policy = _canonical_file(request.policy, "wheel-tool policy")
    if policy != (checkout / _POLICY_RELATIVE_PATH).resolve(strict=True):
        _fail("wheel-tool policy does not match the checked-in path")
    python = _canonical_executable(request.selected_python, "selected Python")
    if os.name != "nt" and not os.access(python, os.X_OK):
        _fail("selected Python is not executable")
    if request.github_output is not None:
        _canonical_file(request.github_output, "GitHub output")
    return python, checkout, work_parent, lock, policy


def _canonical_directory(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        _fail(f"{label} must be a canonical directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise WheelToolError(f"{label} is unavailable") from error
    if resolved != path or not resolved.is_dir():
        _fail(f"{label} must be a canonical directory")
    return resolved


def _canonical_file(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        _fail(f"{label} must be a canonical regular file")
    try:
        resolved = path.resolve(strict=True)
        status = resolved.lstat()
    except OSError as error:
        raise WheelToolError(f"{label} is unavailable") from error
    if resolved != path or not stat.S_ISREG(status.st_mode):
        _fail(f"{label} must be a canonical regular file")
    return resolved


def _canonical_executable(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(f"{label} must be an absolute regular file")
    try:
        resolved = path.resolve(strict=True)
        status = resolved.lstat()
    except OSError as error:
        raise WheelToolError(f"{label} is unavailable") from error
    if not stat.S_ISREG(status.st_mode):
        _fail(f"{label} must be a regular file")
    return resolved


def _create_owned_root(parent: Path) -> _OwnedRoot:
    try:
        path = Path(tempfile.mkdtemp(prefix="servonaut-wheel-tools-", dir=parent))
        path.chmod(0o700)
        resolved = path.resolve(strict=True)
        identity = _directory_identity(resolved)
    except OSError as error:
        raise WheelToolError("private wheel-tool root could not be created") from error
    return _OwnedRoot(resolved, identity)


def _directory_identity(path: Path) -> _DirectoryIdentity:
    status = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(status.st_mode):
        _fail("owned wheel-tool root is not a directory")
    return status.st_dev, status.st_ino


def _remove_owned_root(owned: _OwnedRoot) -> None:
    try:
        if owned.path.is_symlink() or _directory_identity(owned.path) != owned.identity:
            return
        shutil.rmtree(owned.path)
    except (FileNotFoundError, OSError, WheelToolError):
        return


def load_wheel_tool_policy(path: Path) -> WheelToolPolicy:
    """Load the checked-in Python baseline and process/resource limits."""
    try:
        raw = json.loads(
            _read_bounded_file(path, _POLICY_SIZE_CEILING, "wheel-tool policy").decode(
                "utf-8", errors="strict"
            ),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise WheelToolError("wheel-tool policy is invalid") from error
    if not isinstance(raw, dict) or set(raw) != _POLICY_KEYS:
        _fail("wheel-tool policy has unsupported or missing fields")
    if type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
        _fail("wheel-tool policy has an unsupported schema version")
    version = raw.get("python_version")
    match = _PYTHON_VERSION_RE.fullmatch(version) if isinstance(version, str) else None
    limits = raw.get("limits")
    if match is None or not isinstance(limits, dict) or set(limits) != _LIMIT_KEYS:
        _fail("wheel-tool policy is invalid")
    for name, (minimum, maximum) in _LIMIT_BOUNDS.items():
        value = limits[name]
        if type(value) is not int or not minimum <= value <= maximum:
            _fail("wheel-tool policy contains an invalid limit")
    return WheelToolPolicy(
        int(match.group(1)),
        int(match.group(2)),
        WheelToolLimits(**{name: limits[name] for name in _LIMIT_KEYS}),
    )


def _validate_direct_requirements(path: Path, maximum: int) -> tuple[_LockPin, ...]:
    data = _read_bounded_file(path, maximum, "wheel-tool direct requirements")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise WheelToolError("wheel-tool direct requirements must be UTF-8") from error
    pins: list[_LockPin] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _PIN_RE.fullmatch(stripped)
        if match is None or match.group(3) is not None or stripped.endswith("\\"):
            _fail("wheel-tool direct requirements must contain exact unmarked pins")
        pins.append(_LockPin(match.group(1), match.group(2), None, frozenset()))
    names = [pin.name.casefold().replace("_", "-") for pin in pins]
    if len(pins) != len(_DIRECT_TOOL_NAMES) or set(names) != _DIRECT_TOOL_NAMES:
        _fail("wheel-tool direct requirements must define build and hatchling")
    return tuple(pins)


def _validate_lock(
    path: Path, direct: tuple[_LockPin, ...], maximum: int
) -> tuple[_LockPin, ...]:
    data = _read_bounded_file(path, maximum, "wheel-tool lock")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise WheelToolError("wheel-tool lock must be UTF-8") from error
    if "--only-binary :all:" not in text.splitlines():
        _fail("wheel-tool lock must require wheels")
    pins = _parse_lock_pins(text)
    indexed = {pin.name.casefold().replace("_", "-"): pin for pin in pins}
    for requirement in direct:
        name = requirement.name.casefold().replace("_", "-")
        locked = indexed.get(name)
        if (
            locked is None
            or locked.version != requirement.version
            or locked.marker is not None
            or not locked.hashes
        ):
            _fail("wheel-tool direct requirements do not match the generated lock")
    return pins


def _parse_lock_pins(text: str) -> tuple[_LockPin, ...]:
    pins: list[_LockPin] = []
    current: tuple[str, str, str | None] | None = None
    hashes: set[str] = set()
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if (
            not stripped
            or stripped.startswith("#")
            or stripped == "--only-binary :all:"
        ):
            continue
        hash_match = _HASH_RE.fullmatch(stripped)
        if hash_match and current is not None:
            hashes.add(hash_match.group(1))
            continue
        pin_match = _PIN_RE.fullmatch(stripped)
        if pin_match:
            if current is not None:
                pins.append(_finish_pin(current, hashes))
            current = (pin_match.group(1), pin_match.group(2), pin_match.group(3))
            hashes = set()
            continue
        _fail("wheel-tool lock contains an unsupported directive")
    if current is not None:
        pins.append(_finish_pin(current, hashes))
    canonical = [pin.name.casefold().replace("_", "-") for pin in pins]
    if len(pins) < 3 or len(canonical) != len(set(canonical)):
        _fail("wheel-tool lock must contain a unique dependency closure")
    return tuple(pins)


def _finish_pin(fields: tuple[str, str, str | None], hashes: set[str]) -> _LockPin:
    if not hashes:
        _fail("every wheel-tool dependency must be hash locked")
    return _LockPin(fields[0], fields[1], fields[2], frozenset(hashes))


def _verify_selected_python(
    python: Path,
    policy: WheelToolPolicy,
    environment: Mapping[str, str],
    cwd: Path,
    logs: Path,
    runner: _StageRunner,
) -> None:
    result = runner(
        [
            str(python),
            "-I",
            "-c",
            "import json,sys;print(json.dumps({'major':sys.version_info.major,'minor':sys.version_info.minor}))",
        ],
        environment,
        cwd,
        logs,
        "selected-python",
        True,
        policy.limits,
    )
    payload = _decode_json(result.stdout, "selected Python probe")
    if (
        set(payload) != {"major", "minor"}
        or type(payload.get("major")) is not int
        or type(payload.get("minor")) is not int
        or payload.get("major") != policy.python_major
        or payload.get("minor") != policy.python_minor
    ):
        _fail("wheel preparation Python does not match policy")


def _verify_venv_prefix(
    python: Path,
    venv_root: Path,
    policy: WheelToolPolicy,
    environment: Mapping[str, str],
    cwd: Path,
    logs: Path,
    runner: _StageRunner,
) -> None:
    result = runner(
        [
            str(python),
            "-I",
            "-c",
            "import json,sys;print(json.dumps({'major':sys.version_info.major,'minor':sys.version_info.minor,'prefix':sys.prefix}))",
        ],
        environment,
        cwd,
        logs,
        "venv-prefix",
        True,
        policy.limits,
    )
    payload = _decode_json(result.stdout, "venv prefix probe")
    prefix = payload.get("prefix")
    if (
        set(payload) != {"major", "minor", "prefix"}
        or type(payload.get("major")) is not int
        or type(payload.get("minor")) is not int
        or payload.get("major") != policy.python_major
        or payload.get("minor") != policy.python_minor
        or not isinstance(prefix, str)
    ):
        _fail("private wheel-tool interpreter is invalid")
    try:
        if Path(prefix).resolve(strict=True) != venv_root.resolve(strict=True):
            _fail("private wheel-tool interpreter escaped its venv")
    except OSError as error:
        raise WheelToolError("private wheel-tool interpreter is unavailable") from error


def _verify_installed_tools(
    python: Path,
    venv_root: Path,
    pins: tuple[_LockPin, ...],
    environment: Mapping[str, str],
    cwd: Path,
    logs: Path,
    runner: _StageRunner,
    limits: WheelToolLimits,
) -> None:
    runner(
        [str(python), "-m", "pip", "check"],
        environment,
        cwd,
        logs,
        "pip-check",
        False,
        limits,
    )
    result = runner(
        [
            str(python),
            "-I",
            "-c",
            _INSTALLED_TOOLS_PROBE,
            json.dumps(
                [
                    {"name": pin.name, "version": pin.version, "marker": pin.marker}
                    for pin in pins
                ],
                separators=(",", ":"),
            ),
        ],
        environment,
        cwd,
        logs,
        "installed-tools",
        True,
        limits,
    )
    payload = _decode_json(result.stdout, "installed wheel tools")
    if (
        set(payload) != {"ok", "prefix", "count"}
        or payload.get("ok") is not True
        or type(payload.get("count")) is not int
        or not 2 <= payload["count"] <= len(pins)
        or not isinstance(payload.get("prefix"), str)
    ):
        _fail("installed wheel-tool closure is invalid")
    try:
        if Path(payload["prefix"]).resolve(strict=True) != venv_root.resolve(
            strict=True
        ):
            _fail("installed wheel tools escaped their venv")
    except OSError as error:
        raise WheelToolError("installed wheel-tool prefix is unavailable") from error


_INSTALLED_TOOLS_PROBE = r"""
import importlib.metadata as metadata
import json
import re
import sys
from packaging.requirements import Requirement

expected = {}
for item in json.loads(sys.argv[1]):
    raw = item["name"] + "==" + item["version"]
    if item["marker"] is not None:
        raw += "; " + item["marker"]
    requirement = Requirement(raw)
    if requirement.marker is not None and not requirement.marker.evaluate():
        continue
    version = next(iter(requirement.specifier)).version
    expected[re.sub(r"[-_.]+", "-", requirement.name).casefold()] = version
installed = {}
for distribution in metadata.distributions():
    name = distribution.metadata.get("Name")
    if name:
        installed[re.sub(r"[-_.]+", "-", name).casefold()] = distribution.version
bootstrap = {"pip", "setuptools"}
ok = set(installed) <= set(expected) | bootstrap and all(
    installed.get(name) == version for name, version in expected.items()
)
print(json.dumps({"ok": ok, "prefix": sys.prefix, "count": len(expected)}, separators=(",", ":")))
""".strip()


def _run_stage(
    argv: Sequence[str],
    environment: Mapping[str, str],
    cwd: Path,
    logs: Path,
    label: str,
    capture_stdout: bool,
    limits: WheelToolLimits,
) -> _StageResult:
    if not argv or any(not item or "\x00" in item for item in argv):
        _fail("wheel-tool subprocess arguments are invalid")
    stdout_path = logs / f"{label}.stdout.log"
    stderr_path = logs / f"{label}.stderr.log"
    process: subprocess.Popen[bytes] | None = None
    readers: list[threading.Thread] = []
    streams: tuple[BinaryIO, BinaryIO] | None = None
    stdout_state = _PumpState()
    stderr_state = _PumpState()
    wakeup = threading.Event()
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            if process.stdout is None or process.stderr is None:
                _fail(f"{label} capture is unavailable")
            streams = (process.stdout, process.stderr)
            readers = _start_stage_pumps(
                streams,
                stdout,
                stderr,
                limits,
                stdout_state,
                stderr_state,
                wakeup,
            )
            outcome = _wait_for_stage(
                process,
                limits.command_timeout_seconds,
                stdout_state,
                stderr_state,
                wakeup,
            )
            should_kill = outcome == "timeout" or _pump_failed(
                stdout_state, stderr_state
            )
            cleanup_ok = _reap_stage_process(
                process, should_kill, limits.process_cleanup_timeout_seconds
            ) and _settle_stage_pumps(
                readers, streams, limits.process_cleanup_timeout_seconds
            )
    except BaseException as error:
        cleanup_ok = True
        if process is not None:
            cleanup_ok = _reap_stage_process(
                process, True, limits.process_cleanup_timeout_seconds
            )
        cleanup_ok = (
            _settle_stage_pumps(
                readers, streams, limits.process_cleanup_timeout_seconds
            )
            and cleanup_ok
        )
        if not cleanup_ok:
            raise WheelToolError(f"{label} cleanup did not complete") from error
        raise
    if not cleanup_ok:
        _fail(f"{label} cleanup did not complete")
    if outcome == "timeout":
        _fail(f"{label} timed out")
    if stdout_state.exceeded or stderr_state.exceeded:
        _fail(f"{label} exceeded its output limit")
    if stdout_state.failure is not None or stderr_state.failure is not None:
        _fail(f"{label} output could not be captured")
    if process.returncode != 0:
        _fail(f"{label} failed")
    stdout_data = (
        _read_bounded_file(stdout_path, limits.max_stdout_bytes, f"{label} stdout")
        if capture_stdout
        else b""
    )
    return _StageResult(stdout_data)


def _start_stage_pumps(
    streams: tuple[BinaryIO, BinaryIO],
    stdout: BinaryIO,
    stderr: BinaryIO,
    limits: WheelToolLimits,
    stdout_state: _PumpState,
    stderr_state: _PumpState,
    wakeup: threading.Event,
) -> list[threading.Thread]:
    readers = [
        threading.Thread(
            target=_pump_stage_stream,
            args=(
                streams[0],
                stdout,
                limits.max_stdout_bytes,
                stdout_state,
                wakeup,
            ),
            daemon=True,
        ),
        threading.Thread(
            target=_pump_stage_stream,
            args=(
                streams[1],
                stderr,
                limits.max_stderr_bytes,
                stderr_state,
                wakeup,
            ),
            daemon=True,
        ),
    ]
    started: list[threading.Thread] = []
    try:
        for reader in readers:
            reader.start()
            started.append(reader)
    except BaseException:
        _settle_stage_pumps(started, streams, 1)
        raise
    return readers


def _pump_stage_stream(
    stream: BinaryIO,
    destination: BinaryIO,
    maximum: int,
    state: _PumpState,
    wakeup: threading.Event,
) -> None:
    try:
        while chunk := stream.read(min(64 * 1024, maximum - destination.tell() + 1)):
            remaining = max(0, maximum - destination.tell())
            if len(chunk) > remaining:
                if remaining > 0:
                    destination.write(chunk[:remaining])
                state.exceeded = True
                wakeup.set()
                return
            destination.write(chunk)
    except (OSError, ValueError) as error:
        state.failure = error
        wakeup.set()
    finally:
        try:
            stream.close()
        except (OSError, ValueError) as error:
            state.failure = error
            wakeup.set()


def _wait_for_stage(
    process: subprocess.Popen[bytes],
    timeout_seconds: int,
    stdout_state: _PumpState,
    stderr_state: _PumpState,
    wakeup: threading.Event,
) -> str | None:
    deadline = time.monotonic() + timeout_seconds
    while process.poll() is None and not _pump_failed(stdout_state, stderr_state):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        wakeup.wait(min(remaining, _POLL_INTERVAL_SECONDS))
    return None


def _pump_failed(stdout_state: _PumpState, stderr_state: _PumpState) -> bool:
    return (
        stdout_state.exceeded
        or stderr_state.exceeded
        or stdout_state.failure is not None
        or stderr_state.failure is not None
    )


def _reap_stage_process(
    process: subprocess.Popen[bytes], should_kill: bool, timeout_seconds: int
) -> bool:
    if should_kill and process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=timeout_seconds)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def _settle_stage_pumps(
    readers: list[threading.Thread],
    streams: tuple[BinaryIO, BinaryIO] | None,
    timeout_seconds: int,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    for reader in readers:
        reader.join(max(0.0, deadline - time.monotonic()))
    alive = [reader for reader in readers if reader.is_alive()]
    if alive and streams is not None:
        for stream in streams:
            try:
                os.close(stream.fileno())
            except (OSError, ValueError):
                pass
        for reader in alive:
            reader.join(max(0.0, deadline - time.monotonic()))
    return not any(reader.is_alive() for reader in readers)


def _read_project_version(path: Path, maximum: int) -> str:
    import tomllib

    data = _read_bounded_file(path, maximum, "project metadata")
    try:
        raw = tomllib.loads(data.decode("utf-8", errors="strict"))
        project = raw["project"]
        build_system = raw["build-system"]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise WheelToolError("project metadata is invalid") from error
    if (
        not isinstance(project, dict)
        or project.get("name") != "servonaut"
        or not isinstance(project.get("version"), str)
        or not _VERSION_RE.fullmatch(project["version"])
        or not isinstance(build_system, dict)
        or build_system.get("requires") != ["hatchling"]
        or build_system.get("build-backend") != "hatchling.build"
    ):
        _fail("project build metadata does not match the wheel policy")
    return project["version"]


def _validate_build_report(
    report: Path,
    wheel_dir: Path,
    expected_version: str,
    limits: WheelToolLimits,
) -> tuple[Path, str]:
    payload = _decode_json(
        _read_bounded_file(report, limits.max_report_bytes, "wheel build report"),
        "wheel build report",
    )
    artifacts = payload.get("artifacts")
    if set(payload) != {"version", "artifacts"} or payload.get("version") != "1.0":
        _fail("wheel build report has an unsupported schema")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        _fail("wheel build report must contain exactly one artifact")
    artifact = artifacts[0]
    if not isinstance(artifact, dict) or set(artifact) != {
        "name",
        "path",
        "kind",
        "size",
        "hashes",
    }:
        _fail("wheel build report artifact is invalid")
    entries = list(wheel_dir.iterdir())
    if len(entries) != 1:
        _fail("wheel build must produce exactly one output")
    wheel = entries[0]
    status = wheel.lstat()
    if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
        _fail("wheel build output is not a regular file")
    hashes = artifact.get("hashes")
    reported_hash = hashes.get("sha256") if isinstance(hashes, dict) else None
    if (
        artifact.get("name") != wheel.name
        or artifact.get("path") != str(wheel)
        or artifact.get("kind") != "wheel"
        or type(artifact.get("size")) is not int
        or artifact.get("size") != status.st_size
        or not isinstance(hashes, dict)
        or set(hashes) != {"sha256"}
        or not isinstance(reported_hash, str)
        or not _SHA256_RE.fullmatch(reported_hash)
    ):
        _fail("wheel build report does not match its artifact")
    actual_hash = _sha256_file(wheel)
    if reported_hash != actual_hash:
        _fail("wheel build report hash does not match its artifact")
    _validate_wheel_metadata(wheel, expected_version, limits)
    return wheel, actual_hash


def _validate_wheel_metadata(
    wheel: Path, expected_version: str, limits: WheelToolLimits
) -> None:
    if (
        wheel.name != f"servonaut-{expected_version}-py3-none-any.whl"
        or wheel.stat().st_size > limits.max_wheel_bytes
    ):
        _fail("wheel artifact is invalid")
    try:
        with zipfile.ZipFile(wheel) as archive:
            metadata_names = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            direct_urls = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/direct_url.json")
            ]
            if len(metadata_names) != 1 or direct_urls:
                _fail("wheel metadata layout is invalid")
            info = archive.getinfo(metadata_names[0])
            if info.file_size > limits.max_metadata_bytes:
                _fail("wheel metadata exceeds its size limit")
            metadata = BytesParser(policy=default).parsebytes(archive.read(info))
    except (OSError, zipfile.BadZipFile, KeyError, RecursionError) as error:
        raise WheelToolError("wheel metadata could not be read") from error
    name = metadata.get("Name")
    version = metadata.get("Version")
    normalized_name = re.sub(r"[-_.]+", "-", name).casefold() if name else ""
    if normalized_name != "servonaut" or version != expected_version:
        _fail("wheel identity does not match project metadata")


def _write_github_outputs(path: Path, result: WheelToolResult) -> None:
    values = {
        "python-path": str(result.python_path),
        "wheel-path": str(result.wheel_path),
        "wheel-sha256": result.wheel_sha256,
        "tool-lock-sha256": result.tool_lock_sha256,
    }
    if any(
        not value or len(value) > 4096 or "\r" in value or "\n" in value
        for value in values.values()
    ):
        _fail("wheel-tool output is invalid")
    try:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            for name, value in values.items():
                handle.write(f"{name}={value}\n")
    except OSError as error:
        raise WheelToolError("GitHub output could not be written") from error


def _decode_json(data: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise WheelToolError(f"{label} is invalid") from error
    if not isinstance(value, dict):
        _fail(f"{label} is invalid")
    return value


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            _fail("JSON contains duplicate keys")
        value[key] = item
    return value


def _read_bounded_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        status = path.lstat()
        if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
            _fail(f"{label} must be a regular file")
        if status.st_size > maximum:
            _fail(f"{label} exceeds its size limit")
        return path.read_bytes()
    except OSError as error:
        raise WheelToolError(f"{label} is unavailable") from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    """Prepare wheel tools without exposing raw child output in CI logs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--work-parent", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        prepare_wheel_tools(
            WheelToolRequest(
                arguments.python,
                arguments.checkout,
                arguments.work_parent,
                arguments.lock,
                arguments.policy,
                arguments.github_output,
            )
        )
    except WheelToolError:
        print("standalone wheel preparation failed", file=sys.stderr)
        return 1
    print("standalone wheel prepared")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
