"""Policy-bound smoke checks for an extracted standalone CLI artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PureWindowsPath
from typing import NoReturn

from scripts.standalone_cli.bounded_command import (
    run_bounded_process as run_bounded_command_process,
)
from scripts.standalone_cli.release_identity import (
    ReleaseIdentityError,
    validate_marker_identity,
)
from scripts.standalone_cli.smoke_mcp import MCPCheck, MCPTimeouts, run_mcp_smoke

_POLICY_KEYS = frozenset(
    {
        "schema_version",
        "process_argv_max_count",
        "selftest_stdin_max_bytes",
        "stdout_stderr_max_bytes",
        "transcript_max_bytes",
        "public_command_timeout_seconds",
        "selftest_timeout_seconds",
        "mcp_initialize_timeout_seconds",
        "mcp_request_timeout_seconds",
        "mcp_shutdown_timeout_seconds",
        "mcp_frame_max_bytes",
        "docker_image",
        "docker_create_timeout_seconds",
        "docker_start_timeout_seconds",
        "docker_cleanup_timeout_seconds",
        "docker_pids_limit",
        "docker_tmpfs_size_bytes",
    }
)
_MARKER_KEYS = frozenset(
    {
        "schema_version",
        "distribution",
        "product_version",
        "build_revision",
        "channel",
        "packaging_revision",
        "console_helper",
        "desktop_child",
    }
)
_FORWARD_ENV_NAMES = (
    "SSH_AUTH_SOCK",
    "BW_SESSION",
    "BWS_ACCESS_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "SERVONAUT_API_URL",
    "SERVONAUT_MCP_URL",
)
_SAFE_LOCALE_NAMES = ("LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM")
_WINDOWS_RUNTIME_NAMES = ("SystemRoot", "WINDIR", "ComSpec", "PATHEXT")
_CALLER_ENVIRONMENT_CANARIES = {
    "AWS_ACCESS_KEY_ID": "caller-isolation-access-key",
    "AWS_PROFILE": "caller-isolation-profile",
    "AWS_SECRET_ACCESS_KEY": "caller-isolation-secret-key",
    "OVH_APPLICATION_KEY": "caller-isolation-ovh-application",
    "OVH_APPLICATION_SECRET": "caller-isolation-ovh-secret",
    "OVH_CONSUMER_KEY": "caller-isolation-ovh-consumer",
    "OVH_ENDPOINT": "caller-isolation-ovh-endpoint",
}
_CALLER_FILE_CANARIES = (
    "caller-isolation-config",
    "caller-isolation-cache",
    "caller-isolation-credential",
    "caller-isolation-aws-config",
    "caller-isolation-ovh-file",
)
_CALLER_ENTRY_COUNT_CEILING = 64
_CALLER_FILE_SIZE_CEILING = 64 * 1024
_SELFTEST_TOP_KEYS = frozenset(
    {"schema_version", "ok", "check", "runtime", "tui", "fixtures", "diagnostics"}
)
_POLICY_MAXIMUMS = {
    "process_argv_max_count": 256,
    "selftest_stdin_max_bytes": 1024 * 1024,
    "stdout_stderr_max_bytes": 16 * 1024 * 1024,
    "transcript_max_bytes": 16 * 1024 * 1024,
    "public_command_timeout_seconds": 600,
    "selftest_timeout_seconds": 600,
    "mcp_initialize_timeout_seconds": 600,
    "mcp_request_timeout_seconds": 600,
    "mcp_shutdown_timeout_seconds": 600,
    "mcp_frame_max_bytes": 16 * 1024 * 1024,
    "docker_create_timeout_seconds": 600,
    "docker_start_timeout_seconds": 600,
    "docker_cleanup_timeout_seconds": 600,
    "docker_pids_limit": 4096,
    "docker_tmpfs_size_bytes": 1024 * 1024 * 1024,
}


class ArtifactSmokeError(RuntimeError):
    """Raised when an artifact or smoke result violates its fixed contract."""


@dataclass(frozen=True)
class SmokePolicy:
    """Strict, reviewable bounds for native and container smoke checks."""

    process_argv_max_count: int
    selftest_stdin_max_bytes: int
    stdout_stderr_max_bytes: int
    transcript_max_bytes: int
    public_command_timeout_seconds: int
    selftest_timeout_seconds: int
    mcp_initialize_timeout_seconds: int
    mcp_request_timeout_seconds: int
    mcp_shutdown_timeout_seconds: int
    mcp_frame_max_bytes: int
    docker_image: str
    docker_create_timeout_seconds: int
    docker_start_timeout_seconds: int
    docker_cleanup_timeout_seconds: int
    docker_pids_limit: int
    docker_tmpfs_size_bytes: int


@dataclass(frozen=True)
class CheckResult:
    """Content-free record suitable for a private smoke transcript."""

    ok: bool
    exit_code: int
    elapsed_ms: int
    stdout_bytes: int
    stdout_sha256: str
    stderr_bytes: int
    stderr_sha256: str


@dataclass(frozen=True)
class SmokeRequest:
    """Validated inputs for native smoke execution."""

    payload_root: Path
    executable: Path
    product_version: str
    evidence_dir: Path


@dataclass(frozen=True)
class SmokeResult:
    """Native smoke output and all named check results."""

    transcript: Path
    checks: Mapping[str, CheckResult]


@dataclass(frozen=True)
class _ProcessResult:
    exit_code: int
    elapsed_ms: int
    stdout: bytes
    stderr: bytes

    def public(self) -> CheckResult:
        return CheckResult(
            True,
            self.exit_code,
            self.elapsed_ms,
            len(self.stdout),
            hashlib.sha256(self.stdout).hexdigest(),
            len(self.stderr),
            hashlib.sha256(self.stderr).hexdigest(),
        )


@dataclass(frozen=True)
class _CallerEntry:
    relative_path: Path
    identity: tuple[int, int]
    mode: int
    owner: tuple[int, int]
    file_metadata: tuple[int, int] | None
    content: bytes | None


@dataclass(frozen=True)
class _CallerIsolationProof:
    root: Path
    entries: tuple[_CallerEntry, ...]
    credential_path: Path
    credential_descriptor: int | None


def _fail(message: str) -> NoReturn:
    raise ArtifactSmokeError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactSmokeError("JSON contains duplicate keys")
        result[key] = value
    return result


def _read_json(path: Path, limit: int, label: str) -> dict[str, object]:
    try:
        status = path.lstat()
        if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
            _fail(f"{label} is not a regular file")
        if status.st_size > limit:
            _fail(f"{label} exceeds its size limit")
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except ArtifactSmokeError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ArtifactSmokeError(f"{label} is invalid") from error
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _has_schema_version_one(value: Mapping[str, object]) -> bool:
    schema_version = value.get("schema_version")
    return type(schema_version) is int and schema_version == 1


def _is_true_map(value: object, keys: frozenset[str]) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == keys
        and all(type(value[key]) is bool and value[key] is True for key in keys)
    )


def load_smoke_policy(path: Path) -> SmokePolicy:
    """Load the immutable smoke limits with no permissive defaults."""
    raw = _read_json(path, 32768, "smoke policy")
    if set(raw) != _POLICY_KEYS or not _has_schema_version_one(raw):
        _fail("smoke policy schema is invalid")
    for name, maximum in _POLICY_MAXIMUMS.items():
        value = raw[name]
        if type(value) is not int or value < 1 or value > maximum:
            _fail("smoke policy contains an invalid numeric limit")
    image = raw["docker_image"]
    if (
        not isinstance(image, str)
        or not image.startswith("ubuntu:24.04@sha256:")
        or len(image.removeprefix("ubuntu:24.04@sha256:")) != 64
        or any(
            character not in "0123456789abcdef"
            for character in image.removeprefix("ubuntu:24.04@sha256:")
        )
    ):
        _fail("smoke policy Docker image is not digest pinned")
    return SmokePolicy(**{name: raw[name] for name in SmokePolicy.__dataclass_fields__})  # type: ignore[arg-type]


def _validate_request(request: SmokeRequest) -> dict[str, object]:
    root = request.payload_root
    if root.name != "extracted payload" or not root.is_absolute() or root.is_symlink():
        _fail("payload root must be the dedicated extracted payload directory")
    if not root.is_dir():
        _fail("payload root is unavailable")
    try:
        if (
            root.resolve(strict=True) != root
            or request.executable.resolve(strict=True) != request.executable
        ):
            _fail("smoke request paths must be canonical")
    except OSError as error:
        raise ArtifactSmokeError("smoke request paths are unavailable") from error
    if not request.product_version or len(request.product_version) > 128:
        _fail("product version is invalid")
    marker = _read_json(root / "servonaut-runtime.json", 262144, "runtime marker")
    if set(marker) != _MARKER_KEYS or not _has_schema_version_one(marker):
        _fail("runtime marker schema is invalid")
    if marker.get("distribution") != "frozen-cli":
        _fail("runtime marker distribution is invalid")
    if marker.get("product_version") != request.product_version:
        _fail("runtime marker version is invalid")
    if (
        not isinstance(marker.get("build_revision"), str)
        or not marker["build_revision"]
    ):
        _fail("runtime marker revision is invalid")
    try:
        validate_marker_identity(marker)
    except ReleaseIdentityError:
        _fail("runtime marker release identity is invalid")
    if marker.get("desktop_child") is not None:
        _fail("runtime marker desktop child is invalid")
    helper = marker.get("console_helper")
    if not isinstance(helper, str) or helper not in {"servonaut", "servonaut.exe"}:
        _fail("runtime marker helper is invalid")
    expected = root / helper
    if request.executable != expected or not request.executable.is_absolute():
        _fail("smoke executable does not match the marker")
    try:
        status = request.executable.lstat()
    except OSError as error:
        raise ArtifactSmokeError("smoke executable is unavailable") from error
    if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
        _fail("smoke executable is not a regular file")
    if os.name != "nt" and not os.access(request.executable, os.X_OK):
        _fail("smoke executable is not executable")
    evidence = request.evidence_dir
    if not evidence.is_absolute() or evidence.is_symlink():
        _fail("smoke evidence directory is invalid")
    try:
        canonical_evidence = evidence.resolve(strict=False)
        if (
            canonical_evidence != evidence
            or evidence == root
            or evidence.is_relative_to(root)
        ):
            _fail("smoke evidence directory must be canonical and outside the payload")
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        if (
            not evidence.is_dir()
            or evidence.is_symlink()
            or evidence.resolve(strict=True) != evidence
        ):
            _fail("smoke evidence directory is invalid")
    except OSError as error:
        raise ArtifactSmokeError("smoke evidence directory is unavailable") from error
    return marker


def isolated_child_environment(home: Path) -> dict[str, str]:
    """Create a credential-free child environment rooted in private scratch."""
    if not home.is_absolute() or home.is_symlink() or not home.is_dir():
        _fail("smoke scratch home is invalid")
    directories = {
        "PATH": home / "empty-path",
        "TMPDIR": home / "tmp",
        "TEMP": home / "tmp",
        "TMP": home / "tmp",
        "XDG_CONFIG_HOME": home / ".config",
        "XDG_CACHE_HOME": home / ".cache",
        "XDG_DATA_HOME": home / ".local" / "share",
    }
    for directory in set(directories.values()):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        **{name: str(path) for name, path in directories.items()},
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": str(home / ".aws" / "config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(home / ".aws" / "credentials"),
    }
    for name in _SAFE_LOCALE_NAMES:
        value = os.environ.get(name)
        if value and "\x00" not in value and len(value) <= 256:
            environment[name] = value
    if os.name == "nt":
        windows = PureWindowsPath(str(home))
        if not windows.drive or not windows.root:
            _fail("Windows smoke home is invalid")
        environment["HOMEDRIVE"] = windows.drive
        environment["HOMEPATH"] = "\\" + str(windows.relative_to(windows.anchor))
        for name in _WINDOWS_RUNTIME_NAMES:
            value = os.environ.get(name)
            if not value or "\x00" in value or len(value) > 4096:
                _fail("Windows runtime environment is incomplete")
            environment[name] = value
    for command in ("python", "python3", "py"):
        if shutil.which(command, path=environment["PATH"]) is not None:
            _fail("smoke environment exposes a Python launcher")
    return environment


def _selftest_caller_environment(token: str) -> dict[str, str]:
    return {
        **_CALLER_ENVIRONMENT_CANARIES,
        "SERVONAUT_ARTIFACT_SELFTEST_TOKEN": token,
    }


def _prepare_selftest_caller(
    root: Path, home: Path, credential_root: Path
) -> _CallerIsolationProof:
    if (
        not root.is_absolute()
        or root.is_symlink()
        or not root.is_dir()
        or not home.is_relative_to(root)
        or not credential_root.is_relative_to(root)
    ):
        _fail("selftest caller root is invalid")
    config_root = home / ".servonaut"
    credentials_root = credential_root / ".aws"
    config_root.mkdir(mode=0o700)
    credentials_root.mkdir(mode=0o700)
    fixtures = {
        config_root / "config.json": (
            b'{"default_username":"caller-isolation-config","ovh":'
            b'{"application_key":"caller-isolation-ovh-file","enabled":true},'
            b'"version":6}\n'
        ),
        config_root / "cache.json": (
            b'{"instances":[{"id":"caller-isolation-cache"}],'
            b'"timestamp":"2000-01-01T00:00:00"}\n'
        ),
        credentials_root / "config": (
            b"[profile caller-isolation-profile]\n"
            b"region = caller-isolation-aws-config\n"
        ),
        credentials_root / "credentials": (
            b"[caller-isolation-profile]\n"
            b"aws_access_key_id = caller-isolation-credential\n"
            b"aws_secret_access_key = caller-isolation-credential\n"
        ),
        home / ".ovh.conf": (
            b"[default]\nendpoint=caller-isolation-ovh-endpoint\n"
            b"application_key=caller-isolation-ovh-file\n"
        ),
    }
    for path, content in fixtures.items():
        try:
            with path.open("xb") as handle:
                handle.write(content)
            path.chmod(0o600)
        except OSError as error:
            raise ArtifactSmokeError(
                "selftest caller fixtures could not be created"
            ) from error
    credential_path = credentials_root / "credentials"
    credential_descriptor: int | None = None
    try:
        if os.name != "nt":
            if getattr(os, "geteuid", lambda: 0)() == 0:
                _fail("POSIX caller-isolation proof requires an unprivileged user")
            credential_descriptor = os.open(credential_path, os.O_RDONLY)
            if os.get_inheritable(credential_descriptor):
                _fail("selftest caller credential descriptor is inheritable")
            credential_path.chmod(0o000)
            _require_unreadable_credential(credential_path)
        entries = _snapshot_caller_tree(root, credential_path, credential_descriptor)
    except BaseException:
        if credential_descriptor is not None:
            os.close(credential_descriptor)
        raise
    return _CallerIsolationProof(
        root,
        entries,
        credential_path,
        credential_descriptor,
    )


def _verify_selftest_caller(
    proof: _CallerIsolationProof, result: _ProcessResult | None
) -> None:
    actual = _snapshot_caller_tree(
        proof.root,
        proof.credential_path,
        proof.credential_descriptor,
    )
    if actual != proof.entries:
        _fail("artifact selftest modified its caller state")
    if os.name != "nt":
        _require_unreadable_credential(proof.credential_path)
    if result is not None and _contains_caller_canary(result.stdout + result.stderr):
        _fail("artifact selftest exposed caller state")


def _close_selftest_caller(proof: _CallerIsolationProof) -> None:
    if proof.credential_descriptor is not None:
        os.close(proof.credential_descriptor)


def _snapshot_caller_tree(
    root: Path, credential_path: Path, credential_descriptor: int | None
) -> tuple[_CallerEntry, ...]:
    entries: list[_CallerEntry] = []
    descendants: list[Path] = []
    for path in root.rglob("*"):
        descendants.append(path)
        if len(descendants) > _CALLER_ENTRY_COUNT_CEILING:
            _fail("selftest caller state contains too many entries")
    for path in (root, *sorted(descendants, key=lambda item: item.as_posix())):
        try:
            status = path.lstat()
        except OSError as error:
            raise ArtifactSmokeError("selftest caller state is unavailable") from error
        if stat.S_ISLNK(status.st_mode) or not (
            stat.S_ISDIR(status.st_mode) or stat.S_ISREG(status.st_mode)
        ):
            _fail("selftest caller state contains an unsupported entry")
        is_file = stat.S_ISREG(status.st_mode)
        if is_file and status.st_size > _CALLER_FILE_SIZE_CEILING:
            _fail("selftest caller state contains an oversized file")
        content = (
            _read_caller_file(path, credential_path, credential_descriptor)
            if is_file
            else None
        )
        entries.append(
            _CallerEntry(
                path.relative_to(root),
                (status.st_dev, status.st_ino),
                stat.S_IMODE(status.st_mode),
                (status.st_uid, status.st_gid),
                (status.st_size, status.st_mtime_ns) if is_file else None,
                content,
            )
        )
    return tuple(entries)


def _read_caller_file(
    path: Path, credential_path: Path, credential_descriptor: int | None
) -> bytes:
    try:
        if path == credential_path and credential_descriptor is not None:
            os.lseek(credential_descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            while chunk := os.read(credential_descriptor, 4096):
                chunks.append(chunk)
            return b"".join(chunks)
        return path.read_bytes()
    except OSError as error:
        raise ArtifactSmokeError("selftest caller state could not be read") from error


def _require_unreadable_credential(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except PermissionError:
        return
    except OSError as error:
        raise ArtifactSmokeError("selftest caller credential is unavailable") from error
    os.close(descriptor)
    _fail("selftest caller credential is readable")


def _contains_caller_canary(data: bytes) -> bool:
    canaries = (*_CALLER_FILE_CANARIES, *_CALLER_ENVIRONMENT_CANARIES.values())
    return any(value.encode("ascii") in data for value in canaries)


def run_bounded_process(
    argv: Sequence[str],
    *,
    environment: Mapping[str, str],
    working_directory: Path,
    timeout_seconds: int,
    output_limit: int,
    argv_max_count: int,
    stdin: bytes = b"",
) -> _ProcessResult:
    """Run one argv without a shell while bounding time and retained output."""
    if (
        not argv
        or type(argv_max_count) is not int
        or not 1 <= argv_max_count <= _POLICY_MAXIMUMS["process_argv_max_count"]
        or len(argv) > argv_max_count
        or any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in argv)
        or not isinstance(stdin, bytes)
        or len(stdin) > output_limit
    ):
        _fail("smoke process argv is invalid")
    try:
        result = run_bounded_command_process(
            argv,
            environment,
            working_directory,
            timeout_seconds,
            output_limit,
            output_limit,
            stdin=stdin,
        )
    except OSError as error:
        raise ArtifactSmokeError("smoke process could not be started") from error
    if not result.cleaned_up:
        _fail("smoke output drain did not finish")
    if result.failure == "timeout":
        _fail("smoke process timed out or failed during input")
    if result.failure == "overflow":
        _fail("smoke process exceeded its output limit")
    if result.failure == "read-error":
        _fail("smoke process output could not be read")
    if result.failure == "input-error":
        _fail("smoke process did not consume its bounded input")
    assert result.exit_code is not None
    return _ProcessResult(
        result.exit_code,
        round(result.elapsed_seconds * 1000),
        result.stdout,
        result.stderr,
    )


def mcp_check_result(check: MCPCheck) -> CheckResult:
    """Record the measured MCP session in the content-free transcript format."""
    return CheckResult(
        True,
        check.exit_code,
        check.elapsed_ms,
        check.stdout_bytes,
        check.stdout_sha256,
        check.stderr_bytes,
        check.stderr_sha256,
    )


def _require_exit(result: _ProcessResult, code: int, label: str) -> None:
    if result.exit_code != code:
        _fail(f"{label} returned the wrong exit code")


def _decode(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ArtifactSmokeError(f"{label} output is not UTF-8") from error


def _strict_json_bytes(data: bytes, limit: int, label: str) -> dict[str, object]:
    if len(data) > limit or not data.endswith(b"\n") or data.count(b"\n") != 1:
        _fail(f"{label} output framing is invalid")
    try:
        value = json.loads(data[:-1], object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ArtifactSmokeError(f"{label} output is invalid") from error
    if not isinstance(value, dict):
        _fail(f"{label} output is not an object")
    return value


def _validate_selftest_success(result: _ProcessResult, policy: SmokePolicy) -> None:
    _require_exit(result, 0, "artifact selftest")
    if result.stderr:
        _fail("artifact selftest wrote to stderr")
    payload = _strict_json_bytes(
        result.stdout, policy.stdout_stderr_max_bytes, "selftest"
    )
    if set(payload) != _SELFTEST_TOP_KEYS or not _has_schema_version_one(payload):
        _fail("artifact selftest returned an invalid schema")
    if payload.get("ok") is not True or payload.get("check") != "tui":
        _fail("artifact selftest did not succeed")
    runtime = payload.get("runtime")
    if (
        not isinstance(runtime, dict)
        or set(runtime) != {"kind", "marker"}
        or runtime.get("kind") != "frozen-cli"
        or runtime.get("marker") is not True
    ):
        _fail("artifact selftest returned invalid runtime facts")
    if not _is_true_map(
        payload.get("tui"), frozenset({"main", "sidebar", "adjacent", "exited"})
    ):
        _fail("artifact selftest returned invalid TUI facts")
    if not _is_true_map(payload.get("fixtures"), frozenset({"config", "cache"})):
        _fail("artifact selftest did not preserve its fixtures")
    if not _is_true_map(
        payload.get("diagnostics"),
        frozenset({"metadata", "sdk", "crypto", "ca", "keyring"}),
    ):
        _fail("artifact selftest diagnostics are incomplete")


def _validate_selftest_failure(
    result: _ProcessResult, policy: SmokePolicy, forbidden: Sequence[str]
) -> None:
    _require_exit(result, 1, "invalid artifact selftest")
    if result.stderr:
        _fail("invalid artifact selftest wrote to stderr")
    text = _decode(result.stdout, "invalid selftest")
    if any(value in text for value in forbidden):
        _fail("invalid artifact selftest echoed authentication material")
    payload = _strict_json_bytes(
        result.stdout, policy.stdout_stderr_max_bytes, "invalid selftest"
    )
    if set(payload) != {"schema_version", "ok", "error"}:
        _fail("invalid artifact selftest returned an invalid schema")
    if not _has_schema_version_one(payload) or payload.get("ok") is not False:
        _fail("invalid artifact selftest did not fail generically")
    error = payload.get("error")
    if error != "authentication-failed":
        _fail("invalid artifact selftest did not reject authentication")


def _load_claude_mcp_config(path: Path, executable: Path) -> dict[str, object]:
    config = _read_json(path, 262144, "Claude MCP config")
    servers = config.get("mcpServers")
    if not isinstance(servers, dict) or set(servers) != {"servonaut"}:
        _fail("Claude MCP config has an invalid server map")
    entry = servers["servonaut"]
    if not isinstance(entry, dict) or set(entry) != {"type", "command", "args", "env"}:
        _fail("Claude MCP server entry has an invalid schema")
    expected_env = {name: f"${{{name}:-}}" for name in _FORWARD_ENV_NAMES}
    expected = {
        "type": "stdio",
        "command": str(executable),
        "args": ["--mcp"],
        "env": expected_env,
    }
    if entry != expected:
        _fail("Claude MCP server entry does not match the packaged runtime")
    return entry


def _mcp_environment(
    entry: Mapping[str, object], base: Mapping[str, str]
) -> dict[str, str]:
    configured = entry.get("env")
    if not isinstance(configured, dict):
        _fail("Claude MCP environment is invalid")
    environment = dict(base)
    for name, reference in configured.items():
        if not isinstance(name, str) or reference != f"${{{name}:-}}":
            _fail("Claude MCP environment reference is invalid")
        environment[name] = base.get(name, "")
    return environment


def _write_transcript(
    evidence_dir: Path, checks: Mapping[str, CheckResult], policy: SmokePolicy
) -> Path:
    path = evidence_dir / "smoke-transcript.json"
    if path.exists() or path.is_symlink():
        _fail("smoke transcript output already exists")
    data = {
        "schema_version": 1,
        "policy": asdict(policy),
        "checks": {name: asdict(checks[name]) for name in sorted(checks)},
    }
    encoded = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > policy.transcript_max_bytes:
        _fail("smoke transcript exceeds its limit")
    if _contains_caller_canary(encoded):
        _fail("smoke transcript contains caller state")
    try:
        with path.open("xb") as handle:
            handle.write(encoded)
    except OSError as error:
        raise ArtifactSmokeError("smoke transcript could not be written") from error
    return path


def run_smoke(request: SmokeRequest, policy: SmokePolicy) -> SmokeResult:
    """Exercise the artifact's public CLI, private selftest, and real MCP server."""
    _validate_request(request)
    checks: dict[str, CheckResult] = {}

    def invoke(
        name: str,
        arguments: Sequence[str],
        *,
        home: Path,
        timeout: int | None = None,
        stdin: bytes = b"",
        extra_env: Mapping[str, str] | None = None,
        prove_caller_isolation: bool = False,
    ) -> _ProcessResult:
        home.mkdir(mode=0o700, parents=True, exist_ok=False)
        environment = isolated_child_environment(home)
        if extra_env:
            environment.update(extra_env)
        proof = (
            _prepare_selftest_caller(home, home, home)
            if prove_caller_isolation
            else None
        )
        result: _ProcessResult | None = None
        try:
            result = run_bounded_process(
                [str(request.executable), *arguments],
                environment=environment,
                working_directory=home,
                timeout_seconds=timeout or policy.public_command_timeout_seconds,
                output_limit=policy.stdout_stderr_max_bytes,
                argv_max_count=policy.process_argv_max_count,
                stdin=stdin,
            )
        finally:
            if proof is not None:
                try:
                    _verify_selftest_caller(proof, result)
                finally:
                    _close_selftest_caller(proof)
        assert result is not None
        checks[name] = result.public()
        return result

    with tempfile.TemporaryDirectory(
        prefix="native-smoke-", dir=request.evidence_dir
    ) as scratch_text:
        scratch = Path(scratch_text)
        version = invoke("version", ["--version"], home=scratch / "version")
        _require_exit(version, 0, "version")
        if _decode(version.stdout, "version") not in (
            f"servonaut {request.product_version}\n",
            f"servonaut {request.product_version}\r\n",
        ):
            _fail("version output does not match the artifact")
        if version.stderr:
            _fail("version wrote to stderr")

        help_result = invoke("help", ["--help"], home=scratch / "help")
        _require_exit(help_result, 0, "help")
        help_text = _decode(help_result.stdout, "help")
        for option in (
            "--version",
            "--update",
            "--mcp",
            "--mcp-install",
            "--list-backups",
        ):
            if option not in help_text:
                _fail("help output is missing a required option")
        if "--_artifact-selftest" in help_text:
            _fail("help output exposes the private selftest")
        if help_result.stderr:
            _fail("help wrote to stderr")

        update = invoke("update", ["--update"], home=scratch / "update")
        _require_exit(update, 0, "update")
        update_text = _decode(update.stdout, "update")
        if (
            f"Current version: {request.product_version}" not in update_text
            or "Automatic updates are not configured for this packaged Servonaut build."
            not in update_text
        ):
            _fail("update output lacks packaged-build guidance")
        if update.stderr:
            _fail("update wrote to stderr")

        backups = invoke("list_backups", ["--list-backups"], home=scratch / "backups")
        _require_exit(backups, 0, "list backups")
        if _decode(backups.stdout, "list backups") not in (
            "No local backups yet.\n",
            "No local backups yet.\r\n",
        ):
            _fail("isolated backup list is not empty")
        if backups.stderr:
            _fail("list backups wrote to stderr")

        bad = invoke(
            "bad_argument", ["--artifact-smoke-invalid-option"], home=scratch / "bad"
        )
        _require_exit(bad, 2, "bad argument")
        if (
            bad.stdout
            or "unrecognized arguments: --artifact-smoke-invalid-option"
            not in _decode(bad.stderr, "bad argument")
        ):
            _fail("bad argument did not return argparse's diagnostic")

        installer_home = scratch / "installer-mcp"
        installed = invoke(
            "mcp_install", ["--mcp-install", "claude"], home=installer_home
        )
        _require_exit(installed, 0, "MCP install")
        if installed.stderr:
            _fail("MCP install wrote to stderr")
        expected_installer_entries = {
            ".cache",
            ".claude.json",
            ".config",
            ".local",
            "empty-path",
            "tmp",
        }
        if {
            path.name for path in installer_home.iterdir()
        } != expected_installer_entries:
            _fail("MCP install wrote outside its configured file")
        entry = _load_claude_mcp_config(
            installer_home / ".claude.json", request.executable
        )

        valid_token = secrets.token_urlsafe(24)
        valid_request = json.dumps(
            {"schema_version": 1, "token": valid_token, "check": "tui"},
            separators=(",", ":"),
        ).encode()
        if len(valid_request) > policy.selftest_stdin_max_bytes:
            _fail("artifact selftest request exceeds policy")
        selftest = invoke(
            "artifact_selftest",
            ["--_artifact-selftest"],
            home=scratch / "selftest",
            timeout=policy.selftest_timeout_seconds,
            stdin=valid_request,
            extra_env=_selftest_caller_environment(valid_token),
            prove_caller_isolation=True,
        )
        _validate_selftest_success(selftest, policy)
        if any(
            path.name.startswith("servonaut-artifact-selftest-")
            for path in (scratch / "selftest" / "tmp").iterdir()
        ):
            _fail("artifact selftest left its private home behind")

        expected_token = secrets.token_urlsafe(24)
        supplied_token = secrets.token_urlsafe(24)
        invalid_request = json.dumps(
            {"schema_version": 1, "token": supplied_token, "check": "tui"},
            separators=(",", ":"),
        ).encode()
        invalid = invoke(
            "artifact_selftest_invalid_token",
            ["--_artifact-selftest"],
            home=scratch / "selftest-invalid",
            timeout=policy.selftest_timeout_seconds,
            stdin=invalid_request,
            extra_env={"SERVONAUT_ARTIFACT_SELFTEST_TOKEN": expected_token},
        )
        _validate_selftest_failure(invalid, policy, (expected_token, supplied_token))

        mcp_environment = _mcp_environment(
            entry, isolated_child_environment(installer_home)
        )
        mcp = run_mcp_smoke(
            command=Path(str(entry["command"])),
            args=entry["args"],  # type: ignore[arg-type]
            environment=mcp_environment,
            working_directory=installer_home,
            timeouts=MCPTimeouts(
                policy.mcp_initialize_timeout_seconds,
                policy.mcp_request_timeout_seconds,
                policy.mcp_shutdown_timeout_seconds,
                policy.mcp_frame_max_bytes,
                policy.stdout_stderr_max_bytes,
            ),
        )
        checks["mcp_protocol"] = mcp_check_result(mcp)

    transcript = _write_transcript(request.evidence_dir, checks, policy)
    return SmokeResult(transcript, checks)


def assert_smoke(result: SmokeResult) -> None:
    """Raise unless every required smoke check succeeded."""
    required = {
        "version",
        "help",
        "update",
        "list_backups",
        "bad_argument",
        "mcp_install",
        "artifact_selftest",
        "artifact_selftest_invalid_token",
        "mcp_protocol",
    }
    if set(result.checks) != required or not all(
        check.ok for check in result.checks.values()
    ):
        _fail("standalone smoke checks are incomplete")
    if not result.transcript.is_file():
        _fail("standalone smoke transcript is unavailable")


def _default_policy() -> Path:
    return (
        Path(__file__).parents[2] / "packaging" / "standalone_cli" / "smoke-policy.json"
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Extract one archive with the public extractor and run native smoke checks."""
    parser = argparse.ArgumentParser(
        description="Validate a standalone Servonaut artifact"
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--extract-parent", type=Path, required=True)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=_default_policy())
    arguments = parser.parse_args(argv)
    try:
        from scripts.standalone_cli.artifact_archive import extract_archive_for_smoke

        root = extract_archive_for_smoke(
            arguments.archive, arguments.extract_parent / "extracted payload"
        )
        marker = _read_json(root / "servonaut-runtime.json", 262144, "runtime marker")
        helper = marker.get("console_helper")
        if not isinstance(helper, str):
            _fail("runtime marker helper is invalid")
        result = run_smoke(
            SmokeRequest(
                root, root / helper, arguments.product_version, arguments.evidence_dir
            ),
            load_smoke_policy(arguments.policy),
        )
        assert_smoke(result)
    except (ArtifactSmokeError, OSError, ValueError) as error:
        print(f"standalone smoke failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
