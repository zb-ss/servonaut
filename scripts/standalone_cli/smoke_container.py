"""Docker transport for the Linux 24.04 standalone smoke matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import NoReturn

from scripts.standalone_cli.smoke_artifact import (
    ArtifactSmokeError,
    CheckResult,
    SmokePolicy,
    SmokeRequest,
    _close_selftest_caller,
    _contains_caller_canary,
    _decode,
    _load_claude_mcp_config,
    _mcp_environment,
    _prepare_selftest_caller,
    _require_exit,
    _selftest_caller_environment,
    _validate_selftest_failure,
    _validate_selftest_success,
    _verify_selftest_caller,
    isolated_child_environment,
    load_smoke_policy,
    mcp_check_result,
    run_bounded_process,
)
from scripts.standalone_cli.smoke_artifact import (
    _validate_request as _validate_artifact_request,
)
from scripts.standalone_cli.smoke_mcp import MCPTimeouts, run_mcp_smoke

_CONTAINER_PAYLOAD = Path("/opt/servonaut")
_CONTAINER_EXECUTABLE = _CONTAINER_PAYLOAD / "servonaut"
_SHELL_EXECUTABLE = Path("/bin/sh")
_OWNER_LABEL = "org.servonaut.smoke-owner"
_PYTHON_ABSENCE_SCRIPT = (
    'for p in python python3; do command -v "$p" >/dev/null 2>&1 && exit 1; done; '
    "exit 0"
)


class ContainerSmokeError(RuntimeError):
    """Raised when Docker transport or Linux-container smoke validation fails."""


@dataclass(frozen=True)
class ContainerSmokeRequest:
    """Inputs for one Linux 24.04 compatibility run."""

    docker: Path
    payload_root: Path
    executable: Path
    product_version: str
    evidence_dir: Path


@dataclass(frozen=True)
class OwnedContainer:
    """Exact Docker identity permitted for lifecycle operations."""

    container_id: str
    name: str
    owner: str


@dataclass(frozen=True)
class ContainerSmokeResult:
    """Content-free result of the complete container smoke matrix."""

    transcript: Path
    checks: Mapping[str, CheckResult]


def _fail(message: str) -> NoReturn:
    raise ContainerSmokeError(message)


def _valid_hex(value: str, minimum: int, maximum: int) -> bool:
    return minimum <= len(value) <= maximum and all(
        character in "0123456789abcdef" for character in value
    )


def _validate_identity(identity: OwnedContainer) -> None:
    if (
        not _valid_hex(identity.container_id, 64, 64)
        or not _valid_hex(identity.owner, 6, 64)
        or identity.name != f"servonaut-smoke-{identity.owner}"
    ):
        _fail("Docker container identity is invalid")


def _validate_request(request: ContainerSmokeRequest, policy: SmokePolicy) -> None:
    _validate_artifact_request(
        SmokeRequest(
            request.payload_root,
            request.executable,
            request.product_version,
            request.evidence_dir,
        )
    )
    docker = request.docker
    if (
        not docker.is_absolute()
        or docker.is_symlink()
        or not docker.is_file()
        or not os.access(docker, os.X_OK)
    ):
        _fail("Docker executable must be an absolute regular file")
    root = request.payload_root
    if root.name != "extracted payload" or not root.is_absolute() or root.is_symlink():
        _fail("container payload root is invalid")
    if not root.is_dir() or request.executable != root / "servonaut":
        _fail("container payload executable is invalid")
    if (
        request.executable.is_symlink()
        or not request.executable.is_file()
        or not os.access(request.executable, os.X_OK)
    ):
        _fail("container payload executable is unavailable")
    try:
        if (
            root.resolve(strict=True) != root
            or request.executable.resolve(strict=True) != request.executable
        ):
            _fail("container payload paths must be canonical")
    except OSError as error:
        raise ContainerSmokeError("container payload paths are unavailable") from error
    if not request.product_version or len(request.product_version) > 128:
        _fail("container product version is invalid")
    if (
        not request.evidence_dir.is_absolute()
        or "," in str(root)
        or "," in str(request.evidence_dir)
    ):
        _fail("Docker bind paths cannot contain commas")
    request.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if request.evidence_dir.is_symlink() or not request.evidence_dir.is_dir():
        _fail("container evidence directory is invalid")
    if "@sha256:" not in policy.docker_image:
        _fail("container image is not digest pinned")


def _docker_environment(home: Path) -> dict[str, str]:
    return isolated_child_environment(home)


def _container_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {
        "HOME": "/state/home",
        "USERPROFILE": "/state/home",
        "PATH": "/state/empty-path",
        "TMPDIR": "/state/tmp",
        "TEMP": "/state/tmp",
        "TMP": "/state/tmp",
        "XDG_CONFIG_HOME": "/state/xdg-config",
        "XDG_CACHE_HOME": "/state/xdg-cache",
        "XDG_DATA_HOME": "/state/xdg-data",
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": "/state/.aws/config",
        "AWS_SHARED_CREDENTIALS_FILE": "/state/.aws/credentials",
    }
    for name in ("LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM"):
        value = os.environ.get(name)
        if value and "\x00" not in value and len(value) <= 256:
            environment[name] = value
    if extra:
        environment.update(extra)
    for name, value in environment.items():
        if not name or "=" in name or "\x00" in name or "\x00" in value:
            _fail("container environment is invalid")
    return environment


def docker_create_argv(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    *,
    scratch: Path,
    name: str,
    owner: str,
    arguments: Sequence[str],
    environment: Mapping[str, str],
    entrypoint: Path = _CONTAINER_EXECUTABLE,
) -> list[str]:
    """Build the exact hardened Docker create argv for one logical check."""
    if (
        not _valid_hex(owner, 6, 64)
        or name != f"servonaut-smoke-{owner}"
        or not arguments
        or len(arguments) > 4
        or any(not value or "\x00" in value or len(value) > 256 for value in arguments)
        or "," in str(scratch)
        or entrypoint not in {_CONTAINER_EXECUTABLE, _SHELL_EXECUTABLE}
    ):
        _fail("container identity or arguments are invalid")
    if scratch.is_symlink() or not scratch.is_dir():
        _fail("container scratch directory is invalid")
    if len({name.casefold() for name in environment}) != len(environment):
        _fail("container environment has duplicate names")
    payload_mount = (
        f"type=bind,src={request.payload_root},dst={_CONTAINER_PAYLOAD},readonly"
    )
    scratch_mount = f"type=bind,src={scratch},dst=/state"
    argv = [
        str(request.docker),
        "create",
        "--interactive",
        "--name",
        name,
        "--label",
        f"{_OWNER_LABEL}={owner}",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(policy.docker_pids_limit),
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--mount",
        payload_mount,
        "--mount",
        scratch_mount,
        "--tmpfs",
        f"/tmp:rw,nosuid,nodev,noexec,size={policy.docker_tmpfs_size_bytes}",
        "--entrypoint",
        str(entrypoint),
    ]
    for key in sorted(environment):
        argv.extend(("--env", f"{key}={environment[key]}"))
    return [*argv, policy.docker_image, *arguments]


def _docker_command(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    argv: Sequence[str],
    *,
    docker_home: Path,
    timeout: int,
    stdin: bytes = b"",
):
    return run_bounded_process(
        argv,
        environment=_docker_environment(docker_home),
        working_directory=docker_home,
        timeout_seconds=timeout,
        output_limit=policy.stdout_stderr_max_bytes,
        argv_max_count=policy.process_argv_max_count,
        stdin=stdin,
    )


def _parse_container_id(output: bytes) -> str:
    try:
        value = output.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise ContainerSmokeError("Docker returned a non-ASCII container ID") from error
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        _fail("Docker did not return one full container ID")
    return value


def _inspect_owned(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    identity: OwnedContainer,
    docker_home: Path,
) -> bool:
    return _inspect_owned_item(request, policy, identity, docker_home) is not None


def _inspect_owned_item(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    identity: OwnedContainer,
    docker_home: Path,
) -> Mapping[str, object] | None:
    """Return the ownership-verified inspect record, or None once it is gone."""
    _validate_identity(identity)
    inspected = _docker_command(
        request,
        policy,
        [str(request.docker), "inspect", identity.container_id],
        docker_home=docker_home,
        timeout=policy.docker_cleanup_timeout_seconds,
    )
    if inspected.exit_code != 0:
        query = _docker_command(
            request,
            policy,
            [
                str(request.docker),
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                f"id={identity.container_id}",
            ],
            docker_home=docker_home,
            timeout=policy.docker_cleanup_timeout_seconds,
        )
        if query.exit_code != 0:
            _fail("Docker could not confirm container absence")
        if not query.stdout.strip():
            return None
        _fail("Docker could not inspect an existing owned container")
    try:
        payload = json.loads(inspected.stdout)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ContainerSmokeError("Docker inspect returned invalid JSON") from error
    if (
        not isinstance(payload, list)
        or len(payload) != 1
        or not isinstance(payload[0], dict)
    ):
        _fail("Docker inspect returned an invalid result")
    item = payload[0]
    config = item.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        item.get("Id") != identity.container_id
        or item.get("Name") != f"/{identity.name}"
        or not isinstance(labels, dict)
        or labels.get(_OWNER_LABEL) != identity.owner
    ):
        _fail("Docker container ownership does not match")
    if config.get("OpenStdin") is not True:
        _fail("Docker container stdin transport is not open")
    return item


def _require_clean_container_exit(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    identity: OwnedContainer,
    docker_home: Path,
) -> None:
    """Require the container itself, not only the Docker client, to exit 0."""
    item = _inspect_owned_item(request, policy, identity, docker_home)
    if item is None:
        _fail("owned Docker container disappeared before its exit was verified")
    state = item.get("State")
    exit_code = state.get("ExitCode") if isinstance(state, dict) else None
    if (
        not isinstance(state, dict)
        or state.get("Running") is not False
        or type(exit_code) is not int
    ):
        _fail("Docker container did not finish")
    if exit_code != 0:
        _fail("Docker container exited with a non-zero status")


def _recover_container(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    *,
    name: str,
    owner: str,
    docker_home: Path,
) -> OwnedContainer | None:
    query = _docker_command(
        request,
        policy,
        [
            str(request.docker),
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"name=^/{name}$",
            "--filter",
            f"label={_OWNER_LABEL}={owner}",
        ],
        docker_home=docker_home,
        timeout=policy.docker_cleanup_timeout_seconds,
    )
    if query.exit_code != 0:
        _fail("Docker could not query an owned container")
    values = [
        line for line in _decode(query.stdout, "Docker recovery").splitlines() if line
    ]
    if not values:
        return None
    if len(values) != 1:
        _fail("Docker recovery found multiple owned containers")
    return OwnedContainer(_parse_container_id(values[0].encode("ascii")), name, owner)


def create_owned_container(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    *,
    scratch: Path,
    arguments: Sequence[str],
    environment: Mapping[str, str],
    docker_home: Path,
    entrypoint: Path = _CONTAINER_EXECUTABLE,
) -> OwnedContainer:
    """Create and verify one exactly named and labelled container."""
    owner = secrets.token_hex(16)
    name = f"servonaut-smoke-{owner}"
    argv = docker_create_argv(
        request,
        policy,
        scratch=scratch,
        name=name,
        owner=owner,
        arguments=arguments,
        environment=environment,
        entrypoint=entrypoint,
    )
    try:
        created = _docker_command(
            request,
            policy,
            argv,
            docker_home=docker_home,
            timeout=policy.docker_create_timeout_seconds,
        )
        if created.exit_code != 0:
            _fail("Docker create failed")
        identity = OwnedContainer(_parse_container_id(created.stdout), name, owner)
        if not _inspect_owned(request, policy, identity, docker_home):
            _fail("created Docker container could not be inspected")
        return identity
    except BaseException:  # Ownership cleanup also runs on cancellation.
        try:
            recovered = _recover_container(
                request, policy, name=name, owner=owner, docker_home=docker_home
            )
            if recovered is not None:
                _remove_verified_container(request, policy, recovered, docker_home)
        except BaseException:  # noqa: BLE001, S110 - preserve the primary failure
            pass
        raise


def _remove_verified_container(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    identity: OwnedContainer,
    docker_home: Path,
) -> None:
    """Remove an identity already admitted by inspect or exact filtered recovery."""
    _validate_identity(identity)
    stopped = False
    try:
        result = _docker_command(
            request,
            policy,
            [str(request.docker), "stop", "--timeout", "2", identity.container_id],
            docker_home=docker_home,
            timeout=policy.docker_cleanup_timeout_seconds,
        )
        stopped = result.exit_code == 0
    except ArtifactSmokeError:
        pass
    if not stopped:
        try:
            _docker_command(
                request,
                policy,
                [str(request.docker), "kill", identity.container_id],
                docker_home=docker_home,
                timeout=policy.docker_cleanup_timeout_seconds,
            )
        except ArtifactSmokeError:
            pass
    try:
        _docker_command(
            request,
            policy,
            [str(request.docker), "rm", "--force", identity.container_id],
            docker_home=docker_home,
            timeout=policy.docker_cleanup_timeout_seconds,
        )
    except ArtifactSmokeError:
        pass
    if (
        _recover_container(
            request,
            policy,
            name=identity.name,
            owner=identity.owner,
            docker_home=docker_home,
        )
        is not None
    ):
        _fail("owned Docker container remained after cleanup")


def cleanup_owned_container(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    identity: OwnedContainer,
    docker_home: Path,
) -> None:
    """Stop and remove only a still-matching owned container ID."""
    if not _inspect_owned(request, policy, identity, docker_home):
        return
    _remove_verified_container(request, policy, identity, docker_home)


def _start_owned(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    identity: OwnedContainer,
    docker_home: Path,
    stdin: bytes = b"",
    timeout: int | None = None,
):
    if not _inspect_owned(request, policy, identity, docker_home):
        _fail("owned Docker container disappeared before start")
    return _docker_command(
        request,
        policy,
        [str(request.docker), "start", "-ai", identity.container_id],
        docker_home=docker_home,
        timeout=timeout or policy.docker_start_timeout_seconds,
        stdin=stdin,
    )


def validate_container_mcp_entry(entry: Mapping[str, object]) -> None:
    """Accept only the exact executable/argv pair that may be translated to Docker."""
    if set(entry) != {"type", "command", "args", "env"}:
        _fail("container MCP entry has an invalid schema")
    if (
        entry.get("type") != "stdio"
        or entry.get("command") != str(_CONTAINER_EXECUTABLE)
        or entry.get("args") != ["--mcp"]
        or not isinstance(entry.get("env"), dict)
    ):
        _fail("container MCP entry is not the approved packaged command")


def _payload_digest(root: Path) -> str:
    digest = hashlib.sha256()
    pending = [root]
    while pending:
        directory = pending.pop()
        for child in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(child.path)
            status = child.stat(follow_symlinks=False)
            relative = path.relative_to(root).as_posix().encode("utf-8")
            digest.update(
                relative + b"\0" + str(stat.S_IMODE(status.st_mode)).encode() + b"\0"
            )
            if stat.S_ISDIR(status.st_mode):
                digest.update(b"d\0")
                pending.append(path)
            elif stat.S_ISREG(status.st_mode):
                digest.update(b"f\0")
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
            elif stat.S_ISLNK(status.st_mode):
                digest.update(b"l\0" + os.readlink(path).encode("utf-8") + b"\0")
            else:
                _fail("payload contains an unsupported entry")
    return digest.hexdigest()


def _write_transcript(
    request: ContainerSmokeRequest,
    policy: SmokePolicy,
    checks: Mapping[str, CheckResult],
) -> Path:
    path = request.evidence_dir / "container-smoke-transcript.json"
    if path.exists() or path.is_symlink():
        _fail("container smoke transcript already exists")
    encoded = (
        json.dumps(
            {
                "schema_version": 1,
                "policy": asdict(policy),
                "checks": {name: asdict(checks[name]) for name in sorted(checks)},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    if len(encoded) > policy.transcript_max_bytes:
        _fail("container smoke transcript exceeds its limit")
    if _contains_caller_canary(encoded):
        _fail("container smoke transcript contains caller state")
    with path.open("xb") as handle:
        handle.write(encoded)
    return path


def run_container_smoke(
    request: ContainerSmokeRequest, policy: SmokePolicy
) -> ContainerSmokeResult:
    """Run the complete smoke matrix in fresh, hardened Ubuntu 24.04 containers."""
    _validate_request(request, policy)
    before = _payload_digest(request.payload_root)
    checks: dict[str, CheckResult] = {}
    with tempfile.TemporaryDirectory(
        prefix="container-smoke-", dir=request.evidence_dir
    ) as work_text:
        work = Path(work_text)
        docker_home = work / "docker-home"
        docker_home.mkdir(mode=0o700)

        python_scratch = work / "python-absence"
        python_scratch.mkdir(mode=0o700)
        for relative in (
            "home",
            "empty-path",
            "tmp",
            "xdg-config",
            "xdg-cache",
            "xdg-data",
        ):
            (python_scratch / relative).mkdir(mode=0o700, parents=True)
        python_identity = create_owned_container(
            request,
            policy,
            scratch=python_scratch,
            arguments=[
                "-c",
                _PYTHON_ABSENCE_SCRIPT,
            ],
            environment=_container_environment(
                {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
            ),
            docker_home=docker_home,
            entrypoint=_SHELL_EXECUTABLE,
        )
        try:
            python_absence = _start_owned(request, policy, python_identity, docker_home)
        finally:
            cleanup_owned_container(request, policy, python_identity, docker_home)
        _require_exit(python_absence, 0, "container Python absence")
        if python_absence.stdout or python_absence.stderr:
            _fail("container Python absence check produced output")
        checks["python_absence"] = python_absence.public()

        def invoke(
            name: str,
            arguments: Sequence[str],
            *,
            stdin: bytes = b"",
            extra_env: Mapping[str, str] | None = None,
            shared_scratch: Path | None = None,
            timeout: int | None = None,
            prove_caller_isolation: bool = False,
        ):
            scratch = shared_scratch or (work / name)
            if shared_scratch is None:
                scratch.mkdir(mode=0o700)
            for relative in (
                "home",
                "empty-path",
                "tmp",
                "xdg-config",
                "xdg-cache",
                "xdg-data",
            ):
                (scratch / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
            proof = (
                _prepare_selftest_caller(scratch, scratch / "home", scratch)
                if prove_caller_isolation
                else None
            )
            result = None
            try:
                identity = create_owned_container(
                    request,
                    policy,
                    scratch=scratch,
                    arguments=arguments,
                    environment=_container_environment(extra_env),
                    docker_home=docker_home,
                )
                try:
                    result = _start_owned(
                        request, policy, identity, docker_home, stdin, timeout
                    )
                finally:
                    cleanup_owned_container(request, policy, identity, docker_home)
            finally:
                if proof is not None:
                    try:
                        _verify_selftest_caller(proof, result)
                    finally:
                        _close_selftest_caller(proof)
            if result is None:
                _fail("container smoke process did not return a result")
            checks[name] = result.public()
            return result

        version = invoke("version", ["--version"])
        _require_exit(version, 0, "container version")
        if (
            _decode(version.stdout, "container version")
            != f"servonaut {request.product_version}\n"
        ):
            _fail("container version output does not match")
        if version.stderr:
            _fail("container version wrote to stderr")

        help_result = invoke("help", ["--help"])
        _require_exit(help_result, 0, "container help")
        help_text = _decode(help_result.stdout, "container help")
        if (
            any(
                option not in help_text
                for option in (
                    "--version",
                    "--update",
                    "--mcp",
                    "--mcp-install",
                    "--list-backups",
                )
            )
            or "--_artifact-selftest" in help_text
        ):
            _fail("container help output is invalid")
        if help_result.stderr:
            _fail("container help wrote to stderr")

        update = invoke("update", ["--update"])
        _require_exit(update, 0, "container update")
        update_text = _decode(update.stdout, "container update")
        if (
            f"Current version: {request.product_version}" not in update_text
            or "Updates for this packaged Servonaut build are not available yet."
            not in update_text
        ):
            _fail("container update guidance is invalid")
        if update.stderr:
            _fail("container update wrote to stderr")

        backups = invoke("list_backups", ["--list-backups"])
        _require_exit(backups, 0, "container list backups")
        if _decode(backups.stdout, "container backups") != "No local backups yet.\n":
            _fail("container backup state is not empty")
        if backups.stderr:
            _fail("container list backups wrote to stderr")

        bad = invoke("bad_argument", ["--artifact-smoke-invalid-option"])
        _require_exit(bad, 2, "container bad argument")
        if (
            bad.stdout
            or "unrecognized arguments: --artifact-smoke-invalid-option"
            not in _decode(bad.stderr, "container bad argument")
        ):
            _fail("container bad argument diagnostic is invalid")

        token = secrets.token_urlsafe(24)
        selftest_input = json.dumps(
            {"schema_version": 1, "token": token, "check": "tui"},
            separators=(",", ":"),
        ).encode()
        if len(selftest_input) > policy.selftest_stdin_max_bytes:
            _fail("container selftest request exceeds policy")
        selftest = invoke(
            "artifact_selftest",
            ["--_artifact-selftest"],
            stdin=selftest_input,
            extra_env=_selftest_caller_environment(token),
            timeout=policy.selftest_timeout_seconds,
            prove_caller_isolation=True,
        )
        _validate_selftest_success(selftest, policy)
        if any(
            path.name.startswith("servonaut-artifact-selftest-")
            for path in (work / "artifact_selftest" / "tmp").iterdir()
        ):
            _fail("container selftest left its private home behind")

        expected = secrets.token_urlsafe(24)
        supplied = secrets.token_urlsafe(24)
        invalid_input = json.dumps(
            {"schema_version": 1, "token": supplied, "check": "tui"},
            separators=(",", ":"),
        ).encode()
        if len(invalid_input) > policy.selftest_stdin_max_bytes:
            _fail("container invalid selftest request exceeds policy")
        invalid = invoke(
            "artifact_selftest_invalid_token",
            ["--_artifact-selftest"],
            stdin=invalid_input,
            extra_env={"SERVONAUT_ARTIFACT_SELFTEST_TOKEN": expected},
            timeout=policy.selftest_timeout_seconds,
        )
        _validate_selftest_failure(invalid, policy, (expected, supplied))

        shared = work / "installer-mcp"
        shared.mkdir(mode=0o700)
        installed = invoke(
            "mcp_install", ["--mcp-install", "claude"], shared_scratch=shared
        )
        _require_exit(installed, 0, "container MCP install")
        if installed.stderr:
            _fail("container MCP install wrote to stderr")
        expected_installer_entries = {
            "home",
            "empty-path",
            "tmp",
            "xdg-config",
            "xdg-cache",
            "xdg-data",
        }
        if {path.name for path in shared.iterdir()} != expected_installer_entries:
            _fail("container MCP install wrote outside its configured file")
        if {path.name for path in (shared / "home").iterdir()} != {".claude.json"}:
            _fail("container MCP install wrote an unexpected home entry")
        entry = _load_claude_mcp_config(
            shared / "home" / ".claude.json", _CONTAINER_EXECUTABLE
        )
        validate_container_mcp_entry(entry)
        container_mcp_env = _mcp_environment(entry, _container_environment())
        identity = create_owned_container(
            request,
            policy,
            scratch=shared,
            arguments=["--mcp"],
            environment=container_mcp_env,
            docker_home=docker_home,
        )
        try:
            mcp = run_mcp_smoke(
                command=request.docker,
                args=["start", "-ai", identity.container_id],
                environment=_docker_environment(docker_home),
                working_directory=docker_home,
                timeouts=MCPTimeouts(
                    policy.mcp_initialize_timeout_seconds,
                    policy.mcp_request_timeout_seconds,
                    policy.mcp_shutdown_timeout_seconds,
                    policy.mcp_frame_max_bytes,
                    policy.stdout_stderr_max_bytes,
                ),
                expected_args=["start", "-ai", identity.container_id],
            )
            _require_clean_container_exit(request, policy, identity, docker_home)
        finally:
            cleanup_owned_container(request, policy, identity, docker_home)
        checks["mcp_protocol"] = mcp_check_result(mcp)

    if _payload_digest(request.payload_root) != before:
        _fail("container smoke modified the extracted payload")
    transcript = _write_transcript(request, policy, checks)
    return ContainerSmokeResult(transcript, checks)


def _default_policy() -> Path:
    return (
        Path(__file__).parents[2] / "packaging" / "standalone_cli" / "smoke-policy.json"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Linux compatibility smoke in Docker"
    )
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--payload-root", type=Path, required=True)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=_default_policy())
    arguments = parser.parse_args(argv)
    try:
        request = ContainerSmokeRequest(
            arguments.docker.resolve(strict=True),
            arguments.payload_root,
            arguments.payload_root / "servonaut",
            arguments.product_version,
            arguments.evidence_dir,
        )
        run_container_smoke(request, load_smoke_policy(arguments.policy))
    except (ArtifactSmokeError, ContainerSmokeError, OSError, ValueError) as error:
        print(f"container smoke failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
