from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.standalone_cli.smoke_artifact import (
    _FORWARD_ENV_NAMES,
    ArtifactSmokeError,
    _close_selftest_caller,
    _mcp_environment,
    _prepare_selftest_caller,
    _ProcessResult,
    _selftest_caller_environment,
    _verify_selftest_caller,
    load_smoke_policy,
    run_bounded_process,
)
from scripts.standalone_cli.smoke_container import (
    _PYTHON_ABSENCE_SCRIPT,
    ContainerSmokeError,
    ContainerSmokeRequest,
    OwnedContainer,
    _container_environment,
    _inspect_owned,
    _parse_container_id,
    _payload_digest,
    _require_clean_container_exit,
    _start_owned,
    cleanup_owned_container,
    create_owned_container,
    docker_create_argv,
    run_container_smoke,
    validate_container_mcp_entry,
)

POLICY = (
    Path(__file__).parents[2] / "packaging" / "standalone_cli" / "smoke-policy.json"
)


def _request(tmp_path: Path) -> ContainerSmokeRequest:
    tmp_path.mkdir(parents=True, exist_ok=True)
    docker = tmp_path / "docker"
    docker.write_text("executable", encoding="utf-8")
    docker.chmod(0o755)
    payload = tmp_path / "extracted payload"
    payload.mkdir()
    executable = payload / "servonaut"
    executable.write_text("payload", encoding="utf-8")
    executable.chmod(0o755)
    (payload / "servonaut-runtime.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "distribution": "frozen-cli",
                "product_version": "9.8.7",
                "build_revision": "test-revision",
                "console_helper": "servonaut",
                "desktop_child": None,
            }
        ),
        encoding="utf-8",
    )
    return ContainerSmokeRequest(
        docker, payload, executable, "9.8.7", tmp_path / "evidence"
    )


def test_container_smoke_rejects_evidence_inside_payload(tmp_path: Path) -> None:
    request = _request(tmp_path)
    nested_request = ContainerSmokeRequest(
        request.docker,
        request.payload_root,
        request.executable,
        request.product_version,
        request.payload_root / "evidence",
    )

    with pytest.raises(ArtifactSmokeError, match="outside the payload"):
        run_container_smoke(nested_request, load_smoke_policy(POLICY))

    assert not nested_request.evidence_dir.exists()


def test_container_selftest_uses_shared_caller_isolation_boundary(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "container-state"
    home = scratch / "home"
    home.mkdir(parents=True)
    for relative in ("empty-path", "tmp", "xdg-config", "xdg-cache", "xdg-data"):
        (scratch / relative).mkdir()
    proof = _prepare_selftest_caller(scratch, home, scratch)
    try:
        _verify_selftest_caller(proof, _ProcessResult(0, 1, b"ok\n", b""))

        assert (home / ".servonaut/config.json").is_file()
        assert (scratch / ".aws/credentials").is_file()
    finally:
        _close_selftest_caller(proof)


@pytest.mark.skipif(os.name == "nt", reason="POSIX container shell contract")
def test_python_absence_shell_check_has_explicit_success_status(
    tmp_path: Path,
) -> None:
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    command = ["/bin/sh", "-c", _PYTHON_ABSENCE_SCRIPT]

    absent = subprocess.run(
        command,
        env={"PATH": str(empty_path)},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert absent.returncode == 0
    assert not absent.stdout and not absent.stderr

    python = empty_path / "python"
    python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    python.chmod(0o755)
    present = subprocess.run(
        command,
        env={"PATH": str(empty_path)},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert present.returncode == 1
    assert not present.stdout and not present.stderr


def test_docker_create_argv_is_hardened_and_preserves_spaces(tmp_path: Path) -> None:
    request = _request(tmp_path / "parent with spaces")
    policy = load_smoke_policy(POLICY)
    scratch = request.payload_root.parent / "state with spaces"
    scratch.mkdir()

    argv = docker_create_argv(
        request,
        policy,
        scratch=scratch,
        name="servonaut-smoke-abc123",
        owner="abc123",
        arguments=["--version"],
        environment={"HOME": "/state", "PATH": "/state/empty-path"},
    )

    assert argv[0] == str(request.docker)
    assert argv.count("--interactive") == 1
    assert argv.count("--network") == 1
    assert argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    assert ["--cap-drop", "ALL"] == argv[
        argv.index("--cap-drop") : argv.index("--cap-drop") + 2
    ]
    assert "no-new-privileges" in argv
    assert policy.docker_image in argv
    assert argv[-1] == "--version"
    assert any("parent with spaces" in item for item in argv)


def test_production_container_argv_compositions_fit_process_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _request(tmp_path)
    request = ContainerSmokeRequest(
        Path(sys.executable).resolve(),
        fixture.payload_root,
        fixture.executable,
        fixture.product_version,
        fixture.evidence_dir,
    )
    policy = load_smoke_policy(POLICY)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for name in ("LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM"):
        monkeypatch.setenv(name, "C.UTF-8")

    mcp_entry = {"env": {name: f"${{{name}:-}}" for name in _FORWARD_ENV_NAMES}}
    compositions = {
        "mcp": (
            ["--mcp"],
            _mcp_environment(mcp_entry, _container_environment()),
        ),
        "selftest": (
            ["--_artifact-selftest"],
            _container_environment(_selftest_caller_environment("t" * 32)),
        ),
        "maximum_arguments": (
            ["one", "two", "three", "four"],
            _container_environment(_selftest_caller_environment("t" * 32)),
        ),
    }

    counts: dict[str, int] = {}
    for name, (arguments, environment) in compositions.items():
        argv = docker_create_argv(
            request,
            policy,
            scratch=scratch,
            name="servonaut-smoke-abc123",
            owner="abc123",
            arguments=arguments,
            environment=environment,
        )
        counts[name] = len(argv)
        result = run_bounded_process(
            argv,
            environment={
                name: os.environ[name]
                for name in ("PATH", "SystemRoot", "WINDIR")
                if name in os.environ
            },
            working_directory=tmp_path,
            timeout_seconds=5,
            output_limit=policy.stdout_stderr_max_bytes,
            argv_max_count=policy.process_argv_max_count,
        )
        assert result.exit_code != 0

    assert counts == {"mcp": 92, "selftest": 80, "maximum_arguments": 83}
    assert max(counts.values()) <= policy.process_argv_max_count


def test_docker_create_rejects_mount_path_with_comma(tmp_path: Path) -> None:
    request = _request(tmp_path / "parent,comma")
    policy = load_smoke_policy(POLICY)
    scratch = request.payload_root.parent / "scratch"
    scratch.mkdir()

    with pytest.raises(ContainerSmokeError, match="invalid"):
        docker_create_argv(
            request,
            policy,
            scratch=scratch,
            name="servonaut-smoke-abc123",
            owner="abc123",
            arguments=["--version"],
            environment={},
        )


@pytest.mark.parametrize(
    "entry",
    [
        {"type": "stdio", "command": "servonaut", "args": ["--mcp"], "env": {}},
        {
            "type": "stdio",
            "command": "/opt/servonaut/servonaut",
            "args": ["--mcp", "x"],
            "env": {},
        },
        {
            "type": "stdio",
            "command": "/opt/servonaut/../servonaut",
            "args": ["--mcp"],
            "env": {},
        },
        {
            "type": "stdio",
            "command": "/opt/servonaut/servonaut",
            "args": ["--mcp"],
            "env": {},
            "shell": True,
        },
    ],
)
def test_container_mcp_translation_rejects_non_exact_entry(
    entry: dict[str, object],
) -> None:
    with pytest.raises(ContainerSmokeError):
        validate_container_mcp_entry(entry)


def test_container_mcp_translation_accepts_exact_entry() -> None:
    validate_container_mcp_entry(
        {
            "type": "stdio",
            "command": "/opt/servonaut/servonaut",
            "args": ["--mcp"],
            "env": {"AWS_PROFILE": "${AWS_PROFILE:-}"},
        }
    )


@pytest.mark.parametrize("value", [b"short\n", b"g" * 64, b"a" * 64 + b"\nb" * 64])
def test_container_id_must_be_one_full_lowercase_digest(value: bytes) -> None:
    with pytest.raises(ContainerSmokeError, match="container ID"):
        _parse_container_id(value)


def test_inspect_rejects_mismatched_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    policy = load_smoke_policy(POLICY)
    docker_home = tmp_path / "docker-home"
    docker_home.mkdir()
    identity = OwnedContainer("a" * 64, "servonaut-smoke-abc123", "abc123")
    payload = [
        {
            "Id": identity.container_id,
            "Name": f"/{identity.name}",
            "Config": {
                "OpenStdin": True,
                "Labels": {"org.servonaut.smoke-owner": "different"},
            },
        }
    ]
    monkeypatch.setattr(
        "scripts.standalone_cli.smoke_container._docker_command",
        lambda *_args, **_kwargs: _ProcessResult(0, 1, json_bytes(payload), b""),
    )

    with pytest.raises(ContainerSmokeError, match="ownership"):
        _inspect_owned(request, policy, identity, docker_home)


def test_inspect_rejects_closed_stdin_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    policy = load_smoke_policy(POLICY)
    docker_home = tmp_path / "docker-home"
    docker_home.mkdir()
    identity = OwnedContainer("a" * 64, "servonaut-smoke-abc123", "abc123")
    payload = [
        {
            "Id": identity.container_id,
            "Name": f"/{identity.name}",
            "Config": {
                "OpenStdin": False,
                "Labels": {"org.servonaut.smoke-owner": identity.owner},
            },
        }
    ]
    monkeypatch.setattr(
        "scripts.standalone_cli.smoke_container._docker_command",
        lambda *_args, **_kwargs: _ProcessResult(0, 1, json_bytes(payload), b""),
    )

    with pytest.raises(ContainerSmokeError, match="stdin transport"):
        _inspect_owned(request, policy, identity, docker_home)


@pytest.mark.parametrize(
    ("state", "expected"),
    (
        ({"Running": False, "ExitCode": 0}, None),
        ({"Running": False, "ExitCode": 3}, "non-zero status"),
        ({"Running": True, "ExitCode": 0}, "did not finish"),
        ({"Running": False, "ExitCode": True}, "did not finish"),
        (None, "did not finish"),
    ),
)
def test_container_mcp_requires_the_container_itself_to_exit_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: dict[str, object] | None,
    expected: str | None,
) -> None:
    request = _request(tmp_path)
    policy = load_smoke_policy(POLICY)
    docker_home = tmp_path / "docker-home"
    docker_home.mkdir()
    identity = OwnedContainer("a" * 64, "servonaut-smoke-abc123", "abc123")
    item: dict[str, object] = {
        "Id": identity.container_id,
        "Name": f"/{identity.name}",
        "Config": {
            "OpenStdin": True,
            "Labels": {"org.servonaut.smoke-owner": identity.owner},
        },
    }
    if state is not None:
        item["State"] = state
    monkeypatch.setattr(
        "scripts.standalone_cli.smoke_container._docker_command",
        lambda *_args, **_kwargs: _ProcessResult(0, 1, json_bytes([item]), b""),
    )

    if expected is None:
        _require_clean_container_exit(request, policy, identity, docker_home)
    else:
        with pytest.raises(ContainerSmokeError, match=expected):
            _require_clean_container_exit(request, policy, identity, docker_home)


def test_cleanup_targets_only_verified_full_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    policy = load_smoke_policy(POLICY)
    docker_home = tmp_path / "docker-home"
    docker_home.mkdir()
    identity = OwnedContainer("a" * 64, "servonaut-smoke-abc123", "abc123")
    calls: list[list[str]] = []

    ownership = iter((True, False))
    monkeypatch.setattr(
        "scripts.standalone_cli.smoke_container._inspect_owned",
        lambda *_args: next(ownership),
    )

    def fake_command(*_args: object, **kwargs: object) -> _ProcessResult:
        argv = kwargs.get("argv")
        if argv is None and len(_args) >= 3:
            argv = _args[2]
        assert isinstance(argv, list)
        calls.append(argv)
        return _ProcessResult(0, 1, b"", b"")

    monkeypatch.setattr(
        "scripts.standalone_cli.smoke_container._docker_command", fake_command
    )

    cleanup_owned_container(request, policy, identity, docker_home)

    assert calls == [
        [str(request.docker), "stop", "--timeout", "2", "a" * 64],
        [str(request.docker), "rm", "--force", "a" * 64],
        [
            str(request.docker),
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            "name=^/servonaut-smoke-abc123$",
            "--filter",
            "label=org.servonaut.smoke-owner=abc123",
        ],
    ]


def test_payload_digest_changes_when_payload_changes(tmp_path: Path) -> None:
    request = _request(tmp_path)
    before = _payload_digest(request.payload_root)
    request.executable.write_text("modified", encoding="utf-8")

    assert _payload_digest(request.payload_root) != before


def test_owned_container_lifecycle_executes_real_transport_utility(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    request.docker.write_text(
        f"""#!{sys.executable}
import json, os, pathlib, sys
state = pathlib.Path(os.environ['HOME']) / 'fake-docker-state.json'
args = sys.argv[1:]
container_id = 'b' * 64
if args[0] == 'create':
    name = args[args.index('--name') + 1]
    label = args[args.index('--label') + 1].split('=', 1)[1]
    state.write_text(json.dumps({{'Id':container_id,'Name':'/' + name,'Config':{{'OpenStdin':'--interactive' in args,'Labels':{{'org.servonaut.smoke-owner':label}}}}}}))
    print(container_id)
elif args[0] == 'inspect':
    if not state.exists():
        raise SystemExit(1)
    print('[' + state.read_text() + ']')
elif args[0] == 'ps':
    if state.exists():
        print(container_id)
elif args[0] == 'start':
    item = json.loads(state.read_text())
    if not item['Config']['OpenStdin']:
        raise SystemExit(1)
    sys.stdout.buffer.write(sys.stdin.buffer.read())
elif args[0] in ('stop', 'kill'):
    print(container_id)
elif args[0] == 'rm':
    state.unlink(missing_ok=True)
    print(container_id)
else:
    raise SystemExit(2)
""",
        encoding="utf-8",
    )
    request.docker.chmod(0o755)
    policy = load_smoke_policy(POLICY)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    docker_home = tmp_path / "docker-home"
    docker_home.mkdir()

    identity = create_owned_container(
        request,
        policy,
        scratch=scratch,
        arguments=["--version"],
        environment={"HOME": "/state", "PATH": "/state/empty-path"},
        docker_home=docker_home,
    )
    request_bytes = b'{"request":"stdin"}\n'
    started = _start_owned(
        request,
        policy,
        identity,
        docker_home,
        stdin=request_bytes,
    )
    cleanup_owned_container(request, policy, identity, docker_home)

    assert identity.container_id == "b" * 64
    assert started.exit_code == 0
    assert started.stdout == request_bytes
    assert not started.stderr
    assert not (docker_home / "fake-docker-state.json").exists()


@pytest.mark.parametrize("mode", ["malformed-id", "malformed-inspect"])
def test_post_create_failure_recovers_and_removes_exact_owned_container(
    tmp_path: Path, mode: str
) -> None:
    request = _request(tmp_path)
    _write_recovery_docker(request.docker, mode)
    policy = load_smoke_policy(POLICY)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    docker_home = tmp_path / "docker-home"
    docker_home.mkdir()

    with pytest.raises(ContainerSmokeError):
        create_owned_container(
            request,
            policy,
            scratch=scratch,
            arguments=["--version"],
            environment={"HOME": "/state", "PATH": "/state/empty-path"},
            docker_home=docker_home,
        )

    assert not (docker_home / "recovery-state.json").exists()


def test_post_create_recovery_preserves_mismatched_container(tmp_path: Path) -> None:
    request = _request(tmp_path)
    _write_recovery_docker(request.docker, "foreign-label")
    policy = load_smoke_policy(POLICY)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    docker_home = tmp_path / "docker-home"
    docker_home.mkdir()

    with pytest.raises(ContainerSmokeError):
        create_owned_container(
            request,
            policy,
            scratch=scratch,
            arguments=["--version"],
            environment={"HOME": "/state", "PATH": "/state/empty-path"},
            docker_home=docker_home,
        )

    assert (docker_home / "recovery-state.json").is_file()


def test_policy_image_is_linux_amd64_manifest_digest() -> None:
    policy = load_smoke_policy(POLICY)

    assert policy.docker_image == (
        "ubuntu:24.04@sha256:"
        "a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61"
    )


def json_bytes(value: object) -> bytes:
    import json

    return json.dumps(value).encode("utf-8")


def _write_recovery_docker(path: Path, mode: str) -> None:
    path.write_text(
        f"""#!{sys.executable}
import json, os, pathlib, sys
state = pathlib.Path(os.environ['HOME']) / 'recovery-state.json'
args = sys.argv[1:]
container_id = 'c' * 64
mode = {mode!r}
if args[0] == 'create':
    name = args[args.index('--name') + 1]
    label = args[args.index('--label') + 1].split('=', 1)[1]
    if mode == 'foreign-label':
        label = 'd' * 32
    state.write_text(json.dumps({{'Id':container_id,'Name':'/' + name,'Config':{{'OpenStdin':'--interactive' in args,'Labels':{{'org.servonaut.smoke-owner':label}}}}}}))
    print(('prefix-' if mode in ('malformed-id', 'foreign-label') else '') + container_id)
elif args[0] == 'inspect':
    if not state.exists():
        raise SystemExit(1)
    print('{{' if mode == 'malformed-inspect' else '[' + state.read_text() + ']')
elif args[0] == 'ps':
    if state.exists():
        item = json.loads(state.read_text())
        label = item['Config']['Labels']['org.servonaut.smoke-owner']
        requested = [value for value in args if value.startswith('label=org.servonaut.smoke-owner=')]
        if not requested or requested == ['label=org.servonaut.smoke-owner=' + label]:
            print(container_id)
elif args[0] in ('stop', 'kill'):
    print(container_id)
elif args[0] == 'rm':
    state.unlink(missing_ok=True)
    print(container_id)
else:
    raise SystemExit(2)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)
