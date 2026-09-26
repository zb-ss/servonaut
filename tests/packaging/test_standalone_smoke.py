from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.standalone_cli.smoke_artifact import (
    ArtifactSmokeError,
    SmokeRequest,
    _close_selftest_caller,
    _prepare_selftest_caller,
    _ProcessResult,
    _selftest_caller_environment,
    _validate_selftest_failure,
    _validate_selftest_success,
    _verify_selftest_caller,
    isolated_child_environment,
    load_smoke_policy,
    run_bounded_process,
    run_smoke,
)
from scripts.standalone_cli.smoke_mcp import (
    MCPCheck,
    MCPSmokeError,
    MCPTimeouts,
    run_mcp_smoke,
)

POLICY = (
    Path(__file__).parents[2] / "packaging" / "standalone_cli" / "smoke-policy.json"
)
FORWARD_NAMES = (
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


def _payload(
    tmp_path: Path,
    version: str = "9.8.7",
    *,
    version_stdout: str | None = None,
    backups_stdout: str | None = None,
) -> tuple[Path, Path]:
    root = tmp_path / "extracted payload"
    root.mkdir()
    executable = root / "servonaut"
    version_stdout = (
        version_stdout if version_stdout is not None else f"servonaut {version}\n"
    )
    backups_stdout = (
        backups_stdout if backups_stdout is not None else "No local backups yet.\n"
    )
    version_stdout_bytes = version_stdout.encode()
    backups_stdout_bytes = backups_stdout.encode()
    script = f"""#!{sys.executable}
import json, os, pathlib, sys
args = sys.argv[1:]
if args == ['--version']:
    sys.stdout.buffer.write({version_stdout_bytes!r})
elif args == ['--help']:
    print('usage: servonaut --version --update --mcp --mcp-install --list-backups')
elif args == ['--update']:
    print('Current version: {version}')
    print('Checking for updates...')
    print('Automatic updates are not configured for this packaged Servonaut build. Install a newer signed build when one is provided.')
elif args == ['--list-backups']:
    sys.stdout.buffer.write({backups_stdout_bytes!r})
elif args == ['--mcp-install', 'claude']:
    names = {FORWARD_NAMES!r}
    entry = {{'type':'stdio','command':str(pathlib.Path(sys.argv[0]).resolve()),'args':['--mcp'],'env':{{name:'${{' + name + ':-}}' for name in names}}}}
    pathlib.Path.home().joinpath('.claude.json').write_text(json.dumps({{'mcpServers':{{'servonaut':entry}}}}), encoding='utf-8')
elif args == ['--_artifact-selftest']:
    request = json.loads(sys.stdin.read())
    if request.get('token') != os.environ.get('SERVONAUT_ARTIFACT_SELFTEST_TOKEN'):
        print(json.dumps({{'schema_version':1,'ok':False,'error':'authentication-failed'}}, separators=(',', ':')))
        raise SystemExit(1)
    print(json.dumps({{'schema_version':1,'ok':True,'check':'tui','runtime':{{'kind':'frozen-cli','marker':True}},'tui':{{'main':True,'sidebar':True,'adjacent':True,'exited':True}},'fixtures':{{'config':True,'cache':True}},'diagnostics':{{'metadata':True,'sdk':True,'crypto':True,'ca':True,'keyring':True}}}}, separators=(',', ':')))
else:
    print('unrecognized arguments: --artifact-smoke-invalid-option', file=sys.stderr)
    raise SystemExit(2)
"""
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o755)
    marker = {
        "schema_version": 1,
        "distribution": "frozen-cli",
        "product_version": version,
        "build_revision": "test-revision",
        "channel": "stable",
        "packaging_revision": 1,
        "console_helper": "servonaut",
        "desktop_child": None,
    }
    (root / "servonaut-runtime.json").write_text(json.dumps(marker), encoding="utf-8")
    return root, executable


def test_policy_loads_with_fixed_digest() -> None:
    policy = load_smoke_policy(POLICY)

    assert policy.docker_image.startswith("ubuntu:24.04@sha256:")
    assert policy.process_argv_max_count == 96
    assert policy.stdout_stderr_max_bytes == 65536


def test_policy_rejects_unknown_key(tmp_path: Path) -> None:
    value = json.loads(POLICY.read_text(encoding="utf-8"))
    value["unexpected"] = True
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ArtifactSmokeError, match="schema"):
        load_smoke_policy(path)


def test_policy_rejects_boolean_schema_version(tmp_path: Path) -> None:
    value = json.loads(POLICY.read_text(encoding="utf-8"))
    value["schema_version"] = True
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ArtifactSmokeError, match="schema"):
        load_smoke_policy(path)


@pytest.mark.parametrize("value", [0, True, 257])
def test_policy_rejects_invalid_process_argv_limit(
    tmp_path: Path, value: object
) -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    policy["process_argv_max_count"] = value
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(ArtifactSmokeError, match="numeric limit"):
        load_smoke_policy(path)


def test_isolated_environment_drops_parent_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "parent-secret")
    monkeypatch.setenv("PYTHONPATH", "/untrusted/source")
    home = tmp_path / "home"
    home.mkdir()

    environment = isolated_child_environment(home)

    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "PYTHONPATH" not in environment
    assert environment["PYTHON_KEYRING_BACKEND"] == "keyring.backends.null.Keyring"
    assert environment["PYTHONUTF8"] == "1"
    assert environment["PYTHONIOENCODING"] == "utf-8"
    assert environment["AWS_CONFIG_FILE"].startswith(str(home))


def test_selftest_caller_proof_preserves_fixed_state_and_unreadable_credential(
    tmp_path: Path,
) -> None:
    home = tmp_path / "caller-home"
    home.mkdir()
    isolated_child_environment(home)
    proof = _prepare_selftest_caller(home, home, home)
    try:
        _verify_selftest_caller(proof, _ProcessResult(0, 1, b"ok\n", b""))

        assert (home / ".servonaut/config.json").is_file()
        if os.name != "nt":
            credential = home / ".aws/credentials"
            assert stat.S_IMODE(credential.stat().st_mode) == 0
            with pytest.raises(PermissionError):
                credential.read_bytes()
    finally:
        _close_selftest_caller(proof)


@pytest.mark.parametrize(
    "failure", ["bytes", "identity", "extra", "oversized", "output"]
)
def test_selftest_caller_proof_rejects_mutation_or_disclosure(
    tmp_path: Path, failure: str
) -> None:
    home = tmp_path / "caller-home"
    home.mkdir()
    isolated_child_environment(home)
    proof = _prepare_selftest_caller(home, home, home)
    config = home / ".servonaut/config.json"
    result = _ProcessResult(0, 1, b"ok\n", b"")
    try:
        if failure == "bytes":
            config.write_bytes(b"changed")
        elif failure == "identity":
            content = config.read_bytes()
            config.unlink()
            config.write_bytes(content)
            config.chmod(0o600)
        elif failure == "extra":
            (home / ".servonaut/created.log").write_text("created", encoding="utf-8")
        elif failure == "oversized":
            (home / ".servonaut/created.log").write_bytes(b"x" * (64 * 1024 + 1))
        else:
            result = _ProcessResult(0, 1, b"caller-isolation-config\n", b"")

        with pytest.raises(ArtifactSmokeError, match="caller state"):
            _verify_selftest_caller(proof, result)
    finally:
        _close_selftest_caller(proof)


@pytest.mark.skipif(os.name == "nt", reason="POSIX privilege contract")
def test_selftest_caller_proof_rejects_root_only_permission_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "caller-home"
    home.mkdir()
    isolated_child_environment(home)
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    with pytest.raises(ArtifactSmokeError, match="unprivileged"):
        _prepare_selftest_caller(home, home, home)


def test_selftest_caller_environment_is_fixed_and_does_not_read_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OVH_APPLICATION_KEY", "parent-value")

    environment = _selftest_caller_environment("generated-token")

    assert environment == {
        "AWS_ACCESS_KEY_ID": "caller-isolation-access-key",
        "AWS_PROFILE": "caller-isolation-profile",
        "AWS_SECRET_ACCESS_KEY": "caller-isolation-secret-key",
        "OVH_APPLICATION_KEY": "caller-isolation-ovh-application",
        "OVH_APPLICATION_SECRET": "caller-isolation-ovh-secret",
        "OVH_CONSUMER_KEY": "caller-isolation-ovh-consumer",
        "OVH_ENDPOINT": "caller-isolation-ovh-endpoint",
        "SERVONAUT_ARTIFACT_SELFTEST_TOKEN": "generated-token",
    }


def test_bounded_process_rejects_excess_output(tmp_path: Path) -> None:
    policy = load_smoke_policy(POLICY)
    with pytest.raises(ArtifactSmokeError, match="output limit"):
        run_bounded_process(
            [sys.executable, "-c", "print('x' * 5000)"],
            environment={"PATH": ""},
            working_directory=tmp_path,
            timeout_seconds=5,
            output_limit=256,
            argv_max_count=policy.process_argv_max_count,
        )


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_bounded_process_stops_promptly_at_first_excess_byte(
    tmp_path: Path, stream: str
) -> None:
    policy = load_smoke_policy(POLICY)
    started = time.monotonic()

    with pytest.raises(ArtifactSmokeError, match="output limit"):
        run_bounded_process(
            [
                sys.executable,
                "-c",
                (
                    "import sys,time; "
                    f"stream=sys.{stream}.buffer; "
                    "stream.write(b'x'*257); stream.flush(); time.sleep(6)"
                ),
            ],
            environment={"PATH": ""},
            working_directory=tmp_path,
            timeout_seconds=5,
            output_limit=256,
            argv_max_count=policy.process_argv_max_count,
        )

    assert time.monotonic() - started < 3


def test_bounded_process_accepts_exact_output_cap_and_input(tmp_path: Path) -> None:
    policy = load_smoke_policy(POLICY)
    data = b"x" * 256

    result = run_bounded_process(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
        ],
        environment={"PATH": ""},
        working_directory=tmp_path,
        timeout_seconds=5,
        output_limit=256,
        argv_max_count=policy.process_argv_max_count,
        stdin=data,
    )

    assert result.exit_code == 0
    assert result.stdout == data
    assert not result.stderr


def test_bounded_process_terminates_after_policy_timeout(tmp_path: Path) -> None:
    policy = load_smoke_policy(POLICY)
    with pytest.raises(ArtifactSmokeError, match="timed out"):
        run_bounded_process(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            environment={"PATH": ""},
            working_directory=tmp_path,
            timeout_seconds=1,
            output_limit=256,
            argv_max_count=policy.process_argv_max_count,
        )


def test_bounded_process_rejects_argv_over_policy_before_launch(
    tmp_path: Path,
) -> None:
    policy = load_smoke_policy(POLICY)

    with pytest.raises(ArtifactSmokeError, match="argv is invalid"):
        run_bounded_process(
            [
                sys.executable,
                *("argument" for _ in range(policy.process_argv_max_count)),
            ],
            environment={"PATH": ""},
            working_directory=tmp_path,
            timeout_seconds=5,
            output_limit=256,
            argv_max_count=policy.process_argv_max_count,
        )


@pytest.mark.parametrize("line_ending", ("\n", "\r\n"), ids=("lf", "crlf"))
def test_run_smoke_executes_complete_native_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, line_ending: str
) -> None:
    root, executable = _payload(
        tmp_path,
        version_stdout=f"servonaut 9.8.7{line_ending}",
        backups_stdout=f"No local backups yet.{line_ending}",
    )
    evidence = tmp_path / "evidence"

    def fake_mcp(**kwargs: object) -> MCPCheck:
        assert kwargs["command"] == executable
        assert kwargs["args"] == ["--mcp"]
        environment = kwargs["environment"]
        assert isinstance(environment, dict)
        assert environment["AWS_SECRET_ACCESS_KEY"] == ""
        assert "PYTHONPATH" not in environment
        return MCPCheck(12, True, 0, "0" * 64, 0, 7, 42, "1" * 64)

    monkeypatch.setattr("scripts.standalone_cli.smoke_artifact.run_mcp_smoke", fake_mcp)

    result = run_smoke(
        SmokeRequest(root, executable, "9.8.7", evidence), load_smoke_policy(POLICY)
    )

    assert set(result.checks) == {
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
    transcript = json.loads(result.transcript.read_text(encoding="utf-8"))
    assert set(transcript) == {"schema_version", "policy", "checks"}
    checks = transcript["checks"]
    assert checks["version"]["stdout_bytes"] == len(
        f"servonaut 9.8.7{line_ending}".encode()
    )
    assert (
        checks["version"]["stdout_sha256"]
        == hashlib.sha256(f"servonaut 9.8.7{line_ending}".encode()).hexdigest()
    )
    assert checks["list_backups"]["stdout_bytes"] == len(
        f"No local backups yet.{line_ending}".encode()
    )
    assert (
        checks["list_backups"]["stdout_sha256"]
        == hashlib.sha256(f"No local backups yet.{line_ending}".encode()).hexdigest()
    )
    assert "authentication-failed" not in result.transcript.read_text(encoding="utf-8")
    assert checks["mcp_protocol"] == {
        "ok": True,
        "exit_code": 0,
        "elapsed_ms": 7,
        "stdout_bytes": 42,
        "stdout_sha256": "1" * 64,
        "stderr_bytes": 0,
        "stderr_sha256": "0" * 64,
    }


@pytest.mark.parametrize(
    ("output_name", "invalid_output", "expected_error"),
    [
        ("version", "servonaut 9.8.7", "version output does not match the artifact"),
        ("version", "servonaut 9.8.7\r", "version output does not match the artifact"),
        (
            "version",
            "servonaut 9.8.7\n\n",
            "version output does not match the artifact",
        ),
        (
            "version",
            "servonaut 9.8\r.7\n",
            "version output does not match the artifact",
        ),
        ("version", "servonaut 9.8.7 \n", "version output does not match the artifact"),
        (
            "version",
            "servonaut 9.8.7 extra\n",
            "version output does not match the artifact",
        ),
        ("backups", "No local backups yet.", "isolated backup list is not empty"),
        ("backups", "No local backups yet.\r", "isolated backup list is not empty"),
        ("backups", "No local backups yet.\n\n", "isolated backup list is not empty"),
        ("backups", "No local back\rups yet.\n", "isolated backup list is not empty"),
        ("backups", "No local backups yet. \n", "isolated backup list is not empty"),
        (
            "backups",
            "No local backups yet. extra\n",
            "isolated backup list is not empty",
        ),
    ],
    ids=(
        "version-missing-newline",
        "version-bare-cr",
        "version-double-line",
        "version-embedded-cr",
        "version-trailing-space",
        "version-extra-text",
        "backups-missing-newline",
        "backups-bare-cr",
        "backups-double-line",
        "backups-embedded-cr",
        "backups-trailing-space",
        "backups-extra-text",
    ),
)
def test_run_smoke_rejects_noncanonical_public_output_lines(
    tmp_path: Path, output_name: str, invalid_output: str, expected_error: str
) -> None:
    payload_kwargs = (
        {"version_stdout": invalid_output}
        if output_name == "version"
        else {"backups_stdout": invalid_output}
    )
    root, executable = _payload(tmp_path, **payload_kwargs)

    with pytest.raises(ArtifactSmokeError, match=f"^{expected_error}$"):
        run_smoke(
            SmokeRequest(root, executable, "9.8.7", tmp_path / "evidence"),
            load_smoke_policy(POLICY),
        )


def test_run_smoke_rejects_marker_helper_alias(tmp_path: Path) -> None:
    root, executable = _payload(tmp_path)
    marker_path = root / "servonaut-runtime.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["console_helper"] = "../servonaut"
    marker_path.write_text(json.dumps(marker), encoding="utf-8")

    with pytest.raises(ArtifactSmokeError, match="helper"):
        run_smoke(
            SmokeRequest(root, executable, "9.8.7", tmp_path / "evidence"),
            load_smoke_policy(POLICY),
        )


def test_run_smoke_rejects_boolean_marker_schema_version(tmp_path: Path) -> None:
    root, executable = _payload(tmp_path)
    marker_path = root / "servonaut-runtime.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema_version"] = True
    marker_path.write_text(json.dumps(marker), encoding="utf-8")

    with pytest.raises(ArtifactSmokeError, match="schema"):
        run_smoke(
            SmokeRequest(root, executable, "9.8.7", tmp_path / "evidence"),
            load_smoke_policy(POLICY),
        )


def test_run_smoke_rejects_noncanonical_executable(tmp_path: Path) -> None:
    root, executable = _payload(tmp_path)
    alias = root / "alias"
    alias.symlink_to(executable.name)

    with pytest.raises(ArtifactSmokeError, match="marker|canonical"):
        run_smoke(
            SmokeRequest(root, alias, "9.8.7", tmp_path / "evidence"),
            load_smoke_policy(POLICY),
        )


def test_run_smoke_rejects_evidence_inside_payload(tmp_path: Path) -> None:
    root, executable = _payload(tmp_path)
    evidence = root / "evidence"

    with pytest.raises(ArtifactSmokeError, match="outside the payload"):
        run_smoke(
            SmokeRequest(root, executable, "9.8.7", evidence),
            load_smoke_policy(POLICY),
        )

    assert not evidence.exists()


def test_run_smoke_rejects_symlinked_evidence_parent(tmp_path: Path) -> None:
    root, executable = _payload(tmp_path)
    actual_parent = tmp_path / "actual-evidence"
    actual_parent.mkdir()
    alias = tmp_path / "evidence-alias"
    alias.symlink_to(actual_parent, target_is_directory=True)
    evidence = alias / "results"

    with pytest.raises(ArtifactSmokeError, match="canonical"):
        run_smoke(
            SmokeRequest(root, executable, "9.8.7", evidence),
            load_smoke_policy(POLICY),
        )

    assert not (actual_parent / "results").exists()


def test_transcript_cap_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, executable = _payload(tmp_path)
    policy = replace(load_smoke_policy(POLICY), transcript_max_bytes=1)
    monkeypatch.setattr(
        "scripts.standalone_cli.smoke_artifact.run_mcp_smoke",
        lambda **_kwargs: MCPCheck(12, True, 0, "0" * 64, 0, 1, 0, "0" * 64),
    )

    with pytest.raises(ArtifactSmokeError, match="transcript"):
        run_smoke(
            SmokeRequest(root, executable, "9.8.7", tmp_path / "evidence"), policy
        )


def test_process_result_transcript_is_content_free() -> None:
    result = _ProcessResult(0, 4, b"sensitive stdout", b"sensitive stderr").public()

    assert not hasattr(result, "stdout")
    assert result.stdout_bytes == len(b"sensitive stdout")


def _selftest_result(payload: dict[str, object], exit_code: int = 0) -> _ProcessResult:
    stdout = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    return _ProcessResult(exit_code, 1, stdout, b"")


def _selftest_success_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "ok": True,
        "check": "tui",
        "runtime": {"kind": "frozen-cli", "marker": True},
        "tui": {"main": True, "sidebar": True, "adjacent": True, "exited": True},
        "fixtures": {"config": True, "cache": True},
        "diagnostics": {
            "metadata": True,
            "sdk": True,
            "crypto": True,
            "ca": True,
            "keyring": True,
        },
    }


def test_selftest_success_rejects_boolean_schema_version() -> None:
    payload = _selftest_success_payload()
    payload["schema_version"] = True

    with pytest.raises(ArtifactSmokeError, match="schema"):
        _validate_selftest_success(_selftest_result(payload), load_smoke_policy(POLICY))


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("runtime", "marker"),
        ("tui", "main"),
        ("fixtures", "config"),
        ("diagnostics", "sdk"),
    ],
)
def test_selftest_success_rejects_numeric_boolean(section: str, field: str) -> None:
    payload = _selftest_success_payload()
    nested = payload[section]
    assert isinstance(nested, dict)
    nested[field] = 1

    with pytest.raises(ArtifactSmokeError, match="facts|fixtures|diagnostics"):
        _validate_selftest_success(_selftest_result(payload), load_smoke_policy(POLICY))


def test_selftest_failure_rejects_boolean_schema_version() -> None:
    payload = {"schema_version": True, "ok": False, "error": "authentication-failed"}

    with pytest.raises(ArtifactSmokeError, match="generically"):
        _validate_selftest_failure(
            _selftest_result(payload, exit_code=1), load_smoke_policy(POLICY), ()
        )


@pytest.mark.skipif(os.name == "nt", reason="a POSIX shell creates the descendant")
def test_bounded_process_timeout_stops_descendants_holding_output(
    tmp_path: Path,
) -> None:
    policy = load_smoke_policy(POLICY)
    late_write = tmp_path / "descendant-survived"
    script = f"(sleep 3; echo late > '{late_write}') & exec sleep 60"

    started = time.monotonic()
    with pytest.raises(ArtifactSmokeError, match="timed out"):
        run_bounded_process(
            ["/bin/sh", "-c", script],
            environment={"PATH": os.defpath},
            working_directory=tmp_path,
            timeout_seconds=1,
            output_limit=256,
            argv_max_count=policy.process_argv_max_count,
        )
    elapsed = time.monotonic() - started
    time.sleep(3)

    assert elapsed < 2.5
    assert not late_write.exists()


_MCP_TIMEOUTS = MCPTimeouts(10, 10, 5, 1024, 4096)
_FAKE_MCP_SERVER = """\
import json, os, subprocess, sys, time
MODE = {mode!r}
if MODE == "pollute":
    sys.stdout.write("server banner\\n")
    sys.stdout.flush()
if MODE == "environment":
    with open("child-environment.json", "w", encoding="utf-8") as handle:
        json.dump(sorted(os.environ), handle)
if MODE == "descendant":
    subprocess.Popen(
        [sys.executable, "-c", "import pathlib, time; time.sleep(3); "
         "pathlib.Path('descendant-survived').write_text('late')"]
    )
RESULTS = {{
    "initialize": lambda params: {{
        "protocolVersion": params["protocolVersion"],
        "capabilities": {{"tools": {{}}}},
        "serverInfo": {{"name": "fixture", "version": "1"}},
    }},
    "tools/list": lambda params: {{
        "tools": [{{"name": "whoami", "inputSchema": {{"type": "object"}}}}],
        "padding": "x" * (4096 if MODE == "oversized" else 0),
    }},
    "tools/call": lambda params: {{
        "content": [{{"type": "text", "text": json.dumps({{"logged_in": False}})}}],
        "isError": False,
    }},
}}
for line in sys.stdin:
    request = json.loads(line)
    if "id" not in request:
        continue
    result = RESULTS[request["method"]](request.get("params", {{}}))
    response = {{"jsonrpc": "2.0", "id": request["id"], "result": result}}
    sys.stdout.write(json.dumps(response) + "\\n")
    sys.stdout.flush()
sys.stderr.write("x" * (8192 if MODE == "stderr-flood" else 16))
sys.stderr.flush()
if MODE == "hang":
    time.sleep(30)
raise SystemExit(3 if MODE == "crash" else 0)
"""


def _fake_mcp_server(tmp_path: Path, mode: str) -> Path:
    server = tmp_path / f"mcp-{mode}"
    server.write_text(
        f"#!{sys.executable}\n" + _FAKE_MCP_SERVER.format(mode=mode),
        encoding="utf-8",
    )
    server.chmod(0o755)
    return server


def _run_fake_mcp(
    tmp_path: Path, mode: str, timeouts: MCPTimeouts = _MCP_TIMEOUTS
) -> MCPCheck:
    return run_mcp_smoke(
        command=_fake_mcp_server(tmp_path, mode),
        args=["--mcp"],
        environment={"PATH": os.defpath, "HOME": str(tmp_path)},
        working_directory=tmp_path,
        timeouts=timeouts,
    )


@pytest.mark.skipif(os.name == "nt", reason="the fixture server uses a shebang")
def test_mcp_smoke_records_a_conforming_session(tmp_path: Path) -> None:
    check = _run_fake_mcp(tmp_path, "ok")

    assert check.tool_count == 1
    assert check.whoami_logged_out is True
    assert check.exit_code == 0
    assert check.stdout_bytes > 0
    assert check.stderr_bytes == 16
    assert check.stderr_sha256 == hashlib.sha256(b"x" * 16).hexdigest()


@pytest.mark.skipif(os.name == "nt", reason="the fixture server uses a shebang")
@pytest.mark.parametrize(
    ("mode", "expected"),
    (
        ("pollute", "non-JSON-RPC line"),
        ("oversized", "frame limit"),
        ("crash", "non-zero status"),
        ("hang", "did not shut down in time"),
        ("stderr-flood", "stderr exceeds"),
    ),
)
def test_mcp_smoke_rejects_a_misbehaving_server(
    tmp_path: Path, mode: str, expected: str
) -> None:
    started = time.monotonic()

    with pytest.raises(MCPSmokeError, match=expected):
        _run_fake_mcp(tmp_path, mode)

    assert time.monotonic() - started < _MCP_TIMEOUTS.shutdown_seconds + 5


@pytest.mark.skipif(os.name == "nt", reason="the fixture server uses a shebang")
def test_mcp_smoke_gives_the_server_exactly_the_explicit_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", "/parent-home-must-not-pass")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "parent-secret-must-not-pass")

    _run_fake_mcp(tmp_path, "environment")

    names = json.loads((tmp_path / "child-environment.json").read_text("utf-8"))
    assert set(names) - {"LC_CTYPE"} == {"HOME", "PATH"}


@pytest.mark.skipif(os.name == "nt", reason="the fixture server uses a shebang")
def test_mcp_smoke_rejects_and_removes_a_descendant_holding_output(
    tmp_path: Path,
) -> None:
    with pytest.raises(MCPSmokeError, match="output did not close"):
        _run_fake_mcp(tmp_path, "descendant", MCPTimeouts(10, 10, 1, 1024, 4096))
    time.sleep(3.5)

    assert not (tmp_path / "descendant-survived").exists()


@pytest.mark.skipif(os.name == "nt", reason="the fixture server uses a shebang")
def test_mcp_smoke_interoperates_with_the_sdk_stdio_server(tmp_path: Path) -> None:
    server = tmp_path / "sdk-server"
    server.write_text(
        f"#!{sys.executable}\n"
        "import json, anyio\n"
        "import mcp.types as types\n"
        "from mcp.server.lowlevel import Server\n"
        "from mcp.server.stdio import stdio_server\n"
        "server = Server('fixture')\n"
        "@server.list_tools()\n"
        "async def list_tools():\n"
        "    return [types.Tool(name='whoami', inputSchema={'type': 'object'})]\n"
        "@server.call_tool()\n"
        "async def call_tool(name, arguments):\n"
        "    text = json.dumps({'logged_in': False})\n"
        "    return [types.TextContent(type='text', text=text)]\n"
        "async def main():\n"
        "    async with stdio_server() as (reader, writer):\n"
        "        options = server.create_initialization_options()\n"
        "        await server.run(reader, writer, options)\n"
        "anyio.run(main)\n",
        encoding="utf-8",
    )
    server.chmod(0o755)

    check = run_mcp_smoke(
        command=server,
        args=["--mcp"],
        environment={"PATH": os.defpath, "HOME": str(tmp_path)},
        working_directory=tmp_path,
        timeouts=MCPTimeouts(30, 30, 10, 1024 * 1024, 65536),
    )

    assert check.tool_count == 1
    assert check.exit_code == 0
