from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.standalone_cli.wheel_tools import (
    WheelToolError,
    WheelToolLimits,
    WheelToolRequest,
    _parse_lock_pins,
    _pump_stage_stream,
    _PumpState,
    _run_stage,
    _StageResult,
    _validate_build_report,
    _validate_direct_requirements,
    _validate_lock,
    load_wheel_tool_policy,
    prepare_wheel_tools,
    sanitized_environment,
    venv_python,
)

ROOT = Path(__file__).parents[2].resolve()
LOCK = ROOT / "packaging" / "standalone_cli" / "requirements" / "wheel-build-tools.txt"
DIRECT = LOCK.with_suffix(".in")
POLICY = ROOT / "packaging" / "standalone_cli" / "wheel-tools-policy.json"
LIMITS = load_wheel_tool_policy(POLICY).limits
ACTION = ROOT / ".github" / "actions" / "setup-standalone-cli" / "action.yml"


def _write_wheel(path: Path, version: str = "2.26.2") -> str:
    metadata = f"Metadata-Version: 2.4\nName: servonaut\nVersion: {version}\n\n"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"servonaut-{version}.dist-info/METADATA", metadata)
        archive.writestr("servonaut/__init__.py", "")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_report(report: Path, wheel: Path, wheel_hash: str) -> None:
    report.write_text(
        json.dumps(
            {
                "version": "1.0",
                "artifacts": [
                    {
                        "name": wheel.name,
                        "path": str(wheel),
                        "kind": "wheel",
                        "size": wheel.stat().st_size,
                        "hashes": {"sha256": wheel_hash},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_generated_lock_is_complete_hash_locked_wheel_closure() -> None:
    direct = _validate_direct_requirements(DIRECT, LIMITS.max_lock_bytes)
    pins = _validate_lock(LOCK, direct, LIMITS.max_lock_bytes)
    indexed = {pin.name: pin for pin in pins}

    assert set(indexed) == {
        "build",
        "colorama",
        "hatchling",
        "packaging",
        "pathspec",
        "pluggy",
        "pyproject-hooks",
        "tomlkit",
        "trove-classifiers",
    }
    assert indexed["build"].version == "1.6.1"
    assert indexed["hatchling"].version == "1.32.0"
    assert indexed["colorama"].marker == "os_name == 'nt'"
    assert all(pin.hashes for pin in pins)


def test_wheel_tool_policy_is_schema_valid() -> None:
    raw = json.loads(POLICY.read_text(encoding="utf-8"))
    schema = json.loads(
        POLICY.with_name("wheel-tools-policy.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(raw)

    policy = load_wheel_tool_policy(POLICY)

    assert (policy.python_major, policy.python_minor) == (3, 12)
    assert policy.limits.max_stdout_bytes == 16 * 1024 * 1024


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ({"schema_version": True}, "schema version"),
        ({"unknown": 1}, "unsupported or missing"),
        (
            {
                "limits": {
                    **json.loads(POLICY.read_text())["limits"],
                    "max_stdout_bytes": 1,
                }
            },
            "invalid limit",
        ),
    ],
)
def test_wheel_tool_policy_rejects_invalid_shapes(
    tmp_path: Path, replacement: dict[str, object], message: str
) -> None:
    raw = json.loads(POLICY.read_text(encoding="utf-8"))
    raw.update(replacement)
    candidate = tmp_path / "policy.json"
    candidate.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(WheelToolError, match=message):
        load_wheel_tool_policy(candidate)


def test_direct_requirements_are_the_version_authority(tmp_path: Path) -> None:
    direct = tmp_path / "tools.in"
    direct.write_text("build==1.2.3\nhatchling==4.5.6\n", encoding="utf-8")
    lock = tmp_path / "tools.txt"
    lock.write_text(
        "".join(
            (
                "--only-binary :all:\n",
                f"build==1.2.3 \\\n    --hash=sha256:{'a' * 64}\n",
                f"hatchling==4.5.6 \\\n    --hash=sha256:{'b' * 64}\n",
                f"packaging==7.8.9 \\\n    --hash=sha256:{'c' * 64}\n",
            )
        ),
        encoding="utf-8",
    )

    direct_pins = _validate_direct_requirements(direct, 4096)
    pins = _validate_lock(lock, direct_pins, 4096)

    assert {pin.version for pin in pins if pin.name in {"build", "hatchling"}} == {
        "1.2.3",
        "4.5.6",
    }


@pytest.mark.parametrize(
    "line",
    [
        "build>=1.6.1 --hash=sha256:" + "a" * 64,
        "--index-url https://example.invalid/simple",
        "build @ https://example.invalid/build.whl",
        "-r another-lock.txt",
    ],
)
def test_lock_parser_rejects_unpinned_or_external_inputs(line: str) -> None:
    with pytest.raises(WheelToolError, match="unsupported|closure"):
        _parse_lock_pins("--only-binary :all:\n" + line + "\n")


def test_sanitized_environment_drops_python_and_pip_controls_case_insensitively() -> (
    None
):
    source = {
        "PATH": "/tools",
        "SystemRoot": "C:\\Windows",
        "PyThOnPaTh": "/untrusted",
        "PYTHONPLATLIBDIR": "invalid",
        "pIp_InDeX_uRl": "https://example.invalid",
        "SERVONAUT_STANDALONE_OUTPUT_DIR": "/outside",
    }

    result = sanitized_environment(source)

    assert result == {
        "PATH": "/tools",
        "SystemRoot": "C:\\Windows",
        "PIP_CONFIG_FILE": os.devnull,
        "PYTHONNOUSERSITE": "1",
    }


def test_platform_native_venv_python_preserves_lexical_path(tmp_path: Path) -> None:
    posix = tmp_path / "posix" / "bin" / "python"
    windows = tmp_path / "windows" / "Scripts" / "python.exe"
    posix.parent.mkdir(parents=True)
    windows.parent.mkdir(parents=True)
    posix.write_bytes(b"")
    windows.write_bytes(b"")

    assert venv_python(tmp_path / "posix", "posix") == posix.absolute()
    assert venv_python(tmp_path / "windows", "nt") == windows.absolute()


def test_build_report_requires_one_matching_verified_wheel(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    wheel = wheel_dir / "servonaut-2.26.2-py3-none-any.whl"
    wheel_hash = _write_wheel(wheel)
    report = tmp_path / "report.json"
    _write_report(report, wheel, wheel_hash)

    actual_wheel, actual_hash = _validate_build_report(
        report, wheel_dir, "2.26.2", LIMITS
    )

    assert actual_wheel == wheel
    assert actual_hash == wheel_hash


def test_build_report_rejects_boolean_size(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    wheel = wheel_dir / "servonaut-2.26.2-py3-none-any.whl"
    wheel_hash = _write_wheel(wheel)
    report = tmp_path / "report.json"
    _write_report(report, wheel, wheel_hash)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["artifacts"][0]["size"] = True
    report.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(WheelToolError, match="does not match"):
        _validate_build_report(report, wheel_dir, "2.26.2", LIMITS)


def test_build_report_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    wheel = wheel_dir / "servonaut-2.26.2-py3-none-any.whl"
    _write_wheel(wheel)
    report = tmp_path / "report.json"
    report.write_text(
        '{"version":"1.0","version":"1.0","artifacts":[]}', encoding="utf-8"
    )

    with pytest.raises(WheelToolError, match="duplicate"):
        _validate_build_report(report, wheel_dir, "2.26.2", LIMITS)


def test_build_report_rejects_hash_or_identity_drift(
    tmp_path: Path,
) -> None:
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    wheel = wheel_dir / "servonaut-2.26.2-py3-none-any.whl"
    _write_wheel(wheel, version="9.9.9")
    report = tmp_path / "report.json"
    _write_report(report, wheel, "0" * 64)

    with pytest.raises(WheelToolError, match="hash"):
        _validate_build_report(report, wheel_dir, "2.26.2", LIMITS)


def test_build_report_rejects_noncanonical_wheel_name(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    wheel = wheel_dir / "alternate-2.26.2-py3-none-any.whl"
    wheel_hash = _write_wheel(wheel)
    report = tmp_path / "report.json"
    _write_report(report, wheel, wheel_hash)

    with pytest.raises(WheelToolError, match="artifact is invalid"):
        _validate_build_report(report, wheel_dir, "2.26.2", LIMITS)


def test_run_stage_keeps_child_output_in_private_logs(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()

    result = _run_stage(
        [
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ],
        {"PATH": ""},
        tmp_path,
        logs,
        "probe",
        True,
        LIMITS,
    )

    assert result.stdout == b"out\n"
    assert (logs / "probe.stdout.log").read_bytes() == b"out\n"
    assert (logs / "probe.stderr.log").read_bytes() == b"err\n"


@pytest.mark.parametrize(("fd", "log_name"), [(1, "stdout"), (2, "stderr")])
def test_run_stage_bounds_output_while_child_is_running(
    tmp_path: Path, fd: int, log_name: str
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    limits = replace(
        LIMITS,
        command_timeout_seconds=10,
        process_cleanup_timeout_seconds=2,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
    )

    started = time.monotonic()
    with pytest.raises(WheelToolError, match="exceeded its output limit"):
        _run_stage(
            [
                sys.executable,
                "-c",
                "import os,sys,time; os.write(int(sys.argv[1]), b'x' * 1025); time.sleep(30)",
                str(fd),
            ],
            {"PATH": ""},
            tmp_path,
            logs,
            "overflow",
            False,
            limits,
        )

    assert time.monotonic() - started < 5
    assert (logs / f"overflow.{log_name}.log").stat().st_size == 1024


def test_stage_pump_reads_only_one_byte_beyond_remaining_capacity() -> None:
    requested_sizes: list[int] = []

    class SpyStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            requested_sizes.append(size)
            return super().read(size)

    source = SpyStream(b"x" * 1025)
    destination = io.BytesIO()
    state = _PumpState()

    _pump_stage_stream(
        source,
        destination,
        1024,
        state,
        threading.Event(),
    )

    assert requested_sizes == [1025]
    assert state.exceeded is True
    assert destination.getvalue() == b"x" * 1024


def test_run_stage_times_out_and_reaps_its_child(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    pid_file = tmp_path / "pid"
    limits = replace(
        LIMITS,
        command_timeout_seconds=1,
        process_cleanup_timeout_seconds=2,
    )

    started = time.monotonic()
    with pytest.raises(WheelToolError, match="timed out"):
        _run_stage(
            [
                sys.executable,
                "-c",
                "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)",
                str(pid_file),
            ],
            {"PATH": ""},
            tmp_path,
            logs,
            "timeout",
            False,
            limits,
        )

    assert time.monotonic() - started < 5
    assert pid_file.is_file()
    if os.name != "nt":
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text(encoding="utf-8")), 0)


@pytest.mark.skipif(os.name == "nt", reason="POSIX signal interruption contract")
def test_run_stage_interruption_reaps_its_child(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    pid_file = tmp_path / "pid"
    limits = replace(LIMITS, process_cleanup_timeout_seconds=2)

    def interrupt_when_started() -> None:
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if pid_file.exists():
            os.kill(os.getpid(), signal.SIGINT)

    interrupter = threading.Thread(target=interrupt_when_started, daemon=True)
    interrupter.start()
    with pytest.raises(KeyboardInterrupt):
        _run_stage(
            [
                sys.executable,
                "-c",
                "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)",
                str(pid_file),
            ],
            {"PATH": ""},
            tmp_path,
            logs,
            "interrupted",
            False,
            limits,
        )
    interrupter.join(timeout=2)

    assert not interrupter.is_alive()
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text(encoding="utf-8")), 0)


def test_isolated_direct_script_bootstrap_ignores_pythonpath(tmp_path: Path) -> None:
    injected = tmp_path / "injected"
    injected.mkdir()
    marker = tmp_path / "sitecustomize-loaded"
    (injected / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('loaded')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(injected)

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts/standalone_cli/wheel_tools.py"),
            "--help",
        ],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0
    assert not marker.exists()


def test_prepare_builds_exact_argv_and_writes_only_bounded_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work_parent = tmp_path / "work"
    work_parent.mkdir()
    github_output = tmp_path / "github-output"
    github_output.write_text("", encoding="utf-8")
    calls: list[tuple[list[str], Path, str]] = []
    monkeypatch.setattr(
        "scripts.standalone_cli.wheel_tools._read_project_version",
        lambda _path, _maximum: "2.26.2",
    )

    def fake_stage(
        argv: list[str] | tuple[str, ...],
        _environment: object,
        cwd: Path,
        _logs: Path,
        label: str,
        _capture: bool,
        _limits: WheelToolLimits,
    ) -> _StageResult:
        arguments = list(argv)
        calls.append((arguments, cwd, label))
        if label == "selected-python":
            return _StageResult(b'{"major":3,"minor":12}\n')
        if label == "create-venv":
            python = Path(arguments[-1]) / (
                "Scripts/python.exe" if os.name == "nt" else "bin/python"
            )
            python.parent.mkdir(parents=True)
            python.write_bytes(b"")
        elif label == "venv-prefix":
            prefix = str(Path(arguments[0]).parents[1])
            return _StageResult(
                json.dumps({"major": 3, "minor": 12, "prefix": prefix}).encode()
            )
        elif label == "installed-tools":
            prefix = str(Path(arguments[0]).parents[1])
            count = 9 if os.name == "nt" else 8
            return _StageResult(
                json.dumps({"ok": True, "prefix": prefix, "count": count}).encode()
            )
        elif label == "build-wheel":
            wheel_dir = Path(arguments[arguments.index("--outdir") + 1])
            report = Path(arguments[arguments.index("--report") + 1])
            wheel = wheel_dir / "servonaut-2.26.2-py3-none-any.whl"
            wheel_hash = _write_wheel(wheel)
            _write_report(report, wheel, wheel_hash)
        return _StageResult(b"")

    result = prepare_wheel_tools(
        WheelToolRequest(
            Path(sys.executable).resolve(),
            ROOT,
            work_parent.resolve(),
            LOCK.resolve(),
            POLICY.resolve(),
            github_output.resolve(),
        ),
        run_stage=fake_stage,
    )

    install = next(argv for argv, _cwd, label in calls if label == "install-tools")
    build = next(argv for argv, _cwd, label in calls if label == "build-wheel")
    assert install[1:] == [
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
        str(LOCK.resolve()),
    ]
    assert build[1:5] == ["-m", "build", "--wheel", "--no-isolation"]
    assert build[-1] == str(ROOT)
    assert all(cwd != ROOT for _argv, cwd, _label in calls)
    assert result.python_path.parent.parent.name == "wheel-tool-venv"
    output_lines = github_output.read_text(encoding="utf-8").splitlines()
    assert {line.split("=", 1)[0] for line in output_lines} == {
        "python-path",
        "wheel-path",
        "wheel-sha256",
        "tool-lock-sha256",
    }


def test_prepare_failure_removes_only_its_new_owned_root(tmp_path: Path) -> None:
    work_parent = tmp_path / "work"
    work_parent.mkdir()
    foreign = work_parent / "keep"
    foreign.write_text("foreign", encoding="utf-8")

    def fail_stage(
        _argv: object,
        _environment: object,
        _cwd: Path,
        _logs: Path,
        label: str,
        _capture: bool,
        _limits: WheelToolLimits,
    ) -> _StageResult:
        if label == "selected-python":
            raise WheelToolError("probe failed")
        return _StageResult(b"")

    with pytest.raises(WheelToolError, match="probe failed"):
        prepare_wheel_tools(
            WheelToolRequest(
                Path(sys.executable).resolve(),
                ROOT,
                work_parent.resolve(),
                LOCK.resolve(),
                POLICY.resolve(),
            ),
            run_stage=fail_stage,
        )

    assert list(work_parent.iterdir()) == [foreign]
    assert foreign.read_text(encoding="utf-8") == "foreign"


def test_composite_action_has_no_global_path_or_unlocked_install() -> None:
    text = ACTION.read_text(encoding="utf-8")

    assert "GITHUB_PATH" not in text
    assert "pip install" not in text
    assert '"${SELECTED_PYTHON}" -I' in text
    assert (
        '--policy "${CHECKOUT_PATH}/packaging/standalone_cli/wheel-tools-policy.json"'
        in text
    )
    assert '--github-output "${GITHUB_OUTPUT}"' in text
    assert "set -euo pipefail" in text
    for name in ("python-path", "wheel-path", "wheel-sha256", "tool-lock-sha256"):
        assert f"  {name}:" in text


def test_private_work_root_is_mode_0700_after_success(tmp_path: Path) -> None:
    work_parent = tmp_path / "work"
    work_parent.mkdir()

    def stop_after_creation(
        _argv: object,
        _environment: object,
        cwd: Path,
        _logs: Path,
        _label: str,
        _capture: bool,
        _limits: WheelToolLimits,
    ) -> _StageResult:
        assert stat.S_IMODE(cwd.stat().st_mode) == 0o700
        raise WheelToolError("stop")

    with pytest.raises(WheelToolError, match="stop"):
        prepare_wheel_tools(
            WheelToolRequest(
                Path(sys.executable).resolve(),
                ROOT,
                work_parent.resolve(),
                LOCK.resolve(),
                POLICY.resolve(),
            ),
            run_stage=stop_after_creation,
        )
