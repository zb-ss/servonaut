"""Static contracts for standalone qualification workflow composition."""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.evidence_policy import load_evidence_policy
from scripts.standalone_cli.evidence_sanitize import (
    load_bounded_json,
    write_public_json,
)
from scripts.standalone_cli.wheel_tools import (
    WheelToolError,
    WheelToolRequest,
    _validate_request,
)

ROOT = Path(__file__).parents[2]
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github" / "workflows" / "standalone-cli.yml").read_text(
    encoding="utf-8"
)


def _workflow_step(name: str) -> str:
    marker = f"      - name: {name}\n"
    start = WORKFLOW.index(marker)
    end = WORKFLOW.find("\n      - name: ", start + len(marker))
    return WORKFLOW[start : len(WORKFLOW) if end == -1 else end]


def _ci_workflow_step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.index(marker)
    end = source.find("\n      - name: ", start + len(marker))
    return source[start : len(source) if end == -1 else end]


def _workflow_run_block(name: str) -> str:
    step = _workflow_step(name)
    marker = "        run: |\n"
    return textwrap.dedent(step.split(marker, 1)[1])


def _run_workflow_block(
    block: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", block],
        capture_output=True,
        check=False,
        env={"PATH": os.defpath, **environment},
        text=True,
    )


def _write_shell_stub(path: Path, script: str) -> Path:
    path.write_text(f"#!/bin/sh\n{script}", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_existing_ci_keeps_protected_contexts_and_one_312_suite() -> None:
    assert "name: test (${{ matrix.python-version }})" in CI
    assert 'python-version: ["3.10", "3.12", "3.13"]' in CI
    assert "if: matrix.python-version != '3.12'" in CI
    assert "if: matrix.python-version == '3.12'" in CI
    ordinary_test_section = CI.split("- name: Run tests with coverage", 1)[0]
    assert ordinary_test_section.count("python -m pytest --tb=short -q") == 1
    assert "feature/desktop/**" in CI
    native_runtime = _ci_workflow_step(CI, "Run native runtime tests")
    native_runtime_command = native_runtime.split("        run: >-\n", 1)[1]
    assert (
        "tests/packaging/test_standalone_artifact_filesystem_windows.py"
        in native_runtime_command
    )
    assert (
        "tests/packaging/test_standalone_sbom_normalize.py::"
        "test_native_windows_generation_normalizes_full_syft_file_component_path"
        in native_runtime_command
    )


def test_qualification_workflow_has_only_read_permission_and_native_matrix() -> None:
    assert "permissions:\n  contents: read" in WORKFLOW
    assert "pull_request_target" not in WORKFLOW
    assert "persist-credentials: false" in WORKFLOW
    assert "fail-fast: false" in WORKFLOW
    for target, runner, architecture in (
        ("linux-x64-ubuntu-22.04", "ubuntu-22.04", "x64"),
        ("windows-x64", "windows-2022", "x64"),
        ("macos-x64", "macos-15-intel", "x64"),
        ("macos-arm64", "macos-15", "arm64"),
    ):
        assert f"target: {target}" in WORKFLOW
        assert f"runner: {runner}" in WORKFLOW
        assert f"python-architecture: {architecture}" in WORKFLOW


def test_qualification_uses_separate_hash_locked_environment_and_final_gate() -> None:
    assert 'python -m pip install -e ".[test,mcp]"' in WORKFLOW
    assert "qualification-tools-${TARGET}.txt" in WORKFLOW
    assert "--isolated install" in WORKFLOW
    assert "--only-binary=:all: --require-hashes" in WORKFLOW
    assert "python -m pytest --tb=short -q" not in WORKFLOW
    assert "-m scripts.standalone_cli.ci_qualify" in WORKFLOW
    assert "continue-on-error: true" in WORKFLOW
    assert "Sanitize public qualification status" in WORKFLOW
    assert (
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
        in WORKFLOW
    )
    assert "retention-days: 1" in WORKFLOW
    assert "if-no-files-found: error" in WORKFLOW
    assert "include-hidden-files: false" in WORKFLOW
    assert "Require successful qualification" in WORKFLOW
    assert "SOURCE_DATE_EPOCH" in WORKFLOW
    assert 'git -C "${GITHUB_WORKSPACE}" show -s --format=%ct' in WORKFLOW
    assert "qualification-status.json" in WORKFLOW
    assert "warning-candidates.json" in WORKFLOW
    assert "missing-baseline-candidate.json" in WORKFLOW


def test_actions_are_pinned_to_full_commit_shas() -> None:
    action = (
        ROOT / ".github" / "actions" / "setup-standalone-cli" / "action.yml"
    ).read_text(encoding="utf-8")
    references = [
        line.split("uses:", 1)[1].strip()
        for source in (WORKFLOW, action)
        for line in source.splitlines()
        if line.lstrip(" -").startswith("uses:")
    ]

    assert references
    for reference in references:
        if reference.startswith("./"):
            continue
        assert re.fullmatch(
            r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+",
            reference,
        ), reference


def test_every_job_has_a_bounded_runtime() -> None:
    jobs = WORKFLOW.split("\njobs:\n", 1)[1]
    job_names = re.findall(r"^  ([a-z][a-z0-9-]*):$", jobs, flags=re.MULTILINE)
    timeouts = re.findall(r"^    timeout-minutes: ([0-9]+)$", jobs, flags=re.MULTILINE)

    assert job_names == ["contract", "qualify"]
    assert len(timeouts) == len(job_names)
    assert all(0 < int(value) <= 120 for value in timeouts)


def test_windows_diagnostic_uses_only_the_qualified_native_environment() -> None:
    qualification = _workflow_step("Prepare qualification environment")
    diagnostic = _workflow_step("Verify Windows PyInstaller diagnostics")

    assert "qualification-tools-${TARGET}.txt" in qualification
    assert "if: matrix.target == 'windows-x64'" in diagnostic
    assert "QUALIFIED_PYTHON" in diagnostic
    assert "QUALIFICATION_SETUP_ROOT" in diagnostic
    assert 'sys.platform != "win32"' in diagnostic
    assert "PyInstaller.compat import pywintypes" in diagnostic
    assert 'importlib.metadata.version("pyinstaller") != "6.22.3"' in diagnostic
    assert "PyInstaller.building.api import EXE" in diagnostic
    assert "PyInstaller.isolated._parent import SubprocessDiedError" in diagnostic
    assert "test_standalone_windows_pyinstaller_diagnostic.py" in diagnostic
    assert (
        '>"${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-preflight.log" 2>&1'
        in diagnostic
    )
    assert "PYTEST_CONFIG" in diagnostic
    assert 'pytest -c "${PYTEST_CONFIG}"' in diagnostic
    assert "--confcutdir=tests/packaging -q" in diagnostic
    assert "read_diagnostic_outcome" in diagnostic
    assert 'raw["schema_version"] != 2' in diagnostic
    assert '"checkpoint"' in diagnostic
    assert '"error_type"' in diagnostic
    assert "Windows PyInstaller diagnostic stage passed: preflight" in diagnostic
    assert "Windows PyInstaller diagnostic stage failed: preflight" in diagnostic
    assert "Windows PyInstaller diagnostic stage passed: ${stage}" in diagnostic
    assert "Windows PyInstaller diagnostic stage failed: ${stage}" in diagnostic
    assert "Windows PyInstaller diagnostic outcome: ${stage}: ${outcome}" in diagnostic
    assert "Windows PyInstaller diagnostic outcome unavailable: ${stage}" in diagnostic
    for stage in ("share-lock", "isolated-child", "hook-import", "python-library"):
        assert f"run_diagnostic_stage {stage}" in diagnostic
    assert "DIAGNOSTIC_FAILURE=0" in diagnostic
    assert "DIAGNOSTIC_FAILURE=1" in diagnostic
    assert (
        WORKFLOW.index(qualification)
        < WORKFLOW.index(diagnostic)
        < WORKFLOW.index(_workflow_step("Qualify standalone payload"))
    )


def _load_windows_diagnostic_fixture_nodes(
    *, assignments: frozenset[str], functions: frozenset[str]
) -> dict[str, object]:
    """Load selected, platform-neutral fixture nodes without its Windows-only skip."""
    fixture_tree = ast.parse(
        (
            ROOT
            / "tests"
            / "packaging"
            / "test_standalone_windows_pyinstaller_diagnostic.py"
        ).read_text(encoding="utf-8")
    )
    selected_nodes = [
        node
        for node in fixture_tree.body
        if (
            isinstance(node, ast.Import)
            and any(
                alias.name
                in {
                    "json",
                    "os",
                    "shutil",
                    "stat",
                    "subprocess",
                    "sys",
                    "threading",
                    "time",
                }
                for alias in node.names
            )
        )
        or (
            isinstance(node, ast.ImportFrom)
            and (
                node.module == "__future__"
                or (
                    node.module == "pathlib"
                    and any(alias.name == "Path" for alias in node.names)
                )
                or (
                    node.module == "collections.abc"
                    and any(alias.name == "Callable" for alias in node.names)
                )
                or (
                    node.module == "typing"
                    and any(alias.name == "BinaryIO" for alias in node.names)
                )
            )
        )
        or (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in assignments
        )
        or isinstance(node, ast.FunctionDef)
        and node.name in functions
    ]
    module = ast.Module(body=selected_nodes, type_ignores=[])
    namespace: dict[str, object] = {}
    exec(  # noqa: S102 - executes selected nodes from this repository fixture.
        compile(ast.fix_missing_locations(module), "<fixture>", "exec"),
        namespace,
    )
    return namespace


def _integer_frozenset_assignment(tree: ast.Module, name: str) -> frozenset[int]:
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    )
    assert isinstance(assignment.value, ast.Call)
    assert isinstance(assignment.value.func, ast.Name)
    assert assignment.value.func.id == "frozenset"
    assert len(assignment.value.args) == 1 and not assignment.value.keywords
    elements = assignment.value.args[0]
    assert isinstance(elements, ast.Set)
    assert all(
        isinstance(element, ast.Constant) and type(element.value) is int
        for element in elements.elts
    )
    return frozenset(element.value for element in elements.elts)


def _load_windows_observer_helpers() -> dict[str, object]:
    """Load the portable observer helpers from the Windows-only fixture."""
    return _load_windows_diagnostic_fixture_nodes(
        assignments=frozenset(
            {
                "_CHILD_STDERR_LIMIT_BYTES",
                "_CHILD_DEADLINE_SECONDS",
                "_CHILD_STOP_WAIT_SECONDS",
                "_CHECKPOINTS",
                "_ERROR_TYPE_PAIRS",
                "_ERROR_TYPES",
                "_CHILD_CHECKPOINTS",
            }
        ),
        functions=frozenset(
            {
                "_classify_exception_type",
                "_unique_json_object",
                "_read_child_observer",
                "_pump_child_stderr",
                "_stop_owned_child",
                "_startup_checkpoint",
                "_run_observed_child",
                "_select_diagnostic_observation",
            }
        ),
    )


def test_windows_executable_fixture_copy_is_fresh_and_writable(
    tmp_path: Path,
) -> None:
    """Execute the native fixture copy against a synthetic read-only source."""
    namespace = _load_windows_diagnostic_fixture_nodes(
        assignments=frozenset(),
        functions=frozenset({"_copy_writable_fixture"}),
    )
    copy_fixture = namespace["_copy_writable_fixture"]
    assert callable(copy_fixture)
    source = tmp_path / "read-only-python.exe"
    destination = tmp_path / "fixture-python.exe"
    payload = b"MZ\x00controlled executable fixture"
    source.write_bytes(payload)
    source.chmod(stat.S_IREAD)
    try:
        result = copy_fixture(source, destination)
        assert result == destination
        assert destination.read_bytes() == payload
        assert not destination.is_symlink()
        assert stat.S_ISREG(destination.lstat().st_mode)
        assert destination.stat().st_mode & stat.S_IWUSR
        assert not source.stat().st_mode & stat.S_IWUSR
    finally:
        source.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_windows_copied_spec_child_receives_an_owned_userprofile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Execute the fixture's copied-spec launch preparation with a captured child."""
    source_spec = ROOT / "packaging" / "standalone_cli" / "servonaut_cli.spec"
    source_notice_config = (
        ROOT / "packaging" / "standalone_cli" / "embedded-notices.json"
    )
    caller_profile = "private-caller-profile-canary"
    child_path = "controlled-child-path"
    child_system_root = "controlled-system-root"
    outcome_root = tmp_path / "outcomes"
    outcome_root.mkdir()
    monkeypatch.setenv("USERPROFILE", caller_profile)
    monkeypatch.setenv("PATH", child_path)
    monkeypatch.setenv("SystemRoot", child_system_root)

    namespace = _load_windows_diagnostic_fixture_nodes(
        assignments=frozenset({"_OUTCOME_ROOT_VARIABLE"}),
        functions=frozenset(
            {"_write_copied_spec_environment", "_run_copied_spec_child"}
        ),
    )
    namespace["_SPEC_SOURCE"] = source_spec
    namespace["_EMBEDDED_NOTICE_CONFIG_SOURCE"] = source_notice_config
    write_environment = namespace["_write_copied_spec_environment"]
    run_child = namespace["_run_copied_spec_child"]
    assert callable(write_environment)
    assert callable(run_child)

    home_directory = tmp_path / "home"
    assert not home_directory.exists()
    script, environment = write_environment(tmp_path)
    environment_before = dict(environment)
    canonical_root = tmp_path.resolve(strict=True)
    canonical_home = home_directory.resolve(strict=True)
    assert canonical_home.parent == canonical_root
    if os.name == "posix":
        assert home_directory.lstat().st_mode & 0o777 == 0o700
    assert not home_directory.is_symlink()
    assert environment["USERPROFILE"] == str(canonical_home)
    assert caller_profile not in environment.values()
    serialized_environment = json.loads(environment["DIAGNOSTIC_ENV"])
    assert serialized_environment == {
        name: value for name, value in environment.items() if name != "DIAGNOSTIC_ENV"
    }
    copied_spec = tmp_path / "spec" / "servonaut_cli.spec"
    copied_notice_config = tmp_path / "spec" / "embedded-notices.json"
    assert copied_spec.read_bytes() == source_spec.read_bytes()
    assert copied_notice_config.read_bytes() == source_notice_config.read_bytes()
    assert copied_spec.is_file() and not copied_spec.is_symlink()
    assert copied_notice_config.is_file() and not copied_notice_config.is_symlink()

    metadata_directory = (tmp_path / "output" / "build-metadata").resolve(strict=True)
    runtime_notice_source = Path(
        environment["SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE"]
    )
    expected_runtime_notice = (
        metadata_directory / "runtime-notice" / "CPython-LICENSE.txt"
    )
    assert runtime_notice_source == expected_runtime_notice.resolve(strict=True)
    assert runtime_notice_source.is_file() and not runtime_notice_source.is_symlink()
    assert stat.S_ISREG(runtime_notice_source.lstat().st_mode)
    assert runtime_notice_source.stat().st_size > 0
    assert runtime_notice_source.parent.parent == metadata_directory
    assert runtime_notice_source.parent.is_dir()
    assert not runtime_notice_source.parent.is_symlink()

    third_party_root = Path(
        environment["SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT"]
    )
    expected_third_party_root = metadata_directory / "third-party-notices"
    assert third_party_root == expected_third_party_root.resolve(strict=True)
    assert third_party_root.is_dir() and not third_party_root.is_symlink()
    assert stat.S_ISDIR(third_party_root.lstat().st_mode)
    assert third_party_root.parent == metadata_directory
    configured_basenames = sorted(
        Path(notice["payload_path"]).name
        for notice in json.loads(copied_notice_config.read_text(encoding="utf-8"))[
            "notices"
        ]
    )
    entries = sorted(third_party_root.iterdir(), key=lambda entry: entry.name)
    assert [entry.name for entry in entries] == configured_basenames
    assert len(entries) == 5
    for entry in entries:
        assert entry.parent == third_party_root
        assert entry.is_file() and not entry.is_symlink()
        assert stat.S_ISREG(entry.lstat().st_mode)
        assert entry.stat().st_size > 0
        assert entry.stat().st_nlink == 1
    assert (
        serialized_environment["SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE"]
        == environment["SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE"]
    )
    assert (
        serialized_environment["SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT"]
        == environment["SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT"]
    )
    assert not (metadata_directory / "resolved" / "runtime-notice.json").exists()
    assert not (metadata_directory / "resolved" / "third-party-notices.json").exists()

    script_source = script.read_text(encoding="utf-8")
    compile(script_source, str(script), "exec")
    generated_tree = ast.parse(script_source)
    assert _integer_frozenset_assignment(
        generated_tree, "_PYINSTALLER_ACCESS_WINERRORS"
    ) == frozenset({5, 32, 110})
    assert "cause.winerror not in _PYINSTALLER_ACCESS_WINERRORS" in script_source
    generated_exe_class = next(
        node
        for node in ast.walk(generated_tree)
        if isinstance(node, ast.ClassDef) and node.name == "EXE"
    )

    class ControlledPyWinError(Exception):
        def __init__(self, winerror: object) -> None:
            self.winerror = winerror

    class DerivedPyWinError(ControlledPyWinError):
        pass

    class ControlledPyWinTypes:
        error = ControlledPyWinError

    class ControlledWinResource:
        @staticmethod
        def remove_all_resources(path: str) -> None:
            raise AssertionError(f"unexpected direct resource call for {path}")

    generated_captured: dict[str, object] = {}
    generated_cause: BaseException = ControlledPyWinError(32)

    class ControlledPyInstallerExe:
        @staticmethod
        def _retry_operation(
            operation: object,
            *arguments: object,
            max_attempts: int,
        ) -> None:
            generated_captured["operation"] = operation
            generated_captured["arguments"] = arguments
            generated_captured["max_attempts"] = max_attempts
            error = RuntimeError("controlled generated-child failure")
            generated_captured["error"] = error
            raise error from generated_cause

    generated_namespace: dict[str, object] = {
        "PyInstallerEXE": ControlledPyInstallerExe,
        "pyinstaller_winresource": ControlledWinResource,
        "pywintypes": ControlledPyWinTypes,
        "state": {"current": "controlled"},
        "write_observer": lambda *_args: None,
        "locked": tmp_path / "controlled-generated.exe",
    }
    generated_contract = ast.Module(
        body=[
            next(
                node
                for node in generated_tree.body
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and target.id == "_PYINSTALLER_ACCESS_WINERRORS"
                    for target in node.targets
                )
            ),
            generated_exe_class,
        ],
        type_ignores=[],
    )
    exec(  # noqa: S102 - executes selected nodes from the generated test fixture.
        compile(
            ast.fix_missing_locations(generated_contract), "<generated-child>", "exec"
        ),
        generated_namespace,
    )
    generated_exe = generated_namespace["EXE"]
    assert isinstance(generated_exe, type)
    generated_locked = generated_namespace["locked"]
    assert isinstance(generated_locked, Path)
    generated_expected_capture = {
        "operation": ControlledWinResource.remove_all_resources,
        "arguments": (str(generated_locked),),
        "max_attempts": 1,
    }
    for generated_winerror in (5, 32, 110):
        generated_captured.clear()
        generated_cause = ControlledPyWinError(generated_winerror)
        with pytest.raises(RuntimeError) as raised:
            generated_exe()
        assert raised.value is generated_captured.pop("error")
        assert BaseException.__cause__.__get__(raised.value) is generated_cause
        assert generated_captured == generated_expected_capture

    class DerivedInt(int):
        pass

    for generated_cause in (
        DerivedPyWinError(32),
        ControlledPyWinError(True),
        ControlledPyWinError(DerivedInt(32)),
        *(ControlledPyWinError(value) for value in (4, 31, 33, 111)),
    ):
        generated_captured.clear()
        with pytest.raises(SystemExit) as raised:
            generated_exe()
        assert raised.value.code == 202
        retry_error = generated_captured.pop("error")
        assert isinstance(retry_error, RuntimeError)
        assert BaseException.__cause__.__get__(retry_error) is generated_cause
        assert generated_captured == generated_expected_capture
    analysis_class = next(
        node
        for node in ast.walk(generated_tree)
        if isinstance(node, ast.ClassDef) and node.name == "Analysis"
    )
    analysis_init = next(
        node
        for node in analysis_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    )
    assert any(
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Attribute)
        and isinstance(statement.targets[0].value, ast.Name)
        and statement.targets[0].value.id == "self"
        and statement.targets[0].attr == "datas"
        and isinstance(statement.value, ast.Subscript)
        and isinstance(statement.value.value, ast.Name)
        and statement.value.value.id == "kwargs"
        and isinstance(statement.value.slice, ast.Constant)
        and statement.value.slice.value == "datas"
        for statement in analysis_init.body
    )
    fixture_tree = ast.parse(
        (
            ROOT
            / "tests"
            / "packaging"
            / "test_standalone_windows_pyinstaller_diagnostic.py"
        ).read_text(encoding="utf-8")
    )
    fixture_constructor = next(
        node
        for node in fixture_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_write_copied_spec_environment"
    )
    assert not any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        for node in ast.walk(fixture_constructor)
    )

    monkeypatch.setenv(str(namespace["_OUTCOME_ROOT_VARIABLE"]), str(outcome_root))
    captured: dict[str, object] = {}
    checkpoints: list[str] = []

    def capture_child(argv: list[str], **kwargs: object) -> tuple[int, str, str]:
        captured["argv"] = argv
        captured.update(kwargs)
        return 1, "child-spec-analysis", "system-exit"

    namespace["_run_observed_child"] = capture_child
    result = run_child(
        tmp_path,
        script,
        environment,
        "isolated-child",
        "isolated-child",
        set_checkpoint=checkpoints.append,
    )

    observer_path = outcome_root / "windows-pyinstaller-child-isolated-child.json"
    stderr_path = outcome_root / "windows-pyinstaller-child-isolated-child.stderr"
    expected_environment = {
        "PATH": child_path,
        "SystemRoot": child_system_root,
        "DIAGNOSTIC_CLASS": "isolated-child",
        "DIAGNOSTIC_OBSERVER": str(observer_path),
        **environment_before,
    }
    assert result == (1, "child-spec-analysis", "system-exit")
    assert checkpoints == ["parent-before-child-launch"]
    assert captured == {
        "argv": [sys.executable, str(script)],
        "cwd": tmp_path,
        "environment": expected_environment,
        "observer_path": observer_path,
        "stderr_path": stderr_path,
        "set_checkpoint": checkpoints.append,
    }
    assert environment == environment_before


def test_windows_share_lock_fixture_uses_pyinstaller_resource_removal() -> None:
    """Keep both fixture paths on the pinned PyInstaller retry operation."""
    fixture_path = (
        ROOT
        / "tests"
        / "packaging"
        / "test_standalone_windows_pyinstaller_diagnostic.py"
    )
    fixture_source = fixture_path.read_text(encoding="utf-8")
    fixture_tree = ast.parse(fixture_source)
    functions = {
        node.name: ast.get_source_segment(fixture_source, node)
        for node in fixture_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"_assert_share_lock_error", "_write_copied_spec_environment"}
    }
    assert set(functions) == {
        "_assert_share_lock_error",
        "_write_copied_spec_environment",
    }
    for function_source in functions.values():
        assert function_source is not None
        assert "remove_all_resources" in function_source
        assert "BeginUpdateResource(" not in function_source

    access_winerrors = _integer_frozenset_assignment(
        fixture_tree, "_PYINSTALLER_ACCESS_WINERRORS"
    )
    spec_tree = ast.parse(
        (ROOT / "packaging" / "standalone_cli" / "servonaut_cli.spec").read_text(
            encoding="utf-8"
        )
    )
    assert access_winerrors == frozenset({5, 32, 110})
    assert access_winerrors == _integer_frozenset_assignment(
        spec_tree, "_DIAGNOSTIC_ACCESS_WINERRORS"
    )

    class ControlledWinError(Exception):
        def __init__(self, winerror: object) -> None:
            self.winerror = winerror

    class DerivedWinError(ControlledWinError):
        pass

    class ControlledPyWinTypes:
        error = ControlledWinError

    def controlled_remove_all_resources(path: str) -> None:
        raise AssertionError(f"unexpected direct resource call for {path}")

    captured: dict[str, object] = {}
    current_winerror: object = 32
    current_error_type: type[ControlledWinError] = ControlledWinError

    class ControlledExe:
        @staticmethod
        def _retry_operation(
            operation: object, *arguments: object, max_attempts: int
        ) -> None:
            captured["operation"] = operation
            captured["arguments"] = arguments
            captured["max_attempts"] = max_attempts
            error = RuntimeError("controlled retry failure")
            captured["error"] = error
            raise error from current_error_type(current_winerror)

    class ControlledWinResource:
        remove_all_resources = staticmethod(controlled_remove_all_resources)

    namespace = _load_windows_diagnostic_fixture_nodes(
        assignments=frozenset({"_PYINSTALLER_ACCESS_WINERRORS"}),
        functions=frozenset({"_assert_share_lock_error"}),
    )
    namespace.update(
        {
            "pytest": pytest,
            "EXE": ControlledExe,
            "_winresource": ControlledWinResource,
            "pywintypes": ControlledPyWinTypes,
        }
    )
    assert_share_lock_error = namespace["_assert_share_lock_error"]
    assert callable(assert_share_lock_error)
    executable = fixture_path.parent / "controlled.exe"
    expected_checkpoints = [
        "outer-before-resource-call",
        "outer-before-cause-type",
        "outer-before-winerror-type",
        "outer-before-winerror-value",
    ]
    for current_winerror in sorted(access_winerrors):
        captured.clear()
        checkpoints: list[str] = []
        error = assert_share_lock_error(executable, checkpoints.append)

        assert error is captured.pop("error")
        assert captured == {
            "operation": controlled_remove_all_resources,
            "arguments": (str(executable),),
            "max_attempts": 1,
        }
        assert checkpoints == expected_checkpoints

    class DerivedInt(int):
        pass

    for current_winerror in (True, DerivedInt(32), 4, 31, 33, 111):
        checkpoints = []
        with pytest.raises(AssertionError):
            assert_share_lock_error(executable, checkpoints.append)
        if type(current_winerror) is int:
            assert checkpoints == expected_checkpoints
        else:
            assert checkpoints == expected_checkpoints[:-1]

    current_winerror = 32
    current_error_type = DerivedWinError
    checkpoints = []
    with pytest.raises(AssertionError):
        assert_share_lock_error(executable, checkpoints.append)
    assert checkpoints == expected_checkpoints[:-2]


def test_windows_outcome_classifier_matches_the_copied_spec_exit_protocol() -> None:
    """Execute the fixture classifier body against the spec's closed code space."""
    spec_tree = ast.parse(
        (ROOT / "packaging" / "standalone_cli" / "servonaut_cli.spec").read_text(
            encoding="utf-8"
        )
    )
    spec_constants = {
        target.id: node.value.value
        for node in spec_tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance((target := node.targets[0]), ast.Name)
        and isinstance(node.value, ast.Constant)
        and type(node.value.value) is int
    }
    phases = {
        value
        for name, value in spec_constants.items()
        if name.startswith("_DIAGNOSTIC_PHASE_")
    }
    categories = {
        value
        for name, value in spec_constants.items()
        if name.startswith("_DIAGNOSTIC_CATEGORY_")
    }
    assert phases == set(range(7))
    assert categories == set(range(9))
    expected_codes = frozenset(
        spec_constants["_DIAGNOSTIC_EXIT_BASE"] + (phase * 16) + category
        for phase in phases
        for category in categories
    )

    required_assignments = {
        "_DIAGNOSTIC_EXIT_BASE",
        "_DIAGNOSTIC_PHASE_COUNT",
        "_DIAGNOSTIC_CATEGORY_COUNT",
        "_STAGE_EXPECTED_EXIT_CODES",
        "_KNOWN_DIAGNOSTIC_EXIT_CODES",
        "_COPIED_SPEC_PREFLIGHT",
        "_COPIED_SPEC_GENERIC_FAILURE",
        "_EXPECTED_CLASSIFIER",
        "_OTHER_KNOWN_CLASSIFIER",
        "_UNEXPECTED_CHILD_EXIT",
    }
    namespace = _load_windows_diagnostic_fixture_nodes(
        assignments=frozenset(required_assignments),
        functions=frozenset({"_classify_child_outcome"}),
    )

    known_codes = namespace["_KNOWN_DIAGNOSTIC_EXIT_CODES"]
    classifier = namespace["_classify_child_outcome"]
    stage_codes = namespace["_STAGE_EXPECTED_EXIT_CODES"]
    assert known_codes == expected_codes
    assert isinstance(stage_codes, dict)
    assert callable(classifier)
    for stage, expected in stage_codes.items():
        assert isinstance(stage, str) and isinstance(expected, int)
        assert classifier(stage, expected) == "expected-classifier"
        assert classifier(stage, 64) == "copied-spec-preflight"
        assert classifier(stage, 1) == "copied-spec-generic-failure"
        other_known = next(
            code for code in sorted(expected_codes) if code not in {64, expected}
        )
        assert classifier(stage, other_known) == "other-known-classifier"
        assert classifier(stage, 255) == "unexpected-child-exit"


def test_windows_outcome_writer_records_only_the_closed_private_schema(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exercise the Windows-only outcome writer with a controlled local root."""
    outcome_root = tmp_path / "outcomes"
    outcome_root.mkdir()
    namespace = _load_windows_diagnostic_fixture_nodes(
        assignments=frozenset(
            {
                "_OUTCOME_ROOT_VARIABLE",
                "_OUTCOME_SCHEMA_VERSION",
                "_FIXTURE_SETUP_FAILED",
                "_COPIED_SPEC_PREFLIGHT",
                "_COPIED_SPEC_GENERIC_FAILURE",
                "_EXPECTED_CLASSIFIER",
                "_OTHER_KNOWN_CLASSIFIER",
                "_UNEXPECTED_CHILD_EXIT",
                "_STAGE_EXPECTED_EXIT_CODES",
                "_CHECKPOINTS",
                "_ERROR_TYPE_PAIRS",
                "_ERROR_TYPES",
            }
        ),
        functions=frozenset({"_write_diagnostic_outcome"}),
    )
    writer = namespace["_write_diagnostic_outcome"]
    assert callable(writer)
    destination = outcome_root / "windows-pyinstaller-outcome-share-lock.json"

    monkeypatch.delenv("QUALIFICATION_SETUP_ROOT", raising=False)
    writer("share-lock", "expected-classifier", "outer-complete", "none")
    assert not destination.exists()

    monkeypatch.setenv("QUALIFICATION_SETUP_ROOT", str(outcome_root))
    writer("share-lock", "expected-classifier", "outer-complete", "none")
    assert destination.is_file()
    assert not destination.is_symlink()
    assert destination.relative_to(outcome_root).as_posix() == (
        "windows-pyinstaller-outcome-share-lock.json"
    )
    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "schema_version": 2,
        "stage": "share-lock",
        "outcome": "expected-classifier",
        "checkpoint": "outer-complete",
        "error_type": "none",
    }
    with pytest.raises(FileExistsError):
        writer("share-lock", "expected-classifier", "outer-complete", "none")


def test_windows_observer_type_and_precedence_contracts_are_exact() -> None:
    """Exercise the fixture's privacy-safe type map and latched precedence."""
    helpers = _load_windows_observer_helpers()
    classify = helpers["_classify_exception_type"]
    select = helpers["_select_diagnostic_observation"]
    assert callable(classify)
    assert callable(select)

    expected_types = (
        (OSError(), "os-error"),
        (FileNotFoundError(), "file-not-found"),
        (FileExistsError(), "file-exists"),
        (PermissionError(), "permission-error"),
        (NotADirectoryError(), "not-a-directory"),
        (IsADirectoryError(), "is-a-directory"),
        (ImportError(), "import-error"),
        (ModuleNotFoundError(), "module-not-found"),
        (AttributeError(), "attribute-error"),
        (TypeError(), "type-error"),
        (ValueError(), "value-error"),
        (RuntimeError(), "runtime-error"),
        (AssertionError(), "assertion-error"),
        (SystemExit(), "system-exit"),
    )
    for error, token in expected_types:
        assert classify(error) == token

    class DerivedRuntimeError(RuntimeError):
        pass

    assert classify(DerivedRuntimeError()) == "other"
    assert select(
        cleanup_failure=("outer-before-unlink", "os-error"),
        child_observation=("child-spec-analysis", "runtime-error"),
        primary_failure=("parent-before-process-create", "permission-error"),
        success_checkpoint="outer-complete",
    ) == ("outer-before-unlink", "os-error")
    assert select(
        cleanup_failure=None,
        child_observation=("child-spec-analysis", "runtime-error"),
        primary_failure=("parent-before-process-create", "permission-error"),
        success_checkpoint="outer-complete",
    ) == ("child-spec-analysis", "runtime-error")
    assert select(
        cleanup_failure=None,
        child_observation=None,
        primary_failure=("parent-before-process-create", "permission-error"),
        success_checkpoint="outer-complete",
    ) == ("parent-before-process-create", "permission-error")


def test_windows_observer_reader_tokens_match_the_fixture() -> None:
    """Keep the workflow's closed public reader vocabulary in lockstep."""
    helpers = _load_windows_observer_helpers()
    assert helpers["_CHECKPOINTS"] == frozenset(_WINDOWS_DIAGNOSTIC_CHECKPOINTS)
    assert helpers["_ERROR_TYPES"] == frozenset(_WINDOWS_DIAGNOSTIC_ERROR_TYPES)


def _run_portable_observed_child(
    tmp_path: Path, source: str
) -> tuple[tuple[int, str, str], Path, list[str]]:
    helpers = _load_windows_observer_helpers()
    run_child = helpers["_run_observed_child"]
    assert callable(run_child)
    helpers["_CHILD_DEADLINE_SECONDS"] = 0.15
    helpers["_CHILD_STOP_WAIT_SECONDS"] = 1.0
    observer_path = tmp_path / "observer.json"
    stderr_path = tmp_path / "child.stderr"
    pid_path = tmp_path / "child.pid"
    checkpoints: list[str] = []
    environment = {
        "PATH": os.defpath,
        "OBSERVER": str(observer_path),
        "PID_FILE": str(pid_path),
    }
    result = run_child(
        [sys.executable, "-c", source],
        cwd=tmp_path,
        environment=environment,
        observer_path=observer_path,
        stderr_path=stderr_path,
        set_checkpoint=checkpoints.append,
    )
    return result, stderr_path, checkpoints


@pytest.mark.parametrize(
    ("source", "expected_checkpoint"),
    (
        (
            "import sys; sys.stderr.write('SyntaxError: controlled\\n'); sys.exit(1)",
            "child-script-parse",
        ),
        (
            "import sys; sys.stderr.write('Fatal Python error: controlled\\n'); sys.exit(1)",
            "child-interpreter-fatal",
        ),
        (
            "import sys; sys.stderr.write('private-child-canary\\n'); sys.exit(1)",
            "child-startup-unclassified",
        ),
        ("raise SystemExit(1)", "child-startup-no-stderr"),
    ),
)
def test_windows_observer_startup_fallbacks_are_bounded_and_private(
    tmp_path: Path, source: str, expected_checkpoint: str
) -> None:
    """Run real child processes that exit before creating an observer record."""
    (returncode, checkpoint, error_type), _stderr_path, checkpoints = (
        _run_portable_observed_child(tmp_path, source)
    )

    assert returncode == 1
    assert checkpoint == expected_checkpoint
    assert error_type == "unavailable"
    assert checkpoints == [
        "parent-before-process-create",
        "parent-after-child-launch",
    ]
    assert "private-child-canary" not in checkpoint


def test_windows_observer_reaps_silent_timeout_and_stderr_overflow(
    tmp_path: Path,
) -> None:
    """Run direct hanging children to prove deadline and live output bounds."""
    for name, source, expected_checkpoint, expected_size in (
        (
            "silent",
            "import os, pathlib, time; pathlib.Path(os.environ['PID_FILE']).write_text(str(os.getpid())); time.sleep(60)",
            "child-timeout",
            0,
        ),
        (
            "overflow",
            "import os, pathlib, sys, time; pathlib.Path(os.environ['PID_FILE']).write_text(str(os.getpid())); sys.stderr.buffer.write(b'x' * 4097); sys.stderr.flush(); time.sleep(60)",
            "child-stderr-overflow",
            4096,
        ),
    ):
        case_root = tmp_path / name
        case_root.mkdir()
        started = time.monotonic()
        (returncode, checkpoint, error_type), stderr_path, _checkpoints = (
            _run_portable_observed_child(case_root, source)
        )
        assert time.monotonic() - started < 3.0
        assert returncode != 0
        assert checkpoint == expected_checkpoint
        assert error_type == "unavailable"
        assert stderr_path.stat().st_size == expected_size
        if os.name == "posix":
            pid = int((case_root / "child.pid").read_text(encoding="utf-8"))
            with pytest.raises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)


def test_windows_observer_rejects_invalid_record_without_stderr_fallback(
    tmp_path: Path,
) -> None:
    """A malformed observer takes precedence over any private stderr signature."""
    source = (
        "import os, pathlib, sys; "
        "pathlib.Path(os.environ['OBSERVER']).write_text('{not json', encoding='utf-8'); "
        "sys.stderr.write('Fatal Python error: private-child-canary\\n')"
    )
    (returncode, checkpoint, error_type), _stderr_path, _checkpoints = (
        _run_portable_observed_child(tmp_path, source)
    )

    assert returncode == 0
    assert checkpoint == "child-observer-invalid"
    assert error_type == "unavailable"
    assert "private-child-canary" not in checkpoint


@pytest.mark.parametrize(
    ("source", "expected_observation"),
    (
        (
            """
import json
import os
import sys
from pathlib import Path

path = Path(os.environ["OBSERVER"])
primary = {"schema_version": 1, "checkpoint": "child-spec-analysis", "error_type": "runtime-error"}
path.write_text(json.dumps(primary), encoding="utf-8")
path.write_text(json.dumps({"schema_version": 1, "checkpoint": "child-before-unlink", "error_type": "none"}), encoding="utf-8")
path.write_text(json.dumps(primary), encoding="utf-8")
raise SystemExit(1)
""",
            ("child-spec-analysis", "runtime-error"),
        ),
        (
            """
import json
import os
import sys
from pathlib import Path

path = Path(os.environ["OBSERVER"])
path.write_text(json.dumps({"schema_version": 1, "checkpoint": "child-spec-analysis", "error_type": "runtime-error"}), encoding="utf-8")
path.write_text(json.dumps({"schema_version": 1, "checkpoint": "child-before-unlink", "error_type": "permission-error"}), encoding="utf-8")
raise SystemExit(1)
""",
            ("child-before-unlink", "permission-error"),
        ),
    ),
    ids=("successful-cleanup-preserves-primary", "cleanup-failure-replaces-primary"),
)
def test_windows_observer_child_latches_primary_state_through_cleanup(
    tmp_path: Path, source: str, expected_observation: tuple[str, str]
) -> None:
    """Execute child observer records through the runner's validated handoff."""
    (returncode, checkpoint, error_type), _stderr_path, _checkpoints = (
        _run_portable_observed_child(tmp_path, source)
    )

    assert returncode == 1
    assert (checkpoint, error_type) == expected_observation


_WINDOWS_DIAGNOSTIC_NODES = (
    (
        "tests/packaging/test_standalone_windows_pyinstaller_diagnostic.py::"
        "test_native_share_lock_is_classified_by_the_copied_spec"
    ),
    (
        "tests/packaging/test_standalone_windows_pyinstaller_diagnostic.py::"
        "test_native_pinned_pyinstaller_classes_are_classified_by_copied_spec[isolated-child]"
    ),
    (
        "tests/packaging/test_standalone_windows_pyinstaller_diagnostic.py::"
        "test_native_pinned_pyinstaller_classes_are_classified_by_copied_spec[hook-import]"
    ),
    (
        "tests/packaging/test_standalone_windows_pyinstaller_diagnostic.py::"
        "test_native_pinned_pyinstaller_classes_are_classified_by_copied_spec[python-library]"
    ),
)

_WINDOWS_DIAGNOSTIC_STAGES = (
    "share-lock",
    "isolated-child",
    "hook-import",
    "python-library",
)
_WINDOWS_DIAGNOSTIC_OUTCOMES = (
    "fixture-setup-failed",
    "copied-spec-preflight",
    "copied-spec-generic-failure",
    "expected-classifier",
    "other-known-classifier",
    "unexpected-child-exit",
)
_WINDOWS_DIAGNOSTIC_CHECKPOINTS = (
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
)
_WINDOWS_DIAGNOSTIC_ERROR_TYPES = (
    "os-error",
    "file-not-found",
    "file-exists",
    "permission-error",
    "not-a-directory",
    "is-a-directory",
    "import-error",
    "module-not-found",
    "attribute-error",
    "type-error",
    "value-error",
    "runtime-error",
    "assertion-error",
    "system-exit",
    "none",
    "other",
    "unavailable",
)
_WINDOWS_DIAGNOSTIC_OBSERVATIONS = tuple(
    (checkpoint, "none") for checkpoint in _WINDOWS_DIAGNOSTIC_CHECKPOINTS
) + tuple(
    ("outer-complete", error_type)
    for error_type in _WINDOWS_DIAGNOSTIC_ERROR_TYPES
    if error_type != "none"
)


def _run_windows_diagnostic_block(
    tmp_path: Path,
    *,
    preflight_fails: bool,
    failing_nodes: tuple[str, ...],
    outcome: str = "expected-classifier",
    checkpoint: str = "outer-complete",
    error_type: str = "none",
    record_kind: str = "valid",
    reader_fails: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    setup_root = tmp_path / "qualification"
    setup_root.mkdir()
    calls = tmp_path / "calls"
    qualified_python = _write_shell_stub(
        tmp_path / "qualified-python",
        """if [ "$1" = "-c" ]; then
  case "$2" in
    *RECORD_PREFIX*)
      if [ "${READER_FAILS:-0}" = 1 ]; then
        printf 'private-reader-canary\\n' >&2
        exit 23
      fi
      exec __PYTHON__ "$@"
      ;;
  esac
  printf 'private-preflight-canary\\n' >&2
  test "${PREFLIGHT_FAILS}" = 0 && exit 0
  exit 17
fi
if [ "$1" = "-m" ] && [ "$2" = "pytest" ]; then
  node=""
  for argument in "$@"; do
    case "${argument}" in
      *test_standalone_windows_pyinstaller_diagnostic.py::*) node="${argument}" ;;
    esac
  done
  printf '%s\\n' "${node}" >> "${NATIVE_CALLS}"
  printf 'private-pytest-canary\\n' >&2
  case "${node}" in
    *"[isolated-child]") stage=isolated-child ;;
    *"[hook-import]") stage=hook-import ;;
    *"[python-library]") stage=python-library ;;
    *) stage=share-lock ;;
  esac
  record="${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json"
  write_valid_record() {
    printf '{"schema_version":2,"stage":"%s","outcome":"%s","checkpoint":"%s","error_type":"%s"}\\n' \
      "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}"
  }
  if [ "${stage}" = share-lock ]; then
    case "${RECORD_KIND}" in
      missing) ;;
      missing-field) printf '{"schema_version":2,"stage":"%s","outcome":"%s","checkpoint":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" > "${record}" ;;
      extra) printf '{"schema_version":2,"stage":"%s","outcome":"%s","checkpoint":"%s","error_type":"%s","extra":true}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      boolean) printf '{"schema_version":true,"stage":"%s","outcome":"%s","checkpoint":"%s","error_type":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      schema-string) printf '{"schema_version":"2","stage":"%s","outcome":"%s","checkpoint":"%s","error_type":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      duplicate) printf '{"schema_version":2,"schema_version":2,"stage":"%s","outcome":"%s","checkpoint":"%s","error_type":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      malformed) printf '{not json\\n' > "${record}" ;;
      oversized) printf '%4097s' '' | tr ' ' x > "${record}" ;;
      symlink)
        printf 'replacement\\n' > "${QUALIFICATION_SETUP_ROOT}/replacement.json"
        ln -s "${QUALIFICATION_SETUP_ROOT}/replacement.json" "${record}"
        ;;
      stage-mismatch) printf '{"schema_version":2,"stage":"hook-import","outcome":"%s","checkpoint":"%s","error_type":"%s"}\\n' "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      stage-number) printf '{"schema_version":2,"stage":1,"outcome":"%s","checkpoint":"%s","error_type":"%s"}\\n' "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      outcome-number) printf '{"schema_version":2,"stage":"%s","outcome":1,"checkpoint":"%s","error_type":"%s"}\\n' "${stage}" "${DIAGNOSTIC_CHECKPOINT}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      unknown-outcome) printf '{"schema_version":2,"stage":"%s","outcome":"unknown","checkpoint":"%s","error_type":"%s"}\\n' "${stage}" "${DIAGNOSTIC_CHECKPOINT}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      checkpoint-number) printf '{"schema_version":2,"stage":"%s","outcome":"%s","checkpoint":1,"error_type":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      unknown-checkpoint) printf '{"schema_version":2,"stage":"%s","outcome":"%s","checkpoint":"private-checkpoint-canary","error_type":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_ERROR_TYPE}" > "${record}" ;;
      error-type-number) printf '{"schema_version":2,"stage":"%s","outcome":"%s","checkpoint":"%s","error_type":1}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" > "${record}" ;;
      unknown-error-type) printf '{"schema_version":2,"stage":"%s","outcome":"%s","checkpoint":"%s","error_type":"private-error-canary"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" "${DIAGNOSTIC_CHECKPOINT}" > "${record}" ;;
      *) write_valid_record ;;
    esac
  else
    write_valid_record
  fi
  case ";${FAILING_NODES};" in
    *";${node};"*) exit 19 ;;
  esac
  exit 0
fi
exit 31
""".replace("__PYTHON__", shlex.quote(sys.executable)),
    )
    completed = _run_workflow_block(
        _workflow_run_block("Verify Windows PyInstaller diagnostics"),
        {
            "FAILING_NODES": ";".join(failing_nodes),
            "NATIVE_CALLS": str(calls),
            "PATH": os.defpath,
            "PREFLIGHT_FAILS": "1" if preflight_fails else "0",
            "DIAGNOSTIC_OUTCOME": outcome,
            "DIAGNOSTIC_CHECKPOINT": checkpoint,
            "DIAGNOSTIC_ERROR_TYPE": error_type,
            "RECORD_KIND": record_kind,
            "READER_FAILS": "1" if reader_fails else "0",
            "QUALIFICATION_SETUP_ROOT": str(setup_root),
            "QUALIFIED_PYTHON": str(qualified_python),
        },
    )
    return completed, setup_root, calls


@pytest.mark.parametrize(
    ("preflight_fails", "failing_nodes", "expected_returncode", "failed_stages"),
    (
        (False, (), 0, ()),
        (True, (), 1, ("preflight",)),
        (
            False,
            _WINDOWS_DIAGNOSTIC_NODES,
            1,
            (
                "share-lock",
                "isolated-child",
                "hook-import",
                "python-library",
            ),
        ),
        (
            False,
            (_WINDOWS_DIAGNOSTIC_NODES[0], _WINDOWS_DIAGNOSTIC_NODES[2]),
            1,
            (
                "share-lock",
                "hook-import",
            ),
        ),
    ),
)
def test_windows_diagnostic_block_reports_only_fixed_stages(
    tmp_path: Path,
    preflight_fails: bool,
    failing_nodes: tuple[str, ...],
    expected_returncode: int,
    failed_stages: tuple[str, ...],
) -> None:
    completed, setup_root, calls = _run_windows_diagnostic_block(
        tmp_path,
        preflight_fails=preflight_fails,
        failing_nodes=failing_nodes,
    )

    assert completed.returncode == expected_returncode
    assert "private-preflight-canary" not in completed.stdout
    assert "private-preflight-canary" not in completed.stderr
    assert "private-pytest-canary" not in completed.stdout
    assert "private-pytest-canary" not in completed.stderr
    assert "private-reader-canary" not in completed.stdout
    assert "private-reader-canary" not in completed.stderr
    assert (setup_root / "windows-pyinstaller-preflight.log").read_text(
        encoding="utf-8"
    ) == "private-preflight-canary\n"

    if preflight_fails:
        assert not calls.exists()
        assert (
            completed.stderr
            == "Windows PyInstaller diagnostic stage failed: preflight\n"
        )
        return

    assert calls.read_text(encoding="utf-8").splitlines() == list(
        _WINDOWS_DIAGNOSTIC_NODES
    )
    for stage, node in zip(
        _WINDOWS_DIAGNOSTIC_STAGES, _WINDOWS_DIAGNOSTIC_NODES, strict=True
    ):
        assert (setup_root / f"windows-pyinstaller-{stage}.log").read_text(
            encoding="utf-8"
        ) == "private-pytest-canary\n"
        label = (
            f"Windows PyInstaller diagnostic stage failed: {stage}"
            if stage in failed_stages
            else f"Windows PyInstaller diagnostic stage passed: {stage}"
        )
        assert label in completed.stdout + completed.stderr
        assert (
            "Windows PyInstaller diagnostic outcome: "
            f"{stage}: expected-classifier; checkpoint: outer-complete; error type: none"
            in completed.stdout
        )
        assert node in _WINDOWS_DIAGNOSTIC_NODES


@pytest.mark.parametrize(("checkpoint", "error_type"), _WINDOWS_DIAGNOSTIC_OBSERVATIONS)
def test_windows_diagnostic_reader_accepts_each_closed_observer_token(
    tmp_path: Path, checkpoint: str, error_type: str
) -> None:
    completed, _setup_root, calls = _run_windows_diagnostic_block(
        tmp_path,
        preflight_fails=False,
        failing_nodes=(),
        checkpoint=checkpoint,
        error_type=error_type,
    )

    assert completed.returncode == 0
    assert calls.read_text(encoding="utf-8").splitlines() == list(
        _WINDOWS_DIAGNOSTIC_NODES
    )
    for stage in _WINDOWS_DIAGNOSTIC_STAGES:
        assert (
            "Windows PyInstaller diagnostic outcome: "
            f"{stage}: expected-classifier; checkpoint: {checkpoint}; error type: {error_type}"
            in completed.stdout
        )


@pytest.mark.parametrize("outcome", _WINDOWS_DIAGNOSTIC_OUTCOMES)
def test_windows_diagnostic_reader_accepts_each_closed_outcome(
    tmp_path: Path, outcome: str
) -> None:
    completed, _setup_root, calls = _run_windows_diagnostic_block(
        tmp_path, preflight_fails=False, failing_nodes=(), outcome=outcome
    )

    assert completed.returncode == 0
    assert calls.read_text(encoding="utf-8").splitlines() == list(
        _WINDOWS_DIAGNOSTIC_NODES
    )
    for stage in _WINDOWS_DIAGNOSTIC_STAGES:
        assert (
            "Windows PyInstaller diagnostic outcome: "
            f"{stage}: {outcome}; checkpoint: outer-complete; error type: none"
            in completed.stdout
        )


@pytest.mark.parametrize(
    "record_kind",
    (
        "missing",
        "missing-field",
        "extra",
        "boolean",
        "schema-string",
        "duplicate",
        "malformed",
        "oversized",
        "symlink",
        "stage-mismatch",
        "stage-number",
        "outcome-number",
        "unknown-outcome",
        "checkpoint-number",
        "unknown-checkpoint",
        "error-type-number",
        "unknown-error-type",
    ),
)
def test_windows_diagnostic_reader_rejects_invalid_private_records(
    tmp_path: Path, record_kind: str
) -> None:
    completed, setup_root, calls = _run_windows_diagnostic_block(
        tmp_path,
        preflight_fails=False,
        failing_nodes=(),
        record_kind=record_kind,
    )

    assert completed.returncode == 1
    assert calls.read_text(encoding="utf-8").splitlines() == list(
        _WINDOWS_DIAGNOSTIC_NODES
    )
    assert (
        "Windows PyInstaller diagnostic outcome unavailable: share-lock"
        in completed.stderr
    )
    assert "private-pytest-canary" not in completed.stdout + completed.stderr
    assert "private-reader-canary" not in completed.stdout + completed.stderr
    assert "private-checkpoint-canary" not in completed.stdout + completed.stderr
    assert "private-error-canary" not in completed.stdout + completed.stderr
    assert (setup_root / "windows-pyinstaller-outcome-share-lock.log").is_file()


def test_windows_diagnostic_reader_failure_is_private_and_does_not_stop_nodes(
    tmp_path: Path,
) -> None:
    completed, setup_root, calls = _run_windows_diagnostic_block(
        tmp_path,
        preflight_fails=False,
        failing_nodes=(),
        reader_fails=True,
    )

    assert completed.returncode == 1
    assert calls.read_text(encoding="utf-8").splitlines() == list(
        _WINDOWS_DIAGNOSTIC_NODES
    )
    for stage in _WINDOWS_DIAGNOSTIC_STAGES:
        assert (
            f"Windows PyInstaller diagnostic outcome unavailable: {stage}"
            in completed.stderr
        )
        assert (setup_root / f"windows-pyinstaller-outcome-{stage}.log").read_text(
            encoding="utf-8"
        ) == "private-reader-canary\n"


def test_linux_preflight_accepts_quoted_and_unquoted_os_release(tmp_path: Path) -> None:
    start = WORKFLOW.index(
        "          import os\n", WORKFLOW.index("Assert target runtime")
    )
    end = WORKFLOW.index("          PY\n", start)
    snippet = "\n".join(line[10:] for line in WORKFLOW[start:end].splitlines())
    snippet = snippet.replace("(3, 12)", repr(sys.version_info[:2]))
    for facts in ("ID=ubuntu\nVERSION_ID=22.04\n", 'ID="ubuntu"\nVERSION_ID="22.04"\n'):
        release = tmp_path / "os-release"
        release.write_text(facts, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-c", snippet],
            env={
                **os.environ,
                "TARGET": "linux-x64-ubuntu-22.04",
                "SERVONAUT_OS_RELEASE_PATH": str(release),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
    for facts in ("ID=debian\nVERSION_ID=22.04\n", "ID=ubuntu\nVERSION_ID=24.04\n"):
        release.write_text(facts, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-c", snippet],
            env={
                **os.environ,
                "TARGET": "linux-x64-ubuntu-22.04",
                "SERVONAUT_OS_RELEASE_PATH": str(release),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode != 0


def test_runtime_preflight_keeps_the_windows_native_directory_permission_floor() -> (
    None
):
    runtime = _workflow_run_block("Assert target runtime")

    assert 'sys.platform == "win32"' in runtime
    assert "sys.version_info < (3, 12, 4)" in runtime
    assert "runtime assertion failed" in runtime


def test_policy_report_collector_is_finite_and_uses_policy_limit() -> None:
    for name in (
        "architecture.json",
        "dependency-provenance.json",
        "licenses.json",
        "manifest.json",
        "missing-baseline-candidate.json",
        "sbom-payload.cdx.json",
        "sbom-python-closure.cdx.json",
        "sizes.json",
        "warning-candidates.json",
        "warnings.json",
        "qualification-status.json",
    ):
        assert name in WORKFLOW
    assert "load_evidence_policy" in WORKFLOW
    assert "max_metadata_file_bytes" in WORKFLOW
    assert "MANDATORY_REPORTS" in WORKFLOW


def test_policy_report_collector_sanitizes_all_candidates_without_globs(
    tmp_path: Path,
) -> None:
    policy = load_evidence_policy(
        ROOT / "packaging/standalone_cli/evidence-policy.json"
    )
    source = tmp_path / "public-evidence"
    destination = tmp_path / "upload"
    source.mkdir()
    destination.mkdir()
    names = tuple(sorted(policy.public_file_names))
    assert len(names) == 10
    for name in names:
        source.joinpath(name).write_text(
            '{"payload":"' + ("x" * 70_000) + '"}', encoding="utf-8"
        )
    source.joinpath("unexpected.json").write_text("{}", encoding="utf-8")

    for name in names:
        document = load_bounded_json(
            source / name, "qualification report", policy.limits.max_metadata_file_bytes
        )
        write_public_json(
            destination / name,
            document,
            forbidden_roots=(tmp_path,),
            max_bytes=policy.limits.max_metadata_file_bytes,
        )

    assert {path.name for path in destination.iterdir()} == set(names)
    assert not (destination / "unexpected.json").exists()
    source.joinpath("warnings.json").write_text('{"path":"/private"}', encoding="utf-8")
    with pytest.raises(ArtifactEvidenceError):
        write_public_json(
            destination / "rejected.json",
            load_bounded_json(
                source / "warnings.json",
                "qualification report",
                policy.limits.max_metadata_file_bytes,
            ),
            forbidden_roots=(tmp_path,),
            max_bytes=policy.limits.max_metadata_file_bytes,
        )


def test_prepare_setup_root_is_exported_before_initialization_failure(
    tmp_path: Path,
) -> None:
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    selected_python = _write_shell_stub(
        tmp_path / "selected-python",
        "\n".join(
            (
                'if [ "$1" = "-I" ] && [ "$2" = "-c" ]; then',
                f'  exec {shlex.quote(sys.executable)} "$@"',
                "fi",
                "exit 19",
                "",
            )
        ),
    )
    root = runner_temp / "servonaut-qualification-macos-x64-123"
    root_export = 'echo "root=${ROOT}" >> "${GITHUB_OUTPUT}"'
    initialize = (
        "env -u PYTHONPATH -u PYTHONHOME -u PYTHONUSERBASE -u PIP_CONFIG_FILE \\\n"
        '  "${SELECTED_PYTHON}" -m venv "${VENV}"'
    )
    prepare = _workflow_run_block("Prepare qualification environment")
    assert root_export in prepare
    assert initialize in prepare
    environment = {
        "RUNNER_TEMP": str(runner_temp),
        "TARGET": "macos-x64",
        "GITHUB_RUN_ID": "123",
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
        "SELECTED_PYTHON": str(selected_python),
    }

    failed = _run_workflow_block(prepare, environment)

    assert failed.returncode != 0
    assert Path(environment["GITHUB_OUTPUT"]).read_text(encoding="utf-8") == (
        f"root={root}\n"
    )
    assert root.is_dir()
    if os.name != "nt":
        assert stat.S_IMODE(root.stat().st_mode) == 0o700

    for label, prepare_existing in (
        ("directory", lambda path: path.mkdir()),
        ("file", lambda path: path.write_text("keep", encoding="utf-8")),
        ("link", lambda path: path.symlink_to(tmp_path / "link-target")),
    ):
        run_id = f"reuse-{label}"
        existing = runner_temp / f"servonaut-qualification-macos-x64-{run_id}"
        if label == "link":
            (tmp_path / "link-target").write_text("keep", encoding="utf-8")
        prepare_existing(existing)
        rejected_output = tmp_path / f"github-output-{label}"
        rejected = _run_workflow_block(
            prepare,
            {
                **environment,
                "GITHUB_RUN_ID": run_id,
                "GITHUB_OUTPUT": str(rejected_output),
            },
        )

        assert rejected.returncode != 0
        assert rejected.stderr == "qualification setup root could not be created\n"
        assert not rejected_output.exists()
        assert existing.exists()

    without_export = prepare.replace(f"{root_export}\n", "")
    moved_export = without_export.replace(initialize, f"{initialize}\n{root_export}")
    assert without_export != prepare
    assert moved_export != prepare
    for name, mutated in (("removed", without_export), ("moved", moved_export)):
        mutation_environment = {
            **environment,
            "GITHUB_OUTPUT": str(tmp_path / f"github-output-{name}"),
        }
        result = _run_workflow_block(mutated, mutation_environment)

        assert result.returncode != 0
        assert not Path(mutation_environment["GITHUB_OUTPUT"]).exists()


@pytest.mark.parametrize(
    "target",
    ("linux-x64-ubuntu-22.04", "windows-x64", "macos-x64", "macos-arm64"),
)
def test_real_wheel_parent_setup_matches_action_and_helper_contract(
    tmp_path: Path, target: str
) -> None:
    runner_temp = tmp_path / "runner temp"
    runner_temp.mkdir()
    setup = _workflow_run_block("Prepare wheel work parent")
    action = (
        ROOT / ".github" / "actions" / "setup-standalone-cli" / "action.yml"
    ).read_text(encoding="utf-8")
    workflow_action = _workflow_step("Prepare verified wheel tools")
    action_parent = (
        "${{ runner.temp }}/servonaut-wheel-${{ matrix.target }}-${{ github.run_id }}"
    )
    assert f"temporary-directory: {action_parent}" in workflow_action
    assert "WORK_PARENT: ${{ inputs.temporary-directory }}" in action
    assert '--work-parent "${WORK_PARENT}"' in action

    def expected(run_id: str) -> Path:
        return runner_temp / f"servonaut-wheel-{target}-{run_id}"

    def run_setup(run_id: str) -> subprocess.CompletedProcess[str]:
        return _run_workflow_block(
            setup,
            {
                "RUNNER_TEMP": str(runner_temp),
                "SELECTED_PYTHON": sys.executable,
                "TARGET": target,
                "GITHUB_RUN_ID": run_id,
            },
        )

    created = expected("fresh")
    result = run_setup("fresh")

    assert result.returncode == 0
    assert created.is_dir()
    assert created.resolve() == created
    if os.name != "nt":
        assert stat.S_IMODE(created.stat().st_mode) == 0o700

    validated = _validate_request(
        WheelToolRequest(
            Path(sys.executable).resolve(),
            ROOT,
            created.resolve(),
            ROOT / "packaging/standalone_cli/requirements/wheel-build-tools.txt",
            ROOT / "packaging/standalone_cli/wheel-tools-policy.json",
        )
    )
    assert validated[2] == created.resolve()
    with pytest.raises(WheelToolError, match="work parent"):
        _validate_request(
            WheelToolRequest(
                Path(sys.executable).resolve(),
                ROOT,
                expected("absent"),
                ROOT / "packaging/standalone_cli/requirements/wheel-build-tools.txt",
                ROOT / "packaging/standalone_cli/wheel-tools-policy.json",
            )
        )

    reuse_directory = expected("directory")
    reuse_directory.mkdir()
    directory_sentinel = reuse_directory / "sentinel"
    directory_sentinel.write_text("keep", encoding="utf-8")
    reuse_file = expected("file")
    reuse_file.write_text("keep", encoding="utf-8")
    reuse_link = expected("link")
    link_sentinel = runner_temp / "link-sentinel"
    link_sentinel.write_text("keep", encoding="utf-8")
    reuse_link.symlink_to(link_sentinel)
    for run_id, sentinel in (
        ("directory", directory_sentinel),
        ("file", reuse_file),
        ("link", reuse_link),
    ):
        rejected = run_setup(run_id)

        assert rejected.returncode != 0
        assert rejected.stderr == "wheel work parent could not be created\n"
        assert sentinel.read_text(encoding="utf-8") == "keep"

    neighbor = runner_temp / "neighbor"
    neighbor.mkdir()
    cleanup = _run_workflow_block(
        _workflow_run_block("Cleanup qualification material"),
        {
            "QUALIFICATION_SETUP_ROOT": "",
            "RUNNER_TEMP": str(runner_temp),
            "TARGET": target,
            "GITHUB_RUN_ID": "fresh",
        },
    )

    assert cleanup.returncode == 0
    assert not created.exists()
    assert neighbor.is_dir()


def test_missing_setup_root_stops_real_blocks_before_derived_paths(
    tmp_path: Path,
) -> None:
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    stub_directory = tmp_path / "bin"
    stub_directory.mkdir()
    mkdir_calls = tmp_path / "mkdir-calls"
    _write_shell_stub(
        stub_directory / "mkdir",
        'printf "called\\n" > "${MKDIR_CALLS}"\nexit 37\n',
    )
    target = "macos-x64"
    run_id = "123"
    expected_root = runner_temp / f"servonaut-qualification-{target}-{run_id}"
    common = {
        "MKDIR_CALLS": str(mkdir_calls),
        "PATH": f"{stub_directory}{os.pathsep}{os.defpath}",
        "RUNNER_TEMP": str(runner_temp),
        "TARGET": target,
        "GITHUB_RUN_ID": run_id,
        "QUALIFICATION_SETUP_ROOT": "",
    }

    for name in ("Qualify standalone payload", "Sanitize public qualification status"):
        result = _run_workflow_block(_workflow_run_block(name), common)

        assert result.returncode != 0
        assert not (expected_root / "work").exists()
        assert not mkdir_calls.exists()

    assert (
        "if: always() && steps.qualification-env.outputs.root != ''"
        in _workflow_step("Sanitize public qualification status")
    )
    assert "steps.sanitize.outcome == 'success'" in _workflow_step(
        "Upload sanitized qualification status"
    )

    wheel_root = runner_temp / f"servonaut-wheel-{target}-{run_id}"
    wheel_root.mkdir()
    foreign = runner_temp / "foreign"
    foreign.mkdir()
    cleanup = _run_workflow_block(
        _workflow_run_block("Cleanup qualification material"), common
    )

    assert cleanup.returncode == 0
    assert not expected_root.exists()
    assert not wheel_root.exists()
    assert foreign.is_dir()


@pytest.mark.parametrize("timestamp", ("", "-1", "not-an-epoch"))
def test_source_date_epoch_handoff_rejects_malformed_git_timestamp(
    tmp_path: Path, timestamp: str
) -> None:
    stub_directory = tmp_path / "bin"
    stub_directory.mkdir()
    _write_shell_stub(stub_directory / "git", "printf '%s\\n' \"${GIT_TIMESTAMP}\"\n")
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    setup_root = runner_temp / "servonaut-qualification-macos-x64-123"
    setup_root.mkdir()
    helper_calls = tmp_path / "helper-calls"
    qualified_python = _write_shell_stub(
        tmp_path / "qualified-python",
        f"""if [ \"$1\" = \"-I\" ] && [ \"$2\" = \"-c\" ]; then
  exec {shlex.quote(sys.executable)} \"$@\"
fi
if [ \"$1\" = \"-c\" ]; then
  printf '9.8.7\\n'
  exit 0
fi
printf 'called\\n' > \"${{HELPER_CALLS}}\"
exit 31
""",
    )
    environment = {
        "PATH": f"{stub_directory}{os.pathsep}{os.defpath}",
        "GIT_TIMESTAMP": timestamp,
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_SHA": "a" * 40,
        "QUALIFICATION_SETUP_ROOT": str(setup_root),
        "RUNNER_TEMP": str(runner_temp),
        "TARGET": "macos-x64",
        "GITHUB_RUN_ID": "123",
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
        "GITHUB_RUN_ATTEMPT": "1",
        "HELPER_CALLS": str(helper_calls),
        "QUALIFIED_PYTHON": str(qualified_python),
        "WHEEL": str(tmp_path / "wheel.whl"),
    }

    completed = _run_workflow_block(
        _workflow_run_block("Qualify standalone payload"), environment
    )

    assert completed.returncode != 0
    assert (setup_root / "work").is_dir()
    assert not helper_calls.exists()


def test_source_date_epoch_handoff_uses_git_commit_timestamp_for_helper(
    tmp_path: Path,
) -> None:
    stub_directory = tmp_path / "bin"
    stub_directory.mkdir()
    _write_shell_stub(stub_directory / "git", "printf '%s\\n' 1700000000\n")
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    qualify = _workflow_run_block("Qualify standalone payload")

    def run_with(
        block: str, label: str
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        run_root = tmp_path / label
        runner_temp = run_root / "runner-temp"
        runner_temp.mkdir(parents=True)
        setup_root = runner_temp / "servonaut-qualification-macos-x64-123"
        setup_root.mkdir()
        output = tmp_path / f"github-output-{label}"
        epoch_log = tmp_path / f"epoch-{label}"
        qualified_python = _write_shell_stub(
            tmp_path / f"qualified-python-{label}",
            f"""if [ \"$1\" = \"-I\" ] && [ \"$2\" = \"-c\" ]; then
  exec {shlex.quote(sys.executable)} \"$@\"
fi
if [ \"$1\" = \"-c\" ]; then
  printf '9.8.7\\n'
  exit 0
fi
if [ \"$1\" = \"-m\" ]; then
  test \"${{SOURCE_DATE_EPOCH:-}}\" = 1700000000 || exit 29
  printf '%s\\n' \"${{SOURCE_DATE_EPOCH}}\" > \"${{EPOCH_LOG}}\"
  exit 0
fi
exit 31
""",
        )
        environment = {
            "PATH": f"{stub_directory}{os.pathsep}{os.defpath}",
            "EPOCH_LOG": str(epoch_log),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_RUN_ID": "123",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_WORKSPACE": str(workspace),
            "QUALIFICATION_SETUP_ROOT": str(setup_root),
            "QUALIFIED_PYTHON": str(qualified_python),
            "RUNNER_TEMP": str(runner_temp),
            "TARGET": "macos-x64",
            "WHEEL": str(tmp_path / "wheel.whl"),
            "WHEEL_SHA256": "b" * 64,
        }
        return _run_workflow_block(block, environment), output

    completed, output = run_with(qualify, "exported")

    assert completed.returncode == 0
    assert output.read_text(encoding="utf-8") == "status=passed\n"
    assert (tmp_path / "epoch-exported").read_text(encoding="utf-8") == "1700000000\n"

    without_export = qualify.replace("export SOURCE_DATE_EPOCH\n", "")
    mutated, mutated_output = run_with(without_export, "unexported")

    assert without_export != qualify
    assert mutated.returncode == 0
    assert mutated_output.read_text(encoding="utf-8") == "status=failed\n"
    assert not (tmp_path / "epoch-unexported").exists()


@pytest.mark.parametrize(
    ("target", "includes_docker"),
    (("macos-x64", False), ("linux-x64-ubuntu-22.04", True)),
)
def test_qualification_arguments_use_a_nonempty_platform_specific_array(
    tmp_path: Path, target: str, includes_docker: bool
) -> None:
    stub_directory = tmp_path / "bin"
    stub_directory.mkdir()
    _write_shell_stub(stub_directory / "git", "printf '%s\\n' 1700000000\n")
    docker = _write_shell_stub(stub_directory / "docker", "exit 0\n")
    runner_temp = tmp_path / "runner temp"
    runner_temp.mkdir()
    setup_root = runner_temp / f"servonaut-qualification-{target}-123"
    setup_root.mkdir()
    helper_args = tmp_path / "helper-args"
    qualified_python = _write_shell_stub(
        tmp_path / "qualified-python",
        f"""if [ \"$1\" = \"-I\" ] && [ \"$2\" = \"-c\" ]; then
  exec {shlex.quote(sys.executable)} \"$@\"
fi
if [ \"$1\" = \"-c\" ]; then
  printf '9.8.7\\n'
  exit 0
fi
if [ \"$1\" = \"-m\" ]; then
  printf '%s\\n' \"$@\" > \"${{HELPER_ARGS}}\"
  exit 0
fi
exit 31
""",
    )
    environment = {
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": "123",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_WORKSPACE": str(tmp_path),
        "HELPER_ARGS": str(helper_args),
        "PATH": f"{stub_directory}{os.pathsep}{os.defpath}",
        "QUALIFICATION_SETUP_ROOT": str(setup_root),
        "QUALIFIED_PYTHON": str(qualified_python),
        "RUNNER_TEMP": str(runner_temp),
        "TARGET": target,
        "WHEEL": str(tmp_path / "wheel.whl"),
        "WHEEL_SHA256": "b" * 64,
    }

    completed = _run_workflow_block(
        _workflow_run_block("Qualify standalone payload"), environment
    )

    assert completed.returncode == 0
    assert Path(environment["GITHUB_OUTPUT"]).read_text(encoding="utf-8") == (
        "status=passed\n"
    )
    if os.name != "nt":
        assert stat.S_IMODE((setup_root / "work").stat().st_mode) == 0o700
    arguments = helper_args.read_text(encoding="utf-8").splitlines()
    assert arguments[:2] == ["-m", "scripts.standalone_cli.ci_qualify"]
    assert "--wheel" in arguments
    assert arguments[arguments.index("--wheel-sha256") + 1] == "b" * 64
    assert "--qualification-root" in arguments
    if includes_docker:
        docker_index = arguments.index("--docker")
        assert arguments[docker_index + 1] == str(docker)
    else:
        assert "--docker" not in arguments

    neighbor = setup_root / "neighbor"
    neighbor.mkdir()
    work = setup_root / "work"
    sentinel = work / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    rejected = _run_workflow_block(
        _workflow_run_block("Qualify standalone payload"),
        {**environment, "GITHUB_OUTPUT": str(tmp_path / "github-output-rejected")},
    )

    assert rejected.returncode != 0
    assert rejected.stderr == "qualification work root could not be created\n"
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert neighbor.is_dir()

    recorded_arguments = helper_args.read_text(encoding="utf-8")
    for label, prepare_existing in (
        ("file", lambda path: path.write_text("keep", encoding="utf-8")),
        ("link", lambda path: path.symlink_to(tmp_path / "work-link-target")),
    ):
        run_id = f"reuse-{label}"
        collision_root = runner_temp / f"servonaut-qualification-{target}-{run_id}"
        collision_root.mkdir()
        existing = collision_root / "work"
        if label == "link":
            (tmp_path / "work-link-target").write_text("keep", encoding="utf-8")
        prepare_existing(existing)
        collision_neighbor = collision_root / "neighbor"
        collision_neighbor.mkdir()
        collision = _run_workflow_block(
            _workflow_run_block("Qualify standalone payload"),
            {
                **environment,
                "GITHUB_OUTPUT": str(tmp_path / f"github-output-{label}"),
                "GITHUB_RUN_ID": run_id,
                "QUALIFICATION_SETUP_ROOT": str(collision_root),
            },
        )

        assert collision.returncode != 0
        assert collision.stderr == "qualification work root could not be created\n"
        assert existing.exists()
        assert collision_neighbor.is_dir()
        assert helper_args.read_text(encoding="utf-8") == recorded_arguments


def test_real_sanitizer_outputs_match_declared_upload_paths(tmp_path: Path) -> None:
    policy = load_evidence_policy(
        ROOT / "packaging/standalone_cli/evidence-policy.json"
    )
    optional_candidate = "missing-baseline-candidate.json"
    assert optional_candidate in policy.public_file_names
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    setup_root = runner_temp / "servonaut-qualification-macos-x64-123"
    source = setup_root / "work" / "public-evidence"
    source.mkdir(parents=True)
    expected_names = (set(policy.public_file_names) - {optional_candidate}) | {
        "qualification-status.json"
    }
    document = '{"payload":"' + ("x" * 70_000) + '"}\n'
    for name in expected_names:
        (source / name).write_text(document, encoding="utf-8")
    environment = {
        "GITHUB_WORKSPACE": str(ROOT),
        "QUALIFICATION_SETUP_ROOT": str(setup_root),
        "QUALIFIED_PYTHON": sys.executable,
        "RUNNER_TEMP": str(runner_temp),
        "TARGET": "macos-x64",
        "GITHUB_RUN_ID": "123",
    }

    sanitizer = _workflow_run_block("Sanitize public qualification status").replace(
        "${{ steps.qualify.outputs.status }}", "passed"
    )
    sanitized = _run_workflow_block(sanitizer, environment)

    assert sanitized.returncode == 0
    safe_outputs = {
        path.resolve() for path in (setup_root / "work" / "upload").iterdir()
    }
    assert {path.name for path in safe_outputs} == expected_names
    if os.name != "nt":
        assert stat.S_IMODE((setup_root / "work" / "upload").stat().st_mode) == 0o700

    for label, prepare_existing in (
        ("directory", lambda path: path.mkdir()),
        ("file", lambda path: path.write_text("keep", encoding="utf-8")),
        ("link", lambda path: path.symlink_to(tmp_path / "upload-link-target")),
    ):
        collision_root = runner_temp / f"servonaut-qualification-macos-x64-{label}"
        collision_work = collision_root / "work"
        collision_work.mkdir(parents=True)
        existing = collision_work / "upload"
        if label == "link":
            (tmp_path / "upload-link-target").write_text("keep", encoding="utf-8")
        prepare_existing(existing)
        rejected = _run_workflow_block(
            sanitizer,
            {
                **environment,
                "GITHUB_RUN_ID": label,
                "QUALIFICATION_SETUP_ROOT": str(collision_root),
            },
        )

        assert rejected.returncode != 0
        assert rejected.stderr == "qualification upload root could not be created\n"
        assert existing.exists()

    upload_step = _workflow_step("Upload sanitized qualification status")
    prefix = "${{ steps.qualification-env.outputs.root }}"

    def declared_paths(step: str) -> set[Path]:
        paths = {
            (setup_root / line.strip().removeprefix(prefix).lstrip("/")).resolve()
            for line in step.split("          path: |\n", 1)[1]
            .split("          retention-days:", 1)[0]
            .splitlines()
            if line.strip().startswith(prefix)
        }
        assert len(paths) == 11
        return paths

    uploaded = declared_paths(upload_step)

    assert {path for path in uploaded if path.is_file()} == safe_outputs
    assert {path.name for path in uploaded - safe_outputs} == {optional_candidate}

    missing_work = upload_step.replace("/work/upload/", "/upload/")
    mutated = declared_paths(missing_work)

    assert missing_work != upload_step
    assert mutated != uploaded
    assert not any(path.is_file() for path in mutated)


@pytest.mark.parametrize("leaked_root", ("workspace", "home"))
def test_sanitizer_rejects_reports_naming_the_workspace_or_home(
    tmp_path: Path, leaked_root: str
) -> None:
    runner_temp = tmp_path / "runner-temp"
    setup_root = runner_temp / "servonaut-qualification-macos-x64-123"
    source = setup_root / "work" / "public-evidence"
    source.mkdir(parents=True)
    roots = {"workspace": tmp_path / "workspace", "home": tmp_path / "home"}
    for root in roots.values():
        root.mkdir()
    (source / "warnings.json").write_text(
        json.dumps({"note": "copied-from" + str(roots[leaked_root])}),
        encoding="utf-8",
    )
    environment = {
        "GITHUB_WORKSPACE": str(roots["workspace"]),
        "HOME": str(roots["home"]),
        "USERPROFILE": str(roots["home"]),
        "QUALIFICATION_SETUP_ROOT": str(setup_root),
        "QUALIFIED_PYTHON": sys.executable,
        "RUNNER_TEMP": str(runner_temp),
        "TARGET": "macos-x64",
        "GITHUB_RUN_ID": "123",
    }
    sanitizer = _workflow_run_block("Sanitize public qualification status").replace(
        "${{ steps.qualify.outputs.status }}", "failed"
    )

    sanitized = _run_workflow_block(sanitizer, environment)

    assert sanitized.returncode != 0
    assert not (setup_root / "work" / "upload" / "warnings.json").exists()


def test_public_docs_describe_preview_without_download_instructions() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "standalone-cli.md").read_text(encoding="utf-8")
    assert "not published or downloadable yet" in readme.replace("\n", " ")
    assert "not installers, signed releases, or supported downloads" in guide
    assert "Desktop rendering" in guide
    assert "voice runtimes" in guide
