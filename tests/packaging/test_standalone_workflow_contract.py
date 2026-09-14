"""Static contracts for standalone qualification workflow composition."""

from __future__ import annotations

import ast
import json
import os
import shlex
import stat
import subprocess
import sys
import textwrap
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
    assert "actions/upload-artifact@v7" in WORKFLOW
    assert "retention-days: 1" in WORKFLOW
    assert "if-no-files-found: error" in WORKFLOW
    assert "include-hidden-files: false" in WORKFLOW
    assert "Require successful qualification" in WORKFLOW
    assert "SOURCE_DATE_EPOCH" in WORKFLOW
    assert 'git -C "${GITHUB_WORKSPACE}" show -s --format=%ct' in WORKFLOW
    assert "qualification-status.json" in WORKFLOW
    assert "warning-candidates.json" in WORKFLOW
    assert "missing-baseline-candidate.json" in WORKFLOW


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
            and any(alias.name in {"json", "os"} for alias in node.names)
        )
        or (
            isinstance(node, ast.ImportFrom)
            and node.module == "pathlib"
            and any(alias.name == "Path" for alias in node.names)
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
            }
        ),
        functions=frozenset({"_write_diagnostic_outcome"}),
    )
    writer = namespace["_write_diagnostic_outcome"]
    assert callable(writer)
    destination = outcome_root / "windows-pyinstaller-outcome-share-lock.json"

    monkeypatch.delenv("QUALIFICATION_SETUP_ROOT", raising=False)
    writer("share-lock", "expected-classifier")
    assert not destination.exists()

    monkeypatch.setenv("QUALIFICATION_SETUP_ROOT", str(outcome_root))
    writer("share-lock", "expected-classifier")
    assert destination.is_file()
    assert not destination.is_symlink()
    assert destination.relative_to(outcome_root).as_posix() == (
        "windows-pyinstaller-outcome-share-lock.json"
    )
    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "stage": "share-lock",
        "outcome": "expected-classifier",
    }
    with pytest.raises(FileExistsError):
        writer("share-lock", "expected-classifier")


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


def _run_windows_diagnostic_block(
    tmp_path: Path,
    *,
    preflight_fails: bool,
    failing_nodes: tuple[str, ...],
    outcome: str = "expected-classifier",
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
  if [ "${stage}" = share-lock ]; then
    case "${RECORD_KIND}" in
      missing) ;;
      missing-field) printf '{"schema_version":1,"stage":"%s"}\\n' "${stage}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      extra) printf '{"schema_version":1,"stage":"%s","outcome":"%s","extra":true}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      boolean) printf '{"schema_version":true,"stage":"%s","outcome":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      schema-string) printf '{"schema_version":"1","stage":"%s","outcome":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      duplicate) printf '{"schema_version":1,"schema_version":1,"stage":"%s","outcome":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      malformed) printf '{not json\\n' > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      oversized) printf '%4097s' '' | tr ' ' x > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      symlink)
        printf 'replacement\\n' > "${QUALIFICATION_SETUP_ROOT}/replacement.json"
        ln -s "${QUALIFICATION_SETUP_ROOT}/replacement.json" "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json"
        ;;
      stage-mismatch) printf '{"schema_version":1,"stage":"hook-import","outcome":"%s"}\\n' "${DIAGNOSTIC_OUTCOME}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      stage-number) printf '{"schema_version":1,"stage":1,"outcome":"%s"}\\n' "${DIAGNOSTIC_OUTCOME}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      outcome-number) printf '{"schema_version":1,"stage":"%s","outcome":1}\\n' "${stage}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      unknown-outcome) printf '{"schema_version":1,"stage":"%s","outcome":"unknown"}\\n' "${stage}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
      *) printf '{"schema_version":1,"stage":"%s","outcome":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json" ;;
    esac
  else
    printf '{"schema_version":1,"stage":"%s","outcome":"%s"}\\n' "${stage}" "${DIAGNOSTIC_OUTCOME}" > "${QUALIFICATION_SETUP_ROOT}/windows-pyinstaller-outcome-${stage}.json"
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
            f"Windows PyInstaller diagnostic outcome: {stage}: expected-classifier"
            in completed.stdout
        )
        assert node in _WINDOWS_DIAGNOSTIC_NODES


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
            f"Windows PyInstaller diagnostic outcome: {stage}: {outcome}"
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


def test_public_docs_describe_preview_without_download_instructions() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "standalone-cli.md").read_text(encoding="utf-8")
    assert "not published or downloadable yet" in readme.replace("\n", " ")
    assert "not installers, signed releases, or supported downloads" in guide
    assert "Desktop rendering" in guide
    assert "voice runtimes" in guide
