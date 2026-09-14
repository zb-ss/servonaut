"""Static contracts for standalone qualification workflow composition."""

from __future__ import annotations

import os
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
    selected_python = _write_shell_stub(tmp_path / "selected-python", "exit 19\n")
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
        """if [ \"$1\" = \"-c\" ]; then
  printf '9.8.7\\n'
  exit 0
fi
printf 'called\\n' > \"${HELPER_CALLS}\"
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
            """if [ \"$1\" = \"-c\" ]; then
  printf '9.8.7\\n'
  exit 0
fi
if [ \"$1\" = \"-m\" ]; then
  test \"${SOURCE_DATE_EPOCH:-}\" = 1700000000 || exit 29
  printf '%s\\n' \"${SOURCE_DATE_EPOCH}\" > \"${EPOCH_LOG}\"
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
