"""Static contract tests for the desktop shell CI qualification workflow."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_PATH = _REPO_ROOT / ".github" / "workflows" / "desktop-shell.yml"


@pytest.fixture(scope="module")
def workflow_content() -> str:
    """Read the workflow content."""
    assert _WORKFLOW_PATH.is_file(), f"Workflow not found at {_WORKFLOW_PATH}"
    return _WORKFLOW_PATH.read_text(encoding="utf-8")


def test_workflow_permissions_read_only(workflow_content: str):
    """Workflow must only declare contents: read permissions."""
    assert "permissions:\n  contents: read" in workflow_content
    # Ensure no write permissions are granted
    assert "contents: write" not in workflow_content
    assert "packages: write" not in workflow_content
    assert "actions: write" not in workflow_content
    assert "pull_request_target" not in workflow_content


def test_workflow_no_secrets(workflow_content: str):
    """Workflow must not reference any signing credentials or secrets."""
    assert "secrets." not in workflow_content
    assert "CSC_LINK" not in workflow_content
    assert "APPLE_CERTIFICATE" not in workflow_content
    assert "AZURE_KEY_VAULT" not in workflow_content


def test_checkout_persist_credentials_false(workflow_content: str):
    """All checkout steps must specify persist-credentials: false."""
    checkouts = re.findall(r"uses:\s*actions/checkout@[^\n]+", workflow_content)
    persist_false = re.findall(r"persist-credentials:\s*false", workflow_content)
    assert len(checkouts) > 0
    assert len(checkouts) == len(persist_false)


def test_qualification_matrix_covers_all_four_targets(workflow_content: str):
    """Matrix must contain all four targeted platform architectures."""
    required_targets = [
        "linux-x64-ubuntu-22.04",
        "windows-x64",
        "macos-x64",
        "macos-arm64",
    ]
    for target in required_targets:
        assert f"target: {target}" in workflow_content

    assert "fail-fast: false" in workflow_content


def test_contract_job_gates_qualification(workflow_content: str):
    """Contract job must run first and qualify job must depend on it."""
    assert "contract:" in workflow_content
    assert "qualify:" in workflow_content
    assert "needs: contract" in workflow_content


def test_qualification_steps_orchestration(workflow_content: str):
    """Qualify job must invoke build, inspect, and smoke scripts."""
    assert "scripts.desktop_shell.build" in workflow_content
    assert "scripts.desktop_shell.inspect" in workflow_content
    assert "scripts.desktop_shell.smoke_artifact" in workflow_content


def test_no_runnable_executables_retained(workflow_content: str):
    """Workflow must delete executables and only upload sanitized non-executable evidence."""
    # Ensure cleanup step runs always
    assert "Cleanup build material and executables" in workflow_content
    assert "rm -rf" in workflow_content

    # Ensure upload step only retains *.json files
    upload_section = workflow_content.split(
        "Upload sanitized qualification evidence", 1
    )[1]
    upload_block = upload_section.split("Cleanup build material", 1)[0]
    assert "path: ${{ steps.paths.outputs.upload-dir }}/*.json" in upload_block
    assert "retention-days: 1" in upload_block
    assert "*.whl" not in upload_block
    assert "*.exe" not in upload_block


def _job_block(workflow_content: str, job: str) -> str:
    jobs = workflow_content.split("\njobs:\n", 1)[1]
    blocks = re.split(r"\n  (?=[a-z][a-z-]*:\n)", "\n" + jobs)
    return next(block for block in blocks if block.startswith(f"{job}:\n"))


def test_remote_actions_are_pinned_to_commit_shas(workflow_content: str):
    """Every remote action is pinned to a full commit SHA with a version comment."""
    uses = re.findall(r"uses:\s*(\S+)(.*)", workflow_content)
    assert uses
    for reference, comment in uses:
        if reference.startswith("./"):
            continue
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", reference), reference
        assert re.fullmatch(r"\s*# v\d+\.\d+\.\d+", comment), reference


def test_every_job_has_a_timeout(workflow_content: str):
    for job in ("contract", "qualify"):
        assert re.search(r"\n    timeout-minutes: \d+\n", _job_block(workflow_content, job))


def test_path_filters_cover_the_shared_standalone_tooling(workflow_content: str):
    """The desktop build, inspect and smoke import the standalone tooling."""
    for trigger in ("push:", "pull_request:"):
        block = workflow_content.split(f"  {trigger}\n", 1)[1].split("\n  workflow_dispatch", 1)[0]
        paths = block.split("paths:\n", 1)[1].split("\n  pull_request:", 1)[0]
        assert "- 'scripts/standalone_cli/**'" in paths
        assert "- 'packaging/standalone_cli/**'" in paths
        assert "- '.github/actions/setup-standalone-cli/**'" in paths


def test_qualification_toolchain_is_hash_locked(workflow_content: str):
    qualify = _job_block(workflow_content, "qualify")
    assert "uses: ./.github/actions/setup-standalone-cli" in qualify
    assert "--upgrade" not in workflow_content
    assert "python -m build" not in workflow_content
    assert "pip install pyinstaller" not in workflow_content
    installs = [line for line in qualify.splitlines() if " install " in line]
    assert installs
    assert all("--require-hashes" in line for line in installs)
    assert "qualification-tools-${TARGET}.txt" in qualify


def test_contract_dependencies_are_pinned(workflow_content: str):
    contract = _job_block(workflow_content, "contract")
    assert '"pyinstaller==6.22.3"' in contract
    assert '"textual-serve==1.1.3"' in contract


def test_inspect_and_smoke_receive_build_metadata(workflow_content: str):
    qualify = _job_block(workflow_content, "qualify")
    for module in ("scripts.desktop_shell.inspect", "scripts.desktop_shell.smoke_artifact"):
        step = qualify.split(module, 1)[1].split("\n      - ", 1)[0]
        assert '--build-metadata "${METADATA_DIR}"' in step


def test_selftest_skip_is_documented(workflow_content: str):
    qualify = _job_block(workflow_content, "qualify")
    smoke = qualify.split("- name: Run policy-bound smoke checks", 1)
    assert "# --skip-selftest:" in smoke[0].rsplit("\n      - ", 1)[-1]
    assert "--skip-selftest" in smoke[1]
