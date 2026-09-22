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
