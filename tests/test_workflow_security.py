"""Security contracts for the GitHub Actions workflows.

The workflows are parsed with a small line-based reader instead of a YAML
library, so these checks carry no extra test dependency. Every workflow uses
two-space job keys and six-space step items, which the reader relies on.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"
WORKFLOWS = GITHUB / "workflows"
ALL_WORKFLOWS = sorted(WORKFLOWS.glob("*.yml"))
# Workflows whose third-party actions are pinned to commit SHAs here. The
# packaging workflows and the local composite action carry their own pins.
SHA_PINNED_WORKFLOWS = (
    "ci.yml",
    "desktop-probe.yml",
    "leak-guard.yml",
    "publish.yml",
    "release-candidate.yml",
    "release.yml",
)

_PINNED_USES = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40} # v[0-9]+(\.[0-9]+)*$"
)
_DEFAULT_PYTHON_PIP_INSTALL = re.compile(
    r"^\s*(?:run:\s*)?(?:python3?\s+-m\s+pip|pip3?)\s+(?:\S+\s+)*?install\b",
    re.MULTILINE,
)


def _top_level_block(source: str, key: str) -> list[str] | None:
    """The entries of a top-level mapping key, or its inline value as one entry."""
    lines = source.splitlines()
    starts = [index for index, line in enumerate(lines) if line.startswith(f"{key}:")]
    if not starts:
        return None
    start = starts[0]
    inline = lines[start].split(":", 1)[1].strip()
    if inline:
        return [f"all: {inline}"]
    block = []
    for line in lines[start + 1 :]:
        if line and not line.startswith(" "):
            break
        if line.strip() and not line.lstrip().startswith("#"):
            block.append(line.strip())
    return block


def _jobs(source: str) -> dict[str, str]:
    body = source.split("\njobs:\n", 1)[1]
    sections = re.split(r"^  ([A-Za-z0-9_-]+):[ \t]*\n", body, flags=re.MULTILINE)
    return dict(zip(sections[1::2], sections[2::2], strict=True))


def _steps(job: str) -> list[str]:
    if "    steps:\n" not in job:
        return []
    body = job.split("    steps:\n", 1)[1]
    return re.split(r"^      - ", body, flags=re.MULTILINE)[1:]


def _uses(text: str) -> list[str]:
    return [
        match.strip()
        for match in re.findall(r"^\s*(?:- )?uses: (.+)$", text, flags=re.MULTILINE)
    ]


JOBS = [
    (path.name, name, job)
    for path in ALL_WORKFLOWS
    for name, job in _jobs(path.read_text(encoding="utf-8")).items()
]
JOB_IDS = [f"{workflow}:{name}" for workflow, name, _ in JOBS]


@pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=lambda path: path.name)
def test_every_workflow_declares_read_only_top_level_permissions(path: Path) -> None:
    block = _top_level_block(path.read_text(encoding="utf-8"), "permissions")
    assert block, f"{path.name} must declare top-level permissions"
    for entry in block:
        scope, _, level = entry.partition(":")
        assert level.strip() in {"read", "none", "read-all", "{}"}, (
            f"{path.name} grants {scope} {level.strip()} to every job; "
            "grant writes per job instead"
        )


@pytest.mark.parametrize("workflow,job_name,job", JOBS, ids=JOB_IDS)
def test_checkouts_that_never_push_drop_their_credentials(
    workflow: str, job_name: str, job: str
) -> None:
    if "git push" in job:
        return
    for step in _steps(job):
        if "actions/checkout@" in step:
            assert "persist-credentials: false" in step, (workflow, job_name)


def test_only_the_release_job_may_keep_checkout_credentials() -> None:
    pushing = [(workflow, name) for workflow, name, job in JOBS if "git push" in job]
    assert pushing == [("release.yml", "release")]


@pytest.mark.parametrize("workflow", SHA_PINNED_WORKFLOWS)
def test_actions_are_pinned_to_commit_shas(workflow: str) -> None:
    uses = _uses((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    assert uses
    for reference in uses:
        if reference.startswith("./"):
            continue
        assert _PINNED_USES.fullmatch(reference), f"{workflow}: {reference}"


def test_nothing_downloads_a_moving_latest_release() -> None:
    sources = [*ALL_WORKFLOWS, *GITHUB.glob("actions/*/action.yml")]
    for path in sources:
        assert "releases/latest" not in path.read_text(encoding="utf-8"), path.name


@pytest.mark.parametrize("workflow,job_name,job", JOBS, ids=JOB_IDS)
def test_pip_installs_run_after_setup_python(
    workflow: str, job_name: str, job: str
) -> None:
    """The runner's system Python is externally managed; pip needs setup-python."""
    has_setup_python = False
    for step in _steps(job):
        if "actions/setup-python@" in step:
            has_setup_python = True
        if _DEFAULT_PYTHON_PIP_INSTALL.search(step):
            assert has_setup_python, (workflow, job_name)


def test_dependabot_updates_every_pinned_action() -> None:
    source = (GITHUB / "dependabot.yml").read_text(encoding="utf-8")
    assert "package-ecosystem: github-actions" in source
    assert '- "/"' in source
    for action in GITHUB.glob("actions/*/action.yml"):
        assert f'- "/.github/actions/{action.parent.name}"' in source



def test_dependabot_pull_requests_skip_release_notes() -> None:
    source = (GITHUB / "dependabot.yml").read_text(encoding="utf-8")
    assert "      - skip-changelog\n" in source


def _run_leak_guard(tmp_path: Path, commit_message: str) -> subprocess.CompletedProcess:
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=ci", "-c", "user.email=ci@example.com"]
    subprocess.run([*git, "init", "-q"], check=True)
    (repo / "notes.txt").write_text("base\n", encoding="utf-8")
    subprocess.run([*git, "add", "notes.txt"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "base"], check=True)
    base = subprocess.run(
        [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    (repo / "notes.txt").write_text("head\n", encoding="utf-8")
    subprocess.run([*git, "commit", "-q", "-am", commit_message], check=True)
    env = {
        **os.environ,
        "BASE_SHA": base,
        "HEAD_SHA": "HEAD",
        "ALLOWLIST_FILE": str(GITHUB / "leak-allowlist.txt"),
    }
    return subprocess.run(
        ["bash", str(GITHUB / "scripts" / "leak-scan.sh")],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_leak_guard_accepts_the_dependabot_sign_off(tmp_path: Path) -> None:
    result = _run_leak_guard(
        tmp_path,
        "build(deps): bump actions\n\nSigned-off-by: dependabot[bot] <support@github.com>\n",  # leak-guard:allow
    )
    assert result.returncode == 0, result.stdout


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_leak_guard_still_flags_other_addresses_in_commits(tmp_path: Path) -> None:
    address = "someone@mail.invalid"  # leak-guard:allow (deliberate fixture)
    result = _run_leak_guard(tmp_path, f"fix: note\n\nContact: {address}\n")
    assert result.returncode != 0
    assert "email shape matched" in result.stdout
    assert address not in result.stdout

def _mcp_publisher_script() -> str:
    source = (WORKFLOWS / "publish.yml").read_text(encoding="utf-8")
    step = next(
        step
        for step in _steps(_jobs(source)["mcp-registry"])
        if step.startswith("name: Install mcp-publisher")
    )
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


def test_mcp_publisher_is_pinned_to_a_release_and_checksum() -> None:
    source = (WORKFLOWS / "publish.yml").read_text(encoding="utf-8")
    assert re.search(r"MCP_PUBLISHER_VERSION: v[0-9]+\.[0-9]+\.[0-9]+\n", source)
    assert re.search(r"MCP_PUBLISHER_SHA256: [0-9a-f]{64}\n", source)
    script = _mcp_publisher_script()
    assert script.index("sha256sum --check") < script.index("tar xzf")
    assert "| tar" not in script


def _run_mcp_publisher_install(
    tmp_path: Path, expected_sha256: str
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text(
        '#!/bin/sh\nwhile [ "$#" -gt 0 ] && [ "$1" != "-o" ]; do shift; done\n'
        'printf "archive" > "$2"\n',
        encoding="utf-8",
    )
    (bin_dir / "tar").write_text(
        '#!/bin/sh\ntouch "$TAR_MARKER"\n', encoding="utf-8"
    )
    (bin_dir / "uname").write_text(
        '#!/bin/sh\n[ "$1" = "-s" ] && echo Linux || echo x86_64\n', encoding="utf-8"
    )
    for stub in bin_dir.iterdir():
        stub.chmod(0o755)
    return subprocess.run(
        ["bash", "-c", _mcp_publisher_script()],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "MCP_PUBLISHER_VERSION": "v1.0.0",
            "MCP_PUBLISHER_SHA256": expected_sha256,
            "TAR_MARKER": str(tmp_path / "extracted"),
        },
    )


needs_sha256sum = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sha256sum") is None,
    reason="Runs the Linux runner script with POSIX shell stubs",
)


@needs_sha256sum
def test_mcp_publisher_archive_is_rejected_before_extraction(tmp_path: Path) -> None:
    result = _run_mcp_publisher_install(tmp_path, "0" * 64)
    assert result.returncode != 0
    assert not (tmp_path / "extracted").exists()


@needs_sha256sum
def test_mcp_publisher_archive_is_extracted_when_the_checksum_matches(
    tmp_path: Path,
) -> None:
    result = _run_mcp_publisher_install(
        tmp_path, hashlib.sha256(b"archive").hexdigest()
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "extracted").exists()


def test_ci_runs_the_desktop_suite_with_its_dependencies_required() -> None:
    job = _jobs((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))["desktop-host"]
    assert '.[test,desktop-test]"' in job
    assert 'SERVONAUT_REQUIRE_DESKTOP_TESTS: "1"' in job
    assert "pytest --tb=short -q tests/desktop" in job


def test_desktop_test_extra_matches_the_desktop_shell_pins() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    extra = re.search(r"^desktop-test = \[(.*)\]$", pyproject, re.MULTILINE)
    assert extra is not None
    pins = set(re.findall(r'"([^"]+)"', extra.group(1)))
    shipped = (
        ROOT / "packaging/desktop_shell/requirements/requirements.in"
    ).read_text(encoding="utf-8")
    for pin in pins:
        assert re.search(rf"^{re.escape(pin)}$", shipped, re.MULTILINE), pin
    assert {pin.split("==")[0] for pin in pins} == {"aiohttp", "textual-serve"}


def _collect_desktop_tests(
    tmp_path: Path, *, required: bool
) -> subprocess.CompletedProcess[str]:
    # A package that reports itself missing stands in for an absent
    # dependency, even where the real one is installed.
    blocked = tmp_path / "blocked"
    (blocked / "aiohttp").mkdir(parents=True)
    (blocked / "aiohttp" / "__init__.py").write_text(
        'raise ModuleNotFoundError("No module named \'aiohttp\'", name="aiohttp")\n',
        encoding="utf-8",
    )
    env = {**os.environ, "PYTHONPATH": str(blocked)}
    env.pop("SERVONAUT_REQUIRE_DESKTOP_TESTS", None)
    if required:
        env["SERVONAUT_REQUIRE_DESKTOP_TESTS"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "tests/desktop",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def test_desktop_tests_skip_a_missing_host_dependency_by_default(
    tmp_path: Path,
) -> None:
    result = _collect_desktop_tests(tmp_path, required=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_desktop_tests_fail_on_a_missing_host_dependency_when_required(
    tmp_path: Path,
) -> None:
    result = _collect_desktop_tests(tmp_path, required=True)
    assert result.returncode != 0
    assert "servonaut[desktop-test]" in result.stdout + result.stderr
