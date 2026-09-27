"""Contract tests for the workflow that attaches the install scripts to releases.

Static checks pin its triggers, permissions and step order; the steps that
decide, take, verify and upload the scripts also run here for real, under
bash, with the environment the workflow gives them.
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

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_WORKFLOW_PATH = _WORKFLOWS / "release-install-scripts.yml"
_SUMS_ASSET = "install-scripts_SHA256SUMS"
_ASSETS = ("install.sh", "install.ps1", _SUMS_ASSET)

needs_bash_tools = pytest.mark.skipif(
    sys.platform == "win32"
    or shutil.which("bash") is None
    or shutil.which("sha256sum") is None,
    reason="Runs the Linux runner scripts under bash",
)


@pytest.fixture(scope="module")
def workflow() -> str:
    return _WORKFLOW_PATH.read_text(encoding="utf-8")


def _job(workflow: str, name: str) -> str:
    jobs = workflow.split("\njobs:\n", 1)[1]
    blocks = re.split(r"\n  (?=[a-z][a-z-]*:\n)", "\n" + jobs)
    return next(block for block in blocks if block.startswith(f"{name}:\n"))


def _step(workflow: str, name: str) -> str:
    start = workflow.index(f"      - name: {name}\n")
    step = workflow[start:]
    following = re.search(r"\n      - ", step)
    return step[: following.start()] if following else step


def _script(workflow: str, name: str) -> str:
    block = _step(workflow, name).split("        run: |\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


def _run(
    script: str, tmp_path: Path, *, cwd: Path | None = None, **env: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    result = subprocess.run(
        ["bash", "-c", script],
        cwd=cwd or tmp_path,
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": os.environ["PATH"],
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
            "RUNNER_TEMP": str(tmp_path),
            **env,
        },
    )
    values = dict(
        line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines()
    )
    return result, values


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Triggers, permissions and isolation
# ---------------------------------------------------------------------------


def test_runs_for_published_releases_and_on_request_only(workflow: str) -> None:
    triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]

    # "published" covers pre-releases, so candidates carry the scripts too.
    assert "  release:\n    types: [published]\n" in triggers
    assert "  workflow_dispatch:\n" in triggers
    for trigger in ("push:", "pull_request", "schedule:", "workflow_run:", "workflow_call:"):
        assert trigger not in triggers
    for name in ("tag:", "dry_run:"):
        assert f"      {name}\n" in triggers
    assert "        type: boolean\n" in triggers.split("dry_run:", 1)[1]


def test_never_runs_for_forks(workflow: str) -> None:
    assert "    if: github.repository == 'zb-ss/servonaut'\n" in _job(workflow, "resolve")
    assert "    needs: resolve\n    if: needs.resolve.outputs.attach == 'true'\n" in _job(
        workflow, "prepare"
    )
    assert "    needs: [resolve, prepare]\n" in _job(workflow, "upload")


def test_each_job_has_the_least_privilege_it_needs(workflow: str) -> None:
    assert "\npermissions:\n  contents: read\n" in workflow
    assert "    permissions: {}\n" in _job(workflow, "resolve")
    assert "    permissions:\n      contents: read\n    outputs:" in _job(workflow, "prepare")
    upload = _job(workflow, "upload")
    granted = upload.split("    permissions:\n", 1)[1].split("\n    env:", 1)[0]
    assert re.findall(r"^      ([a-z-]+): (\w+)$", granted, re.MULTILINE) == [
        ("contents", "write"),
    ]
    for job in ("resolve", "prepare"):
        assert "write" not in _job(workflow, job).split("\n    steps:", 1)[0]


def test_only_the_built_in_token_reaches_the_upload_steps(workflow: str) -> None:
    assert "secrets." not in workflow
    assert "github.token" not in _job(workflow, "resolve")
    assert "github.token" not in _job(workflow, "prepare")
    upload = _job(workflow, "upload")
    assert upload.count("GH_TOKEN: ${{ github.token }}") == 2
    assert "GH_TOKEN" not in upload.split("\n    steps:", 1)[0]


def test_the_upload_job_runs_no_repository_code(workflow: str) -> None:
    upload = _job(workflow, "upload")

    assert "actions/checkout" not in upload
    assert "python" not in upload
    assert "uses: ./" not in upload
    # The scripts are only measured and uploaded, never run.
    assert not re.search(r"(?<![\w.])(?:ba)?sh \S*scripts/", upload)
    assert "./scripts/" not in upload


def test_checkouts_keep_no_credentials(workflow: str) -> None:
    checkouts = re.findall(r"uses: actions/checkout@", workflow)

    assert len(checkouts) == 1
    assert workflow.count("persist-credentials: false") == len(checkouts)


def test_actions_are_pinned_like_the_other_release_workflows(workflow: str) -> None:
    uses = re.findall(r"uses:\s*(\S+)(.*)", workflow)
    assert uses
    for reference, comment in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", reference), reference
        assert re.fullmatch(r"\s*# v\d+\.\d+\.\d+", comment), reference
    shared = {
        reference
        for path in ("desktop-preview-deb.yml", "publish.yml")
        for reference in re.findall(r"uses:\s*(\S+)", (_WORKFLOWS / path).read_text("utf-8"))
    }
    assert {reference for reference, _ in uses} <= shared


def test_the_pypi_publish_does_not_wait_for_it(workflow: str) -> None:
    publish = (_WORKFLOWS / "publish.yml").read_text(encoding="utf-8")

    assert "install-scripts" not in publish
    assert "workflow_run" not in workflow
    assert "publish.yml" not in workflow


def test_every_job_has_a_timeout(workflow: str) -> None:
    for job in ("resolve", "prepare", "upload"):
        assert re.search(r"\n    timeout-minutes: \d+\n", _job(workflow, job)), job


def test_runs_for_one_tag_queue_instead_of_cancelling(workflow: str) -> None:
    assert (
        "\nconcurrency:\n"
        "  group: release-install-scripts-${{ github.event.release.tag_name || inputs.tag"
        " || github.ref }}\n"
        "  cancel-in-progress: false\n"
    ) in workflow


def test_inputs_reach_scripts_only_through_the_environment(workflow: str) -> None:
    run_blocks = re.findall(r"\n        run: \|\n(.*?)(?=\n      - |\n  [a-z]|\Z)", workflow, re.S)

    assert run_blocks
    assert not re.findall(r"\n        run: (?!\|)(.*)", workflow)
    for block in run_blocks:
        assert "${{" not in block


def test_only_the_scripts_leave_the_prepare_job(workflow: str) -> None:
    handoff = _step(_job(workflow, "prepare"), "Hand the scripts to the upload job")

    assert "name: install-scripts\n" in handoff
    assert "path: |\n            install.sh\n            install.ps1\n" in handoff
    assert "retention-days: 1\n" in handoff
    assert "if-no-files-found: error\n" in handoff
    assert "overwrite: true\n" in handoff
    assert "name: install-scripts\n" in _step(_job(workflow, "upload"), "Receive the scripts")


def test_the_scripts_are_checked_before_they_are_uploaded(workflow: str) -> None:
    upload = _job(workflow, "upload")
    order = [
        "- name: Receive the scripts",
        "- name: Verify the scripts and write their checksums",
        "- name: Confirm the release and its tag",
        "- name: Upload the scripts to the release",
    ]
    positions = [upload.index(marker) for marker in order]

    assert positions == sorted(positions)
    assert "continue-on-error" not in workflow
    assert "if: always()" not in workflow
    assert "if: env.DRY_RUN != 'true'" in _step(upload, "Upload the scripts to the release")
    assert "if: env.TAG != ''" in _step(upload, "Confirm the release and its tag")


def test_the_upload_replaces_only_its_own_assets(workflow: str) -> None:
    upload = _step(_job(workflow, "upload"), "Upload the scripts to the release")

    assert (
        'gh release upload "${TAG}" scripts/install.sh scripts/install.ps1 '
        '"scripts/${SUMS_ASSET}" --clobber'
    ) in upload
    assert f"      SUMS_ASSET: {_SUMS_ASSET}\n" in _job(workflow, "upload")
    for forbidden in ("gh release delete", "delete-asset", "gh release create", "gh release edit"):
        assert forbidden not in workflow
    assert 'sha256sum --check --strict "${SUMS_ASSET}"' in upload


# ---------------------------------------------------------------------------
# The resolve step, executed
# ---------------------------------------------------------------------------


def _resolve(workflow: str, tmp_path: Path, **env: str):
    return _run(
        _script(workflow, "Decide what to attach"),
        tmp_path,
        **{
            "GITHUB_SHA": "c" * 40,
            "RELEASE_TAG": "",
            "INPUT_TAG": "",
            "INPUT_DRY_RUN": "",
            **env,
        },
    )


@pytest.mark.parametrize("tag", ["v2.28.0rc1", "v2.28.0", "v3.0.0rc12"])
def test_a_published_release_attaches_its_tag(workflow: str, tmp_path: Path, tag: str) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF=f"refs/tags/{tag}",
        RELEASE_TAG=tag,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs == {
        "attach": "true",
        "tag": tag,
        "dry-run": "false",
        "checkout-ref": f"refs/tags/{tag}",
        "expected-commit": "c" * 40,
    }


@pytest.mark.parametrize("tag", ["v2.28.0-preview.1", "desktop-1", "v2.28.0a1"])
def test_other_releases_are_skipped_without_failing(
    workflow: str, tmp_path: Path, tag: str
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF=f"refs/tags/{tag}",
        RELEASE_TAG=tag,
    )

    assert result.returncode == 0, result.stderr
    assert outputs == {"attach": "false"}


def test_a_release_event_for_another_ref_fails(workflow: str, tmp_path: Path) -> None:
    result, _ = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF="refs/tags/v2.27.0",
        RELEASE_TAG="v2.28.0",
    )

    assert result.returncode == 1


def test_a_re_run_from_a_branch_takes_the_tags_scripts(workflow: str, tmp_path: Path) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/master",
        INPUT_TAG="v2.28.0",
        INPUT_DRY_RUN="false",
    )

    assert result.returncode == 0, result.stderr
    assert outputs["dry-run"] == "false"
    assert outputs["checkout-ref"] == "refs/tags/v2.28.0"
    # The branch's commit is not the tag's; the tag decides what is attached.
    assert outputs["expected-commit"] == ""


def test_a_re_run_on_the_tag_expects_its_commit(workflow: str, tmp_path: Path) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/tags/v2.28.0rc1",
        INPUT_TAG="v2.28.0rc1",
        INPUT_DRY_RUN="true",
    )

    assert result.returncode == 0, result.stderr
    assert outputs["dry-run"] == "true"
    assert outputs["checkout-ref"] == "refs/tags/v2.28.0rc1"
    assert outputs["expected-commit"] == "c" * 40


def test_a_dry_run_without_a_tag_checks_its_own_commit(workflow: str, tmp_path: Path) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/feature",
        INPUT_DRY_RUN="true",
    )

    assert result.returncode == 0, result.stderr
    assert outputs == {
        "attach": "true",
        "tag": "",
        "dry-run": "true",
        "checkout-ref": "c" * 40,
        "expected-commit": "c" * 40,
    }


@pytest.mark.parametrize(
    "tag,dry_run",
    [("", "false"), ("2.28.0", "false"), ("v2.28.0-preview.1", "true"), ("master", "true")],
)
def test_invalid_requests_are_refused(
    workflow: str, tmp_path: Path, tag: str, dry_run: str
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/master",
        INPUT_TAG=tag,
        INPUT_DRY_RUN=dry_run,
    )

    assert result.returncode == 1
    assert "::error::" in result.stdout
    assert outputs == {}


def test_other_events_are_refused(workflow: str, tmp_path: Path) -> None:
    result, outputs = _resolve(
        workflow, tmp_path, GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/master"
    )

    assert result.returncode == 1
    assert outputs == {}


# ---------------------------------------------------------------------------
# The prepare job, executed
# ---------------------------------------------------------------------------


def _checkout(tmp_path: Path, *, with_workflow: bool) -> tuple[Path, str]:
    repo = tmp_path / "checkout"
    repo.mkdir()
    (repo / "install.sh").write_text("#!/bin/sh\necho install\n", encoding="utf-8")
    (repo / "install.ps1").write_text("Write-Host install\n", encoding="utf-8")
    if with_workflow:
        (repo / ".github" / "workflows").mkdir(parents=True)
        (repo / ".github" / "workflows" / "release-install-scripts.yml").write_text(
            "name: stand-in\n", encoding="utf-8"
        )
    git = ["git", "-C", str(repo), "-c", "user.name=ci", "-c", "user.email=ci@example.com"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "scripts"], check=True)
    commit = subprocess.run(
        [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    return repo, commit


def _take_scripts(workflow: str, tmp_path: Path, repo: Path, **env: str):
    return _run(
        _script(workflow, "Take the scripts from the commit"),
        tmp_path,
        cwd=repo,
        **{"TAG": "v2.28.0", "EXPECTED_COMMIT": "", **env},
    )


@needs_bash_tools
@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_the_prepare_job_measures_the_tagged_scripts(workflow: str, tmp_path: Path) -> None:
    repo, commit = _checkout(tmp_path, with_workflow=True)

    result, outputs = _take_scripts(workflow, tmp_path, repo, EXPECTED_COMMIT=commit)

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs == {
        "commit": commit,
        "sh-sha256": _sha256(repo / "install.sh"),
        "ps1-sha256": _sha256(repo / "install.ps1"),
    }


@needs_bash_tools
@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_the_prepare_job_refuses_a_tag_that_predates_it(workflow: str, tmp_path: Path) -> None:
    """Older scripts install the default branch when PyPI fails."""
    repo, _ = _checkout(tmp_path, with_workflow=False)

    result, outputs = _take_scripts(workflow, tmp_path, repo)

    assert result.returncode == 1
    assert "::error::v2.28.0 predates the release install scripts" in result.stdout
    assert outputs == {}


@needs_bash_tools
@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_the_prepare_job_refuses_a_moved_tag(workflow: str, tmp_path: Path) -> None:
    repo, _ = _checkout(tmp_path, with_workflow=True)

    result, outputs = _take_scripts(workflow, tmp_path, repo, EXPECTED_COMMIT="d" * 40)

    assert result.returncode == 1
    assert "no longer points at the commit" in result.stdout
    assert outputs == {}


# ---------------------------------------------------------------------------
# The upload job, executed
# ---------------------------------------------------------------------------


def _received(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    scripts = workspace / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "install.sh").write_text("#!/bin/sh\necho install\n", encoding="utf-8")
    (scripts / "install.ps1").write_text("Write-Host install\n", encoding="utf-8")
    return workspace


def _verify(workflow: str, tmp_path: Path, workspace: Path, **env: str):
    scripts = workspace / "scripts"
    return _run(
        _script(workflow, "Verify the scripts and write their checksums"),
        tmp_path,
        cwd=scripts,
        **{
            "SUMS_ASSET": _SUMS_ASSET,
            "SH_SHA256": _sha256(scripts / "install.sh"),
            "PS1_SHA256": _sha256(scripts / "install.ps1"),
            **env,
        },
    )


@needs_bash_tools
def test_the_upload_job_writes_checksums_users_can_check(
    workflow: str, tmp_path: Path
) -> None:
    workspace = _received(tmp_path)

    result, _ = _verify(workflow, tmp_path, workspace)

    assert result.returncode == 0, result.stderr + result.stdout
    scripts = workspace / "scripts"
    assert (scripts / _SUMS_ASSET).read_text(encoding="utf-8") == (
        f"{_sha256(scripts / 'install.sh')}  install.sh\n"
        f"{_sha256(scripts / 'install.ps1')}  install.ps1\n"
    )
    checked = subprocess.run(
        ["sha256sum", "--check", "--strict", _SUMS_ASSET], cwd=scripts, check=False
    )
    assert checked.returncode == 0


@needs_bash_tools
def test_the_upload_job_refuses_scripts_it_was_not_promised(
    workflow: str, tmp_path: Path
) -> None:
    workspace = _received(tmp_path)

    result, _ = _verify(workflow, tmp_path, workspace, SH_SHA256="0" * 64)

    assert result.returncode != 0
    assert not (workspace / "scripts" / _SUMS_ASSET).exists()


@needs_bash_tools
def test_the_upload_job_refuses_an_unexpected_file(workflow: str, tmp_path: Path) -> None:
    workspace = _received(tmp_path)
    (workspace / "scripts" / "extra.sh").write_text("echo extra\n", encoding="utf-8")

    result, _ = _verify(workflow, tmp_path, workspace)

    assert result.returncode == 1
    assert "Expected exactly install.sh and install.ps1" in result.stdout


# A stand-in for gh: the release is a directory of assets.
_GH_STUB = r"""
gh() {
  printf '%s\n' "$*" >> "${TEST_GH_LOG}"
  case "$1 $2" in
    "release upload")
      shift 2
      local tag="$1"; shift
      for file in "$@"; do
        [ "${file}" = "--clobber" ] && continue
        cp "${file}" "${TEST_RELEASE}/"
        if [ -n "${TEST_CORRUPT:-}" ]; then printf 'x' >> "${TEST_RELEASE}/$(basename "${file}")"; fi
      done
      if [ -n "${TEST_DROP:-}" ]; then rm "${TEST_RELEASE}/${TEST_DROP}"; fi
      ;;
    "api repos/"*/releases/tags/*)
      [ -z "${TEST_NO_RELEASE:-}" ] || return 1
      ls -1 "${TEST_RELEASE}"
      ;;
    "api repos/"*/commits/refs/tags/*)
      echo "${TEST_TAGGED}"
      ;;
    "release download")
      local dir="" names=()
      shift 3
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --dir) dir="$2"; shift 2 ;;
          --pattern) names+=("$2"); shift 2 ;;
          *) shift ;;
        esac
      done
      for name in "${names[@]}"; do cp "${TEST_RELEASE}/${name}" "${dir}/"; done
      ;;
    *) return 1 ;;
  esac
}
"""


def _release_step(
    workflow: str, name: str, tmp_path: Path, **env: str
) -> subprocess.CompletedProcess[str]:
    workspace = _received(tmp_path)
    scripts = workspace / "scripts"
    (scripts / _SUMS_ASSET).write_text(
        "".join(f"{_sha256(scripts / n)}  {n}\n" for n in ("install.sh", "install.ps1")),
        encoding="utf-8",
    )
    release = tmp_path / "release"
    release.mkdir()
    for asset in ("notes.txt", *_ASSETS):
        (release / asset).write_text("published earlier\n", encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    (runner_temp / "assets-before").write_text(
        "".join(f"{path.name}\n" for path in sorted(release.iterdir())), encoding="utf-8"
    )
    return subprocess.run(
        ["bash", "-c", _GH_STUB + _script(workflow, name)],
        cwd=workspace,
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": os.environ["PATH"],
            "RUNNER_TEMP": str(runner_temp),
            "GH_REPO": "example/project",
            "TAG": "v2.28.0rc1",
            "COMMIT": "c" * 40,
            "DRY_RUN": "false",
            "SUMS_ASSET": _SUMS_ASSET,
            "TEST_RELEASE": str(release),
            "TEST_TAGGED": "c" * 40,
            "TEST_GH_LOG": str(tmp_path / "gh.log"),
            **env,
        },
    )


@needs_bash_tools
def test_the_upload_replaces_its_assets_and_checks_what_users_download(
    workflow: str, tmp_path: Path
) -> None:
    result = _release_step(workflow, "Upload the scripts to the release", tmp_path)

    assert result.returncode == 0, result.stderr + result.stdout
    release = tmp_path / "release"
    assert sorted(path.name for path in release.iterdir()) == sorted(["notes.txt", *_ASSETS])
    assert (release / "notes.txt").read_text(encoding="utf-8") == "published earlier\n"
    assert (release / "install.sh").read_text(encoding="utf-8") == "#!/bin/sh\necho install\n"
    calls = (tmp_path / "gh.log").read_text(encoding="utf-8").splitlines()
    assert calls[0] == (
        "release upload v2.28.0rc1 scripts/install.sh scripts/install.ps1 "
        f"scripts/{_SUMS_ASSET} --clobber"
    )
    assert not any("delete" in call for call in calls)


@needs_bash_tools
def test_the_upload_fails_if_another_asset_disappeared(workflow: str, tmp_path: Path) -> None:
    result = _release_step(
        workflow, "Upload the scripts to the release", tmp_path, TEST_DROP="notes.txt"
    )

    assert result.returncode == 1
    assert "::error::The upload removed another asset of v2.28.0rc1." in result.stdout


@needs_bash_tools
def test_the_upload_fails_if_the_published_scripts_do_not_match(
    workflow: str, tmp_path: Path
) -> None:
    result = _release_step(
        workflow, "Upload the scripts to the release", tmp_path, TEST_CORRUPT="1"
    )

    assert result.returncode != 0
    assert "FAILED" in result.stdout + result.stderr


@needs_bash_tools
def test_the_release_and_its_tag_are_confirmed(workflow: str, tmp_path: Path) -> None:
    result = _release_step(workflow, "Confirm the release and its tag", tmp_path)

    assert result.returncode == 0, result.stderr + result.stdout
    before = (tmp_path / "runner-temp" / "assets-before").read_text(encoding="utf-8")
    assert before.splitlines() == sorted(["notes.txt", *_ASSETS])


@needs_bash_tools
def test_a_moved_tag_is_not_given_the_scripts(workflow: str, tmp_path: Path) -> None:
    result = _release_step(
        workflow, "Confirm the release and its tag", tmp_path, TEST_TAGGED="d" * 40
    )

    assert result.returncode == 1
    assert "was moved after its install scripts were taken" in result.stdout


@needs_bash_tools
@pytest.mark.parametrize("dry_run,code", [("false", 1), ("true", 0)])
def test_a_missing_release_stops_a_real_run_only(
    workflow: str, tmp_path: Path, dry_run: str, code: int
) -> None:
    result = _release_step(
        workflow,
        "Confirm the release and its tag",
        tmp_path,
        DRY_RUN=dry_run,
        TEST_NO_RELEASE="1",
    )

    assert result.returncode == code, result.stderr + result.stdout
    assert "has no published release" in result.stdout
