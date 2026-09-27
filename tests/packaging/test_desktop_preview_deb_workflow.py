"""Contract tests for the workflow that attaches the desktop preview .deb to releases.

Static checks pin its triggers, permissions and step order; the steps that
decide, plan, package and verify also run here for real, under bash, with the
environment the workflow gives them.
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

from scripts.desktop_shell.linux_abi import (
    GUI_SMOKE_SYSTEM_DEPS,
    REQUIRED_SYSTEM_DEPS,
    SOURCE_BUILD_SYSTEM_DEPS,
)
from scripts.distribution.desktop_preview import (
    DesktopPreviewError,
    declared_versions,
    preview_for_tag,
)
from scripts.distribution.package_deb import REQUIRED_PAYLOAD_FILES, package_deb

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_WORKFLOW_PATH = _WORKFLOWS / "desktop-preview-deb.yml"
_ATTEST_PIN = (
    "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2"
)
_MAINTAINER = "Package Maintainer <maintainer@example.org>"
_HAS_DPKG_DEB = shutil.which("dpkg-deb") is not None


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
    workflow: str, name: str, tmp_path: Path, *, cwd: Path | None = None, **env: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    result = subprocess.run(
        ["bash", "-c", _script(workflow, name)],
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


# ---------------------------------------------------------------------------
# Triggers, permissions and isolation
# ---------------------------------------------------------------------------


def test_runs_for_published_releases_and_on_request_only(workflow: str) -> None:
    triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]

    assert "  release:\n    types: [published]\n" in triggers
    assert "  workflow_dispatch:\n" in triggers
    for trigger in ("push:", "pull_request", "schedule:", "workflow_run:", "workflow_call:"):
        assert trigger not in triggers
    for name in ("tag:", "dry_run:", "rehearsal_version:"):
        assert f"      {name}\n" in triggers
    assert "        type: boolean\n" in triggers.split("dry_run:", 1)[1]


def test_never_runs_for_forks(workflow: str) -> None:
    resolve = _job(workflow, "resolve")

    assert "    if: github.repository == 'zb-ss/servonaut'\n" in resolve
    assert "    needs: resolve\n    if: needs.resolve.outputs.build == 'true'\n" in _job(
        workflow, "qualify"
    )
    assert "    needs: [resolve, qualify]\n" in _job(workflow, "publish")


def test_each_job_has_the_least_privilege_it_needs(workflow: str) -> None:
    assert "\npermissions:\n  contents: read\n" in workflow
    assert "    permissions: {}\n" in _job(workflow, "resolve")
    assert "    permissions:\n      contents: read\n    outputs:" in _job(workflow, "qualify")
    publish = _job(workflow, "publish")
    granted = publish.split("    permissions:\n", 1)[1].split("\n    env:", 1)[0]
    assert re.findall(r"^      ([a-z-]+): (\w+)$", granted, re.MULTILINE) == [
        ("contents", "write"),
        ("id-token", "write"),
        ("attestations", "write"),
    ]
    for job in ("resolve", "qualify"):
        assert "write" not in _job(workflow, job).split("\n    steps:", 1)[0]


def test_only_the_built_in_token_reaches_the_publish_steps(workflow: str) -> None:
    assert "secrets." not in workflow
    assert "github.token" not in _job(workflow, "resolve")
    assert "github.token" not in _job(workflow, "qualify")
    publish = _job(workflow, "publish")
    assert publish.count("GH_TOKEN: ${{ github.token }}") == 2
    assert "GH_TOKEN" not in publish.split("\n    steps:", 1)[0]


def test_the_publish_job_runs_no_repository_code(workflow: str) -> None:
    publish = _job(workflow, "publish")

    assert "actions/checkout" not in publish
    assert "python" not in publish
    assert "scripts." not in publish
    assert "uses: ./" not in publish


def test_checkouts_keep_no_credentials(workflow: str) -> None:
    checkouts = re.findall(r"uses: actions/checkout@", workflow)

    assert len(checkouts) == 1
    assert workflow.count("persist-credentials: false") == len(checkouts)


def test_actions_are_pinned_like_the_desktop_qualification(workflow: str) -> None:
    uses = re.findall(r"uses:\s*(\S+)(.*)", workflow)
    assert uses
    for reference, comment in uses:
        if reference.startswith("./"):
            continue
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", reference), reference
        assert re.fullmatch(r"\s*# v\d+\.\d+\.\d+", comment), reference
    shared = {
        reference
        for path in ("desktop-shell.yml", "release-candidate.yml")
        for reference in re.findall(r"uses:\s*(\S+)", (_WORKFLOWS / path).read_text("utf-8"))
    }
    ours = {reference for reference, _ in uses if not reference.startswith("./")}
    assert ours - shared == {_ATTEST_PIN.split(" ", 1)[0]}
    assert f"uses: {_ATTEST_PIN}\n" in workflow


def test_the_pypi_publish_does_not_wait_for_it(workflow: str) -> None:
    publish = (_WORKFLOWS / "publish.yml").read_text(encoding="utf-8")

    assert "desktop" not in publish.lower()
    assert "workflow_run" not in workflow
    assert "publish.yml" not in workflow


def test_every_job_has_a_timeout(workflow: str) -> None:
    for job in ("resolve", "qualify", "publish"):
        assert re.search(r"\n    timeout-minutes: \d+\n", _job(workflow, job)), job


def test_runs_for_one_tag_queue_instead_of_cancelling(workflow: str) -> None:
    assert (
        "\nconcurrency:\n"
        "  group: desktop-preview-deb-${{ github.event.release.tag_name || inputs.tag"
        " || github.ref }}\n"
        "  cancel-in-progress: false\n"
    ) in workflow


def test_inputs_reach_scripts_only_through_the_environment(workflow: str) -> None:
    run_blocks = re.findall(r"\n        run: \|\n(.*?)(?=\n      - |\n  [a-z]|\Z)", workflow, re.S)
    one_liners = re.findall(r"\n        run: (?!\|)(.*)", workflow)

    assert run_blocks and one_liners
    for block in [*run_blocks, *one_liners]:
        assert "${{" not in block


# ---------------------------------------------------------------------------
# Qualification before anything is published
# ---------------------------------------------------------------------------


def _positions(job: str, markers: list[str]) -> list[int]:
    return [job.index(marker) for marker in markers]


def test_the_package_is_qualified_before_it_leaves_the_job(workflow: str) -> None:
    qualify = _job(workflow, "qualify")
    order = [
        "- name: Plan the preview from the release tag",
        "-m scripts.desktop_shell.build",
        "-m scripts.desktop_shell.inspect",
        "-m scripts.desktop_shell.smoke_artifact",
        "-m scripts.desktop_shell.window_smoke",
        "-m scripts.distribution.package_deb",
        "- name: Install, run and remove the package",
        "- name: Hand the qualified package to the publish job",
    ]
    positions = _positions(qualify, order)
    assert positions == sorted(positions)
    # No qualification step is allowed to fail and carry on.
    before_handoff = qualify.split("- name: Hand the qualified package", 1)[0]
    assert "continue-on-error" not in qualify
    assert "if: always()" not in before_handoff


def test_qualification_calls_the_desktop_scripts_like_the_desktop_workflow(
    workflow: str,
) -> None:
    qualify = _job(workflow, "qualify")
    smoke = _step(qualify, "Run policy-bound smoke checks")
    window = _step(qualify, "Run packaged window smoke")
    inspect = _step(qualify, "Inspect desktop onedir payload")

    assert "--selftest" in smoke.split()
    assert "--selftest-window" not in smoke
    for step in (smoke, inspect):
        assert '--build-metadata "${METADATA_DIR}"' in step
        assert '--product-version "${PRODUCT_VERSION}"' in step
        assert "PRODUCT_VERSION: ${{ steps.plan.outputs.product-version }}" in step
    assert 'xvfb-run --auto-servernum --server-args="-screen 0 1280x800x24"' in window
    assert '--screenshot "${SCREENSHOT_DIR}/desktop-window-${TARGET}.png"' in window
    assert "    runs-on: ubuntu-22.04\n" in qualify
    assert "      TARGET: linux-x64-ubuntu-22.04\n" in qualify


def test_the_build_is_the_checked_out_commit_with_locked_tools(workflow: str) -> None:
    qualify = _job(workflow, "qualify")
    build = _step(qualify, "Build internal desktop onedir payload")

    assert "uses: ./.github/actions/setup-standalone-cli" in qualify
    assert '--commit "${COMMIT}"' in build
    assert "COMMIT: ${{ steps.source.outputs.commit }}" in build
    installs = [line for line in qualify.splitlines() if "pip" in line and " install " in line]
    assert installs and all("--require-hashes" in line for line in installs)
    assert "--upgrade" not in workflow


def test_linux_system_packages_follow_the_abi_contract(workflow: str) -> None:
    step = _step(_job(workflow, "qualify"), "Install Linux GTK build and window packages")
    installed = set(step.split("--no-install-recommends", 1)[1].replace("\\", " ").split())

    assert installed == {*REQUIRED_SYSTEM_DEPS, *SOURCE_BUILD_SYSTEM_DEPS, *GUI_SMOKE_SYSTEM_DEPS}


def test_only_the_package_leaves_the_job_briefly(workflow: str) -> None:
    handoff = _step(_job(workflow, "qualify"), "Hand the qualified package to the publish job")
    evidence = _step(_job(workflow, "qualify"), "Upload qualification evidence")

    assert "name: desktop-preview-deb\n" in handoff
    assert "path: ${{ steps.package.outputs.deb-path }}\n" in handoff
    assert "retention-days: 1\n" in handoff
    assert "if-no-files-found: error\n" in handoff
    assert "*.json" in evidence and "*.png" in evidence
    assert ".deb" not in evidence
    assert "name: desktop-preview-deb\n" in _step(
        _job(workflow, "publish"), "Receive the qualified package"
    )


def test_a_rehearsal_sets_the_version_as_the_release_workflow_does(workflow: str) -> None:
    step = _step(_job(workflow, "qualify"), "Rehearse as a release commit")

    assert "if: needs.resolve.outputs.rehearsal-version != ''" in step
    assert 'run: python .github/scripts/release-policy.py set-version "${REHEARSAL_VERSION}"' in step
    qualify = _job(workflow, "qualify")
    assert qualify.index("Rehearse as a release commit") < qualify.index(
        "Plan the preview from the release tag"
    )


# ---------------------------------------------------------------------------
# Publishing: attestation, idempotent upload, dry runs
# ---------------------------------------------------------------------------


def test_the_package_is_attested_before_it_is_uploaded(workflow: str) -> None:
    publish = _job(workflow, "publish")
    attest = _step(publish, "Attest the package's build provenance")
    upload = _step(publish, "Upload the preview to the release")

    assert "subject-path: preview/${{ needs.qualify.outputs.deb-asset }}" in attest
    for step in (attest, upload):
        assert "if: env.DRY_RUN != 'true'" in step
    positions = _positions(
        publish,
        [
            "- name: Verify the package and write its checksums",
            "- name: Confirm the release and its tag",
            "- name: Attest the package's build provenance",
            "- name: Upload the preview to the release",
        ],
    )
    assert positions == sorted(positions)


def test_the_upload_replaces_only_its_own_assets(workflow: str) -> None:
    upload = _step(_job(workflow, "publish"), "Upload the preview to the release")

    assert (
        'gh release upload "${TAG}" "preview/${DEB_ASSET}" "preview/${SUMS_ASSET}" --clobber'
        in upload
    )
    assert "gh release delete" not in workflow
    assert "delete-asset" not in workflow
    assert "gh release create" not in workflow
    assert "gh release edit" not in workflow
    assert "--prerelease" not in workflow
    # What users download is checked against the published sums.
    assert 'sha256sum --check --strict "${SUMS_ASSET}"' in upload


def test_the_tag_must_still_name_the_built_commit(workflow: str) -> None:
    confirm = _step(_job(workflow, "publish"), "Confirm the release and its tag")

    assert 'gh api "repos/${GH_REPO}/commits/refs/tags/${TAG}"' in confirm
    assert '"${tagged}" != "${COMMIT}"' in confirm
    assert "if: env.REHEARSAL_VERSION == ''" in confirm


# ---------------------------------------------------------------------------
# The resolve step, executed
# ---------------------------------------------------------------------------


def _resolve(workflow: str, tmp_path: Path, **env: str):
    return _run(
        workflow,
        "Decide what to build",
        tmp_path,
        **{
            "GITHUB_SHA": "c" * 40,
            "RELEASE_TAG": "",
            "INPUT_TAG": "",
            "INPUT_DRY_RUN": "",
            "INPUT_REHEARSAL_VERSION": "",
            **env,
        },
    )


@pytest.mark.parametrize("tag", ["v2.28.0rc1", "v2.28.0", "v3.0.0rc12"])
def test_a_published_release_builds_its_tag(workflow: str, tmp_path: Path, tag: str) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF=f"refs/tags/{tag}",
        RELEASE_TAG=tag,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert outputs == {
        "build": "true",
        "tag": tag,
        "dry-run": "false",
        "rehearsal-version": "",
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
    assert outputs == {"build": "false"}


def test_a_release_event_for_another_ref_fails(workflow: str, tmp_path: Path) -> None:
    result, _ = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF="refs/tags/v2.27.0",
        RELEASE_TAG="v2.28.0",
    )

    assert result.returncode == 1


def test_a_re_run_publishes_from_the_tag_itself(workflow: str, tmp_path: Path) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/tags/v2.28.0rc1",
        INPUT_TAG="v2.28.0rc1",
        INPUT_DRY_RUN="false",
    )

    assert result.returncode == 0, result.stderr
    assert outputs["dry-run"] == "false"
    assert outputs["checkout-ref"] == "refs/tags/v2.28.0rc1"
    assert outputs["expected-commit"] == "c" * 40


def test_publishing_from_a_branch_is_refused(workflow: str, tmp_path: Path) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/master",
        INPUT_TAG="v2.28.0rc1",
        INPUT_DRY_RUN="false",
    )

    assert result.returncode == 1
    assert "--ref v2.28.0rc1 -f tag=v2.28.0rc1" in result.stdout
    assert outputs == {}


def test_a_dry_run_from_a_branch_builds_the_tag(workflow: str, tmp_path: Path) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/master",
        INPUT_TAG="v2.28.0",
        INPUT_DRY_RUN="true",
    )

    assert result.returncode == 0, result.stderr
    assert outputs["dry-run"] == "true"
    assert outputs["checkout-ref"] == "refs/tags/v2.28.0"
    # The branch's commit is not the tag's; the tag decides what is built.
    assert outputs["expected-commit"] == ""


def test_a_rehearsal_builds_its_own_commit_as_a_stand_in_tag(
    workflow: str, tmp_path: Path
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/feature/example",
        INPUT_DRY_RUN="true",
        INPUT_REHEARSAL_VERSION="2.28.0rc1",
    )

    assert result.returncode == 0, result.stderr
    assert outputs == {
        "build": "true",
        "tag": "v2.28.0rc1",
        "dry-run": "true",
        "rehearsal-version": "2.28.0rc1",
        "checkout-ref": "c" * 40,
        "expected-commit": "c" * 40,
    }


@pytest.mark.parametrize(
    ("tag", "dry_run", "rehearsal"),
    [
        ("", "false", "2.28.0rc1"),
        ("v2.28.0rc1", "true", "2.28.0rc1"),
        ("", "true", "2.28.0-rc1"),
        ("", "true", "v2.28.0rc1"),
        ("", "true", ""),
        ("v2.28.0; true", "true", ""),
        ("v2.28.0-preview.1", "true", ""),
    ],
)
def test_invalid_requests_are_refused(
    workflow: str, tmp_path: Path, tag: str, dry_run: str, rehearsal: str
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/master",
        INPUT_TAG=tag,
        INPUT_DRY_RUN=dry_run,
        INPUT_REHEARSAL_VERSION=rehearsal,
    )

    assert result.returncode == 1
    assert outputs == {}


def test_other_events_are_refused(workflow: str, tmp_path: Path) -> None:
    result, _ = _resolve(
        workflow, tmp_path, GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/master"
    )

    assert result.returncode == 1


@pytest.mark.parametrize(
    "tag",
    [
        "v0.0.0",
        "v2.28.0",
        "v2.28.0rc1",
        "v2.28.0rc0",
        "v02.28.0",
        "v2.28.0rc01",
        "v2.28",
        "v2.28.0.1",
        "2.28.0",
        "v2.28.0-rc1",
        "V2.28.0",
    ],
)
def test_the_step_and_the_planner_accept_the_same_tags(
    workflow: str, tmp_path: Path, tag: str
) -> None:
    result, outputs = _resolve(
        workflow,
        tmp_path,
        GITHUB_EVENT_NAME="release",
        GITHUB_REF=f"refs/tags/{tag}",
        RELEASE_TAG=tag,
    )
    try:
        preview_for_tag(tag)
        planned = True
    except DesktopPreviewError:
        planned = False

    assert result.returncode == 0
    assert (outputs["build"] == "true") is planned


# ---------------------------------------------------------------------------
# Plan, package and verify steps, executed
# ---------------------------------------------------------------------------


def test_the_plan_step_accepts_the_checkout_version(workflow: str, tmp_path: Path) -> None:
    version = declared_versions(_REPO_ROOT)[0]
    result, outputs = _run(
        workflow,
        "Plan the preview from the release tag",
        tmp_path,
        cwd=_REPO_ROOT,
        TAG=f"v{version}",
        QUALIFIED_PYTHON=sys.executable,
        GITHUB_WORKSPACE=str(_REPO_ROOT),
    )

    assert result.returncode == 0, result.stderr
    assert outputs == preview_for_tag(f"v{version}").outputs()


def test_the_plan_step_stops_a_tag_its_checkout_disagrees_with(
    workflow: str, tmp_path: Path
) -> None:
    result, outputs = _run(
        workflow,
        "Plan the preview from the release tag",
        tmp_path,
        cwd=_REPO_ROOT,
        TAG="v999.0.0rc1",
        QUALIFIED_PYTHON=sys.executable,
        GITHUB_WORKSPACE=str(_REPO_ROOT),
    )

    assert result.returncode == 1
    assert "::error::v999.0.0rc1 does not match the package version" in result.stderr
    assert outputs == {}


def test_the_plan_step_names_a_tag_that_predates_the_tooling(
    workflow: str, tmp_path: Path
) -> None:
    result, _ = _run(
        workflow,
        "Plan the preview from the release tag",
        tmp_path,
        TAG="v2.27.0",
        QUALIFIED_PYTHON=sys.executable,
        GITHUB_WORKSPACE=str(tmp_path),
    )

    assert result.returncode == 1
    assert "v2.27.0 predates the desktop preview packaging" in result.stdout


@pytest.fixture
def payload(tmp_path: Path) -> Path:
    root = tmp_path / "payload"
    root.mkdir()
    for name in REQUIRED_PAYLOAD_FILES:
        path = root / name
        path.write_bytes(b"\x7fELF payload" if not name.endswith(".json") else b"{}")
        path.chmod(0o755)
    return root


def _package_env(tmp_path: Path, payload: Path, tag: str) -> dict[str, str]:
    preview = preview_for_tag(tag).outputs()
    deb_dir = tmp_path / "deb"
    deb_dir.mkdir()
    return {
        "TAG": tag,
        "QUALIFIED_PYTHON": sys.executable,
        "GITHUB_WORKSPACE": str(_REPO_ROOT),
        "PAYLOAD_DIR": str(payload),
        "DEB_DIR": str(deb_dir),
        "SOURCE_EPOCH": "1700000000",
        "PRODUCT_VERSION": preview["product-version"],
        "DEBIAN_VERSION": preview["debian-version"],
        "PACKAGE_NAME": preview["package-name"],
        "ARCHITECTURE": preview["architecture"],
        "DEB_ASSET": preview["deb-asset"],
        "DEB_MAINTAINER": _MAINTAINER,
    }


@pytest.mark.skipif(not _HAS_DPKG_DEB, reason="dpkg-deb not installed")
def test_the_package_step_packages_and_measures_the_payload(
    workflow: str, tmp_path: Path, payload: Path
) -> None:
    env = _package_env(tmp_path, payload, "v2.28.0rc1")

    result, outputs = _run(
        workflow, "Package the qualified payload", tmp_path, cwd=_REPO_ROOT, **env
    )

    assert result.returncode == 0, result.stderr
    deb = Path(outputs["deb-path"])
    assert deb == Path(env["DEB_DIR"]) / "servonaut-desktop-preview_2.28.0rc1_amd64.deb"
    assert outputs["deb-sha256"] == hashlib.sha256(deb.read_bytes()).hexdigest()
    fields = subprocess.run(
        ["dpkg-deb", "--field", str(deb), "Package", "Version", "Architecture"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert fields.splitlines() == [
        "Package: servonaut",
        "Version: 2.28.0~rc1",
        "Architecture: amd64",
    ]


@pytest.mark.skipif(not _HAS_DPKG_DEB, reason="dpkg-deb not installed")
def test_the_package_step_fails_when_the_package_disagrees_with_the_tag(
    workflow: str, tmp_path: Path, payload: Path
) -> None:
    env = _package_env(tmp_path, payload, "v2.28.0rc1")
    env["DEBIAN_VERSION"] = "2.28.0rc1"

    result, outputs = _run(
        workflow, "Package the qualified payload", tmp_path, cwd=_REPO_ROOT, **env
    )

    assert result.returncode == 1
    assert "The package's Version is 2.28.0~rc1, but v2.28.0rc1 needs 2.28.0rc1." in result.stdout
    assert "deb-sha256" not in outputs


def _handed_over(tmp_path: Path, payload: Path, tag: str) -> tuple[Path, dict[str, str]]:
    preview = preview_for_tag(tag)
    received = tmp_path / "preview"
    deb, sha256, _ = package_deb(
        payload_dir=payload,
        output_dir=received,
        product_version=preview.product_version,
        maintainer=_MAINTAINER,
        filename=preview.deb_asset,
    )
    return received, {
        "TAG": tag,
        "DEB_ASSET": preview.deb_asset,
        "SUMS_ASSET": preview.sums_asset,
        "DEB_SHA256": sha256,
        "DEBIAN_VERSION": preview.debian_version,
        "PACKAGE_NAME": "servonaut",
        "ARCHITECTURE": "amd64",
    }


@pytest.mark.skipif(not _HAS_DPKG_DEB, reason="dpkg-deb not installed")
def test_the_publish_job_writes_checksums_users_can_check(
    workflow: str, tmp_path: Path, payload: Path
) -> None:
    received, env = _handed_over(tmp_path, payload, "v2.28.0rc1")

    result, _ = _run(
        workflow, "Verify the package and write its checksums", tmp_path, cwd=received, **env
    )

    assert result.returncode == 0, result.stderr + result.stdout
    sums = received / "servonaut-desktop-preview_2.28.0rc1_SHA256SUMS"
    assert sums.read_text(encoding="utf-8") == (
        f"{env['DEB_SHA256']}  servonaut-desktop-preview_2.28.0rc1_amd64.deb\n"
    )
    subprocess.run(["sha256sum", "--check", "--strict", sums.name], cwd=received, check=True)


@pytest.mark.skipif(not _HAS_DPKG_DEB, reason="dpkg-deb not installed")
@pytest.mark.parametrize(
    "tamper",
    ["digest", "version", "extra-file"],
)
def test_the_publish_job_refuses_a_package_it_was_not_promised(
    workflow: str, tmp_path: Path, payload: Path, tamper: str
) -> None:
    received, env = _handed_over(tmp_path, payload, "v2.28.0")
    if tamper == "digest":
        env["DEB_SHA256"] = "0" * 64
    elif tamper == "version":
        env["DEBIAN_VERSION"] = "2.28.1"
    else:
        (received / "other.deb").write_bytes(b"not qualified")

    result, _ = _run(
        workflow, "Verify the package and write its checksums", tmp_path, cwd=received, **env
    )

    assert result.returncode != 0
    assert not (received / env["SUMS_ASSET"]).exists()


def test_the_user_guide_matches_the_published_names() -> None:
    guide = (_REPO_ROOT / "docs" / "release-candidates.md").read_text(encoding="utf-8")
    section = guide.split("## Linux desktop preview\n", 1)[1].split("\n## ", 1)[0]
    preview = preview_for_tag("v2.28.0rc1")

    assert f"sha256sum -c {preview.sums_asset}\n" in section
    assert f"gh attestation verify {preview.deb_asset} --repo zb-ss/servonaut\n" in section
    assert f"sudo apt install ./{preview.deb_asset}\n" in section
    assert "sudo apt remove servonaut\n" in section
    assert f"`{preview.debian_version}`" in section
    assert "does **not** update itself yet" in section
    assert "**preview**" in section


# A stand-in for gh: the release is a directory of assets.
_GH_STUB = r"""
gh() {
  printf '%s\n' "$*" >> "${TEST_GH_LOG}"
  case "$1 $2" in
    "release upload")
      shift 3
      for file in "$@"; do
        [ "${file}" = "--clobber" ] && continue
        cp "${file}" "${TEST_RELEASE}/"
        if [ -n "${TEST_CORRUPT:-}" ]; then printf 'x' >> "${TEST_RELEASE}/$(basename "${file}")"; fi
      done
      if [ -n "${TEST_DROP:-}" ]; then rm "${TEST_RELEASE}/${TEST_DROP}"; fi
      ;;
    "api repos/"*)
      ls -1 "${TEST_RELEASE}"
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


def _upload(workflow: str, tmp_path: Path, **env: str) -> subprocess.CompletedProcess[str]:
    preview = preview_for_tag("v2.28.0rc1")
    workspace = tmp_path / "workspace"
    (workspace / "preview").mkdir(parents=True)
    deb = workspace / "preview" / preview.deb_asset
    deb.write_bytes(b"qualified package")
    (workspace / "preview" / preview.sums_asset).write_text(
        f"{hashlib.sha256(deb.read_bytes()).hexdigest()}  {preview.deb_asset}\n",
        encoding="utf-8",
    )
    release = tmp_path / "release"
    release.mkdir()
    for name in ("notes.txt", preview.deb_asset, preview.sums_asset):
        (release / name).write_text("published earlier\n", encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    (runner_temp / "assets-before").write_text(
        "".join(f"{path.name}\n" for path in sorted(release.iterdir())), encoding="utf-8"
    )
    return subprocess.run(
        ["bash", "-c", _GH_STUB + _script(workflow, "Upload the preview to the release")],
        cwd=workspace,
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": os.environ["PATH"],
            "RUNNER_TEMP": str(runner_temp),
            "GH_REPO": "example/project",
            "TAG": preview.tag,
            "DEB_ASSET": preview.deb_asset,
            "SUMS_ASSET": preview.sums_asset,
            "TEST_RELEASE": str(release),
            "TEST_GH_LOG": str(tmp_path / "gh.log"),
            **env,
        },
    )


def test_the_upload_replaces_its_assets_and_checks_what_users_download(
    workflow: str, tmp_path: Path
) -> None:
    result = _upload(workflow, tmp_path)

    assert result.returncode == 0, result.stderr + result.stdout
    preview = preview_for_tag("v2.28.0rc1")
    release = tmp_path / "release"
    assert sorted(path.name for path in release.iterdir()) == sorted(
        ["notes.txt", preview.deb_asset, preview.sums_asset]
    )
    assert (release / "notes.txt").read_text(encoding="utf-8") == "published earlier\n"
    assert (release / preview.deb_asset).read_bytes() == b"qualified package"
    calls = (tmp_path / "gh.log").read_text(encoding="utf-8").splitlines()
    assert calls[0] == (
        f"release upload v2.28.0rc1 preview/{preview.deb_asset} "
        f"preview/{preview.sums_asset} --clobber"
    )
    assert not any("delete" in call for call in calls)


def test_the_upload_fails_if_another_asset_disappeared(workflow: str, tmp_path: Path) -> None:
    result = _upload(workflow, tmp_path, TEST_DROP="notes.txt")

    assert result.returncode == 1
    assert "::error::The upload removed another asset of v2.28.0rc1." in result.stdout


def test_the_upload_fails_if_the_published_package_does_not_match(
    workflow: str, tmp_path: Path
) -> None:
    result = _upload(workflow, tmp_path, TEST_CORRUPT="1")

    assert result.returncode != 0
    assert "FAILED" in result.stdout + result.stderr
