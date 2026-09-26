"""Exercise release decisions with real, disposable Git histories."""

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github/scripts/release-policy.py"
PUSH = ROOT / ".github/scripts/release-push.sh"
PYPI_CHECK = ROOT / ".github/scripts/candidate-on-pypi.sh"
WORKFLOWS = ROOT / ".github/workflows"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def commit(repo: Path, path: str, message: str, content: str = "changed\n") -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    git(repo, "add", "--", path)
    git(repo, "commit", "-m", message)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    git(tmp_path, "init", "--template=", "-b", "master")
    git(tmp_path, "config", "user.name", "Release Test")
    git(tmp_path, "config", "user.email", "user@example.com")
    commit(
        tmp_path,
        "pyproject.toml",
        "chore: initialize package",
        '[project]\nversion = "1.2.3"\n',
    )
    commit(
        tmp_path,
        "src/servonaut/__init__.py",
        "chore: initialize module",
        "__version__ = '1.2.3'\n",
    )
    git(tmp_path, "tag", "v1.2.3")
    return tmp_path


def release(tag: str = "v1.2.3", **changes: Any) -> dict[str, Any]:
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "published_at": "2025-01-02T12:00:00Z",
        **changes,
    }


def run_policy(
    repo: Path, *args: str, payload: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(POLICY), *args],
        cwd=repo,
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )


def outputs(result: subprocess.CompletedProcess[str]) -> dict[str, str]:
    assert result.returncode == 0, result.stderr
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def event_result(
    repo: Path, metadata: dict[str, Any], **changes: Any
) -> subprocess.CompletedProcess[str]:
    path = repo / "event.json"
    path.write_text(
        json.dumps({"action": "published", "release": metadata, **changes}),
        encoding="utf-8",
    )
    return run_policy(repo, "check-event", str(path), "--ref", "refs/tags/v1.2.3")


def plan(
    repo: Path, releases: list[dict[str, Any]] | None = None, bump: str = "auto"
) -> dict[str, str]:
    payload = json.dumps([release()] if releases is None else releases)
    return outputs(run_policy(repo, "plan", "--bump", bump, payload=payload))


def test_stable_event_pins_the_validated_revision(repo: Path) -> None:
    assert outputs(event_result(repo, release())) == {
        "publish": "true",
        "revision": git(repo, "rev-parse", "HEAD"),
        "prerelease": "false",
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"prerelease": True},
        {"draft": True},
        {"prerelease": None},
        {"draft": None},
        {"prerelease": "false"},
        {"draft": 0},
        {"published_at": None},
        {"published_at": "invalid"},
        {"published_at": "2025-01-02"},
        {"tag_name": "v1.2.3-rc.1"},
        {"tag_name": "v1.2.3-desktop-r1"},
        {"tag_name": "v1.2.3+desktop.1"},
        {"tag_name": "1.2.3"},
        {"tag_name": "v01.2.3"},
        {"tag_name": "v1.2"},
        {"tag_name": None},
        {"tag_name": "v1.2.3\npublish=true"},
        {"tag_name": "v1.2.3rc1"},
        {"tag_name": "v1.2.3rc1", "prerelease": False},
        {"tag_name": "v1.2.3-preview.1", "prerelease": True},
        {"tag_name": "v1.2.3rc0", "prerelease": True},
        {"tag_name": "v1.2.3rc01", "prerelease": True},
        {"tag_name": "v1.2.3a1", "prerelease": True},
        {"tag_name": "v1.2.3.rc1", "prerelease": True},
        {"tag_name": "v1.2.3rc1.dev1", "prerelease": True},
        {"tag_name": "v1.2.3rc1", "prerelease": True, "draft": True},
    ],
)
def test_unpublishable_events_never_enable_publishing(
    repo: Path, changes: dict[str, Any]
) -> None:
    assert outputs(event_result(repo, release(**changes))) == {"publish": "false"}


@pytest.mark.parametrize("action", ["created", "edited", "prereleased", None])
def test_only_published_events_are_eligible(repo: Path, action: str | None) -> None:
    assert outputs(event_result(repo, release(), action=action)) == {"publish": "false"}


@pytest.mark.parametrize("field", ["draft", "prerelease", "published_at", "tag_name"])
def test_missing_metadata_fails_closed(repo: Path, field: str) -> None:
    metadata = release()
    del metadata[field]
    assert outputs(event_result(repo, metadata)) == {"publish": "false"}


@pytest.mark.parametrize(
    "path,content",
    [
        ("pyproject.toml", '[project]\nversion = "1.2.4"\n'),
        ("src/servonaut/__init__.py", "__version__ = '1.2.4'\n"),
        ("pyproject.toml", '[project]\ndynamic = ["version"]\n'),
        ("src/servonaut/__init__.py", "__version__ = '1.2.3'\n__version__ = '1.2.3'\n"),
    ],
)
def test_package_version_mismatch_fails_before_publishing(
    repo: Path, path: str, content: str
) -> None:
    (repo / path).write_text(content, encoding="utf-8")
    result = event_result(repo, release())
    assert result.returncode != 0
    assert "publish=true" not in result.stdout


def test_release_ref_mismatch_is_rejected(repo: Path) -> None:
    assert event_result(repo, release("v1.2.4")).returncode != 0


def test_release_checkout_mismatch_is_rejected(repo: Path) -> None:
    commit(repo, "README.md", "docs: update guide")
    assert event_result(repo, release()).returncode != 0


@pytest.mark.parametrize("payload", ["invalid", "[]", "null"])
def test_malformed_event_is_rejected(repo: Path, payload: str) -> None:
    path = repo / "event.json"
    path.write_text(payload, encoding="utf-8")
    result = run_policy(repo, "check-event", str(path), "--ref", "refs/tags/v1.2.3")
    assert result.returncode != 0
    assert not result.stdout


@pytest.mark.parametrize(
    "path",
    ["tests/test_example.py", "docs/example.md", ".github/workflows/example.yml"],
)
def test_development_only_changes_do_not_release(repo: Path, path: str) -> None:
    commit(repo, path, "feat: improve development checks")
    assert plan(repo) == {"release": "false", "last_tag": "v1.2.3"}


def test_development_only_merge_does_not_release(repo: Path) -> None:
    git(repo, "switch", "-c", "feature/example")
    commit(repo, "tests/test_example.py", "feat: add checks")
    git(repo, "switch", "master")
    git(repo, "merge", "--no-ff", "feature/example", "-m", "feat: merge checks")
    assert plan(repo)["release"] == "false"


@pytest.mark.parametrize(
    "message,path,bump,next_tag",
    [
        ("fix: correct output", "src/servonaut/example.py", "patch", "v1.2.4"),
        ("feat(cli): add output", "src/servonaut/example.py", "minor", "v1.3.0"),
        ("fix!: replace output", "src/servonaut/example.py", "major", "v2.0.0"),
        ("fix(cli)!: replace output", "src/servonaut/example.py", "major", "v2.0.0"),
        (
            "fix: replace output\n\nBREAKING CHANGE: output changed",
            "src/servonaut/example.py",
            "major",
            "v2.0.0",
        ),
        ("fix: migrate config", "src/servonaut/config/migration.py", "minor", "v1.3.0"),
        ("fix: adjust packaging", "pyproject.toml", "patch", "v1.2.4"),
    ],
)
def test_shipped_changes_select_expected_bump(
    repo: Path, message: str, path: str, bump: str, next_tag: str
) -> None:
    commit(repo, path, message)
    assert plan(repo) == {
        "release": "true",
        "last_tag": "v1.2.3",
        "next": next_tag,
        "bump": bump,
        "count": "1",
    }


def test_documentation_breaking_footer_does_not_bump_runtime_major(repo: Path) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    commit(
        repo,
        "docs/example.md",
        "docs: change examples\n\nBREAKING CHANGE: new example format",
    )
    assert plan(repo)["bump"] == "patch"


def test_version_bump_commit_alone_does_not_release(repo: Path) -> None:
    commit(
        repo, "pyproject.toml", "chore: bump version to 1.2.4", 'version = "1.2.4"\n'
    )
    assert plan(repo)["release"] == "false"


@pytest.mark.parametrize(
    "bump,next_tag", [("major", "v2.0.0"), ("minor", "v1.3.0"), ("patch", "v1.2.4")]
)
def test_explicit_bump_is_preserved(repo: Path, bump: str, next_tag: str) -> None:
    commit(repo, "src/servonaut/example.py", "feat!: replace output")
    assert plan(repo, bump=bump)["next"] == next_tag


def test_preview_draft_and_unpublished_tags_do_not_set_baseline(repo: Path) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    for tag in ("v9.0.0-rc.1", "v8.0.0", "v7.0.0", "v6.0.0", "v5.0.0"):
        git(repo, "tag", tag)
    releases = [
        release("v9.0.0-rc.1"),
        release("v8.0.0", prerelease=True),
        release("v7.0.0", draft=True),
        release("v6.0.0", published_at=None),
        release(),
    ]
    assert plan(repo, releases)["next"] == "v1.2.4"


def test_baseline_is_sorted_numerically_and_supports_paginated_api(repo: Path) -> None:
    for tag in ("v1.9.0", "v1.10.0"):
        git(repo, "tag", tag)
    payload = (
        json.dumps([release(), release("v1.9.0")])
        + "\n"
        + json.dumps([release("v1.10.0")])
    )
    assert outputs(run_policy(repo, "plan", payload=payload))["last_tag"] == "v1.10.0"


def test_baseline_is_the_highest_published_release_on_any_branch(repo: Path) -> None:
    # Users already have the highest published version, wherever it was cut,
    # so the next version must be above it.
    git(repo, "switch", "-c", "feature/example")
    commit(repo, "src/servonaut/example.py", "feat: add output")
    git(repo, "tag", "v9.0.0")
    git(repo, "switch", "master")
    commit(repo, "src/servonaut/other.py", "fix: correct output")
    result = plan(repo, [release("v9.0.0"), release()])
    assert (result["last_tag"], result["next"]) == ("v9.0.0", "v9.0.1")


def cut_release_branch(repo: Path, version: str, *, pick: str | None = None) -> str:
    """Branch release/<version> from HEAD, cherry-pick *pick*, tag v<version>."""
    git(repo, "switch", "-c", f"release/{version}")
    if pick:
        git(repo, "cherry-pick", pick)
    commit(repo, "pyproject.toml", f"chore: bump version to {version}", f'[project]\nversion = "{version}"\n')
    git(repo, "tag", f"v{version}")
    git(repo, "switch", "master")
    git(repo, "branch", "-D", f"release/{version}")
    return f"v{version}"


def test_release_branch_changes_are_not_released_twice(repo: Path) -> None:
    commit(repo, "src/servonaut/one.py", "fix: first")
    commit(repo, "src/servonaut/two.py", "feat: second")
    second = git(repo, "rev-parse", "HEAD")
    git(repo, "switch", "--detach", "HEAD~1")
    git(repo, "switch", "-c", "base")
    tag = cut_release_branch(repo, "1.2.4", pick=second)
    git(repo, "switch", "master")
    git(repo, "branch", "-D", "base")
    releases = [release(tag), release()]
    # "first" shipped from the branch point, "second" as a cherry-pick.
    assert plan(repo, releases) == {"release": "false", "last_tag": "v1.2.4"}
    commit(repo, "src/servonaut/version.py", "chore: bump version to 1.2.4")
    assert plan(repo, releases)["release"] == "false"
    commit(repo, "src/servonaut/three.py", "fix: third")
    assert plan(repo, releases) == {
        "release": "true",
        "last_tag": "v1.2.4",
        "next": "v1.2.5",
        "bump": "patch",
        "count": "1",
    }


def test_annotated_release_tag_resolves_to_its_commit(repo: Path) -> None:
    git(repo, "tag", "-a", "v1.2.4", "-m", "Release 1.2.4")
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    result = plan(repo, [release("v1.2.4"), release()])
    assert result["last_tag"] == "v1.2.4"
    assert result["next"] == "v1.2.5"


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "[]",
        "{}",
        "[null]",
        "invalid",
        '[{"tag_name": "v1.2.3"}]',
        '[]\n{"message": "error"}',
    ],
)
def test_no_baseline_or_invalid_api_fails_closed(repo: Path, payload: str) -> None:
    result = run_policy(repo, "plan", payload=payload)
    assert result.returncode != 0
    assert not result.stdout


def test_missing_published_tag_fails_closed(repo: Path) -> None:
    result = run_policy(
        repo, "plan", payload=json.dumps([release("v9.0.0"), release()])
    )
    assert result.returncode != 0
    assert not result.stdout
    assert "Fetch the full history and release tags" in result.stderr


def test_existing_next_tag_fails_before_any_mutation(repo: Path) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    git(repo, "tag", "v1.2.4")
    result = run_policy(repo, "plan", payload=json.dumps([release()]))
    assert result.returncode != 0
    assert not result.stdout


@pytest.mark.parametrize("has_changes", [False, True])
def test_plan_is_read_only_and_writes_summary(
    repo: Path, tmp_path: Path, has_changes: bool
) -> None:
    if has_changes:
        commit(repo, "src/servonaut/example.py", "fix: correct output")
    before_refs = git(repo, "show-ref")
    before_diff = git(repo, "diff", "HEAD")
    summary = tmp_path / "summary.md"
    result = run_policy(
        repo, "plan", "--summary", str(summary), payload=json.dumps([release()])
    )
    assert outputs(result)["release"] == str(has_changes).lower()
    assert "v1.2.3" in summary.read_text(encoding="utf-8")
    assert git(repo, "show-ref") == before_refs
    assert git(repo, "diff", "HEAD") == before_diff


def workflow_step(workflow: str, name: str) -> str:
    """Extract a named step's literal block without a YAML test dependency."""
    source = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    start = source.index(f"      - name: {name}\n")
    step = source[start:]
    following = re.search(r"\n      - ", step)
    return step[: following.start()] if following else step


def step_script(workflow: str, name: str) -> str:
    """A named step's literal run block, without any following YAML job."""
    block = workflow_step(workflow, name).split("        run: |\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


def run_cadence(
    tmp_path: Path, workflow: str, name: str, **env: str
) -> subprocess.CompletedProcess[str]:
    script = 'gh() { printf "%s" "$TEST_GH_OUTPUT"; return "$TEST_GH_STATUS"; }\n'
    script += step_script(workflow, name)
    return subprocess.run(
        ["bash", "-c", script],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "GITHUB_OUTPUT": str(tmp_path / "output"),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
            "REPO": "example/project",
            "TEST_GH_STATUS": "0",
            "TEST_GH_OUTPUT": "",
            **env,
        },
    )


@pytest.mark.parametrize(
    "event,shipped,status,code,allowed",
    [
        ("schedule", "v1.2.3", "0", 0, "false"),
        ("schedule", "v1.2.3-rc.1", "0", 0, "false"),
        ("workflow_dispatch", "v1.2.3", "0", 1, "false"),
        ("schedule", "", "1", 1, "false"),
        ("schedule", "", "0", 0, "true"),
        ("workflow_dispatch", "", "0", 0, "true"),
    ],
)
def test_release_cadence_step(
    tmp_path: Path, event: str, shipped: str, status: str, code: int, allowed: str
) -> None:
    result = run_cadence(
        tmp_path,
        "release.yml",
        "Refuse if a release already went out today",
        GITHUB_EVENT_NAME=event,
        TEST_GH_OUTPUT=shipped,
        TEST_GH_STATUS=status,
    )
    assert result.returncode == code, result.stderr
    output = dict(
        line.split("=", 1) for line in (tmp_path / "output").read_text().splitlines()
    )
    assert output["allowed"] == allowed


@pytest.mark.parametrize(
    "shipped,status,override,code",
    [
        ("v1.2.3-rc.1", "0", "false", 1),
        ("", "0", "false", 0),
        ("", "1", "false", 1),
        ("v1.2.3-rc.1", "0", "true", 0),
    ],
)
def test_publish_cadence_step(
    tmp_path: Path, shipped: str, status: str, override: str, code: int
) -> None:
    result = run_cadence(
        tmp_path,
        "publish.yml",
        "Refuse a second release on the same day",
        THIS_TAG="v1.2.4",
        THIS_PUBLISHED="2025-01-02T12:00:00Z",
        OVERRIDE=override,
        TEST_GH_OUTPUT=shipped,
        TEST_GH_STATUS=status,
    )
    assert result.returncode == code, result.stderr


def test_mutation_step_requires_cadence_and_not_dry_run() -> None:
    step = workflow_step("release.yml", "Promote the candidate")
    assert "if: steps.cadence.outputs.allowed == 'true'" in step
    assert "id: cadence" in workflow_step(
        "release.yml", "Refuse if a release already went out today"
    )
    jobs = release_jobs()
    assert "needs.plan.outputs.dry_run == 'false'" in jobs["candidate"]
    assert "needs.plan.outputs.dry_run == 'false'" in jobs["approval"]
    assert "needs.plan.outputs.dry_run == 'false'" in jobs["promote"]


def test_stable_publishing_jobs_all_depend_on_channel_gate() -> None:
    source = (WORKFLOWS / "publish.yml").read_text(encoding="utf-8")
    sections = re.split(r"^  ([a-z-]+):\n", source, flags=re.MULTILINE)
    jobs = dict(zip(sections[1::2], sections[2::2]))
    for name in ("cadence", "test", "publish", "mcp-registry"):
        job = jobs[name]
        assert re.search(r"^    needs: .*eligibility", job, re.MULTILINE)
        assert "if: needs.eligibility.outputs.publish == 'true'" in job
        if name != "cadence":
            assert "ref: ${{ needs.eligibility.outputs.revision }}" in job
    assert "needs: [eligibility, cadence, test]" in jobs["publish"]
    assert "needs: [eligibility, publish]" in jobs["mcp-registry"]
    assert 'check-event "$GITHUB_EVENT_PATH"' in jobs["eligibility"]
    assert "OVERRIDE" not in jobs["eligibility"]


def test_release_planner_uses_published_metadata_and_pipefail() -> None:
    step = workflow_step("release.yml", "Plan the release")
    assert "set -euo pipefail" in step
    assert 'gh api --paginate "repos/$REPO/releases"' in step
    assert 'release-policy.py "$STAGE" --bump "$BUMP"' in step
    assert "git describe" not in step


def test_generated_notes_support_development_only_exclusion() -> None:
    source = (ROOT / ".github/release.yml").read_text(encoding="utf-8")
    assert source == "changelog:\n  exclude:\n    labels:\n      - skip-changelog\n"


def _job(source: str, name: str) -> str:
    sections = re.split(r"^  ([a-z-]+):\n", source, flags=re.MULTILINE)
    jobs = dict(zip(sections[1::2], sections[2::2]))
    return jobs[name]


def test_release_candidate_workflow_runs_ordered_stage_gates() -> None:
    source = (WORKFLOWS / "release-candidate.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in source
    assert "persist-credentials: false" in source
    order = [
        source.index("  source:\n"),
        source.index("  candidate:\n"),
        source.index("  sign:\n"),
        source.index("  verify:\n"),
        source.index("  record:\n"),
    ]
    assert order == sorted(order)
    for name, needs in (
        ("candidate", "source"),
        ("sign", "candidate"),
        ("verify", "candidate"),
        ("record", "candidate"),
    ):
        assert f"needs: {needs}" in _job(source, name) or (
            f"needs: [{needs}, " in _job(source, name)
        )
    assert "needs: [candidate, sign]" in _job(source, "verify")
    assert "needs: [candidate, verify]" in _job(source, "record")
    # The digest is pinned once and passed to every later stage.
    assert "id: plan" in _job(source, "candidate")
    assert "digest: ${{ steps.plan.outputs.digest }}" in _job(source, "candidate")
    assert "DIGEST: ${{ needs.candidate.outputs.digest }}" in _job(source, "verify")
    assert "release_candidate.py verify" in _job(source, "verify")
    assert "release_candidate.py plan" in _job(source, "candidate")
    assert "release_candidate.py check-publish" not in source
    # The channel is a first-class input asserted at plan time.
    assert "channel:\n" in source.split("jobs:", 1)[0]
    assert "--channel \"$CHANNEL\"" in _job(source, "candidate")
    # Assembling and verifying both hash the real release files.
    assert "--artifacts-dir candidate" in _job(source, "candidate")
    assert "--artifacts-dir candidate" in _job(source, "verify")


def test_release_candidate_downloads_inputs_from_the_source_run() -> None:
    source = (WORKFLOWS / "release-candidate.yml").read_text(encoding="utf-8")
    trigger = source.split("jobs:", 1)[0]
    assert re.search(
        r"      source_run_id:\n        description: .+\n        required: true\n", trigger
    )
    for name in ("candidate", "verify"):
        job = _job(source, name)
        assert "    permissions:\n      contents: read\n      actions: read\n" in job
        assert job.count("run-id: ${{ inputs.source_run_id }}") == 1
        assert job.count("github-token: ${{ github.token }}") == 1
    for name in ("source", "sign", "record"):
        assert "actions: read" not in _job(source, name)


@pytest.mark.parametrize(
    "run_id,built,code",
    [
        ("12345", "a" * 40, 0),
        ("12345", "b" * 40, 1),
        ("", "a" * 40, 1),
        ("123/../1", "a" * 40, 1),
    ],
)
def test_release_candidate_source_run_must_match_the_commit(
    run_id: str, built: str, code: int
) -> None:
    script = 'gh() { printf "%s" "$TEST_BUILT"; }\n' + step_script(
        "release-candidate.yml", "Require the source run to have built this commit"
    )
    result = subprocess.run(
        ["bash", "-c", script],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "GITHUB_SHA": "a" * 40,
            "REPO": "example/project",
            "SOURCE_RUN_ID": run_id,
            "TEST_BUILT": built,
        },
    )
    assert result.returncode == code, result.stdout + result.stderr


def test_release_candidate_signing_is_secret_gated_not_optional() -> None:
    source = (WORKFLOWS / "release-candidate.yml").read_text(encoding="utf-8")
    sign = _job(source, "sign")
    assert "RELEASE_SIGNING_KEY" in sign
    assert "::error::" in sign
    assert "exit 1" in sign
    # An unsigned candidate must never silently pass the gate.
    assert "::notice::Signing is not required" in sign
    # The job must say what it does and does not check.
    assert "checks only that the secret exists" in sign
    assert "does not sign artifacts or verify their signatures" in sign
    assert "uses:" not in sign


def test_release_candidate_never_publishes_or_builds_on_publish_event() -> None:
    source = (WORKFLOWS / "release-candidate.yml").read_text(encoding="utf-8")
    trigger = source.split("jobs:", 1)[0]
    assert "release:" not in trigger
    assert "gh release create" not in source
    assert "gh release edit" not in source
    assert "secrets.PYPI_API_TOKEN" not in source
    assert "mcp-publisher" not in source
    assert "id-token" not in source


def test_publish_requires_candidate_only_when_enabled() -> None:
    source = (WORKFLOWS / "publish.yml").read_text(encoding="utf-8")
    candidate = _job(source, "candidate")
    assert re.search(r"^    needs: eligibility", candidate, re.MULTILINE)
    assert "vars.REQUIRE_RELEASE_CANDIDATE" in candidate
    assert "release_candidate.py check-publish" in candidate
    assert "candidate-evidence.json" in candidate
    # The stable path must assert the stable channel, so preview evidence can
    # never authorize a stable publish.
    assert "--channel stable" in candidate
    # The evidence must come from the validated release commit, and the
    # release files it names must be downloaded and hashed.
    assert "REVISION: ${{ needs.eligibility.outputs.revision }}" in candidate
    assert '--commit "$REVISION"' in candidate
    assert '--artifacts-dir "$WORK/artifacts"' in candidate
    # New steps stay behind the staged gate variable.
    assert "if: env.REQUIRE_CANDIDATE == 'true'" in candidate
    # A stable publish also needs the attached qualification record to pass
    # for the same evidence, after the release files have been verified.
    assert "--pattern qualification-record.json" in candidate
    assert "python -m scripts.distribution.qualification check" in candidate
    assert '--record "$WORK/qualification-record.json"' in candidate
    assert candidate.count("--channel stable") == 2
    assert candidate.index("release_candidate.py check-publish") < candidate.index(
        "scripts.distribution.qualification check"
    )
    # Publishing stays gated behind eligibility and, when enabled, the
    # candidate job as well.
    assert "needs: [eligibility, candidate]" in _job(source, "test")
    assert "needs: [eligibility, cadence, test]" in _job(source, "publish")


def test_publish_defaults_to_disabled_candidate_gate() -> None:
    """The staged gate must fail closed only when explicitly enabled."""
    script = (
        "gh() { return 0; }\n"
        "jq() { return 0; }\n"
        "pip() { return 0; }\n"
        "python() { return 0; }\n"
    ) + step_script("publish.yml", "Require candidate verification when enabled")
    for value, expected_code in (("", 0), ("false", 0), ("true", 0)):
        result = subprocess.run(
            ["bash", "-c", script],
            text=True,
            capture_output=True,
            check=False,
            env={
                **os.environ,
                "REQUIRE_CANDIDATE": value,
                "REPO": "example/project",
                "THIS_TAG": "v1.2.3",
                "REVISION": "c" * 40,
            },
        )
        assert result.returncode == expected_code, (value, result.stderr)
    enabled = subprocess.run(
        ["bash", "-c", script],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "REQUIRE_CANDIDATE": "true",
            "REPO": "example/project",
            "THIS_TAG": "v1.2.3",
            "REVISION": "c" * 40,
        },
    )
    assert "::notice::Release-candidate verification is not required yet." not in enabled.stdout


_GATE_STUBS = r"""
gh() {
  echo "gh $*" >> "$TEST_LOG"
  pattern="" dir=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --pattern) pattern="$2"; shift ;;
      --dir) dir="$2"; shift ;;
    esac
    shift
  done
  if [ "$pattern" = "candidate-evidence.json" ]; then
    printf '%s' "$TEST_EVIDENCE" > "$dir/$pattern"
    return 0
  fi
  case " $TEST_ATTACHED " in *" $pattern "*) : > "$dir/$pattern" ;; *) return 1 ;; esac
}
python() { echo "python $*" >> "$TEST_LOG"; }
"""


def run_enabled_candidate_gate(
    tmp_path: Path, attached: str
) -> tuple[subprocess.CompletedProcess[str], str]:
    evidence = json.dumps(
        {"artifacts": [{"filename": "one.tar.gz"}, {"filename": "two.zip"}]}
    )
    log = tmp_path / "calls.log"
    result = subprocess.run(
        [
            "bash",
            "-c",
            _GATE_STUBS
            + step_script("publish.yml", "Require candidate verification when enabled"),
        ],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "REQUIRE_CANDIDATE": "true",
            "REPO": "example/project",
            "THIS_TAG": "v1.2.3",
            "REVISION": "c" * 40,
            "TEST_EVIDENCE": evidence,
            "TEST_ATTACHED": attached,
            "TEST_LOG": str(log),
        },
    )
    return result, log.read_text(encoding="utf-8") if log.exists() else ""


@pytest.mark.skipif(shutil.which("jq") is None, reason="The runner script uses jq")
def test_enabled_candidate_gate_hashes_the_release_files_it_names(
    tmp_path: Path,
) -> None:
    result, calls = run_enabled_candidate_gate(
        tmp_path, "one.tar.gz two.zip qualification-record.json"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "--pattern one.tar.gz" in calls
    assert "--pattern two.zip" in calls
    check = next(line for line in calls.splitlines() if "check-publish" in line)
    assert f"--commit {'c' * 40}" in check
    assert re.search(r"--artifacts-dir \S+/artifacts ", check)


@pytest.mark.skipif(shutil.which("jq") is None, reason="The runner script uses jq")
def test_enabled_candidate_gate_checks_qualification_after_the_files(
    tmp_path: Path,
) -> None:
    result, calls = run_enabled_candidate_gate(
        tmp_path, "one.tar.gz two.zip qualification-record.json"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    lines = calls.splitlines()
    publish = next(i for i, line in enumerate(lines) if "check-publish" in line)
    qualify = next(
        i for i, line in enumerate(lines) if "scripts.distribution.qualification" in line
    )
    assert publish < qualify
    assert re.fullmatch(
        r"python -m scripts\.distribution\.qualification check"
        r" --evidence (\S+)/candidate-evidence\.json"
        r" --record \1/qualification-record\.json --channel stable",
        lines[qualify],
    )


@pytest.mark.skipif(shutil.which("jq") is None, reason="The runner script uses jq")
def test_enabled_candidate_gate_refuses_a_missing_release_file(tmp_path: Path) -> None:
    result, calls = run_enabled_candidate_gate(
        tmp_path, "one.tar.gz qualification-record.json"
    )
    assert result.returncode == 1
    assert "::error::" in result.stdout
    assert "check-publish" not in calls
    assert "scripts.distribution.qualification" not in calls


@pytest.mark.skipif(shutil.which("jq") is None, reason="The runner script uses jq")
def test_enabled_candidate_gate_refuses_a_missing_qualification_record(
    tmp_path: Path,
) -> None:
    result, calls = run_enabled_candidate_gate(tmp_path, "one.tar.gz two.zip")
    assert result.returncode == 1
    assert "::error::No qualification-record.json is attached to v1.2.3" in result.stdout
    assert "--pattern one.tar.gz" not in calls
    assert "check-publish" not in calls
    assert "scripts.distribution.qualification" not in calls


@pytest.mark.parametrize("value", ["", "false", "TRUE"])
def test_disabled_candidate_gate_downloads_and_checks_nothing(
    tmp_path: Path, value: str
) -> None:
    log = tmp_path / "calls.log"
    result = subprocess.run(
        [
            "bash",
            "-c",
            _GATE_STUBS
            + step_script("publish.yml", "Require candidate verification when enabled"),
        ],
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "REQUIRE_CANDIDATE": value,
            "REPO": "example/project",
            "THIS_TAG": "v1.2.3",
            "REVISION": "c" * 40,
            "TEST_LOG": str(log),
        },
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == (
        "::notice::Release-candidate verification is not required yet.\n"
    )
    assert not log.exists()


def test_enabling_the_gate_needs_files_the_release_workflow_does_not_attach() -> None:
    """Pins the documented precondition for turning the candidate gate on.

    With REQUIRE_RELEASE_CANDIDATE on, publishing needs candidate evidence and
    a qualification record attached to the release, and the Release workflow
    creates the release without either, so the guide must say so.
    """
    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "gh release create" in release
    assert "gh release upload" not in release
    candidate = _job((WORKFLOWS / "publish.yml").read_text(encoding="utf-8"), "candidate")
    for name in ("candidate-evidence.json", "qualification-record.json"):
        assert name not in release
        assert f"--pattern {name}" in candidate
    guide = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    section = guide.split("## Release qualification\n", 1)[1].split("\n## ", 1)[0]
    prose = " ".join(section.split())
    assert "`REQUIRE_RELEASE_CANDIDATE`" in prose
    assert "needs at least one fully qualified binary artifact" in prose
    assert "The Release workflow attaches none of these" in prose
    assert "without blocking pip/pipx" not in prose


def test_release_candidate_emits_a_qualification_template_after_verify() -> None:
    source = (WORKFLOWS / "release-candidate.yml").read_text(encoding="utf-8")
    verify = _job(source, "verify")
    prepare_at = verify.index("      - name: Prepare the qualification record template\n")
    upload_at = verify.index("      - name: Upload the qualification record template\n")
    assert verify.index("release_candidate.py verify") < prepare_at < upload_at
    prepare, upload = verify[prepare_at:upload_at], verify[upload_at:]
    assert "python -m scripts.distribution.qualification template" in prepare
    assert "--evidence candidate-evidence.json" in prepare
    assert (
        "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
        in upload
    )
    assert "name: qualification-record-template\n" in upload
    assert "path: qualification/qualification-record.json\n" in upload
    assert "if-no-files-found: error" in upload
    assert "secrets." not in prepare + upload


def test_release_candidate_template_step_writes_a_loadable_record(
    tmp_path: Path,
) -> None:
    # Imported here so the release-policy tests keep a light module import.
    import io
    import tarfile

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from scripts.distribution.qualification import load_matrix, load_record
    from scripts.distribution.release_candidate import plan_candidate
    from servonaut.distribution.builder import ManifestBuilder
    from servonaut.distribution.manifest import (
        ArtifactKind,
        ReleaseChannel,
        canonicalize_json,
    )
    from servonaut.runtime import DistributionKind

    release_file = tmp_path / "servonaut.tar.gz"
    marker = {
        "schema_version": 1,
        "distribution": "frozen-cli",
        "product_version": "1.2.3",
        "build_revision": "ci-r1",
        "channel": "stable",
        "packaging_revision": 1,
        "console_helper": "servonaut",
        "desktop_child": None,
    }
    with tarfile.open(release_file, "w:gz") as archive:
        for name, data in (
            ("servonaut", b"PAYLOAD"),
            ("servonaut-runtime.json", json.dumps(marker).encode("utf-8")),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    builder = ManifestBuilder(
        product_version="1.2.3",
        channel=ReleaseChannel.STABLE,
        packaging_revision=1,
        expires_at="2099-01-01T00:00:00Z",
    )
    artifact = builder.add_artifact_file(
        release_file,
        kind=ArtifactKind.STANDALONE_CLI,
        distribution=DistributionKind.FROZEN_CLI,
        platform="linux",
        arch="x86_64",
        download_url="https://example.com/servonaut.tar.gz",
    )
    builder.sign_artifact(artifact.artifact_id, Ed25519PrivateKey.generate())
    candidate = plan_candidate(
        builder.build(),
        tag="v1.2.3",
        source_commit="c" * 40,
        artifact_files={artifact.artifact_id: release_file},
    )
    (tmp_path / "candidate-evidence.json").write_bytes(
        canonicalize_json(candidate.to_evidence()) + b"\n"
    )
    script = 'python() { "$TEST_PYTHON" "$@"; }\n' + step_script(
        "release-candidate.yml", "Prepare the qualification record template"
    )
    result = subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "TEST_PYTHON": sys.executable,
            "PYTHONPATH": os.pathsep.join((str(ROOT), str(ROOT / "src"))),
        },
    )
    assert result.returncode == 0, result.stderr
    matrix = load_matrix()
    record = load_record(tmp_path / "qualification" / "qualification-record.json", matrix)
    assert record.tag == "v1.2.3"
    assert record.candidate_digest == candidate.digest
    assert [entry.row_id for entry in record.entries] == [
        "cli-ubuntu-22.04-x64",
        "cli-ubuntu-24.04-x64",
    ]


# ---------------------------------------------------------------------------
# Release candidates: publishing, version edits and planning
# ---------------------------------------------------------------------------


def release_jobs() -> dict[str, str]:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    body = source.split("\njobs:\n", 1)[1]
    sections = re.split(r"^  ([a-z-]+):\n", body, flags=re.MULTILINE)
    return dict(zip(sections[1::2], sections[2::2]))


def set_versions(repo: Path, version: str, message: str | None = None) -> str:
    (repo / "pyproject.toml").write_text(
        f'[project]\nname = "example"\nversion = "{version}"\n', encoding="utf-8"
    )
    (repo / "src/servonaut/__init__.py").write_text(
        f'"""Package."""\n__version__ = \'{version}\'\n', encoding="utf-8"
    )
    git(repo, "commit", "-am", message or f"chore: bump version to {version}")
    return git(repo, "rev-parse", "HEAD")


def versions(repo: Path, revision: str = "HEAD") -> tuple[str, str]:
    project = git(repo, "show", f"{revision}:pyproject.toml")
    module = git(repo, "show", f"{revision}:src/servonaut/__init__.py")
    return (
        re.search(r'^version = "([^"]+)"$', project, re.MULTILINE).group(1),
        re.search(r"^__version__ = '([^']+)'$", module, re.MULTILINE).group(1),
    )


def candidate_release(tag: str, **changes: Any) -> dict[str, Any]:
    return release(tag, prerelease=True, **changes)


def test_candidate_event_publishes_as_a_prerelease(repo: Path) -> None:
    set_versions(repo, "1.2.4rc1")
    git(repo, "tag", "v1.2.4rc1")
    path = repo / "event.json"
    path.write_text(
        json.dumps({"action": "published", "release": candidate_release("v1.2.4rc1")}),
        encoding="utf-8",
    )
    result = run_policy(repo, "check-event", str(path), "--ref", "refs/tags/v1.2.4rc1")
    assert outputs(result) == {
        "publish": "true",
        "revision": git(repo, "rev-parse", "HEAD"),
        "prerelease": "true",
    }


def test_candidate_event_with_final_package_versions_is_rejected(repo: Path) -> None:
    set_versions(repo, "1.2.4")
    git(repo, "tag", "v1.2.4rc1")
    path = repo / "event.json"
    path.write_text(
        json.dumps({"action": "published", "release": candidate_release("v1.2.4rc1")}),
        encoding="utf-8",
    )
    result = run_policy(repo, "check-event", str(path), "--ref", "refs/tags/v1.2.4rc1")
    assert result.returncode != 0
    assert "publish=true" not in result.stdout


# set-version ---------------------------------------------------------------


def test_set_version_rewrites_both_declarations_only(repo: Path) -> None:
    before = (repo / "pyproject.toml").read_text(encoding="utf-8")
    assert outputs(run_policy(repo, "set-version", "1.2.4rc1")) == {
        "changed": "true",
        "previous": "1.2.3",
    }
    assert (repo / "pyproject.toml").read_text(encoding="utf-8") == before.replace(
        '"1.2.3"', '"1.2.4rc1"'
    )
    assert (repo / "src/servonaut/__init__.py").read_text(encoding="utf-8") == (
        "__version__ = '1.2.4rc1'\n"
    )
    assert outputs(run_policy(repo, "set-version", "1.2.4"))["previous"] == "1.2.4rc1"


@pytest.mark.parametrize(
    "current,requested,changed",
    [
        ("1.2.3", "1.2.4", "true"),
        ("1.2.4rc2", "1.2.4", "true"),
        ("1.2.4", "1.2.4", "false"),
        ("1.2.5", "1.2.4", "false"),
        ("1.3.0rc1", "1.2.4", "false"),
    ],
)
def test_set_version_only_if_newer(
    repo: Path, current: str, requested: str, changed: str
) -> None:
    set_versions(repo, current)
    result = outputs(run_policy(repo, "set-version", requested, "--only-if-newer"))
    assert result == {"changed": changed, "previous": current}
    expected = requested if changed == "true" else current
    assert package_file_versions(repo) == (expected, expected)


def package_file_versions(repo: Path) -> tuple[str, str]:
    project = (repo / "pyproject.toml").read_text(encoding="utf-8")
    module = (repo / "src/servonaut/__init__.py").read_text(encoding="utf-8")
    return (
        re.search(r'^version = "([^"]+)"$', project, re.MULTILINE).group(1),
        re.search(r"^__version__ = '([^']+)'$", module, re.MULTILINE).group(1),
    )


@pytest.mark.parametrize(
    "version", ["1.2", "v1.2.4", "1.2.4-rc1", "1.2.4rc0", "1.2.4a1", "1.2.4\nx", ""]
)
def test_set_version_rejects_other_version_forms(repo: Path, version: str) -> None:
    result = run_policy(repo, "set-version", version)
    assert result.returncode != 0
    assert package_file_versions(repo) == ("1.2.3", "1.2.3")


def test_set_version_refuses_disagreeing_declarations(repo: Path) -> None:
    (repo / "src/servonaut/__init__.py").write_text("__version__ = '1.2.2'\n", encoding="utf-8")
    assert run_policy(repo, "set-version", "1.2.4").returncode != 0
    assert (repo / "pyproject.toml").read_text(encoding="utf-8").endswith('"1.2.3"\n')


# candidate planning --------------------------------------------------------


def open_branch(repo: Path, version: str, revision: str = "HEAD") -> None:
    """Record release/<version> as a branch on the remote, as a fetch would."""
    target = git(repo, "rev-parse", revision)
    git(repo, "update-ref", f"refs/remotes/origin/release/{version}", target)


def candidate_plan(
    repo: Path,
    releases: list[dict[str, Any]] | None = None,
    bump: str = "auto",
    command: str = "candidate",
) -> subprocess.CompletedProcess[str]:
    payload = json.dumps([release()] if releases is None else releases)
    return run_policy(repo, command, "--bump", bump, payload=payload)


def test_first_candidate_opens_a_release_branch(repo: Path) -> None:
    commit(repo, "src/servonaut/example.py", "feat: add output")
    assert outputs(candidate_plan(repo)) == {
        "action": "new",
        "last_tag": "v1.2.3",
        "version": "1.3.0",
        "branch": "release/1.3.0",
        "base": git(repo, "rev-parse", "HEAD"),
        "tag": "v1.3.0rc1",
        "bump": "minor",
        "count": "1",
    }


def test_first_candidate_honours_an_explicit_bump(repo: Path) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    assert outputs(candidate_plan(repo, bump="major"))["tag"] == "v2.0.0rc1"


def test_no_candidate_without_shipped_changes(repo: Path) -> None:
    commit(repo, "docs/guide.md", "feat: document output")
    assert outputs(candidate_plan(repo)) == {"action": "none", "last_tag": "v1.2.3"}


def test_candidate_numbers_are_never_reused(repo: Path) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    # An abandoned branch was deleted, but its candidates stay published.
    git(repo, "tag", "v1.2.4rc1")
    git(repo, "tag", "v1.2.4rc2", "HEAD~1")
    git(repo, "tag", "v1.2.40rc7")
    assert outputs(candidate_plan(repo))["tag"] == "v1.2.4rc3"


def test_open_branch_gets_the_next_candidate_from_its_head(repo: Path) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    git(repo, "switch", "-c", "release/1.2.4")
    set_versions(repo, "1.2.4rc1")
    git(repo, "tag", "v1.2.4rc1")
    commit(repo, "src/servonaut/fix.py", "fix: cherry-picked fix")
    head = git(repo, "rev-parse", "HEAD")
    git(repo, "switch", "master")
    commit(repo, "src/servonaut/later.py", "feat: not in this release")
    open_branch(repo, "1.2.4", head)
    assert outputs(candidate_plan(repo)) == {
        "action": "next",
        "last_tag": "v1.2.3",
        "version": "1.2.4",
        "branch": "release/1.2.4",
        "base": head,
        "tag": "v1.2.4rc2",
    }


def test_open_branch_without_a_candidate_gets_the_first(repo: Path) -> None:
    open_branch(repo, "1.2.4")
    assert outputs(candidate_plan(repo))["tag"] == "v1.2.4rc1"


def test_unchanged_open_branch_cuts_nothing(repo: Path, tmp_path: Path) -> None:
    set_versions(repo, "1.2.4rc1")
    git(repo, "tag", "v1.2.4rc1")
    open_branch(repo, "1.2.4")
    summary = tmp_path / "summary.md"
    payload = json.dumps([release(), candidate_release("v1.2.4rc1")])
    result = run_policy(repo, "candidate", "--summary", str(summary), payload=payload)
    assert outputs(result)["action"] == "none"
    assert outputs(result)["tag"] == "v1.2.4rc1"
    assert "has not changed since v1.2.4rc1" in summary.read_text(encoding="utf-8")


def test_candidate_tag_without_a_release_gets_only_its_release(repo: Path) -> None:
    # An earlier run pushed the branch and tag, then failed to create the release.
    head = set_versions(repo, "1.2.4rc1")
    git(repo, "tag", "v1.2.4rc1")
    open_branch(repo, "1.2.4")
    assert outputs(candidate_plan(repo)) == {
        "action": "release",
        "last_tag": "v1.2.3",
        "version": "1.2.4",
        "branch": "release/1.2.4",
        "base": head,
        "tag": "v1.2.4rc1",
    }


def index_page(tmp_path: Path, versions: list[str]) -> Path:
    page = tmp_path / "simple.json"
    page.write_text(json.dumps({"meta": {"api-version": "1.4"}, "versions": versions}))
    return page


@pytest.mark.parametrize("branch_open", [False, True])
def test_candidate_numbers_already_on_the_index_are_skipped(
    repo: Path, tmp_path: Path, branch_open: bool
) -> None:
    # rc1 and rc2 are on the index though their tags and releases were deleted.
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    if branch_open:
        open_branch(repo, "1.2.4")
    page = index_page(tmp_path, ["1.2.3", "1.2.4rc1", "1.2.4rc2", "1.2.40rc9"])
    payload = json.dumps([release(), candidate_release("v1.2.4rc3", draft=True)])
    result = run_policy(repo, "candidate", "--index-versions", str(page), payload=payload)
    assert outputs(result)["tag"] == "v1.2.4rc4"


@pytest.mark.parametrize("page", ['{"versions": "1.2.4rc1"}', "[]", '{"meta": {}}', "{"])
def test_unreadable_index_versions_fail_closed(repo: Path, tmp_path: Path, page: str) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    path = tmp_path / "simple.json"
    path.write_text(page)
    result = run_policy(
        repo, "candidate", "--index-versions", str(path), payload=json.dumps([release()])
    )
    assert result.returncode != 0
    assert not result.stdout


@pytest.mark.parametrize("command", ["candidate", "final"])
def test_unreleased_final_tag_blocks_a_new_cycle(repo: Path, command: str) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    git(repo, "tag", "v1.2.4")
    git(repo, "tag", "v1.2.5")
    result = candidate_plan(repo, command=command)
    assert result.returncode != 0
    assert "Tagged without a published release: v1.2.4, v1.2.5" in result.stderr
    assert "delete the never-released tag by hand" in result.stderr


def test_deleting_a_never_released_tag_starts_a_new_candidate(repo: Path) -> None:
    # The promoted candidate was withdrawn before its release was created.
    promoted_without_release(repo)
    git(repo, "tag", "-d", "v1.2.4")
    releases = [release(), candidate_release("v1.2.4rc1")]
    planned = outputs(candidate_plan(repo, releases))
    assert (planned["action"], planned["tag"]) == ("new", "v1.2.4rc2")


def test_other_branch_names_are_not_release_branches(repo: Path) -> None:
    for name in ("release/notes", "release/1.2", "release/1.2.4/x", "releases/1.2.4"):
        git(repo, "update-ref", f"refs/remotes/origin/{name}", "HEAD")
    git(repo, "update-ref", "refs/remotes/upstream/release/1.2.4", "HEAD")
    assert outputs(candidate_plan(repo))["action"] == "none"


@pytest.mark.parametrize("command", ["candidate", "final"])
def test_two_open_release_branches_are_refused(repo: Path, command: str) -> None:
    open_branch(repo, "1.2.4")
    open_branch(repo, "1.3.0")
    result = candidate_plan(repo, command=command)
    assert result.returncode != 0
    assert not result.stdout
    assert "More than one release branch is open (release/1.2.4, release/1.3.0)" in result.stderr


@pytest.mark.parametrize("command", ["candidate", "final"])
def test_branch_of_a_released_version_is_refused(repo: Path, command: str) -> None:
    git(repo, "tag", "v1.2.4")
    open_branch(repo, "1.2.4")
    result = candidate_plan(repo, [release(), release("v1.2.4")], command=command)
    assert result.returncode != 0
    assert "v1.2.4 is already tagged" in result.stderr


@pytest.mark.parametrize("command", ["candidate", "final"])
def test_branch_not_above_the_latest_release_is_refused(repo: Path, command: str) -> None:
    open_branch(repo, "1.2.2")
    result = candidate_plan(repo, command=command)
    assert result.returncode != 0
    assert "not newer than the latest stable release v1.2.3" in result.stderr


def test_bump_is_refused_while_a_branch_is_open(repo: Path) -> None:
    open_branch(repo, "1.2.4")
    result = candidate_plan(repo, bump="minor")
    assert result.returncode != 0
    assert "release/1.2.4 is open" in result.stderr


@pytest.mark.parametrize("command", ["candidate", "final"])
def test_candidate_and_final_plans_are_read_only(repo: Path, command: str) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    open_branch(repo, "1.2.4")
    before = git(repo, "show-ref"), git(repo, "status", "--porcelain")
    candidate_plan(repo, command=command)
    assert (git(repo, "show-ref"), git(repo, "status", "--porcelain")) == before


# final planning ------------------------------------------------------------


def branch_with_candidates(repo: Path, *numbers: int) -> str:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    git(repo, "switch", "-c", "release/1.2.4")
    for number in numbers:
        if number > numbers[0]:
            commit(repo, f"src/servonaut/fix{number}.py", f"fix: candidate {number}")
        set_versions(repo, f"1.2.4rc{number}")
        git(repo, "tag", f"v1.2.4rc{number}")
    head = git(repo, "rev-parse", "HEAD")
    git(repo, "switch", "master")
    open_branch(repo, "1.2.4", head)
    return head


def test_final_promotes_the_latest_published_candidate(repo: Path) -> None:
    head = branch_with_candidates(repo, 1, 2)
    releases = [release(), candidate_release("v1.2.4rc1"), candidate_release("v1.2.4rc2")]
    assert outputs(candidate_plan(repo, releases, command="final")) == {
        "action": "promote",
        "last_tag": "v1.2.3",
        "version": "1.2.4",
        "branch": "release/1.2.4",
        "base": head,
        "candidate": "v1.2.4rc2",
        "tag": "v1.2.4",
    }


def test_final_without_a_release_branch_promotes_nothing(repo: Path, tmp_path: Path) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    summary = tmp_path / "summary.md"
    payload = json.dumps([release()])
    result = run_policy(repo, "final", "--summary", str(summary), payload=payload)
    assert outputs(result) == {"action": "none", "last_tag": "v1.2.3"}
    assert "No candidate to promote" in summary.read_text(encoding="utf-8")


def test_final_without_a_candidate_promotes_nothing(repo: Path) -> None:
    open_branch(repo, "1.2.4")
    assert outputs(candidate_plan(repo, command="final"))["action"] == "none"


def test_final_refuses_changes_no_candidate_contains(repo: Path) -> None:
    head = branch_with_candidates(repo, 1)
    git(repo, "switch", "--detach", head)
    commit(repo, "src/servonaut/late.py", "fix: untested")
    open_branch(repo, "1.2.4")
    git(repo, "switch", "master")
    result = candidate_plan(repo, [release(), candidate_release("v1.2.4rc1")], command="final")
    assert result.returncode != 0
    assert "has changes that no candidate contains yet (after v1.2.4rc1)" in result.stderr


@pytest.mark.parametrize(
    "releases",
    [
        [release()],
        [release(), candidate_release("v1.2.4rc1", draft=True)],
        [release(), candidate_release("v1.2.4rc1", published_at=None)],
        [release(), release("v1.2.4rc1")],
    ],
)
def test_final_refuses_an_unpublished_candidate(
    repo: Path, releases: list[dict[str, Any]]
) -> None:
    branch_with_candidates(repo, 1)
    result = candidate_plan(repo, releases, command="final")
    assert result.returncode != 0
    assert "v1.2.4rc1 is not a published pre-release" in result.stderr


def test_final_refuses_a_candidate_with_other_package_versions(repo: Path) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    git(repo, "tag", "v1.2.4rc1")
    open_branch(repo, "1.2.4")
    result = candidate_plan(repo, [release(), candidate_release("v1.2.4rc1")], command="final")
    assert result.returncode != 0
    assert "do not match v1.2.4rc1" in result.stderr


def promoted_without_release(repo: Path, *, extra_change: bool = False) -> str:
    """A promotion whose tag landed but whose release was never created."""
    head = branch_with_candidates(repo, 1)
    git(repo, "update-ref", "-d", "refs/remotes/origin/release/1.2.4")
    git(repo, "switch", "--detach", head)
    if extra_change:
        commit(repo, "src/servonaut/untested.py", "fix: untested")
    promoted = set_versions(repo, "1.2.4")
    git(repo, "tag", "v1.2.4")
    git(repo, "switch", "master")
    return promoted


def test_final_creates_only_the_missing_release_of_a_promotion(
    repo: Path, tmp_path: Path
) -> None:
    promoted = promoted_without_release(repo)
    summary = tmp_path / "summary.md"
    payload = json.dumps([release(), candidate_release("v1.2.4rc1")])
    result = run_policy(repo, "final", "--summary", str(summary), payload=payload)
    assert outputs(result) == {
        "action": "release",
        "last_tag": "v1.2.3",
        "version": "1.2.4",
        "base": promoted,
        "candidate": "v1.2.4rc1",
        "tag": "v1.2.4",
    }
    assert "only the release is created" in summary.read_text(encoding="utf-8")


def test_final_refuses_a_stray_tag_that_was_not_promoted(repo: Path) -> None:
    promoted_without_release(repo, extra_change=True)
    result = candidate_plan(repo, [release(), candidate_release("v1.2.4rc1")], command="final")
    assert result.returncode != 0
    assert "was not promoted from a candidate" in result.stderr


def test_final_refuses_a_missing_release_while_a_branch_is_open(repo: Path) -> None:
    promoted_without_release(repo)
    open_branch(repo, "1.2.5")
    result = candidate_plan(repo, [release(), candidate_release("v1.2.4rc1")], command="final")
    assert result.returncode != 0
    assert "Tagged without a published release: v1.2.4" in result.stderr


def test_final_refuses_a_bump(repo: Path) -> None:
    result = candidate_plan(repo, bump="patch", command="final")
    assert result.returncode != 0
    assert "A bump applies to new candidates only" in result.stderr


# ---------------------------------------------------------------------------
# Release workflow: stages, approval and the mutating steps
# ---------------------------------------------------------------------------


def run_step(
    workflow: str, name: str, *, prelude: str = "", cwd: Path | None = None, **env: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", prelude + step_script(workflow, name)],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, **env},
    )


@pytest.mark.parametrize(
    "event,schedule,requested,stage",
    [
        ("schedule", "47 8 * * 1", "", "candidate"),
        ("schedule", "47 8 * * 4", "", "final"),
        ("schedule", "0 0 * * 0", "", None),
        ("workflow_dispatch", "", "candidate", "candidate"),
        ("workflow_dispatch", "", "final", "final"),
        ("workflow_dispatch", "", "", None),
        ("workflow_dispatch", "", "final;x", None),
    ],
)
def test_stage_follows_the_schedule_or_the_input(
    tmp_path: Path, event: str, schedule: str, requested: str, stage: str | None
) -> None:
    result = run_step(
        "release.yml",
        "Choose the stage",
        GITHUB_EVENT_NAME=event,
        SCHEDULE=schedule,
        REQUESTED=requested,
        DRY_RUN="false",
        GITHUB_OUTPUT=str(tmp_path / "output"),
        GITHUB_STEP_SUMMARY=str(tmp_path / "summary"),
    )
    if stage is None:
        assert result.returncode == 1
        assert "::error::" in result.stdout
        return
    assert result.returncode == 0, result.stdout + result.stderr
    written = (tmp_path / "output").read_text(encoding="utf-8").splitlines()
    assert written == [f"stage={stage}", "dry_run=false"]


def test_every_schedule_maps_to_a_stage() -> None:
    source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    trigger = source.split("\njobs:\n", 1)[0]
    crons = re.findall(r'^    - cron: "([^"]+)"', trigger, re.MULTILINE)
    assert crons == ["47 8 * * 1", "47 8 * * 4"]
    script = step_script("release.yml", "Choose the stage")
    for cron in crons:
        assert f'"{cron}") stage=' in script


def test_final_waits_for_approval_before_anything_is_written() -> None:
    jobs = release_jobs()
    assert set(jobs) == {"plan", "candidate", "approval", "promote"}
    approval = jobs["approval"]
    assert "    environment: release-approval\n" in approval
    assert "    permissions: {}\n" in approval
    assert "needs.plan.outputs.action == 'promote'" in approval
    assert "uses:" not in approval and "secrets." not in approval
    promote = jobs["promote"]
    assert "    needs: [plan, approval]\n" in promote
    assert "needs.approval.result == 'success'" in promote
    for name in ("plan", "approval"):
        assert "git push" not in jobs[name] and "release-push.sh" not in jobs[name]
        assert "gh release create" not in jobs[name]
    assert "secrets." not in approval
    # Each stage's writes queue behind that stage only, so a queued candidate
    # run can never cancel an approved promotion; approval holds no lock.
    groups = {}
    for name in ("candidate", "promote"):
        match = re.search(
            r"^    concurrency:\n      group: (\S+)\n      cancel-in-progress: false\n",
            jobs[name],
            re.MULTILINE,
        )
        assert match, name
        groups[name] = match.group(1)
    assert groups == {"candidate": "release-stage-candidate", "promote": "release-stage-final"}
    assert "concurrency" not in jobs["approval"] and "concurrency" not in jobs["plan"]
    assert "\nconcurrency:" not in (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    # No other workflow shares a group name with these jobs.
    for path in WORKFLOWS.glob("*.yml"):
        if path.name != "release.yml":
            text = path.read_text(encoding="utf-8")
            assert not any(f"group: {group}\n" in text for group in groups.values()), path.name


def test_candidate_job_runs_only_for_a_planned_candidate() -> None:
    candidate = release_jobs()["candidate"]
    assert "needs.plan.outputs.stage == 'candidate'" in candidate
    assert "needs.plan.outputs.action == 'new' || needs.plan.outputs.action == 'next'" in candidate
    assert "environment:" not in candidate


def test_releases_are_created_with_generated_notes_and_right_channel() -> None:
    cut = step_script("release.yml", "Cut the candidate")
    promote = step_script("release.yml", "Promote the candidate")
    for script in (cut, promote):
        assert '--generate-notes --notes-start-tag "$LAST"' in script
        assert "--verify-tag" in script
        assert 'bash "$RUNNER_TEMP/release-push.sh" --atomic' in script
        assert "--force-with-lease=" in script
    assert "--prerelease" in cut
    assert "--prerelease" not in promote


def fake_gh(tmp_path: Path, stdout: str = "", status: int = 0) -> str:
    """A gh stand-in that logs its arguments and prints fixed output."""
    log = tmp_path / "gh.log"
    output = tmp_path / "gh.out"
    output.write_text(stdout, encoding="utf-8")
    return (
        f'gh() {{ printf "%s\\n" "$*" >> "{log}"; cat "{output}"; return {status}; }}\n'
    )


@pytest.mark.parametrize(
    "reviewers,status,code",
    [("1", 0, 0), ("2", 0, 0), ("0", 0, 1), ("", 0, 1), ("", 1, 1), ('{"x":1}', 0, 1)],
)
def test_promotion_needs_a_required_reviewer(
    tmp_path: Path, reviewers: str, status: int, code: int
) -> None:
    result = run_step(
        "release.yml",
        "Require a reviewer for the promotion",
        prelude=fake_gh(tmp_path, reviewers, status),
        REPO="example/project",
    )
    assert result.returncode == code, result.stdout + result.stderr
    if code:
        assert "::error::The release-approval environment must require a reviewer" in result.stdout
    log = (tmp_path / "gh.log").read_text(encoding="utf-8")
    assert "repos/example/project/environments/release-approval" in log
    assert 'select(.type == "required_reviewers")' in log


RELEASES_FIXTURE = [
    {"tag_name": "v1.2.5rc1", "draft": False, "prerelease": True,
     "published_at": "2025-01-02T08:00:00Z"},
    {"tag_name": "v1.2.5-preview.1", "draft": False, "prerelease": True,
     "published_at": "2025-01-02T09:00:00Z"},
    {"tag_name": "v1.2.6", "draft": True, "prerelease": False, "published_at": None},
    {"tag_name": "v1.2.3", "draft": False, "prerelease": False,
     "published_at": "2025-01-01T23:59:59Z"},
]


def jq_gh(tmp_path: Path, releases: list[dict[str, Any]]) -> str:
    """A gh stand-in that applies the step's own --jq filter to fixture data."""
    fixture = tmp_path / "releases.json"
    fixture.write_text(json.dumps(releases), encoding="utf-8")
    return (
        "gh() {\n"
        '  while [ "$#" -gt 0 ] && [ "$1" != "--jq" ]; do shift; done\n'
        f'  jq -r "$2" "{fixture}"\n'
        "}\n"
        'date() { echo "2025-01-02"; }\n'
    )


needs_jq = pytest.mark.skipif(shutil.which("jq") is None, reason="The step uses jq")


@needs_jq
@pytest.mark.parametrize(
    "extra,code",
    [
        ([], 0),
        ([{"tag_name": "v1.2.4", "draft": False, "prerelease": False,
           "published_at": "2025-01-02T07:00:00Z"}], 1),
    ],
)
def test_only_stable_releases_count_towards_the_daily_limit(
    tmp_path: Path, extra: list[dict[str, Any]], code: int
) -> None:
    common = {
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "REPO": "example/project",
    }
    releases = RELEASES_FIXTURE + extra
    final = run_step(
        "release.yml",
        "Refuse if a release already went out today",
        prelude=jq_gh(tmp_path, releases),
        GITHUB_EVENT_NAME="workflow_dispatch",
        **common,
    )
    assert final.returncode == code, final.stdout + final.stderr
    publish = run_step(
        "publish.yml",
        "Refuse a second release on the same day",
        prelude=jq_gh(tmp_path, releases),
        THIS_TAG="v1.2.7",
        THIS_PUBLISHED="2025-01-02T12:00:00Z",
        PRERELEASE="false",
        OVERRIDE="",
        **common,
    )
    assert publish.returncode == code, publish.stdout + publish.stderr
    if code:
        assert "v1.2.4" in final.stdout and "v1.2.4" in publish.stdout
        assert "rc1" not in publish.stdout and "preview" not in publish.stdout


def test_prereleases_skip_the_daily_limit(tmp_path: Path) -> None:
    result = run_step(
        "publish.yml",
        "Refuse a second release on the same day",
        prelude=fake_gh(tmp_path, "v1.2.4", 0),
        REPO="example/project",
        THIS_TAG="v1.2.5rc1",
        THIS_PUBLISHED="2025-01-02T12:00:00Z",
        PRERELEASE="true",
        OVERRIDE="",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "gh.log").exists()


def test_prereleases_publish_to_pypi_but_not_the_mcp_registry() -> None:
    source = (WORKFLOWS / "publish.yml").read_text(encoding="utf-8")
    assert "prerelease: ${{ steps.policy.outputs.prerelease }}" in _job(source, "eligibility")
    assert "if: needs.eligibility.outputs.publish == 'true'\n" in _job(source, "publish")
    assert (
        "if: needs.eligibility.outputs.publish == 'true'"
        " && needs.eligibility.outputs.prerelease == 'false'\n"
    ) in _job(source, "mcp-registry")
    assert "PRERELEASE: ${{ needs.eligibility.outputs.prerelease }}" in _job(source, "cadence")


# The mutating steps run for real against a local bare repository standing in
# for GitHub, with gh stubbed out.


@pytest.fixture
def origin(repo: Path, tmp_path: Path) -> Path:
    remote = tmp_path / "origin.git"
    git(tmp_path, "init", "--bare", "--template=", "-b", "master", str(remote))
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "origin", "master", "v1.2.3")
    return remote


def checkout(origin: Path, tmp_path: Path, name: str) -> Path:
    """A fresh clone with every branch and tag, like a full-history checkout."""
    clone = tmp_path / name
    git(tmp_path, "clone", "--quiet", str(origin), str(clone))
    git(clone, "fetch", "--quiet", "--tags", "origin")
    return clone


def runner_temp(tmp_path: Path) -> Path:
    """RUNNER_TEMP holding the run's release tooling, as the jobs prepare it."""
    directory = tmp_path / "runner-temp"
    directory.mkdir(exist_ok=True)
    shutil.copy(POLICY, directory / "release-policy.py")
    shutil.copy(PUSH, directory / "release-push.sh")
    return directory


def gh_calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "gh.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


RELEASE_LOOKUP = (
    "api --paginate repos/example/project/releases"
    ' --jq .[] | select(.tag_name == "{tag}") | .id'
)


def python_shim() -> str:
    return f'python3() {{ "{sys.executable}" "$@"; }}\n'


def run_mutation(
    tmp_path: Path, clone: Path, name: str, gh_output: str = "", **env: str
) -> subprocess.CompletedProcess[str]:
    return run_step(
        "release.yml",
        name,
        prelude=fake_gh(tmp_path, gh_output) + python_shim(),
        cwd=clone,
        RUNNER_TEMP=str(runner_temp(tmp_path)),
        GITHUB_STEP_SUMMARY=str(tmp_path / "summary"),
        GH_TOKEN="test-token",
        REPO="example/project",
        DRAFT="false",
        **env,
    )


def remote_refs(origin: Path) -> dict[str, str]:
    refs = {}
    for line in git(origin, "show-ref").splitlines():
        sha, ref = line.split(" ", 1)
        refs[ref] = sha
    return refs


def test_cut_opens_the_branch_and_tags_the_first_candidate(
    repo: Path, origin: Path, tmp_path: Path
) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    git(repo, "push", "origin", "master")
    base = git(repo, "rev-parse", "HEAD")
    clone = checkout(origin, tmp_path, "runner")
    result = run_mutation(
        tmp_path, clone, "Cut the candidate",
        ACTION="new", TAG="v1.2.4rc1", BRANCH="release/1.2.4", BASE=base, LAST="v1.2.3",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    refs = remote_refs(origin)
    head = refs["refs/heads/release/1.2.4"]
    assert refs["refs/tags/v1.2.4rc1"] == head
    assert refs["refs/heads/master"] == base
    assert git(origin, "rev-parse", f"{head}^") == base
    assert versions(origin, head) == ("1.2.4rc1", "1.2.4rc1")
    assert git(origin, "log", "-1", "--format=%s%n%an", head) == (
        "chore: bump version to 1.2.4rc1\ngithub-actions[bot]"
    )
    assert gh_calls(tmp_path) == [
        RELEASE_LOOKUP.format(tag="v1.2.4rc1"),
        "release create v1.2.4rc1 --title v1.2.4rc1 --prerelease --verify-tag"
        " --generate-notes --notes-start-tag v1.2.3",
    ]


def test_cut_adds_the_next_candidate_to_the_open_branch(
    repo: Path, origin: Path, tmp_path: Path
) -> None:
    git(repo, "switch", "-c", "release/1.2.4")
    set_versions(repo, "1.2.4rc1")
    git(repo, "tag", "v1.2.4rc1")
    commit(repo, "src/servonaut/fix.py", "fix: cherry-picked fix")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "push", "origin", "release/1.2.4", "v1.2.4rc1")
    clone = checkout(origin, tmp_path, "runner")
    result = run_mutation(
        tmp_path, clone, "Cut the candidate",
        ACTION="next", TAG="v1.2.4rc2", BRANCH="release/1.2.4", BASE=base, LAST="v1.2.3",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    refs = remote_refs(origin)
    assert refs["refs/tags/v1.2.4rc2"] == refs["refs/heads/release/1.2.4"]
    assert git(origin, "rev-parse", "release/1.2.4^") == base
    assert versions(origin, "release/1.2.4") == ("1.2.4rc2", "1.2.4rc2")


@pytest.mark.parametrize("action", ["new", "next"])
def test_cut_pushes_nothing_when_the_branch_moved(
    repo: Path, origin: Path, tmp_path: Path, action: str
) -> None:
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "switch", "-c", "release/1.2.4")
    commit(repo, "src/servonaut/other.py", "fix: pushed meanwhile")
    git(repo, "push", "origin", "release/1.2.4")
    before = remote_refs(origin)
    clone = checkout(origin, tmp_path, "runner")
    result = run_mutation(
        tmp_path, clone, "Cut the candidate",
        ACTION=action, TAG="v1.2.4rc1", BRANCH="release/1.2.4", BASE=base, LAST="v1.2.3",
    )
    assert result.returncode != 0
    assert remote_refs(origin) == before
    assert gh_calls(tmp_path) == []


def prepare_promotion(repo: Path, origin: Path, *, master_version: str | None = None) -> str:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    git(repo, "switch", "-c", "release/1.2.4")
    candidate = set_versions(repo, "1.2.4rc1")
    git(repo, "tag", "v1.2.4rc1")
    git(repo, "switch", "master")
    commit(repo, "src/servonaut/later.py", "feat: next week")
    if master_version:
        set_versions(repo, master_version)
    git(repo, "push", "origin", "master", "release/1.2.4", "v1.2.4rc1")
    return candidate


def promote(
    tmp_path: Path, origin: Path, base: str, action: str = "promote", gh_output: str = ""
) -> subprocess.CompletedProcess[str]:
    clone = checkout(origin, tmp_path, f"runner-{action}")
    return run_mutation(
        tmp_path, clone, "Promote the candidate", gh_output,
        ACTION=action, VERSION="1.2.4", TAG="v1.2.4", CANDIDATE="v1.2.4rc1",
        BRANCH="release/1.2.4" if action == "promote" else "", BASE=base, LAST="v1.2.3",
    )


def test_promotion_changes_only_the_version(
    repo: Path, origin: Path, tmp_path: Path
) -> None:
    candidate = prepare_promotion(repo, origin)
    master = git(repo, "rev-parse", "master")
    result = promote(tmp_path, origin, candidate)
    assert result.returncode == 0, result.stdout + result.stderr
    refs = remote_refs(origin)
    assert "refs/heads/release/1.2.4" not in refs
    assert git(origin, "rev-parse", "v1.2.4^") == candidate
    assert git(origin, "diff", "--name-only", "v1.2.4rc1", "v1.2.4").splitlines() == [
        "pyproject.toml",
        "src/servonaut/__init__.py",
    ]
    assert versions(origin, "v1.2.4") == ("1.2.4", "1.2.4")
    # Master keeps its own work and now carries the released version.
    assert git(origin, "rev-parse", "master^") == master
    assert versions(origin, "master") == ("1.2.4", "1.2.4")
    assert git(origin, "log", "-1", "--format=%s", "master") == "chore: bump version to 1.2.4"
    assert gh_calls(tmp_path) == [
        RELEASE_LOOKUP.format(tag="v1.2.4"),
        "release create v1.2.4 --title v1.2.4 --verify-tag"
        " --generate-notes --notes-start-tag v1.2.3",
    ]


def test_promotion_leaves_a_higher_master_version_alone(
    repo: Path, origin: Path, tmp_path: Path
) -> None:
    candidate = prepare_promotion(repo, origin, master_version="1.3.0")
    master = git(repo, "rev-parse", "master")
    result = promote(tmp_path, origin, candidate)
    assert result.returncode == 0, result.stdout + result.stderr
    assert remote_refs(origin)["refs/heads/master"] == master
    assert "refs/tags/v1.2.4" in remote_refs(origin)


def test_promotion_pushes_nothing_when_the_branch_moved(
    repo: Path, origin: Path, tmp_path: Path
) -> None:
    candidate = prepare_promotion(repo, origin)
    git(repo, "switch", "release/1.2.4")
    commit(repo, "src/servonaut/late.py", "fix: after approval")
    git(repo, "push", "origin", "release/1.2.4")
    before = remote_refs(origin)
    result = promote(tmp_path, origin, candidate)
    assert result.returncode != 0
    assert remote_refs(origin) == before
    assert gh_calls(tmp_path) == []


def test_promotion_refuses_more_than_a_version_change(
    repo: Path, origin: Path, tmp_path: Path
) -> None:
    prepare_promotion(repo, origin)
    # A base that is not the tagged candidate would ship untested changes.
    master = git(repo, "rev-parse", "master")
    before = remote_refs(origin)
    result = promote(tmp_path, origin, master)
    assert result.returncode == 1
    assert "would differ from v1.2.4rc1 in more than its version" in result.stdout
    assert remote_refs(origin) == before


@pytest.mark.parametrize(
    "change,message",
    [
        (None, None),
        ("commit", "has changes that no candidate contains yet"),
        ("candidate", "The release branch changed while v1.2.4rc1 waited for approval"),
    ],
)
def test_promotion_rechecks_the_candidate_after_approval(
    repo: Path, origin: Path, tmp_path: Path, change: str | None, message: str | None
) -> None:
    candidate = prepare_promotion(repo, origin)
    releases = [release(), candidate_release("v1.2.4rc1")]
    if change:
        git(repo, "switch", "release/1.2.4")
        commit(repo, "src/servonaut/late.py", "fix: after approval")
        if change == "candidate":
            set_versions(repo, "1.2.4rc2")
            git(repo, "tag", "v1.2.4rc2")
            git(repo, "push", "origin", "v1.2.4rc2")
            releases.append(candidate_release("v1.2.4rc2"))
        git(repo, "push", "origin", "release/1.2.4")
    clone = checkout(origin, tmp_path, "runner")
    result = run_step(
        "release.yml",
        "Confirm the approved candidate is unchanged",
        prelude=fake_gh(tmp_path, json.dumps(releases)) + python_shim(),
        cwd=clone,
        RUNNER_TEMP=str(runner_temp(tmp_path)),
        REPO="example/project",
        ACTION="promote",
        CANDIDATE="v1.2.4rc1",
        TAG="v1.2.4",
        BASE=candidate,
    )
    if message is None:
        assert result.returncode == 0, result.stdout + result.stderr
        return
    assert result.returncode == 1
    assert "::error::" in result.stdout + result.stderr
    assert message in result.stdout + result.stderr


def test_cut_creates_only_the_missing_prerelease(
    repo: Path, origin: Path, tmp_path: Path
) -> None:
    git(repo, "switch", "-c", "release/1.2.4")
    head = set_versions(repo, "1.2.4rc1")
    git(repo, "tag", "v1.2.4rc1")
    git(repo, "push", "origin", "release/1.2.4", "v1.2.4rc1")
    before = remote_refs(origin)
    clone = checkout(origin, tmp_path, "runner")
    result = run_mutation(
        tmp_path, clone, "Cut the candidate",
        ACTION="release", TAG="v1.2.4rc1", BRANCH="release/1.2.4", BASE=head, LAST="v1.2.3",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert remote_refs(origin) == before
    assert gh_calls(tmp_path)[-1].startswith("release create v1.2.4rc1 --title v1.2.4rc1 --prerelease")


@pytest.mark.parametrize("step", ["Cut the candidate", "Promote the candidate"])
def test_an_existing_draft_release_is_never_duplicated(
    repo: Path, origin: Path, tmp_path: Path, step: str
) -> None:
    git(repo, "tag", "v1.2.4rc1")
    git(repo, "tag", "v1.2.4")
    git(repo, "push", "origin", "v1.2.4rc1", "v1.2.4")
    clone = checkout(origin, tmp_path, "runner")
    tag = "v1.2.4rc1" if step == "Cut the candidate" else "v1.2.4"
    result = run_mutation(
        tmp_path, clone, step, "123",
        ACTION="release", TAG=tag, VERSION="1.2.4", CANDIDATE="v1.2.4rc1",
        BRANCH="", BASE=git(repo, "rev-parse", "HEAD"), LAST="v1.2.3",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"::notice::{tag} already has a release" in result.stdout
    assert not any(call.startswith("release create") for call in gh_calls(tmp_path))


def test_promotion_rerun_creates_only_the_missing_release(
    repo: Path, origin: Path, tmp_path: Path
) -> None:
    candidate = prepare_promotion(repo, origin)
    assert promote(tmp_path, origin, candidate).returncode == 0
    promoted = remote_refs(origin)
    (tmp_path / "gh.log").unlink()
    result = promote(tmp_path, origin, promoted["refs/tags/v1.2.4"], action="release")
    assert result.returncode == 0, result.stdout + result.stderr
    assert remote_refs(origin) == promoted
    assert gh_calls(tmp_path)[-1].startswith("release create v1.2.4 --title v1.2.4 --verify-tag")


def test_release_failure_says_how_to_recover(repo: Path, origin: Path, tmp_path: Path) -> None:
    candidate = prepare_promotion(repo, origin)
    clone = checkout(origin, tmp_path, "runner")
    prelude = (
        'gh() { [ "$1" = "api" ] && return 0; echo "gh: HTTP 502"; return 1; }\n'
        + python_shim()
    )
    result = run_step(
        "release.yml", "Promote the candidate", prelude=prelude, cwd=clone,
        RUNNER_TEMP=str(runner_temp(tmp_path)), GITHUB_STEP_SUMMARY=str(tmp_path / "summary"),
        GH_TOKEN="test-token", REPO="example/project", DRAFT="false", ACTION="promote",
        VERSION="1.2.4", TAG="v1.2.4", CANDIDATE="v1.2.4rc1", BRANCH="release/1.2.4",
        BASE=candidate, LAST="v1.2.3",
    )
    assert result.returncode == 1
    assert "Run the final stage again: after approval it creates only the release" in result.stdout
    # The push had landed, so the next plan offers exactly that.
    assert "refs/tags/v1.2.4" in remote_refs(origin)


# The release token never reaches disk or argv -------------------------------


def test_release_push_passes_the_token_only_through_the_environment(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "git.record"
    (bin_dir / "git").write_text(
        "#!/bin/sh\n"
        f'{{ echo "argv=$*"; env | grep "^GIT_CONFIG_" | sort; }} > "{record}"\n',
        encoding="utf-8",
    )
    (bin_dir / "git").chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    result = subprocess.run(
        ["bash", str(PUSH), "--atomic", "origin", "HEAD:refs/heads/x"],
        env={**env, "GH_TOKEN": "s3cret-token"},
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    recorded = record.read_text(encoding="utf-8").splitlines()
    assert recorded[0] == "argv=push --atomic origin HEAD:refs/heads/x"
    expected = "AUTHORIZATION: basic " + base64.b64encode(b"x-access-token:s3cret-token").decode()
    assert recorded[1:] == [
        "GIT_CONFIG_COUNT=1",
        "GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
        f"GIT_CONFIG_VALUE_0={expected}",
    ]
    assert "s3cret-token" not in result.stdout + result.stderr
    missing = subprocess.run(
        ["bash", str(PUSH), "origin"],
        env={key: value for key, value in env.items() if key != "GH_TOKEN"},
        text=True, capture_output=True, check=False,
    )
    assert missing.returncode != 0
    assert not record.exists() or record.read_text(encoding="utf-8").startswith("argv=push --atomic")


def test_release_token_is_only_in_the_steps_that_write() -> None:
    jobs = release_jobs()
    plan_steps = re.split(r"^      - ", jobs["plan"], flags=re.MULTILINE)[1:]
    reading = [
        step.splitlines()[0]
        for step in plan_steps
        if "secrets.RELEASE_TOKEN }}" in step
    ]
    # The plan only reads with it, to see draft releases.
    assert reading == ["name: Look for a draft release"]
    assert "gh release" not in jobs["plan"] and "release-push.sh" not in jobs["plan"]
    for name, writer in (("candidate", "Cut the candidate"), ("promote", "Promote the candidate")):
        steps = re.split(r"^      - ", jobs[name], flags=re.MULTILINE)[1:]
        holding = [step.splitlines()[0] for step in steps if "secrets.RELEASE_TOKEN" in step]
        assert holding == [f"name: {writer}"], name
        checkout = next(step for step in steps if "actions/checkout@" in step)
        assert "persist-credentials: false" in checkout
        assert "token:" not in checkout
        assert 'bash "$RUNNER_TEMP/release-push.sh" --atomic' in jobs[name]
        assert "git push" not in jobs[name].replace("release-push.sh", "")


# PyPI checks before asking for approval --------------------------------------


def run_pypi_check(
    tmp_path: Path, *args: str, served: bool = True, yanked: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run the PyPI check with a curl stand-in on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    document = json.dumps({"info": {"version": "1.2.4rc1", "yanked": yanked}})
    body = f"printf '%s' '{document}'" if served else "exit 22"
    (bin_dir / "curl").write_text(
        f'#!/bin/sh\necho "$*" >> "{tmp_path / "curl.log"}"\n{body}\n', encoding="utf-8"
    )
    (bin_dir / "curl").chmod(0o755)
    return subprocess.run(
        ["bash", str(PYPI_CHECK), *args],
        env={**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"},
        text=True, capture_output=True, check=False,
    )


@needs_jq
@pytest.mark.parametrize(
    "served,yanked,args,code,message",
    [
        (True, False, ("v1.2.4rc1",), 0, "PyPI serves v1.2.4rc1, and it is not yanked."),
        (True, True, ("v1.2.4rc1",), 1, "v1.2.4rc1 is yanked on PyPI, so it will not be promoted"),
        (
            True, True, ("v1.2.4rc1", "v1.2.4"), 1,
            "delete the never-released tag by hand (git push origin :refs/tags/v1.2.4)",
        ),
        (False, False, ("v1.2.4rc1",), 1, "v1.2.4rc1 is not on PyPI, or PyPI could not be read"),
    ],
)
def test_promotion_needs_the_candidate_on_pypi_and_not_yanked(
    tmp_path: Path, served: bool, yanked: bool, args: tuple[str, ...], code: int, message: str
) -> None:
    result = run_pypi_check(tmp_path, *args, served=served, yanked=yanked)
    assert result.returncode == code, result.stdout + result.stderr
    assert message in result.stdout
    assert "https://pypi.org/pypi/servonaut/1.2.4rc1/json" in (tmp_path / "curl.log").read_text()


def test_pypi_is_checked_before_approval_and_again_before_pushing() -> None:
    plan = step_script("release.yml", "Require the candidate on PyPI")
    assert 'bash .github/scripts/candidate-on-pypi.sh "${args[@]}"' in plan
    promote = release_jobs()["promote"]
    names = re.findall(r"^      - name: (.+)$", promote, re.MULTILINE)
    assert names[-3:] == [
        "Refuse if a release already went out today",
        "Require the candidate on PyPI, still",
        "Promote the candidate",
    ]
    again = workflow_step("release.yml", "Require the candidate on PyPI, still")
    assert "if: steps.cadence.outputs.allowed == 'true'" in again
    assert 'bash "$RUNNER_TEMP/candidate-on-pypi.sh" "${args[@]}"' in again
    assert '.github/scripts/candidate-on-pypi.sh "$RUNNER_TEMP/"' in promote


@pytest.mark.parametrize(
    "token,existing,waiting",
    [("test-token", "123", "true"), ("test-token", "", "false"), ("", "123", "false")],
)
def test_a_draft_stable_release_is_not_sent_for_approval(
    tmp_path: Path, token: str, existing: str, waiting: str
) -> None:
    output = tmp_path / "output"
    result = run_step(
        "release.yml", "Look for a draft release",
        prelude=fake_gh(tmp_path, existing),
        GH_TOKEN=token, REPO="example/project", TAG="v1.2.4",
        GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(tmp_path / "summary"),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert output.read_text(encoding="utf-8").splitlines()[-1] == f"waiting={waiting}"
    if waiting == "true":
        assert "v1.2.4 already has a release waiting as a draft" in result.stdout
    plan = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert (
        "action: ${{ steps.draft.outputs.waiting == 'true' && 'none' "
        "|| steps.plan.outputs.action }}"
    ) in plan


def test_candidate_plan_reads_the_index_versions(repo: Path, tmp_path: Path) -> None:
    commit(repo, "src/servonaut/example.py", "fix: correct output")
    index = json.dumps({"meta": {"api-version": "1.4"}, "versions": ["1.2.3", "1.2.4rc1"]})
    curl = (
        "curl() {\n"
        '  while [ "$#" -gt 0 ]; do\n'
        f'    [ "$1" = "-o" ] && printf \'%s\' \'{index}\' > "$2"\n'
        "    shift\n"
        "  done\n"
        "}\n"
    )
    releases = json.dumps([release()])
    output = tmp_path / "output"
    (repo / ".github/scripts").mkdir(parents=True)
    shutil.copy(POLICY, repo / ".github/scripts/release-policy.py")
    result = run_step(
        "release.yml", "Plan the release",
        prelude=curl + fake_gh(tmp_path, releases) + python_shim(), cwd=repo,
        STAGE="candidate", BUMP="auto", REPO="example/project",
        RUNNER_TEMP=str(runner_temp(tmp_path)), GITHUB_OUTPUT=str(output),
        GITHUB_STEP_SUMMARY=str(tmp_path / "summary"),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "tag=v1.2.4rc2" in output.read_text(encoding="utf-8").splitlines()


def test_candidate_plan_refuses_without_the_index(repo: Path, tmp_path: Path) -> None:
    result = run_step(
        "release.yml", "Plan the release",
        prelude="curl() { return 22; }\n" + fake_gh(tmp_path) + python_shim(), cwd=repo,
        STAGE="candidate", BUMP="auto", REPO="example/project",
        RUNNER_TEMP=str(runner_temp(tmp_path)), GITHUB_OUTPUT=str(tmp_path / "output"),
        GITHUB_STEP_SUMMARY=str(tmp_path / "summary"),
    )
    assert result.returncode == 1
    assert "::error::Could not read the published versions from PyPI." in result.stdout
    assert gh_calls(tmp_path) == []


# The binary candidate gate applies to stable releases only -------------------


def test_python_release_candidates_pass_the_binary_candidate_gate(tmp_path: Path) -> None:
    log = tmp_path / "calls.log"
    result = subprocess.run(
        ["bash", "-c", _GATE_STUBS + step_script("publish.yml", "Require candidate verification when enabled")],
        text=True, capture_output=True, check=False,
        env={
            **os.environ, "REQUIRE_CANDIDATE": "true", "PRERELEASE": "true",
            "REPO": "example/project", "THIS_TAG": "v1.2.4rc1", "REVISION": "c" * 40,
            "TEST_LOG": str(log),
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "v1.2.4rc1 is a Python release candidate" in result.stdout
    assert not log.exists()
    job = _job((WORKFLOWS / "publish.yml").read_text(encoding="utf-8"), "candidate")
    assert "PRERELEASE: ${{ needs.eligibility.outputs.prerelease }}" in job
    assert "if: env.REQUIRE_CANDIDATE == 'true' && env.PRERELEASE != 'true'" in job
    # Skipping the job itself would skip the tests and the upload after it.
    assert "if: needs.eligibility.outputs.publish == 'true'\n" in job


@needs_jq
@pytest.mark.parametrize("action,names_tag", [("promote", False), ("release", True)])
def test_pypi_step_names_the_pushed_tag_only_when_it_exists(
    tmp_path: Path, action: str, names_tag: bool
) -> None:
    run_pypi_check(tmp_path, "v1.2.4rc1")  # creates the curl stand-in
    result = subprocess.run(
        ["bash", "-c", step_script("release.yml", "Require the candidate on PyPI")],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
            "ACTION": action,
            "CANDIDATE": "v1.2.4rc1",
            "TAG": "v1.2.4",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    (tmp_path / "bin" / "curl").write_text(
        "#!/bin/sh\nprintf '%s' '{\"info\": {\"yanked\": true}}'\n", encoding="utf-8"
    )
    yanked = subprocess.run(
        ["bash", "-c", step_script("release.yml", "Require the candidate on PyPI")],
        cwd=ROOT, text=True, capture_output=True, check=False,
        env={
            **os.environ,
            "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
            "ACTION": action, "CANDIDATE": "v1.2.4rc1", "TAG": "v1.2.4",
        },
    )
    assert yanked.returncode == 1
    assert ("refs/tags/v1.2.4" in yanked.stdout) is names_tag
