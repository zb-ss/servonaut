"""Exercise release decisions with real, disposable Git histories."""

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
    ],
)
def test_nonstable_events_never_enable_publishing(
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


def test_stable_release_on_another_branch_is_not_a_baseline(repo: Path) -> None:
    git(repo, "switch", "-c", "feature/example")
    commit(repo, "src/servonaut/example.py", "feat: add output")
    git(repo, "tag", "v9.0.0")
    git(repo, "switch", "master")
    assert plan(repo, [release("v9.0.0"), release()])["last_tag"] == "v1.2.3"


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
    step = workflow_step("release.yml", "Bump, tag and release")
    assert "steps.plan.outputs.release == 'true'" in step
    assert "env.DRY_RUN != 'true'" in step
    assert "steps.cadence.outputs.allowed == 'true'" in step
    assert "id: cadence" in workflow_step(
        "release.yml", "Refuse if a release already went out today"
    )


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
    step = workflow_step("release.yml", "Decide the version")
    assert "set -euo pipefail" in step
    assert 'gh api --paginate "repos/$REPO/releases"' in step
    assert 'release-policy.py plan --bump "$BUMP"' in step
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
    release_file.write_bytes(b"PAYLOAD")
    builder = ManifestBuilder(
        product_version="1.2.3",
        channel=ReleaseChannel.STABLE,
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
    candidate = plan_candidate(builder.build(), tag="v1.2.3", source_commit="c" * 40)
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
