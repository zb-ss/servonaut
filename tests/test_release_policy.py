"""Exercise release decisions with real, disposable Git histories."""

import json
import os
import re
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


def run_cadence(
    tmp_path: Path, workflow: str, name: str, **env: str
) -> subprocess.CompletedProcess[str]:
    step = workflow_step(workflow, name)
    block = step.split("        run: |\n", 1)[1]
    # Only execute the literal run block, not any following YAML job.
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    script = 'gh() { printf "%s" "$TEST_GH_OUTPUT"; return "$TEST_GH_STATUS"; }\n'
    script += textwrap.dedent("\n".join(lines))
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


def test_release_candidate_signing_is_secret_gated_not_optional() -> None:
    source = (WORKFLOWS / "release-candidate.yml").read_text(encoding="utf-8")
    sign = _job(source, "sign")
    assert "RELEASE_SIGNING_KEY" in sign
    assert "::error::" in sign
    assert "exit 1" in sign
    # An unsigned candidate must never silently pass the gate.
    assert "::notice::Signing is not required" in sign


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
    # Publishing stays gated behind eligibility and, when enabled, the
    # candidate job as well.
    assert "needs: [eligibility, candidate]" in _job(source, "test")
    assert "needs: [eligibility, cadence, test]" in _job(source, "publish")


def test_publish_defaults_to_disabled_candidate_gate() -> None:
    """The staged gate must fail closed only when explicitly enabled."""
    step = workflow_step("publish.yml", "Require candidate verification when enabled")
    block = step.split("        run: |\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line)
    script = (
        "gh() { return 0; }\n"
        "pip() { return 0; }\n"
        "python() { return 0; }\n"
    ) + textwrap.dedent("\n".join(lines))
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
        },
    )
    assert "::notice::Release-candidate verification is not required yet." not in enabled.stdout

