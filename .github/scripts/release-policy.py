"""Release planning, publishing checks and version edits for the release workflows.

Every command except ``set-version`` is read-only. Planning reads the GitHub
releases API JSON on stdin and the local Git checkout; it never pushes, tags
or edits files.
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

_NUMBER = r"(0|[1-9][0-9]*)"
_CORE = rf"{_NUMBER}\.{_NUMBER}\.{_NUMBER}"
STABLE_TAG = re.compile(rf"v{_CORE}")
# PEP 440 release candidates in their normalized spelling, such as v1.2.3rc1.
CANDIDATE_TAG = re.compile(rf"v{_CORE}rc([1-9][0-9]*)")
PACKAGE_VERSION = re.compile(rf"{_CORE}(?:rc([1-9][0-9]*))?")
RELEASE_BRANCH = re.compile(
    r"release/((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))"
)
REMOTE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
VERSION_FILES = (
    (
        Path("pyproject.toml"),
        re.compile(r'^version = "([^"\n]*)"$', re.MULTILINE),
        'version = "{}"',
    ),
    (
        Path("src/servonaut/__init__.py"),
        re.compile(r"^__version__ = ['\"]([^'\"\n]*)['\"]$", re.MULTILINE),
        "__version__ = '{}'",
    ),
)
BUMPS = ("auto", "patch", "minor", "major")


class ReleasePolicyError(ValueError):
    """A policy failure with a safe, actionable message for public logs."""


def git(*args: str) -> str:
    """Run Git without a shell or emitting repository data on failure."""
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def ref_exists(ref: str) -> bool:
    result = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", ref],
        capture_output=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise ReleasePolicyError("Could not check the release tags.")
    return result.returncode == 0


def commit_of(ref: str) -> str:
    return git("rev-parse", "--verify", f"{ref}^{{commit}}")


def version_key(version: str) -> tuple[int, ...]:
    """Order X.Y.Z and X.Y.ZrcN versions; a final release follows its candidates."""
    match = PACKAGE_VERSION.fullmatch(version)
    if match is None:
        raise ReleasePolicyError("Expected a version of the form X.Y.Z or X.Y.ZrcN.")
    major, minor, patch, candidate = match.groups()
    stage = (0, int(candidate)) if candidate else (1, 0)
    return (int(major), int(minor), int(patch), *stage)


def published_channel(release: dict[str, Any]) -> str | None:
    """``stable`` or ``candidate`` for a publishable release, otherwise None.

    A stable release is a published, non-draft, non-prerelease vX.Y.Z; a
    candidate is a published, non-draft prerelease vX.Y.ZrcN. Anything else,
    such as a desktop preview, never publishes the Python package.
    """
    tag = release.get("tag_name")
    if release.get("draft") is not False or not isinstance(tag, str):
        return None
    published_at = release.get("published_at")
    if not isinstance(published_at, str):
        return None
    try:
        timestamp = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.utcoffset() is None:
        return None
    prerelease = release.get("prerelease")
    if prerelease is False and STABLE_TAG.fullmatch(tag):
        return "stable"
    if prerelease is True and CANDIDATE_TAG.fullmatch(tag):
        return "candidate"
    return None


def is_stable_release(release: dict[str, Any]) -> bool:
    return published_channel(release) == "stable"


def declared_version(text: str, pattern: re.Pattern[str]) -> str:
    matches = pattern.findall(text)
    if len(matches) != 1 or PACKAGE_VERSION.fullmatch(matches[0]) is None:
        raise ReleasePolicyError("Expected one static package version assignment.")
    return matches[0]


def package_versions(revision: str | None = None) -> tuple[str, ...]:
    """Both package version declarations, from the worktree or a commit."""
    versions = []
    for path, pattern, _ in VERSION_FILES:
        if revision is None:
            text = path.read_text(encoding="utf-8")
        else:
            text = git("show", f"{revision}:{path.as_posix()}")
        versions.append(declared_version(text, pattern))
    return tuple(versions)


def check_event(event_path: Path, ref: str) -> dict[str, str]:
    event = json.loads(event_path.read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        raise TypeError("Expected a release event object.")
    release = event.get("release")
    if event.get("action") != "published" or not isinstance(release, dict):
        return {"publish": "false"}
    channel = published_channel(release)
    if channel is None:
        return {"publish": "false"}
    tag = release["tag_name"]
    if ref != f"refs/tags/{tag}":
        raise ReleasePolicyError("Release tag and workflow ref do not match.")
    if any(version != tag[1:] for version in package_versions()):
        raise ReleasePolicyError("Release tag and package versions do not match.")
    revision = git("rev-parse", "HEAD")
    if revision != commit_of(f"refs/tags/{tag}"):
        raise ReleasePolicyError("Checkout does not match the release tag.")
    return {
        "publish": "true",
        "revision": revision,
        "prerelease": "true" if channel == "candidate" else "false",
    }


def read_releases(payload: str) -> list[dict[str, Any]]:
    """Accept the consecutive JSON arrays emitted by gh api --paginate."""
    decoder = json.JSONDecoder()
    releases: list[dict[str, Any]] = []
    remaining = payload.strip()
    while remaining:
        page, end = decoder.raw_decode(remaining)
        if not isinstance(page, list) or any(
            not isinstance(item, dict) for item in page
        ):
            raise ReleasePolicyError(
                "Expected release API pages containing release objects."
            )
        releases.extend(page)
        remaining = remaining[end:].lstrip()
    return releases


def stable_baseline(releases: list[dict[str, Any]]) -> str:
    """The highest published stable release, wherever its tag was cut.

    Stable releases are tagged on short-lived release branches, so the
    baseline need not be an ancestor of the default branch. A new version is
    always above every version users have already been offered.
    """
    tags = {release["tag_name"] for release in releases if is_stable_release(release)}
    if not tags:
        raise ReleasePolicyError("No published stable release was found.")
    baseline = max(tags, key=lambda tag: version_key(tag[1:]))
    # A missing tag indicates an incomplete checkout: do not silently use an
    # older baseline and risk assigning an already-published version.
    commit_of(f"refs/tags/{baseline}")
    return baseline


def shipped_changes(baseline: str) -> list[tuple[str, list[str]]]:
    """Messages and paths of the shipped-source commits since the baseline.

    Commits whose change the baseline release already contains, such as
    fixes cherry-picked onto its release branch, are not counted again.
    """
    changes = []
    revisions = git(
        "rev-list", "--no-merges", "--cherry-pick", "--right-only", f"{baseline}...HEAD"
    )
    for revision in revisions.splitlines():
        message = git("log", "-1", "--format=%B", revision)
        if message.startswith("chore: bump version"):
            continue
        paths = git(
            "diff-tree", "--no-commit-id", "--name-only", "-r", revision
        ).splitlines()
        # These paths define the existing Python distribution's source surface.
        if any(path.startswith("src/") or path == "pyproject.toml" for path in paths):
            changes.append((message, paths))
    return changes


def choose_bump(changes: list[tuple[str, list[str]]], requested: str) -> str:
    if requested != "auto":
        return requested
    messages = [message for message, _ in changes]
    if any(
        re.match(r"^[a-z]+(\([^)]*\))?!:", message)
        or re.search(r"^BREAKING CHANGE:", message, re.MULTILINE)
        for message in messages
    ):
        return "major"
    if any(re.match(r"^feat(\(|!|:)", message) for message in messages):
        return "minor"
    if any("src/servonaut/config/migration.py" in paths for _, paths in changes):
        return "minor"
    return "patch"


def plan_next_version(baseline: str, requested: str) -> dict[str, str]:
    changes = shipped_changes(baseline)
    if not changes:
        return {"release": "false", "last_tag": baseline}
    bump = choose_bump(changes, requested)
    major, minor, patch = map(int, baseline[1:].split("."))
    versions = {
        "major": f"v{major + 1}.0.0",
        "minor": f"v{major}.{minor + 1}.0",
        "patch": f"v{major}.{minor}.{patch + 1}",
    }
    next_tag = versions[bump]
    if ref_exists(f"refs/tags/{next_tag}"):
        raise ReleasePolicyError("The next version tag already exists.")
    return {
        "release": "true",
        "last_tag": baseline,
        "next": next_tag,
        "bump": bump,
        "count": str(len(changes)),
    }


def plan_release(payload: str, requested: str) -> dict[str, str]:
    return plan_next_version(stable_baseline(read_releases(payload)), requested)


def open_release_branches(remote: str) -> list[tuple[str, str]]:
    """(version, commit) of every release/X.Y.Z branch on the remote."""
    if REMOTE_NAME.fullmatch(remote) is None:
        raise ReleasePolicyError("Expected a plain Git remote name.")
    prefix = f"refs/remotes/{remote}/"
    branches = []
    refs = git("for-each-ref", "--format=%(refname)", f"{prefix}release/")
    for ref in refs.splitlines():
        match = RELEASE_BRANCH.fullmatch(ref[len(prefix) :])
        if match:
            branches.append((match.group(1), commit_of(ref)))
    return sorted(branches, key=lambda branch: version_key(branch[0]))


def single_release_branch(remote: str) -> tuple[str, str] | None:
    branches = open_release_branches(remote)
    if len(branches) > 1:
        names = ", ".join(f"release/{version}" for version, _ in branches)
        raise ReleasePolicyError(
            f"More than one release branch is open ({names}). "
            "Promote or delete all but one."
        )
    return branches[0] if branches else None


def candidate_tags(version: str) -> list[tuple[int, str]]:
    """(number, tag) of every vX.Y.ZrcN tag of one version, in order."""
    found = []
    for tag in git("tag", "--list", f"v{version}rc*").splitlines():
        match = CANDIDATE_TAG.fullmatch(tag)
        if match and ".".join(match.groups()[:3]) == version:
            found.append((int(match.group(4)), tag))
    return sorted(found)


def next_candidate_number(
    version: str, releases: list[dict[str, Any]], index_versions: list[str]
) -> int:
    """One above every candidate number of *version* already used anywhere.

    A number counts once it has a tag, a GitHub release or a package on the
    index: the index never accepts the same version twice, even after a tag
    or release is deleted.
    """
    used = [number for number, _ in candidate_tags(version)]
    names = [f"v{name}" for name in index_versions]
    names += [str(release.get("tag_name")) for release in releases]
    for name in names:
        match = CANDIDATE_TAG.fullmatch(name)
        if match and ".".join(match.groups()[:3]) == version:
            used.append(int(match.group(4)))
    return max(used, default=0) + 1


def read_index_versions(path: Path | None) -> list[str]:
    """The ``versions`` list of a PEP 691 JSON simple-index project page."""
    if path is None:
        return []
    page = json.loads(path.read_text(encoding="utf-8"))
    versions = page.get("versions") if isinstance(page, dict) else None
    if not isinstance(versions, list) or any(not isinstance(v, str) for v in versions):
        raise ReleasePolicyError("Expected the package index's list of versions.")
    return versions


def has_release(releases: list[dict[str, Any]], tag: str) -> bool:
    return any(release.get("tag_name") == tag for release in releases)


def unreleased_final_tags(baseline: str) -> list[str]:
    """vX.Y.Z tags above the latest published stable release, in order.

    One exists when a promotion pushed its tag but its release was never
    created or is still a draft.
    """
    tags = [
        tag
        for tag in git("tag", "--list", "v*").splitlines()
        if STABLE_TAG.fullmatch(tag) and version_key(tag[1:]) > version_key(baseline[1:])
    ]
    return sorted(tags, key=lambda tag: version_key(tag[1:]))


def refuse_unreleased_final_tags(baseline: str) -> None:
    tags = unreleased_final_tags(baseline)
    if tags:
        raise ReleasePolicyError(
            f"Tagged without a published release: {', '.join(tags)}. Publish its "
            "draft release or run the final stage to create the release; if its "
            "candidate was withdrawn, delete the never-released tag by hand instead."
        )


def require_unreleased(version: str, baseline: str) -> None:
    if ref_exists(f"refs/tags/v{version}"):
        raise ReleasePolicyError(
            f"v{version} is already tagged, so release/{version} should have been "
            "deleted. Delete the branch."
        )
    if version_key(version) <= version_key(baseline[1:]):
        raise ReleasePolicyError(
            f"release/{version} is not newer than the latest stable release "
            f"{baseline}. Delete the branch."
        )


def plan_candidate(
    payload: str, requested: str, remote: str, index_versions: list[str]
) -> dict[str, str]:
    """Plan the next vX.Y.ZrcN: a new release branch, or the next candidate on it."""
    releases = read_releases(payload)
    baseline = stable_baseline(releases)
    refuse_unreleased_final_tags(baseline)
    branch = single_release_branch(remote)
    if branch is None:
        return plan_first_candidate(baseline, requested, releases, index_versions)
    version, head = branch
    if requested != "auto":
        raise ReleasePolicyError(
            f"release/{version} is open, so its version is already chosen. "
            "Run with bump=auto, or delete the branch to plan again."
        )
    require_unreleased(version, baseline)
    tags = candidate_tags(version)
    plan = {
        "last_tag": baseline,
        "version": version,
        "branch": f"release/{version}",
        "base": head,
    }
    if tags and commit_of(f"refs/tags/{tags[-1][1]}") == head:
        latest = tags[-1][1]
        # The tag was pushed but its release was never created: create only that.
        action = "none" if has_release(releases, latest) else "release"
        return {"action": action, **plan, "tag": latest}
    number = next_candidate_number(version, releases, index_versions)
    return {"action": "next", **plan, "tag": f"v{version}rc{number}"}


def plan_first_candidate(
    baseline: str,
    requested: str,
    releases: list[dict[str, Any]],
    index_versions: list[str],
) -> dict[str, str]:
    planned = plan_next_version(baseline, requested)
    if planned["release"] == "false":
        return {"action": "none", "last_tag": baseline}
    version = planned["next"][1:]
    number = next_candidate_number(version, releases, index_versions)
    return {
        "action": "new",
        "last_tag": baseline,
        "version": version,
        "branch": f"release/{version}",
        "base": git("rev-parse", "HEAD"),
        "tag": f"v{version}rc{number}",
        "bump": planned["bump"],
        "count": planned["count"],
    }


def promoted_from(tag: str) -> str:
    """The candidate a vX.Y.Z tag was promoted from, verified, or an error.

    A promotion tags the candidate's commit plus a single change of the two
    version declarations.
    """
    version = tag[1:]
    tags = candidate_tags(version)
    parent = git("rev-parse", "--verify", f"{tag}^{{commit}}^")
    candidate = tags[-1][1] if tags else None
    changed = git("diff", "--name-only", candidate or parent, tag).splitlines()
    if (
        candidate is None
        or commit_of(f"refs/tags/{candidate}") != parent
        or changed != [path.as_posix() for path, _, _ in VERSION_FILES]
        or package_versions(tag) != (version,) * len(VERSION_FILES)
    ):
        raise ReleasePolicyError(
            f"{tag} is tagged without a release, but was not promoted from a "
            "candidate. Create or delete its release by hand."
        )
    return candidate


def plan_final(payload: str, requested: str, remote: str) -> dict[str, str]:
    """Plan promoting the open release branch's latest candidate to vX.Y.Z."""
    if requested != "auto":
        raise ReleasePolicyError(
            "A bump applies to new candidates only; promotion keeps the "
            "candidate's version."
        )
    releases = read_releases(payload)
    baseline = stable_baseline(releases)
    branch = single_release_branch(remote)
    pending = unreleased_final_tags(baseline)
    if pending and (branch is not None or len(pending) > 1):
        refuse_unreleased_final_tags(baseline)
    if pending:
        # A promotion pushed its tag but the release was not created.
        tag = pending[0]
        return {
            "action": "release",
            "last_tag": baseline,
            "version": tag[1:],
            "base": commit_of(f"refs/tags/{tag}"),
            "candidate": promoted_from(tag),
            "tag": tag,
        }
    if branch is None:
        return {"action": "none", "last_tag": baseline}
    version, head = branch
    require_unreleased(version, baseline)
    tags = candidate_tags(version)
    if not tags:
        return {"action": "none", "last_tag": baseline, "branch": f"release/{version}"}
    candidate = tags[-1][1]
    if commit_of(f"refs/tags/{candidate}") != head:
        raise ReleasePolicyError(
            f"release/{version} has changes that no candidate contains yet (after "
            f"{candidate}). Cut and test the next candidate before promoting."
        )
    if not any(
        release.get("tag_name") == candidate and published_channel(release) == "candidate"
        for release in releases
    ):
        raise ReleasePolicyError(
            f"{candidate} is not a published pre-release. Publish and test it "
            "before promoting."
        )
    if any(declared != candidate[1:] for declared in package_versions(head)):
        raise ReleasePolicyError(
            f"The package versions on release/{version} do not match {candidate}."
        )
    return {
        "action": "promote",
        "last_tag": baseline,
        "version": version,
        "branch": f"release/{version}",
        "base": head,
        "candidate": candidate,
        "tag": f"v{version}",
    }


def set_version(version: str, only_if_newer: bool) -> dict[str, str]:
    """Rewrite both package version declarations in the worktree."""
    target = version_key(version)
    current = set(package_versions())
    if len(current) != 1:
        raise ReleasePolicyError("The package version declarations disagree.")
    previous = current.pop()
    if only_if_newer and target <= version_key(previous):
        return {"changed": "false", "previous": previous}
    for path, pattern, template in VERSION_FILES:
        text = path.read_text(encoding="utf-8")
        line = template.format(version)
        path.write_text(pattern.sub(lambda _: line, text), encoding="utf-8")
    if package_versions() != (version,) * len(VERSION_FILES):
        raise ReleasePolicyError("The package versions did not take the change.")
    return {"changed": "true", "previous": previous}


def summary_text(command: str, output: dict[str, str]) -> str:
    baseline = output["last_tag"]
    action = output.get("action")
    if command == "plan":
        if output["release"] == "false":
            return f"Nothing to release since **{baseline}**.\n"
        return (
            f"## {baseline} → {output['next']}\n\n"
            f"**{output['bump']}** bump; {output['count']} shipped-source change(s).\n"
        )
    if action == "new":
        return (
            f"## Candidate {output['tag']}\n\n"
            f"New branch `{output['branch']}` from the default branch: "
            f"**{output['bump']}** bump over {baseline}; "
            f"{output['count']} shipped-source change(s).\n"
        )
    if action == "next":
        return f"## Candidate {output['tag']}\n\nCut from the head of `{output['branch']}`.\n"
    if action == "release" and command == "candidate":
        return (
            f"## Candidate {output['tag']}\n\n"
            "The tag was pushed but has no release yet: only the pre-release "
            "is created.\n"
        )
    if action == "release":
        return (
            f"## Release {output['tag']}\n\n"
            f"{output['tag']} was promoted from {output['candidate']} but has no "
            "release yet: only the release is created, after approval in the "
            "`release-approval` environment.\n"
        )
    if action == "promote":
        return (
            f"## Promote {output['candidate']} → {output['tag']}\n\n"
            "Only the version changes from the tested candidate. The promotion "
            "waits for approval in the `release-approval` environment.\n"
        )
    if command == "candidate":
        if "branch" in output:
            return (
                f"No candidate to cut: `{output['branch']}` has not changed since "
                f"{output['tag']}.\n"
            )
        return f"No candidate to cut: nothing to release since **{baseline}**.\n"
    return "No candidate to promote, so there is no release this week.\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    event = commands.add_parser("check-event", help="Gate PyPI publishing")
    event.add_argument("event_path", type=Path)
    event.add_argument("--ref", required=True)
    for name, text in (
        ("plan", "Plan the next stable version from HEAD"),
        ("candidate", "Plan the next release candidate"),
        ("final", "Plan promoting the open release candidate"),
    ):
        command = commands.add_parser(name, help=f"{text} (release API JSON on stdin)")
        command.add_argument("--bump", choices=BUMPS, default="auto")
        command.add_argument("--summary", type=Path)
        if name != "plan":
            command.add_argument("--remote", default="origin")
        if name == "candidate":
            command.add_argument(
                "--index-versions",
                type=Path,
                help="PEP 691 JSON simple-index page, to skip candidate numbers "
                "already on the package index",
            )
    edit = commands.add_parser("set-version", help="Set both package versions")
    edit.add_argument("version")
    edit.add_argument(
        "--only-if-newer",
        action="store_true",
        help="Leave the files unchanged unless the version is above the current one",
    )
    args = parser.parse_args()
    try:
        if args.command == "check-event":
            output = check_event(args.event_path, args.ref)
        elif args.command == "set-version":
            output = set_version(args.version, args.only_if_newer)
        else:
            payload = sys.stdin.read()
            if args.command == "plan":
                output = plan_release(payload, args.bump)
            elif args.command == "candidate":
                output = plan_candidate(
                    payload, args.bump, args.remote, read_index_versions(args.index_versions)
                )
            else:
                output = plan_final(payload, args.bump, args.remote)
            if args.summary:
                with args.summary.open("a", encoding="utf-8") as stream:
                    stream.write(summary_text(args.command, output))
    except ReleasePolicyError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError:
        print(
            "::error::Git check failed. Fetch the full history and release tags.",
            file=sys.stderr,
        )
        return 1
    except (OSError, TypeError, ValueError):
        # Event, Git and API data must not leak into public workflow logs.
        print(
            "::error::Release policy failed. Check release metadata, tags and package versions.",
            file=sys.stderr,
        )
        return 1
    for key, value in output.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
