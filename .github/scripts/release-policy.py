"""Read-only stable-release checks shared by the release workflows."""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

STABLE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


class ReleasePolicyError(ValueError):
    """A policy failure with a safe, actionable message for public logs."""


def git(*args: str) -> str:
    """Run Git without a shell or emitting repository data on failure."""
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def is_stable_release(release: dict[str, Any]) -> bool:
    tag = release.get("tag_name")
    if (
        release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(tag, str)
        or STABLE_TAG.fullmatch(tag) is None
    ):
        return False
    published_at = release.get("published_at")
    if not isinstance(published_at, str):
        return False
    try:
        timestamp = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return timestamp.utcoffset() is not None


def package_version(path: Path, pattern: str) -> str:
    matches = re.findall(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if len(matches) != 1:
        raise ReleasePolicyError("Expected one static package version assignment.")
    return matches[0]


def check_event(event_path: Path, ref: str) -> dict[str, str]:
    event = json.loads(event_path.read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        raise TypeError("Expected a release event object.")
    release = event.get("release")
    if (
        event.get("action") != "published"
        or not isinstance(release, dict)
        or not is_stable_release(release)
    ):
        return {"publish": "false"}
    tag = release["tag_name"]
    if ref != f"refs/tags/{tag}":
        raise ReleasePolicyError("Release tag and workflow ref do not match.")
    versions = (
        package_version(Path("pyproject.toml"), r'^version = "([0-9.]+)"$'),
        package_version(
            Path("src/servonaut/__init__.py"), r"^__version__ = ['\"]([0-9.]+)['\"]$"
        ),
    )
    if any(version != tag[1:] for version in versions):
        raise ReleasePolicyError("Release tag and package versions do not match.")
    revision = git("rev-parse", "HEAD")
    if revision != git("rev-parse", f"refs/tags/{tag}^{{commit}}"):
        raise ReleasePolicyError("Checkout does not match the release tag.")
    return {"publish": "true", "revision": revision}


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
    tags = {release["tag_name"] for release in releases if is_stable_release(release)}
    ordered = sorted(
        tags, key=lambda tag: tuple(map(int, tag[1:].split("."))), reverse=True
    )
    for tag in ordered:
        # Missing tags indicate an incomplete checkout: do not silently use an
        # older baseline and risk assigning an already-published version.
        revision = git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return tag
        if result.returncode != 1:
            raise ReleasePolicyError("Could not check stable-release ancestry.")
    raise ReleasePolicyError(
        "No published stable release is reachable from this checkout."
    )


def shipped_messages(baseline: str) -> list[str]:
    messages = []
    for revision in git("rev-list", "--no-merges", f"{baseline}..HEAD").splitlines():
        message = git("log", "-1", "--format=%B", revision)
        if message.startswith("chore: bump version"):
            continue
        paths = git(
            "diff-tree", "--no-commit-id", "--name-only", "-r", revision
        ).splitlines()
        # These paths define the existing Python distribution's source surface.
        if any(path.startswith("src/") or path == "pyproject.toml" for path in paths):
            messages.append(message)
    return messages


def choose_bump(baseline: str, messages: list[str], requested: str) -> str:
    if requested != "auto":
        return requested
    if any(
        re.match(r"^[a-z]+(\([^)]*\))?!:", message)
        or re.search(r"^BREAKING CHANGE:", message, re.MULTILINE)
        for message in messages
    ):
        return "major"
    if any(re.match(r"^feat(\(|!|:)", message) for message in messages):
        return "minor"
    if git(
        "diff",
        "--name-only",
        f"{baseline}..HEAD",
        "--",
        "src/servonaut/config/migration.py",
    ):
        return "minor"
    return "patch"


def plan_release(payload: str, requested: str) -> dict[str, str]:
    baseline = stable_baseline(read_releases(payload))
    messages = shipped_messages(baseline)
    if not messages:
        return {"release": "false", "last_tag": baseline}
    bump = choose_bump(baseline, messages, requested)
    major, minor, patch = map(int, baseline[1:].split("."))
    versions = {
        "major": f"v{major + 1}.0.0",
        "minor": f"v{major}.{minor + 1}.0",
        "patch": f"v{major}.{minor}.{patch + 1}",
    }
    next_tag = versions[bump]
    result = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/tags/{next_tag}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 1:
        raise ReleasePolicyError(
            "The next version tag already exists or could not be checked."
        )
    return {
        "release": "true",
        "last_tag": baseline,
        "next": next_tag,
        "bump": bump,
        "count": str(len(messages)),
    }


def write_summary(path: Path, output: dict[str, str]) -> None:
    baseline = output["last_tag"]
    if output["release"] == "false":
        summary = f"Nothing to release since **{baseline}**.\n"
    else:
        summary = (
            f"## {baseline} → {output['next']}\n\n"
            f"**{output['bump']}** bump; {output['count']} shipped-source change(s).\n"
        )
    with path.open("a", encoding="utf-8") as stream:
        stream.write(summary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    event = commands.add_parser("check-event", help="Gate stable publishing")
    event.add_argument("event_path", type=Path)
    event.add_argument("--ref", required=True)
    plan = commands.add_parser("plan", help="Plan from release API JSON on stdin")
    plan.add_argument(
        "--bump", choices=("auto", "patch", "minor", "major"), default="auto"
    )
    plan.add_argument("--summary", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "check-event":
            output = check_event(args.event_path, args.ref)
        else:
            output = plan_release(sys.stdin.read(), args.bump)
            if args.summary:
                write_summary(args.summary, output)
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
