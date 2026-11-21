#!/usr/bin/env python3
"""Record release alert transitions without replacing the incident history."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

KINDS = {
    "rotation": "APT signing key rotation",
    "audit": "APT archive audit",
    "publish": "APT archive renewal",
    "upstream": "APT admitted package evidence",
    "unqualified": "APT release qualification",
}
DESKTOP_KINDS = {
    "desktop-controls": "Desktop update policy controls",
    "desktop-publish": "Desktop update policy publication",
    "desktop-audit": "Desktop update policy audit",
    "desktop-stale": "Desktop update policy is near expiry",

}
BOT = "github-actions[bot]"
ALERT_LABEL = "apt-archive-alert"
DESKTOP_ALERT_LABEL = "desktop-update-alert"


@dataclass(frozen=True)
class IssueState:
    number: int
    open: bool
    active: bool
    last_report: datetime


def marker(kind: str, active: bool) -> str:
    family = "desktop-policy" if kind.startswith("desktop-") else "apt-archive"
    return f"<!-- {family}:{kind}:{'active' if active else 'clear'} -->"


def decision(
    previous: IssueState | None, active: bool, now: datetime, reminder_interval: timedelta,
) -> str:
    if previous is None:
        return "create" if active else ""
    if active != previous.active:
        return "create" if active and not previous.open else "comment"
    if active and previous.open and now - previous.last_report >= reminder_interval:
        return "comment"
    return ""


def observed(env: dict[str, str]) -> dict[str, bool]:
    publish_succeeded = env.get("PRODUCTION_RESULT") == "success"
    audit_succeeded = env.get("AUDIT_RESULT") == "success"
    result = {}
    if env.get("AUDIT_RESULT") in ("success", "failure"):
        result["audit"] = not audit_succeeded
    if env.get("CHECK_SCHEDULED_PUBLISH") == "true" and env.get("PUBLISH_RESULT") in ("success", "failure"):
        result["publish"] = env["PUBLISH_RESULT"] == "failure"
    rotation = env.get("PUBLISH_ROTATION") == "true" or env.get("AUDIT_ROTATION") == "true"
    if rotation or publish_succeeded or audit_succeeded:
        result["rotation"] = rotation
    for kind in ("upstream", "unqualified"):
        active = env.get(kind.upper()) == "true"
        if active or publish_succeeded:
            result[kind] = active
    return result


def observed_desktop(env: dict[str, str]) -> dict[str, bool]:
    result = {}
    publish = env.get("DESKTOP_PUBLISH_RESULT")
    audit = env.get("DESKTOP_AUDIT_RESULT")
    controls = env.get("DESKTOP_CONTROLS_UNAVAILABLE") == "true" or env.get("DESKTOP_CHECKPOINT_INVALID") == "true"
    stale = env.get("DESKTOP_POLICY_STALE")
    if publish in ("success", "failure"):
        result["desktop-publish"] = publish == "failure"
    if controls or publish == "success":
        result["desktop-controls"] = controls
    if audit in ("success", "failure"):
        result["desktop-audit"] = audit == "failure"
    if stale in ("true", "false"):
        result["desktop-stale"] = stale == "true"
    return result


class GitHub:
    def __init__(
        self, repo: str, timeout: float, reminder_interval: timedelta, *, label: str = ALERT_LABEL,
    ) -> None:
        self.repo = repo
        self.timeout = timeout
        self.reminder_interval = reminder_interval
        self.label = label
        self.kinds = DESKTOP_KINDS if label == DESKTOP_ALERT_LABEL else KINDS

    def run(self, *args: str) -> str:
        return subprocess.run(
            ["gh", *args], capture_output=True, check=True, text=True, timeout=self.timeout,
        ).stdout

    def issues(self) -> list[dict]:
        # The repository filter sees new issues immediately, including closed
        # alerts whose last reported condition still controls deduplication.
        pages = json.loads(self.run(
            "api", "--paginate", "--slurp",
            f"repos/{self.repo}/issues?state=all&labels={self.label}&per_page=100",
        ))
        return [issue for page in pages for issue in page if "pull_request" not in issue]

    def state(self, kind: str, candidates: list[dict]) -> IssueState | None:
        title = self.kinds[kind]
        opening = marker(kind, True)
        eligible = [
            issue for issue in candidates if issue["title"] == title
            and (issue.get("user") or {}).get("login") == BOT
            and opening in (issue.get("body") or "").splitlines()
        ]
        if not eligible:
            return None
        latest = max(eligible, key=lambda issue: issue["number"])
        return self.latest_state(kind, latest)

    def latest_state(self, kind: str, issue: dict) -> IssueState:
        pages = json.loads(self.run(
            "api", "--paginate", "--slurp",
            f'repos/{self.repo}/issues/{issue["number"]}/comments?per_page=100',
        ))
        transitions = {marker(kind, active): active for active in (True, False)}
        at = issue["created_at"]
        active = True
        for page in pages:
            for comment in page:
                if (comment.get("user") or {}).get("login") != BOT:
                    continue
                line = comment["body"].splitlines()[0] if comment["body"] else ""
                if line in transitions:
                    active = transitions[line]
                    at = comment["created_at"]
        return IssueState(
            issue["number"], issue["state"] == "open", active,
            datetime.fromisoformat(at.replace("Z", "+00:00")),
        )

    def update(self, kind: str, active: bool, previous: IssueState | None, run_url: str, now: datetime) -> None:
        action = decision(previous, active, now, self.reminder_interval)
        if not action:
            return
        with tempfile.TemporaryDirectory(prefix="release-alert-") as directory:
            path = Path(directory) / "body.md"
            state = "Condition active" if active else "Condition cleared"
            path.write_text(f"{marker(kind, active)}\n{state}.\n\nRun: {run_url}\n", encoding="utf-8")
            if action == "create":
                description = (
                    "Automated desktop update policy alerts" if self.label == DESKTOP_ALERT_LABEL
                    else "Automated APT archive alerts"
                )
                self.run(
                    "label", "create", self.label, "--repo", self.repo, "--force",
                    "--description", description, "--color", "d93f0b",
                )
                self.run(
                    "issue", "create", "--repo", self.repo, "--title", self.kinds[kind],
                    "--label", self.label, "--body-file", str(path),
                )
            elif previous is not None:
                self.run("issue", "comment", str(previous.number), "--repo", self.repo, "--body-file", str(path))


def main() -> int:
    desktop = os.environ.get("RELEASE_ALERT_PROFILE") == "desktop"
    if desktop:
        hours = int(os.environ.get("DESKTOP_ALERT_REMINDER_HOURS") or "24")
        if hours <= 0:
            raise ValueError("Desktop alert reminder interval must be positive.")
        observations = observed_desktop(dict(os.environ))
    else:
        hours = int(os.environ["APT_ALERT_REMINDER_HOURS"])
        if hours <= 0:
            raise ValueError("APT alert reminder interval must be positive.")
        observations = observed(dict(os.environ))
    options = {"label": DESKTOP_ALERT_LABEL} if desktop else {}
    github = GitHub(os.environ["GH_REPO"], float(os.environ["APT_TIMEOUT"]), timedelta(hours=hours), **options)
    now = datetime.now(timezone.utc)
    if observations:
        issues = github.issues()
        for kind, active in observations.items():
            github.update(kind, active, github.state(kind, issues), os.environ["RUN_URL"], now)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
