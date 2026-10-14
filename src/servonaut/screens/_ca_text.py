"""Plain-language text for the SSH Certificates screen.

The CA service methods return structured results meant for programs: key
material, ids and nested records. The screen shows these summaries instead,
and the same ``key: value`` rows the CLI prints for the less common reports.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from servonaut.services.vault.display import flatten_rows, terminal_safe

# Enrollment steps, in the words the screen uses.
_STEP_NAMES = {
    "precheck": "pre-check",
    "managed_files": "managed files",
    "host_certificate": "host certificate",
    "sshd_config_test": "sshd config test",
    "reload": "sshd reload",
    "certificate_login_proof": "certificate login",
}


def _duration(seconds: Any) -> str | None:
    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds <= 0:
        return None
    for unit, size in (("h", 3600), ("min", 60)):
        if seconds % size == 0:
            return f"{seconds // size} {unit}"
    return f"{seconds} s"


def _lifetimes(policy: Mapping[str, Any]) -> str | None:
    people = _duration(policy.get("interactive_ttl_seconds"))
    automation = _duration(policy.get("automation_ttl_seconds"))
    longest = _duration(policy.get("max_ttl_seconds"))
    parts = [f"{people} for people" if people else "", f"{automation} for automation" if automation else ""]
    text = ", ".join(part for part in parts if part)
    if not text:
        return None
    return f"Certificates last {text}" + (f" (at most {longest})." if longest else ".")


def _logins(logins_by_server: Any, server_labels: Mapping[str, str]) -> list[str]:
    if not isinstance(logins_by_server, Mapping):
        return []
    lines = []
    for server_id, logins in logins_by_server.items():
        names = [terminal_safe(login) for login in logins] if isinstance(logins, Sequence) and not isinstance(logins, str) else []
        if not names:
            continue
        server = server_labels.get(str(server_id)) or f"server {str(server_id)[:8]}"
        lines.append(f"Logins on {terminal_safe(server)}: {', '.join(names)}")
    return lines


def status_text(status: Mapping[str, Any], *, team: str, server_labels: Mapping[str, str]) -> str:
    """A team's CA status (``ca_status``) in words."""
    if not status.get("enabled"):
        return (
            "SSH certificates are not switched on for this team.\n"
            "Switch them on from a terminal:\n"
            f"  servonaut ca enable --team {terminal_safe(team)}"
        )
    lines = ["SSH certificates are on for this team."]
    for label, key in (("User CA", "user_ca_fingerprint"), ("Next user CA", "user_ca_next_fingerprint"),
                       ("Host CA", "host_ca_fingerprint")):
        if status.get(key):
            lines.append(f"{label}: {terminal_safe(status[key])}")
    policy = status.get("policy") if isinstance(status.get("policy"), Mapping) else {}
    lifetimes = _lifetimes(policy)
    if lifetimes:
        lines.append(lifetimes)
    if policy.get("require_member_mfa") is True:
        lines.append("Members need MFA to get a certificate.")
    lines.extend(_logins(status.get("logins_by_server"), server_labels))
    if isinstance(status.get("krl_version"), int):
        lines.append(f"Revocation list: version {status['krl_version']}")
    return "\n".join(lines)


def enroll_text(result: Mapping[str, Any], *, server: str) -> str:
    """The outcome of enrolling *server* (``ca_enroll``) in words."""
    outcome = result.get("result") if isinstance(result.get("result"), Mapping) else result
    steps = [step for step in outcome.get("steps") or [] if isinstance(step, Mapping)]
    checks = " · ".join(
        f"{_STEP_NAMES.get(str(step.get('name')), terminal_safe(step.get('name')))} {terminal_safe(step.get('status'))}"
        for step in steps
    )
    status = str(outcome.get("status") or "unknown")
    if status == "succeeded":
        lines = [f"{server} is enrolled: it accepts this team's SSH certificates."]
    else:
        error = outcome.get("error_code")
        lines = [f"Enrolling {server} did not complete: {terminal_safe(status)}"
                 + (f" ({terminal_safe(error)})." if error else ".")]
        lines.extend(
            f"{_STEP_NAMES.get(str(step.get('name')), terminal_safe(step.get('name')))}: {terminal_safe(step['detail'])}"
            for step in steps if step.get("detail") and step.get("status") != "ok"
        )
    if checks:
        lines.append(f"Checks: {checks}")
    if result.get("resumed") is True:
        lines.append("This continued an enrollment that was already under way.")
    return "\n".join(lines)


def audit_text(report: Mapping[str, Any]) -> str:
    """The issuance-chain audit (``ca_audit``) in words."""
    checked = report.get("entries_checked")
    gaps = report.get("gaps") or []
    events = report.get("break_glass_events") or []
    lines = [
        f"Issuance chain audit: {checked if isinstance(checked, int) else 'unknown number of'} entries checked, "
        + ("no gaps." if not gaps else f"{len(gaps)} gap(s) found."),
    ]
    if events:
        lines.append(f"Break-glass events in the log: {len(events)}")
    if report.get("head_hash"):
        lines.append(f"Chain head: {terminal_safe(report['head_hash'])}")
    lines.extend(f"Gap: {terminal_safe(gap)}" for gap in gaps)
    return "\n".join(lines)


def report_text(title: str, result: Any) -> str:
    """*title*, then *result* as the ``key: value`` rows the CLI prints."""
    if not isinstance(result, Mapping):
        return f"{title}\n{terminal_safe(result)}"
    rows = [f"{key}: {terminal_safe(value)}" for key, value in flatten_rows(result)]
    return "\n".join([title, *rows])
