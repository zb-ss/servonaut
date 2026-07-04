"""Guarded executor helpers for proactive-remediation relay dispatches.

Phase 3 of proactive monitoring: after the user confirms a server-issued
byte-for-byte preview in the TUI, the server dispatches a command
envelope over the relay with ``source: "proactive_remediation"``. Unlike
probes (read-only, tool-shaped) a remediation MUTATES the box — so the
execution surface is deliberately tiny:

- The envelope's ``type`` is a REMEDIATION VERB from a fixed allowlist
  (pilot: ``certbot_renew`` only). It is never ``run_command`` and the
  server never supplies command text — the CLI builds the exact command
  locally from validated, typed payload fields.
- Every payload field that reaches the command line is validated against
  a strict shape first; anything else is rejected with a snake_case slug
  the server surfaces as ``failure_evidence``.
- The remote command is wrapped with an exit-code marker so success is
  judged on the actual exit status, not on "ssh didn't blow up".

Pure helpers live here (imported by the relay listener and unit tests);
the listener owns transport, dedup, and the always-answer contract.
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any, Dict, Optional, Tuple

#: Relay envelopes with this ``source`` route to the remediation path.
REMEDIATION_SOURCE = "proactive_remediation"

#: The verbs this CLI knows how to execute. Grows one playbook at a time,
#: in lockstep with the server-side allowlist — never a generic shell.
REMEDIATION_VERBS = frozenset({"certbot_renew"})

#: Marker echoed after the remote command so the caller can recover the
#: exit code from stdout (the SSH seam doesn't expose it directly).
EXIT_MARKER = "__SRV_REMEDIATION_EXIT:"

#: Bound stdout/stderr tails in the result payload (chars).
_RESULT_TAIL_CHARS = 2000

# certbot lineage names: idna hostname subset + wildcard prefix + the
# ``-NNNN`` duplicate-lineage suffix certbot appends. Anything a shell
# could interpret is outside this class.
_SAFE_CERT_NAME_RE = re.compile(r"^(?:\*\.)?[A-Za-z0-9][A-Za-z0-9.-]{0,251}$")


class RemediationValidationError(ValueError):
    """Rejected before execution. ``str(exc)`` LEADS with a snake_case
    slug (``slug: detail``) — the server stores it verbatim as the
    remediation's failure evidence, mirroring the probe contract."""


def _require_cert_name(payload: Dict[str, Any]) -> str:
    cert_name = payload.get("cert_name")
    if not isinstance(cert_name, str) or not cert_name:
        raise RemediationValidationError(
            "invalid_cert_name: payload is missing a cert_name",
        )
    if ".." in cert_name or not _SAFE_CERT_NAME_RE.match(cert_name):
        raise RemediationValidationError(
            f"invalid_cert_name: {cert_name!r} is not a valid "
            f"certificate lineage name",
        )
    return cert_name


def _build_certbot_renew(payload: Dict[str, Any]) -> str:
    cert_name = _require_cert_name(payload)
    argv = [
        "sudo", "-n", "certbot", "renew",
        "--cert-name", cert_name,
        "--non-interactive",
    ]
    if bool(payload.get("dry_run")):
        argv.append("--dry-run")
    return " ".join(shlex.quote(a) for a in argv)


_VERB_BUILDERS = {
    "certbot_renew": _build_certbot_renew,
}


def build_remediation_command(verb: str, payload: Dict[str, Any]) -> str:
    """Build the exact remote command for an allowlisted verb.

    Raises :class:`RemediationValidationError` (slug-first message) for
    unknown verbs or payloads that fail shape validation.
    """
    builder = _VERB_BUILDERS.get(verb)
    if builder is None:
        raise RemediationValidationError(
            f"unknown_remediation_verb: {verb!r} is not in this CLI's "
            f"remediation allowlist",
        )
    if not isinstance(payload, dict):
        raise RemediationValidationError(
            "invalid_remediation_payload: payload must be an object",
        )
    return builder(payload)


def _marker_prefix(nonce: str) -> str:
    """The line prefix the epilogue echoes and the parser matches.

    A per-dispatch nonce is interpolated so target-side output cannot
    forge a "success" line by echoing a *static* marker: a spoofer would
    have to know the exact nonce chosen for this one invocation. This
    raises the bar against non-privileged target output (log lines,
    unprivileged plugins) — it is NOT a defence against a root process
    on the target, which can read the nonce from the command line; the
    real integrity backstop there is the server's post-remediation
    re-probe, which only settles the finding to ``resolved`` if the
    detector confirms the fix.
    """
    return f"{EXIT_MARKER}{nonce}:" if nonce else EXIT_MARKER


def wrap_with_exit_marker(command: str, nonce: str = "") -> str:
    """Append the exit-code epilogue so the remote exit status can be
    recovered from stdout.

    The marker is echoed to STDERR: the relay executor truncates stdout
    to a bounded line count but appends the stderr block untruncated, so
    a marker on stderr survives a chatty command whose stdout would push
    a stdout-echoed marker past the truncation window (which would
    otherwise misreport a clean exit as a transport failure). The marker
    can still be ABSENT (a genuine transport failure) — the parser then
    returns ``None`` and the caller treats it as failure (fail-closed).
    It can also be preceded by forged marker lines in target-controlled
    output; :func:`parse_exit_marker` is last-match-wins and the nonce
    mitigates static forgery, but the authoritative confirmation of a
    real fix is the server re-probe, not this marker.
    """
    prefix = _marker_prefix(nonce)
    return f'{command}; rc=$?; echo "{prefix}$rc" >&2'


def parse_exit_marker(
    output: str, nonce: str = "",
) -> Tuple[Optional[int], str]:
    """Extract ``(exit_code, output_without_marker)`` from command output.

    Matches the nonce-qualified marker (last occurrence wins). Returns
    ``(None, output_without_markers)`` when no valid marker is present
    (transport failure, or the genuine marker was truncated away) — the
    caller treats ``None`` as a failure, never a success.
    """
    prefix = _marker_prefix(nonce)
    exit_code: Optional[int] = None
    kept = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            try:
                exit_code = int(stripped[len(prefix):])
            except ValueError:
                pass
            continue
        kept.append(line)
    return exit_code, "\n".join(kept).strip()


def classify_failure(verb: str, exit_code: Optional[int], output: str) -> str:
    """Map a failed execution to a snake_case slug for failure evidence."""
    lowered = output.lower()
    if exit_code is None:
        return "remediation_transport_failed"
    if "a password is required" in lowered or (
        "sudo:" in lowered
        and ("password" in lowered or "not allowed" in lowered)
    ):
        return f"{verb}_permission_denied"
    if verb == "certbot_renew" and (
        "no certificate found" in lowered
        or "no matching certificate" in lowered
    ):
        return "cert_name_not_found"
    if "command not found" in lowered:
        return f"{verb}_not_installed"
    return f"{verb}_failed"


def build_remediation_result(
    *,
    verb: str,
    ok: bool,
    exit_code: Optional[int],
    output: str,
    payload: Dict[str, Any],
) -> str:
    """JSON result payload posted back on the command-result route.

    Bounded tails only — the server attaches this to the finding as
    remediation evidence, so it must stay small and structured.
    """
    result: Dict[str, Any] = {
        "verb": verb,
        "ok": ok,
        "exit_code": exit_code,
        "output_tail": output[-_RESULT_TAIL_CHARS:],
        "dry_run": bool(payload.get("dry_run")),
    }
    if verb == "certbot_renew" and isinstance(payload.get("cert_name"), str):
        result["cert_name"] = payload["cert_name"]
    return json.dumps(result)
