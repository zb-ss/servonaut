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

import ipaddress
import json
import re
import shlex
from typing import Any, Dict, Optional, Tuple

#: Relay envelopes with this ``source`` route to the remediation path.
REMEDIATION_SOURCE = "proactive_remediation"

#: Verbs executed as an SSH command on the target box (built locally
#: from validated payload fields, judged via the exit marker).
SSH_COMMAND_VERBS = frozenset({"certbot_renew"})

#: Verbs handled by a dedicated ``_execute_*`` method rather than the
#: generic SSH-command builder. ``block_ip`` / ``unblock_ip`` each dispatch
#: to :class:`IPBanService` (WAF / security group / NACL) for the AWS
#: methods — already audited via the IP-ban audit trail — and fall back to
#: an on-box firewall command over the relay SSH path for the on-box
#: methods (see :data:`ONBOX_BLOCK_METHODS`). Named "local dispatch"
#: because these verbs never go through :func:`build_remediation_command`.
LOCAL_DISPATCH_VERBS = frozenset({"block_ip", "unblock_ip"})

#: The verbs this CLI knows how to execute. Grows one playbook at a time,
#: in lockstep with the server-side allowlist — never a generic shell.
REMEDIATION_VERBS = SSH_COMMAND_VERBS | LOCAL_DISPATCH_VERBS

assert not (SSH_COMMAND_VERBS & LOCAL_DISPATCH_VERBS), (
    "a remediation verb cannot be both SSH-command and local-dispatch"
)

#: AWS control-plane ban methods — dispatched to :class:`IPBanService`
#: (WAF / security group / NACL boto3 strategies), gated on a configured
#: :class:`IPBanConfig`. These never touch the target box.
AWS_BLOCK_METHODS = frozenset({"waf", "security_group", "nacl"})

#: On-box firewall ban methods — dispatched as an SSH command that runs
#: the box's own firewall tool (like ``certbot_renew``'s SSH path), argv
#: built LOCALLY from the validated IP, never server text. These are the
#: only methods that actually protect a non-AWS box (WAF can't shield an
#: OVH/bare-metal host). The unban handle is the IP itself.
ONBOX_BLOCK_METHODS = frozenset({"nftables", "ufw", "firewalld"})

#: Ban mechanisms the ``block_ip`` envelope may request. AWS methods
#: resolve an :class:`IPBanConfig`; on-box methods run on the target via
#: the relay. Kept in lockstep with the server-side method enum.
BLOCK_IP_METHODS = AWS_BLOCK_METHODS | ONBOX_BLOCK_METHODS

assert not (AWS_BLOCK_METHODS & ONBOX_BLOCK_METHODS), (
    "a block_ip method cannot be both AWS-plane and on-box"
)

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


def _coerce_dry_run(payload: Dict[str, Any]) -> bool:
    """Strict dry_run coercion.

    ``bool("false")`` is ``True`` in Python — a payload that arrives with
    a string instead of a JSON boolean (a server templating slip, not
    something a well-formed dispatch would send) would otherwise silently
    build a DIFFERENT command than the one the confirm_token was signed
    over, undermining the byte-for-byte guarantee the whole confirm flow
    rests on. Only recognised bool-ish shapes are accepted; anything else
    is treated as falsy (the CLI-side default) rather than guessed at.
    """
    value = payload.get("dry_run")
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return False


#: Public name for callers outside this module (the relay listener's
#: local-dispatch path); the leading-underscore original predates it.
coerce_dry_run = _coerce_dry_run


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
    if _coerce_dry_run(payload):
        argv.append("--dry-run")
    return " ".join(shlex.quote(a) for a in argv)


_VERB_BUILDERS = {
    "certbot_renew": _build_certbot_renew,
}

# A builder registered here without a matching entry in SSH_COMMAND_VERBS
# (or vice versa) would silently activate a verb the allowlist doesn't
# document — fail the import instead of drifting quietly.
assert set(_VERB_BUILDERS) == SSH_COMMAND_VERBS, (
    "SSH_COMMAND_VERBS and _VERB_BUILDERS have drifted out of sync"
)


def validate_block_ip_payload(
    payload: Dict[str, Any],
    refused_ips: frozenset[str] = frozenset(),
) -> Tuple[str, str]:
    """Validate a ``block_ip`` payload; return ``(canonical_ip, method)``.

    Client-side mirror of the server's rails (defense-in-depth — the
    server derives the ip from the finding's stored evidence and applies
    the same refusals authoritatively on its side):

    - exactly ONE ip address, no CIDR (v1)
    - globally routable only — private / loopback / link-local /
      multicast / reserved / unspecified are all refused (a ban on any
      of those is at best a no-op and at worst a self-lockout)
    - never an address in ``refused_ips`` (the target instance's own
      public/private addresses, where the caller knows them)
    - ``method`` from :data:`BLOCK_IP_METHODS`
    """
    raw_ip = payload.get("ip")
    if not isinstance(raw_ip, str) or not raw_ip.strip():
        raise RemediationValidationError(
            "invalid_block_ip_address: payload is missing an ip",
        )
    candidate = raw_ip.strip()
    if "/" in candidate:
        raise RemediationValidationError(
            f"invalid_block_ip_address: {candidate!r} is a network — "
            f"block_ip takes exactly one address (no CIDR in v1)",
        )
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        raise RemediationValidationError(
            f"invalid_block_ip_address: {candidate!r} is not a valid "
            f"IPv4/IPv6 address",
        ) from None
    # Explicit category checks alongside is_global: Python's is_global
    # follows the IANA special registries, which mark some multicast
    # ranges "globally reachable" — never a valid ban target here.
    if (addr.is_multicast or addr.is_loopback or addr.is_link_local
            or addr.is_private or addr.is_reserved or addr.is_unspecified
            or not addr.is_global):
        raise RemediationValidationError(
            f"block_ip_address_not_public: {addr} is private, loopback, "
            f"link-local, multicast, or reserved — refusing to ban it",
        )
    canonical = str(addr)
    if canonical in refused_ips or candidate in refused_ips:
        raise RemediationValidationError(
            f"block_ip_self_ban_refused: {canonical} belongs to the "
            f"target instance — banning it would cut the box off",
        )
    method = payload.get("method")
    if not isinstance(method, str) or method not in BLOCK_IP_METHODS:
        allowed = ", ".join(sorted(BLOCK_IP_METHODS))
        raise RemediationValidationError(
            f"invalid_block_ip_method: {method!r} is not one of "
            f"{allowed}",
        )
    return canonical, method


def build_onbox_block_command(method: str, ip: str) -> str:
    """Build the on-box firewall ban command for an ON-BOX ``block_ip``
    method (nftables / ufw / firewalld).

    ``ip`` MUST already be canonicalised + validated by
    :func:`validate_block_ip_payload` (a strict single public address, no
    CIDR, no shell metacharacters) — this builder interpolates it into
    the firewall syntax and does NOT re-parse it. Every method ends with
    a VERIFY step (``grep`` the active ruleset for the ip) so the exit
    code means "the ip is now blocked" — making a repeat ban an
    idempotent success rather than a duplicate-rule error, and a
    silently-failed ban (e.g. no ``sudo -n``) a clean failure.

    All firewall writes go through ``sudo -n`` (non-interactive) with the
    same posture as the other probes; a password prompt fails closed.
    """
    if method not in ONBOX_BLOCK_METHODS:
        raise RemediationValidationError(
            f"invalid_block_ip_method: {method!r} is not an on-box "
            f"firewall method",
        )
    is_v6 = ipaddress.ip_address(ip).version == 6
    if method == "ufw":
        # ufw takes v4/v6 transparently; it skips a duplicate rule (exit 0).
        return (
            f"sudo -n ufw deny from {ip} to any; "
            f"sudo -n ufw status | grep -qF '{ip}'"
        )
    if method == "firewalld":
        fam = "ipv6" if is_v6 else "ipv4"
        rule = f'rule family="{fam}" source address="{ip}" drop'
        return (
            f"sudo -n firewall-cmd --add-rich-rule='{rule}'; "
            f"sudo -n firewall-cmd --permanent --add-rich-rule='{rule}'; "
            f"sudo -n firewall-cmd --list-rich-rules | grep -qF '{ip}'"
        )
    # nftables: a dedicated servonaut_ban table/set/chain/drop-rule,
    # bootstrapped ONCE (guarded on table existence so a repeat ban never
    # appends a duplicate drop rule), then the ip added as a set element
    # (idempotent). Separate v4/v6 sets keep the address types clean.
    set_name = "banned6" if is_v6 else "banned4"
    addr_type = "ipv6_addr" if is_v6 else "ipv4_addr"
    saddr = "ip6 saddr" if is_v6 else "ip saddr"
    bootstrap = (
        "sudo -n nft add table inet servonaut_ban; "
        f"sudo -n nft add set inet servonaut_ban {set_name} "
        f"'{{ type {addr_type}; flags interval; }}'; "
        "sudo -n nft add chain inet servonaut_ban input "
        "'{ type filter hook input priority -100; policy accept; }'; "
        f"sudo -n nft add rule inet servonaut_ban input {saddr} "
        f"@{set_name} drop; "
    )
    return (
        "if ! sudo -n nft list table inet servonaut_ban "
        f">/dev/null 2>&1; then {bootstrap}fi; "
        f"sudo -n nft add element inet servonaut_ban {set_name} "
        f"'{{ {ip} }}' 2>/dev/null; "
        f"sudo -n nft list set inet servonaut_ban {set_name} "
        f"| grep -qF '{ip}'"
    )


def validate_unblock_ip_payload(payload: Dict[str, Any]) -> Tuple[str, str]:
    """Validate an ``unblock_ip`` payload; return ``(canonical_ip, method)``.

    The inverse of :func:`validate_block_ip_payload`, and its client-side
    mirror of the server's rails — the server derives the ip and method
    from the ban's captured handle and applies the same floor authoritatively:

    - exactly ONE ip address, no CIDR
    - globally routable only (private / loopback / link-local / multicast /
      reserved / unspecified are refused, same floor as the ban path)
    - ``method`` from :data:`BLOCK_IP_METHODS`

    Unlike the ban validator this takes no ``refused_ips`` set: the self-ban
    guard exists to stop a ban cutting the box off; *unbanning* an address is
    never a lock-out, so there is nothing to refuse.
    """
    raw_ip = payload.get("ip")
    if not isinstance(raw_ip, str) or not raw_ip.strip():
        raise RemediationValidationError(
            "invalid_unblock_ip_address: payload is missing an ip",
        )
    candidate = raw_ip.strip()
    if "/" in candidate:
        raise RemediationValidationError(
            f"invalid_unblock_ip_address: {candidate!r} is a network — "
            f"unblock_ip takes exactly one address (no CIDR)",
        )
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        raise RemediationValidationError(
            f"invalid_unblock_ip_address: {candidate!r} is not a valid "
            f"IPv4/IPv6 address",
        ) from None
    if (addr.is_multicast or addr.is_loopback or addr.is_link_local
            or addr.is_private or addr.is_reserved or addr.is_unspecified
            or not addr.is_global):
        raise RemediationValidationError(
            f"unblock_ip_address_not_public: {addr} is private, loopback, "
            f"link-local, multicast, or reserved — never a valid ban target",
        )
    method = payload.get("method")
    if not isinstance(method, str) or method not in BLOCK_IP_METHODS:
        allowed = ", ".join(sorted(BLOCK_IP_METHODS))
        raise RemediationValidationError(
            f"invalid_unblock_ip_method: {method!r} is not one of {allowed}",
        )
    return str(addr), method


def build_onbox_unblock_command(method: str, ip: str) -> str:
    """Build the on-box firewall UNBAN command for an on-box method.

    The exact inverse of :func:`build_onbox_block_command`: remove the box
    firewall rule for *ip*, then VERIFY the ip is **no longer** in the active
    ruleset so exit 0 means "the ip is not blocked". This makes the operation
    idempotent by construction — unbanning an ip that was never banned removes
    nothing and still verifies clean (exit 0), so a double Undo, or undoing a
    ban that already expired, is a success rather than an error.

    *ip* MUST already be canonicalised + validated by
    :func:`validate_unblock_ip_payload` (single public address, no CIDR, no
    shell metacharacters) — this builder interpolates it and does NOT
    re-parse it. All writes go through non-interactive ``sudo -n``; a
    password prompt fails closed. Rule-removal exit codes are swallowed
    (``2>/dev/null``) so only the VERIFY step decides success.
    """
    if method not in ONBOX_BLOCK_METHODS:
        raise RemediationValidationError(
            f"invalid_unblock_ip_method: {method!r} is not an on-box "
            f"firewall method",
        )
    is_v6 = ipaddress.ip_address(ip).version == 6
    if method == "ufw":
        return (
            f"sudo -n ufw delete deny from {ip} to any 2>/dev/null; "
            f"! sudo -n ufw status | grep -qF '{ip}'"
        )
    if method == "firewalld":
        fam = "ipv6" if is_v6 else "ipv4"
        rule = f'rule family="{fam}" source address="{ip}" drop'
        return (
            f"sudo -n firewall-cmd --remove-rich-rule='{rule}' 2>/dev/null; "
            f"sudo -n firewall-cmd --permanent --remove-rich-rule='{rule}' "
            f"2>/dev/null; "
            f"! sudo -n firewall-cmd --list-rich-rules 2>/dev/null "
            f"| grep -qF '{ip}'"
        )
    # nftables: drop the ip from the servonaut_ban set (the ban added it as
    # a set element). The set/table may not exist if the ip was never banned
    # via servonaut — delete + list both tolerate that (2>/dev/null → empty),
    # so VERIFY finds nothing and exits 0.
    set_name = "banned6" if is_v6 else "banned4"
    return (
        f"sudo -n nft delete element inet servonaut_ban {set_name} "
        f"'{{ {ip} }}' 2>/dev/null; "
        f"! sudo -n nft list set inet servonaut_ban {set_name} 2>/dev/null "
        f"| grep -qF '{ip}'"
    )


def build_remediation_command(verb: str, payload: Dict[str, Any]) -> str:
    """Build the exact remote command for an allowlisted SSH verb.

    Raises :class:`RemediationValidationError` (slug-first message) for
    unknown verbs, local-dispatch verbs (which never become a command
    line), or payloads that fail shape validation.
    """
    if verb in LOCAL_DISPATCH_VERBS:
        raise RemediationValidationError(
            f"local_dispatch_verb: {verb!r} executes via a local curated "
            f"service call, never an SSH command",
        )
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


#: Delimiter the relay executor inserts between stdout and stderr in the
#: combined command output (relay_executors._run_command).
_STDERR_DELIMITER = "\nSTDERR:\n"


def _split_streams(combined: str) -> Tuple[str, str]:
    """Best-effort split of the executor's combined output back into
    ``(stdout, stderr)`` on the delimiter the relay inserts. When the
    delimiter is absent (no stderr), everything is stdout."""
    if _STDERR_DELIMITER in combined:
        idx = combined.index(_STDERR_DELIMITER)
        return combined[:idx], combined[idx + len(_STDERR_DELIMITER):]
    return combined, ""


def build_remediation_result(
    *,
    verb: str,
    ok: bool,
    exit_code: Optional[int],
    output: str,
    payload: Dict[str, Any],
    slug: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    """JSON result payload posted back on the command-result route.

    The server lifts ``ok`` / ``exit_code`` / ``slug`` / ``stdout_tail`` /
    ``stderr_tail`` straight out of this object on the success path, so
    the field names are load-bearing (contract §F.3). Bounded tails only
    — this is attached to the finding as remediation evidence, so it
    stays small and structured.
    """
    stdout, stderr = _split_streams(output)
    result: Dict[str, Any] = {
        "verb": verb,
        "ok": ok,
        "exit_code": exit_code,
        "stdout_tail": stdout[-_RESULT_TAIL_CHARS:],
        "stderr_tail": stderr[-_RESULT_TAIL_CHARS:],
        "dry_run": _coerce_dry_run(payload),
    }
    if slug is not None:
        result["slug"] = slug
    if verb == "certbot_renew" and isinstance(payload.get("cert_name"), str):
        result["cert_name"] = payload["cert_name"]
    if extra:
        # Verb-specific structured fields (block_ip: strategy / rule_id /
        # ip). Additive only — the §F.3 core keys always win.
        for key, value in extra.items():
            result.setdefault(key, value)
    return json.dumps(result)
