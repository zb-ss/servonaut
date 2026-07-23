"""Parsers for the system-health probe tools (journal / TLS / auth log).

The MCP layer runs bounded read-only commands over SSH with section
markers and hands raw stdout to these pure functions, which produce the
wire shapes pinned in the proactive-monitoring tool contract:

- ``journal_errors``    → ``{entries: [{unit, level, count, sample}],
  oom_kills: [{unit, count, last_at}], restarts: [{unit, count,
  last_at}]}``
- ``tls_cert_check``    → ``{certs: [{domain, path, expires_at,
  days_left, issuer, self_signed}]}``
- ``auth_log_summary``  → ``{failed_logins: [{ip, user, count,
  method}], invalid_users: [{ip, count}], accepted_logins: [{ip, user,
  count, method}], fail2ban?: {installed, active, ssh_jail, banned_ips}}``
  (``fail2ban`` present only when the probe emitted the section)
- ``disk_usage``        → ``{filesystems: [{mount, size_bytes,
  used_pct, inodes_used_pct}], fullest_mount, top_consumers: [{path,
  size_bytes}]}``
- ``pending_updates``   → ``{manager, security_count, total_count,
  reboot_required, sample_packages: []}``

Every function tolerates malformed lines — skipped, never raised.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# journald PRIORITY → syslog level name (err and worse is all we ship).
_PRIORITY_NAMES = {
    "0": "emerg", "1": "alert", "2": "crit", "3": "err",
    "4": "warning", "5": "notice", "6": "info", "7": "debug",
}

_SAMPLE_MAX_CHARS = 200

_OOM_PROC_RE = re.compile(r"[Kk]illed process \d+ \(([^)]+)\)")
_RESTART_RE = re.compile(
    r"([\w@.\\-]+\.(?:service|socket|timer)): "
    r"(Scheduled restart|Failed with result)"
)

# sshd auth.log patterns. Order matters: "invalid user" lines also match
# the failed-password pattern, so they carry the user through it too.
_FAILED_RE = re.compile(
    r"Failed (password|publickey|keyboard-interactive[^ ]*) for "
    r"(?:invalid user )?(\S+) from (\S+)"
)
_INVALID_USER_RE = re.compile(r"Invalid user (\S+) from (\S+)")
_ACCEPTED_RE = re.compile(
    r"Accepted (password|publickey|keyboard-interactive[^ ]*) for "
    r"(\S+) from (\S+)"
)


def _split_sections(stdout: str) -> Dict[str, List[str]]:
    """Split marker-delimited output (``===NAME===`` or ``===NAME:detail===``)."""
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("===") and stripped.endswith("==="):
            current = stripped.strip("=").split(":", 1)[0]
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)
    return sections


def _syslog_ts(line: str) -> str:
    """Best-effort timestamp prefix from a syslog-format line."""
    return line[:15].strip()


def parse_journal_errors(stdout: str, top_n: int = 20) -> Dict[str, Any]:
    """``===ERR===`` (journalctl -o json) + ``===OOM===`` + ``===RESTARTS===``."""
    sections = _split_sections(stdout)

    entries: Dict[tuple, Dict[str, Any]] = {}
    for line in sections.get("ERR", []):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        unit = (
            row.get("_SYSTEMD_UNIT")
            or row.get("SYSLOG_IDENTIFIER")
            or ("kernel" if row.get("_TRANSPORT") == "kernel" else "unknown")
        )
        level = _PRIORITY_NAMES.get(str(row.get("PRIORITY")), "err")
        message = row.get("MESSAGE")
        if isinstance(message, list):  # journald binary-safe arrays
            message = bytes(message).decode("utf-8", errors="replace")
        key = (unit, level)
        entry = entries.setdefault(key, {
            "unit": unit, "level": level, "count": 0, "sample": "",
        })
        entry["count"] += 1
        if not entry["sample"] and isinstance(message, str):
            entry["sample"] = message[:_SAMPLE_MAX_CHARS]

    oom: Dict[str, Dict[str, Any]] = {}
    for line in sections.get("OOM", []):
        m = _OOM_PROC_RE.search(line)
        name = m.group(1) if m else "unknown"
        row = oom.setdefault(name, {"unit": name, "count": 0, "last_at": ""})
        row["count"] += 1
        row["last_at"] = _syslog_ts(line) or row["last_at"]

    restarts: Dict[str, Dict[str, Any]] = {}
    for line in sections.get("RESTARTS", []):
        m = _RESTART_RE.search(line)
        if not m:
            continue
        unit = m.group(1)
        row = restarts.setdefault(unit, {"unit": unit, "count": 0, "last_at": ""})
        row["count"] += 1
        row["last_at"] = _syslog_ts(line) or row["last_at"]

    # ``===FAILED===`` — systemctl --failed --plain --no-legend: current
    # failed-unit STATE, which journal-derived signal alone misses (a
    # unit that failed before the lookback window has no recent lines).
    failed_units: List[Dict[str, Any]] = []
    for line in sections.get("FAILED", []):
        parts = line.split(None, 4)
        if not parts or "." not in parts[0]:
            continue
        failed_units.append({
            "unit": parts[0],
            "description": parts[4].strip() if len(parts) > 4 else "",
        })

    top = max(1, top_n)
    by_count = lambda rows: sorted(  # noqa: E731 — tiny local sort key
        rows, key=lambda r: r["count"], reverse=True,
    )[:top]
    return {
        "entries": by_count(list(entries.values())),
        "oom_kills": by_count(list(oom.values())),
        "restarts": by_count(list(restarts.values())),
        "failed_units": failed_units[:top],
    }


def _cert_cn(field: str) -> Optional[str]:
    """Extract CN from an openssl subject/issuer line (both formats)."""
    m = re.search(r"CN\s*=\s*([^,/]+)", field)
    return m.group(1).strip() if m else None


def parse_tls_certs(stdout: str, *, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """``===CERT:<path>===`` blocks of ``openssl x509 -noout`` output."""
    now = now or datetime.now(timezone.utc)
    certs: List[Dict[str, Any]] = []
    seen_paths = set()
    path: Optional[str] = None
    block: Dict[str, str] = {}

    def _flush() -> None:
        nonlocal block, path
        if path and block.get("notAfter") and path not in seen_paths:
            seen_paths.add(path)
            expires_at = None
            days_left = None
            try:
                parsed = datetime.strptime(
                    block["notAfter"].strip(), "%b %d %H:%M:%S %Y %Z",
                ).replace(tzinfo=timezone.utc)
                expires_at = parsed.isoformat()
                days_left = (parsed - now).days
            except ValueError:
                pass
            subject = block.get("subject", "")
            issuer = block.get("issuer", "")
            domain = _cert_cn(subject)
            if not domain and "/live/" in path:
                # certbot layout: /etc/letsencrypt/live/<domain>/…
                domain = path.split("/live/", 1)[1].split("/", 1)[0]
            certs.append({
                "domain": domain,
                "path": path,
                "expires_at": expires_at,
                "days_left": days_left,
                "issuer": _cert_cn(issuer) or issuer.replace(
                    "issuer=", "",
                ).strip() or None,
                "self_signed": bool(subject and issuer and (
                    subject.replace("subject=", "").strip()
                    == issuer.replace("issuer=", "").strip()
                )),
            })
        block = {}
        path = None

    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("===CERT:") and stripped.endswith("==="):
            _flush()
            path = stripped[len("===CERT:"):-3].strip()
            continue
        for field in ("subject", "issuer"):
            if stripped.startswith(f"{field}="):
                block[field] = stripped
        if stripped.startswith("notAfter="):
            block["notAfter"] = stripped[len("notAfter="):]
    _flush()
    return certs


def _int_or_none(value: str) -> Optional[int]:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return None


def _parse_fail2ban(lines: List[str], top_n: int = 20) -> Dict[str, Any]:
    """Parse the ``===FAIL2BAN===`` section (key=value lines the probe
    emits) into the additive block.

    ``active``/``ssh_jail`` are ``None`` when undeterminable (fail2ban
    installed but the client socket is unreadable even via ``sudo -n``)
    — never a misleading ``False``. ``banned_ips`` is bounded to
    ``top_n``.
    """
    block: Dict[str, Any] = {
        "installed": False, "active": None,
        "ssh_jail": None, "banned_ips": [],
    }
    jail: Dict[str, Any] = {}
    banned: List[str] = []
    jail_readable = False
    for raw in lines:
        line = raw.strip()
        if line == "INSTALLED=true":
            block["installed"] = True
        elif line == "INSTALLED=false":
            block["installed"] = False
        elif line.startswith("ACTIVE="):
            state = line.split("=", 1)[1].strip()
            block["active"] = True if state == "active" else (
                False if state in ("inactive", "failed") else None
            )
        elif line == "CLIENT_UNREADABLE=true":
            jail_readable = False
        elif line.startswith("MAXRETRY="):
            jail["maxretry"] = _int_or_none(line.split("=", 1)[1])
            jail_readable = True
        elif line.startswith("FINDTIME="):
            jail["findtime"] = _int_or_none(line.split("=", 1)[1])
        elif line.startswith("BANTIME="):
            jail["bantime"] = _int_or_none(line.split("=", 1)[1])
        elif line.startswith("JAIL_ACTIVE="):
            jail["active"] = line.split("=", 1)[1].strip() == "true"
        elif line.startswith("BANNED="):
            banned.extend(line.split("=", 1)[1].split())
    if jail_readable:
        block["ssh_jail"] = {
            "active": jail.get("active", False),
            "maxretry": jail.get("maxretry"),
            "findtime": jail.get("findtime"),
            "bantime": jail.get("bantime"),
        }
    block["banned_ips"] = banned[:max(1, top_n)]
    return block


def summarize_auth_log(stdout: str, top_n: int = 20) -> Dict[str, Any]:
    """sshd auth-log lines → grouped failed / invalid-user / accepted rows.

    When the probe emits a ``===FAIL2BAN===`` section, an additive
    ``fail2ban`` block is included (what's already mitigated on the box).
    Older probes omit the section → no ``fail2ban`` key (the detector
    reads it as "not probed").
    """
    failed: Dict[tuple, Dict[str, Any]] = {}
    invalid: Dict[str, Dict[str, Any]] = {}
    accepted: Dict[tuple, Dict[str, Any]] = {}

    sections = _split_sections(stdout)
    # The auth regexes are specific enough that scanning the whole stream
    # (markers + fail2ban lines never match them) is safe and keeps the
    # journald/file paths identical.
    for line in stdout.splitlines():
        m = _FAILED_RE.search(line)
        if m:
            method, user, ip = m.group(1), m.group(2), m.group(3)
            key = (ip, user, method)
            row = failed.setdefault(key, {
                "ip": ip, "user": user, "count": 0, "method": method,
            })
            row["count"] += 1
        m = _INVALID_USER_RE.search(line)
        if m:
            ip = m.group(2)
            row = invalid.setdefault(ip, {"ip": ip, "count": 0})
            row["count"] += 1
        m = _ACCEPTED_RE.search(line)
        if m:
            method, user, ip = m.group(1), m.group(2), m.group(3)
            key = (ip, user, method)
            row = accepted.setdefault(key, {
                "ip": ip, "user": user, "count": 0, "method": method,
            })
            row["count"] += 1

    top = max(1, top_n)
    by_count = lambda rows: sorted(  # noqa: E731 — tiny local sort key
        rows, key=lambda r: r["count"], reverse=True,
    )[:top]
    result: Dict[str, Any] = {
        "failed_logins": by_count(list(failed.values())),
        "invalid_users": by_count(list(invalid.values())),
        "accepted_logins": by_count(list(accepted.values())),
    }
    if "FAIL2BAN" in sections:
        result["fail2ban"] = _parse_fail2ban(sections["FAIL2BAN"], top_n)
    return result


def parse_disk_usage(stdout: str, top_n: int = 20) -> Dict[str, Any]:
    """``===FS===`` (df -P -B1) + ``===INODES===`` (df -P -i) + ``===TOP===``
    (du -x -B1 -d 2 under the fullest filesystem, size-sorted)."""
    sections = _split_sections(stdout)

    filesystems: Dict[str, Dict[str, Any]] = {}
    for line in sections.get("FS", []):
        parts = line.split()
        if len(parts) < 6:
            continue
        mount = parts[5]
        try:
            size_bytes = int(parts[1])
            used_pct = float(parts[4].rstrip("%"))
        except ValueError:
            continue
        filesystems[mount] = {
            "mount": mount,
            "size_bytes": size_bytes,
            "used_pct": used_pct,
            "inodes_used_pct": None,
        }

    for line in sections.get("INODES", []):
        parts = line.split()
        if len(parts) < 6:
            continue
        row = filesystems.get(parts[5])
        if row is None:
            continue
        try:
            row["inodes_used_pct"] = float(parts[4].rstrip("%"))
        except ValueError:
            pass  # xfs prints '-' when inode accounting is dynamic

    top_consumers: List[Dict[str, Any]] = []
    for line in sections.get("TOP", []):
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        try:
            size_bytes = int(parts[0])
        except ValueError:
            continue
        top_consumers.append({
            "path": parts[1].strip(),
            "size_bytes": size_bytes,
        })

    ranked = sorted(
        filesystems.values(), key=lambda r: r["used_pct"], reverse=True,
    )
    top = max(1, top_n)
    return {
        "filesystems": ranked,
        "fullest_mount": ranked[0]["mount"] if ranked else None,
        "top_consumers": top_consumers[:top],
    }


#: apt simulation lines: ``Inst <pkg> [old] (new origin ...)`` — a
#: security origin marks the row as a security update.
_APT_INST_RE = re.compile(r"^Inst\s+(\S+)")


def parse_pending_updates(stdout: str, sample_n: int = 10) -> Dict[str, Any]:
    """``===APT===``/``===DNF_SEC===``+``===DNF_ALL===`` + ``===REBOOT===``."""
    sections = _split_sections(stdout)

    manager: Optional[str] = None
    total = 0
    security = 0
    samples: List[str] = []

    if "APT" in sections:
        manager = "apt"
        for line in sections["APT"]:
            m = _APT_INST_RE.match(line.strip())
            if not m:
                continue
            total += 1
            if "security" in line.lower():
                security += 1
            if len(samples) < sample_n:
                samples.append(m.group(1))
    elif "DNF_SEC" in sections or "DNF_ALL" in sections:
        manager = "dnf"
        sec_names = set()
        for line in sections.get("DNF_SEC", []):
            parts = line.split()
            # updateinfo rows: <advisory> <severity/type> <pkg-ver-rel.arch>
            if len(parts) >= 3:
                sec_names.add(parts[-1])
        security = len(sec_names)
        for line in sections.get("DNF_ALL", []):
            parts = line.split()
            # check-update rows: <pkg.arch> <version> <repo>
            if len(parts) == 3 and "." in parts[0]:
                total += 1
                if len(samples) < sample_n:
                    samples.append(parts[0])
        total = max(total, security)

    reboot_required: Optional[bool] = None
    for line in sections.get("REBOOT", []):
        flag = line.strip().lower()
        if flag == "yes":
            reboot_required = True
        elif flag == "no":
            reboot_required = False

    return {
        "manager": manager,
        "security_count": security,
        "total_count": total,
        "reboot_required": reboot_required,
        "sample_packages": samples,
    }


def _classify_file_perm(path: str, mode: str, owner: str) -> Optional[str]:
    """Flag a curated sensitive path as insecure, or return ``None``.

    Two checks only (the curated candidate list is the safety boundary):

    * **world-writable** — the ``other`` write bit is set. On any of these
      system paths that is a privilege-escalation red flag with no benign
      cause.
    * **bad owner** — the file is not owned by ``root``. These paths
      (sshd/sudoers/cron/passwd-family/root's keys) are all root-owned on a
      correctly configured host; a non-root owner is a tampering signal.

    ``mode`` is the octal string from ``stat -c %a`` and may carry a leading
    special-bits digit (e.g. ``4755``); only the trailing three permission
    digits are inspected. A malformed mode yields ``None`` (skip, never
    raise) so a partial probe still reports the rows it could read.
    """
    triad = mode[-3:] if len(mode) >= 3 else mode.rjust(3, "0")
    try:
        _owner_bits, _group_bits, other_bits = (int(d) for d in triad)
    except ValueError:
        return None

    issues: List[str] = []
    if other_bits & 0b010:  # world-writable
        issues.append("world-writable")
    if owner and owner != "root":
        issues.append(f"not owned by root (owner={owner})")
    return "; ".join(issues) if issues else None


def parse_security_audit(stdout: str) -> Dict[str, Any]:
    """Parse the ``security_audit`` probe output into the frozen wire shape.

    ``{"sshd": {<directive>: <value>}, "insecure_files": [{path, mode,
    owner, issue}]}``.

    Input is two kinds of marker lines (see ``ServonautTools.security_audit``):

    * ``SSHD|<directive>|<value>`` — effective sshd settings straight from
      ``sshd -T``. Keys stay in ``sshd -T`` form (lowercase, no separators);
      the server normalises them to canonical directive names, so they are
      passed through UNREMAPPED here.
    * ``FILE|<path>|<mode>|<owner>|<group>`` — a stat of one curated
      candidate path. Only paths that :func:`_classify_file_perm` flags are
      emitted into ``insecure_files`` (a clean host yields an empty list).

    Malformed lines are skipped rather than raising, so a partial probe still
    yields what it could read.
    """
    sshd: Dict[str, str] = {}
    insecure: List[Dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line.startswith("SSHD|"):
            parts = line.split("|", 2)
            if len(parts) == 3 and parts[1]:
                sshd[parts[1].strip()] = parts[2].strip()
        elif line.startswith("FILE|"):
            parts = line.split("|")
            if len(parts) != 5 or not parts[1]:
                continue
            _, path, mode, owner, _group = (p.strip() for p in parts)
            issue = _classify_file_perm(path, mode, owner)
            if issue:
                insecure.append({
                    "path": path,
                    "mode": mode,
                    "owner": owner,
                    "issue": issue,
                })
    return {"sshd": sshd, "insecure_files": insecure}
