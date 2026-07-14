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
  count, method}]}``
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


def summarize_auth_log(stdout: str, top_n: int = 20) -> Dict[str, Any]:
    """sshd auth-log lines → grouped failed / invalid-user / accepted rows."""
    failed: Dict[tuple, Dict[str, Any]] = {}
    invalid: Dict[str, Dict[str, Any]] = {}
    accepted: Dict[tuple, Dict[str, Any]] = {}

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
    return {
        "failed_logins": by_count(list(failed.values())),
        "invalid_users": by_count(list(invalid.values())),
        "accepted_logins": by_count(list(accepted.values())),
    }


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
