"""Pure parsers for incident-response tools.

These functions are deliberately free of any IO so they can be unit-tested
with fixtures — the SSH round-trip lives in the MCP tool layer and only
hands raw stdout strings to the parsers here.

Two families:

- :func:`summarize_web_traffic` — turns raw access-log lines (combined /
  common log format, optionally with X-Forwarded-For appended) into a
  per-vhost summary: request volume, req/s, status-code mix, top client
  IPs (XFF / mod_remoteip aware) and top URLs. Backs ``web_traffic_summary``.
- :func:`parse_fleet_probe` / :func:`format_fleet_table` — turn the
  ``KEY=VALUE`` output of the fleet health one-liner into a structured
  row and a sortable table. Backs ``fleet_health_snapshot``.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

# Marker the remote one-liner prints before each vhost's log tail so we can
# split a multi-file pull back into per-vhost sections.
VHOST_MARKER_PREFIX = "===VHOST:"

# Combined / common log format head:
#   192.0.2.1 - - [10/Oct/2024:13:55:36 +0000] "GET /path?q=1 HTTP/1.1" 200 1234 ...
_LOG_RE = re.compile(
    r'^(?P<host>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)[^"]*"\s+'
    r'(?P<status>\d{3})'
)

# IPv4 + a loose IPv6 token matcher. Candidates are validated through
# ``ipaddress`` so false positives (version strings, etc.) are dropped.
_IP_TOKEN_RE = re.compile(
    r'\b\d{1,3}(?:\.\d{1,3}){3}\b'           # IPv4
    r'|\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b'  # IPv6 (loose)
)

# Apache/nginx access-log timestamp, e.g. ``10/Oct/2024:13:55:36 +0000``.
_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _is_public(ip: str) -> Optional[bool]:
    """Return True/False for a valid IP's public-ness, or None if not an IP."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return not (parsed.is_private or parsed.is_loopback or parsed.is_reserved
                or parsed.is_link_local)


def extract_client_ip(line: str, host_field: str) -> str:
    """Resolve the *real* client IP for one access-log line.

    Strategy (mod_remoteip / X-Forwarded-For aware):

    1. If the leading ``%h`` field is already a public IP, trust it — the
       server is either internet-facing or mod_remoteip already rewrote
       ``%h`` to the real client.
    2. Otherwise (``%h`` is the ALB / private hop, or not an IP at all),
       scan the rest of the line for the first public IP — this catches
       the case where the real client lives in a logged
       ``X-Forwarded-For`` field instead.
    3. Fall back to the raw ``%h`` field if nothing public is found.
    """
    if _is_public(host_field):
        return host_field
    for token in _IP_TOKEN_RE.findall(line):
        if token == host_field:
            continue
        if _is_public(token):
            return token
    return host_field


# Generic log basenames that don't name a site — keep the full path instead so
# distinct default logs don't collide and the operator can see which one it is.
_GENERIC_LOG_NAMES = frozenset({
    "", "access", "error", "other", "default", "ssl", "other_vhosts", "host",
})


def vhost_label(path: str) -> str:
    """Derive a site label from an access-log path (full path if it's generic)."""
    base = path.rsplit("/", 1)[-1] or path
    name = re.sub(r"\.(access|error)?[._-]?log(\.\d+)?$", "", base, flags=re.I)
    name = re.sub(r"[._-]?(access|error)$", "", name, flags=re.I)
    if name.lower() in _GENERIC_LOG_NAMES:
        return path  # keep the full path to disambiguate generic/default logs
    return name


def _split_vhosts(raw: str) -> Dict[str, List[str]]:
    """Split raw output into ``{vhost_label: [lines]}``.

    Labels are derived site names (``app.access.log`` → ``app``); generic
    logs (``access.log``) keep their full path so default/catch-all vhosts are
    distinguishable. When no marker is present the whole blob is ``"(all)"``.
    """
    sections: Dict[str, List[str]] = {}
    current = "(all)"
    saw_marker = False
    for line in raw.splitlines():
        if line.startswith(VHOST_MARKER_PREFIX):
            saw_marker = True
            full = line[len(VHOST_MARKER_PREFIX):].rstrip("=").strip()
            current = vhost_label(full) or full
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(line)
    if not saw_marker:
        return {"(all)": raw.splitlines()}
    return sections


def _summarize_section(lines: List[str], top_n: int) -> Dict[str, Any]:
    total = 0
    parsed = 0
    statuses: Counter = Counter()
    ips: Counter = Counter()
    urls: Counter = Counter()
    timestamps: List[datetime] = []

    for line in lines:
        if not line.strip():
            continue
        total += 1
        m = _LOG_RE.match(line)
        if not m:
            continue
        parsed += 1
        statuses[m.group("status")] += 1
        client = extract_client_ip(line, m.group("host"))
        ips[client] += 1
        # Strip the query string so /search?q=a and /search?q=b group together.
        url = m.group("url").split("?", 1)[0]
        urls[url] += 1
        try:
            timestamps.append(datetime.strptime(m.group("ts"), _TS_FMT))
        except ValueError:
            pass

    window_seconds = 0.0
    if len(timestamps) >= 2:
        window_seconds = (max(timestamps) - min(timestamps)).total_seconds()
    req_per_sec = (parsed / window_seconds) if window_seconds > 0 else 0.0

    return {
        "requests": parsed,
        "unparsed": total - parsed,
        "window_seconds": round(window_seconds, 1),
        "req_per_sec": round(req_per_sec, 2),
        "status_mix": dict(statuses.most_common()),
        "top_ips": ips.most_common(top_n),
        "top_urls": urls.most_common(top_n),
    }


def summarize_web_traffic(raw: str, top_n: int = 15) -> Dict[str, Any]:
    """Summarize access-log output into a per-vhost structure.

    Returns ``{"vhosts": {label: {...}}, "total_requests": int}``. Each
    vhost summary carries ``requests``, ``req_per_sec``, ``window_seconds``,
    ``status_mix``, ``top_ips`` and ``top_urls``.
    """
    sections = _split_vhosts(raw)
    vhosts: Dict[str, Any] = {}
    total = 0
    unparsed_total = 0
    for label, lines in sections.items():
        summary = _summarize_section(lines, top_n)
        unparsed_total += summary["unparsed"]
        # Drop sections with nothing parseable — they'd only show empty
        # tables. The unparsed count is preserved at the top level so the
        # formatter can still tell the user "we saw lines but couldn't read
        # them" (wrong path / non-standard format).
        if summary["requests"] == 0:
            continue
        vhosts[label] = summary
        total += summary["requests"]
    return {
        "vhosts": vhosts,
        "total_requests": total,
        "unparsed_total": unparsed_total,
    }


def format_web_traffic(summary: Dict[str, Any], log_hint: str = "") -> str:
    """Render :func:`summarize_web_traffic` output as a readable report."""
    vhosts = summary.get("vhosts", {})
    if not vhosts:
        unparsed = summary.get("unparsed_total", 0)
        seen = f" ({unparsed} line(s) seen but unparseable)" if unparsed else ""
        return (
            "No parseable access-log lines found"
            + (f" (looked at: {log_hint})" if log_hint else "")
            + seen
            + ". The log may use a non-standard format, or the path may be wrong."
        )
    out: List[str] = []
    if log_hint:
        out.append(f"Source: {log_hint}")
    out.append(f"Total parsed requests: {summary.get('total_requests', 0)}")
    # Busiest vhost first.
    ordered = sorted(
        vhosts.items(), key=lambda kv: kv[1].get("requests", 0), reverse=True
    )
    for label, s in ordered:
        out.append("")
        # A label that's still a path is a generic/default log we couldn't tie
        # to a named site — flag it so the operator knows it's the catch-all.
        suffix = "  (default/unmatched vhost — log path shown)" if "/" in label else ""
        out.append(f"── {label} ──{suffix}")
        rps = s.get("req_per_sec", 0.0)
        win = s.get("window_seconds", 0.0)
        out.append(
            f"  Requests: {s.get('requests', 0)}"
            f"   ~{rps} req/s over {win}s"
            + (f"   ({s['unparsed']} unparsed lines)" if s.get("unparsed") else "")
        )
        mix = s.get("status_mix", {})
        if mix:
            mix_str = "  ".join(f"{code}×{cnt}" for code, cnt in mix.items())
            out.append(f"  Status:   {mix_str}")
        top_ips = s.get("top_ips", [])
        if top_ips:
            out.append("  Top client IPs:")
            for ip, cnt in top_ips:
                out.append(f"    {ip:<40} {cnt}")
        top_urls = s.get("top_urls", [])
        if top_urls:
            out.append("  Top URLs:")
            for url, cnt in top_urls:
                out.append(f"    {url[:60]:<60} {cnt}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Fleet health
# ---------------------------------------------------------------------------

def parse_fleet_probe(raw: str) -> Dict[str, str]:
    """Parse ``KEY=VALUE`` lines emitted by the fleet health one-liner."""
    out: Dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.isupper() and key.replace("_", "").isalpha():
            out[key] = value.strip()
    return out


def fleet_row_from_probe(name: str, raw: str) -> Dict[str, Any]:
    """Turn one host's probe output into a normalized row dict.

    If the SSH call succeeded but produced no recognizable ``KEY=VALUE`` data
    (restricted shell, missing perms, non-POSIX login shell), return an error
    row with a reason rather than a silent all-blank line.
    """
    kv = parse_fleet_probe(raw)
    if not any(k in kv for k in ("LOAD", "CPU", "MEM")):
        return {"name": name,
                "error": "connected, no probe data (restricted shell / perms?)"}
    load1 = ""
    load_field = kv.get("LOAD", "")
    if load_field:
        load1 = load_field.split()[0]
    mem = kv.get("MEM", "")  # "total used free" in MB
    mem_pct = ""
    if mem:
        parts = mem.split()
        if len(parts) >= 2:
            try:
                total_mb = float(parts[0])
                used_mb = float(parts[1])
                if total_mb > 0:
                    mem_pct = f"{round(used_mb / total_mb * 100)}%"
            except ValueError:
                pass
    fpm = kv.get("FPM", "")  # "active/max" or "" when no php-fpm
    cores = kv.get("CPU", "")
    # Load-per-core is the triage ratio (≈1.0 = saturated; >2 = overloaded).
    load_per_core = ""
    try:
        if load1 and cores and float(cores) > 0:
            load_per_core = f"{float(load1) / float(cores):.2f}"
    except (ValueError, ZeroDivisionError):
        pass
    return {
        "name": name,
        "load1": load1,
        "load": load_field,
        "cores": cores,
        "load_per_core": load_per_core,
        "mem_pct": mem_pct,
        "mem": mem,
        "fpm": fpm,
        "stack": kv.get("STACK", ""),
        "listen": kv.get("LISTEN", ""),
    }


def _load_sort_key(row: Dict[str, Any]) -> float:
    try:
        return float(row.get("load1") or -1)
    except (ValueError, TypeError):
        return -1.0


def format_fleet_table(rows: List[Dict[str, Any]]) -> str:
    """Render fleet rows as a table, busiest (highest load) first."""
    if not rows:
        return "No reachable instances to report on."
    ok_rows = [r for r in rows if not r.get("error")]
    err_rows = [r for r in rows if r.get("error")]
    ok_rows.sort(key=_load_sort_key, reverse=True)

    out: List[str] = [
        f"{'Instance':<28} {'Load(1m)':<9} {'Cores':<6} {'L/core':<7} "
        f"{'Mem':<6} {'FPM':<10} {'Web stack':<22} Listen",
        "-" * 108,
    ]
    for r in ok_rows:
        out.append(
            f"{str(r.get('name', ''))[:28]:<28} "
            f"{str(r.get('load1', '') or '-'):<9} "
            f"{str(r.get('cores', '') or '-'):<6} "
            f"{str(r.get('load_per_core', '') or '-'):<7} "
            f"{str(r.get('mem_pct', '') or '-'):<6} "
            f"{str(r.get('fpm', '') or '-'):<10} "
            f"{str(r.get('stack', '') or '-')[:22]:<22} "
            f"{str(r.get('listen', '') or '-')}"
        )
    for r in err_rows:
        out.append(
            f"{str(r.get('name', ''))[:28]:<28} "
            f"{str(r.get('error', ''))[:60]}"
        )
    if err_rows:
        out.append(f"\n({len(err_rows)} host(s) returned no data — see reasons above.)")
    return "\n".join(out)
