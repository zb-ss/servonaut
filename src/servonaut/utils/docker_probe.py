"""Parsers for the docker_* read-only probe tools.

The MCP/probe layer runs ``docker`` CLI commands over SSH with
``--format '{{json .}}'``-style templates and hands the raw stdout to
these pure functions, which produce the wire shapes pinned in the
proactive-monitoring tool contract:

- ``docker_ps``     → ``{"containers": [{name, image, status, health,
  restart_count, started_at, ports, compose_project, compose_service}]}``
- ``docker_stats``  → ``{"containers": [{name, cpu_percent,
  mem_used_bytes, mem_limit_bytes, mem_percent, pids}]}``
- ``docker_events_summary`` → ``{"events": [{container, event, count,
  last_at}]}``

Every function tolerates malformed lines (a container racing away
between ``ps`` and ``inspect`` produces partial output) — bad lines are
skipped, never raised.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
_COMPOSE_SERVICE_LABEL = "com.docker.compose.service"

# docker stats human units → bytes multipliers (docker uses binary units
# with decimal-ish suffixes; "B" through "PiB"/"PB" all appear in the wild).
_MEM_UNITS = {
    "b": 1,
    "kb": 1000, "kib": 1024,
    "mb": 1000 ** 2, "mib": 1024 ** 2,
    "gb": 1000 ** 3, "gib": 1024 ** 3,
    "tb": 1000 ** 4, "tib": 1024 ** 4,
}

_MEM_RE = re.compile(r"^([0-9.]+)\s*([a-zA-Z]+)$")


def parse_mem_bytes(value: str) -> Optional[int]:
    """``"11.3MiB"`` → bytes; None when unparseable."""
    m = _MEM_RE.match((value or "").strip())
    if not m:
        return None
    mult = _MEM_UNITS.get(m.group(2).lower())
    if mult is None:
        return None
    try:
        return int(float(m.group(1)) * mult)
    except ValueError:
        return None


def _percent(value: str) -> Optional[float]:
    try:
        return float((value or "").strip().rstrip("%"))
    except ValueError:
        return None


def _ports_from_inspect(ports: Any) -> List[Dict[str, Any]]:
    """NetworkSettings.Ports map → ``[{host, container, proto}]``.

    Input shape: ``{"80/tcp": [{"HostIp": "0.0.0.0", "HostPort":
    "8080"}], "9000/tcp": null}`` — unpublished ports (null bindings)
    are omitted.
    """
    out: List[Dict[str, Any]] = []
    if not isinstance(ports, dict):
        return out
    for key, bindings in ports.items():
        if not bindings:
            continue
        container_port, _, proto = str(key).partition("/")
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            try:
                host = int(binding.get("HostPort") or 0)
                container = int(container_port)
            except (TypeError, ValueError):
                continue
            out.append({
                "host": host,
                "container": container,
                "proto": proto or "tcp",
            })
    return out


def parse_docker_ps_lines(stdout: str) -> List[Dict[str, Any]]:
    """One JSON object per line (from the inspect template) → contract rows."""
    containers: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        labels = row.get("labels") or {}
        if not isinstance(labels, dict):
            labels = {}
        containers.append({
            "name": str(row.get("name") or "").lstrip("/"),
            "image": row.get("image"),
            "status": row.get("status"),
            "health": row.get("health"),
            "restart_count": row.get("restart_count"),
            "started_at": row.get("started_at"),
            "ports": _ports_from_inspect(row.get("ports")),
            "compose_project": labels.get(_COMPOSE_PROJECT_LABEL),
            "compose_service": labels.get(_COMPOSE_SERVICE_LABEL),
        })
    return containers


def parse_docker_stats_lines(stdout: str) -> List[Dict[str, Any]]:
    """``docker stats --no-stream --format '{{json .}}'`` → contract rows."""
    containers: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        mem_used = mem_limit = None
        mem_usage = str(row.get("MemUsage") or "")
        if "/" in mem_usage:
            used_raw, _, limit_raw = mem_usage.partition("/")
            mem_used = parse_mem_bytes(used_raw)
            mem_limit = parse_mem_bytes(limit_raw)
        try:
            pids: Optional[int] = int(row.get("PIDs"))
        except (TypeError, ValueError):
            pids = None
        containers.append({
            "name": row.get("Name"),
            "cpu_percent": _percent(row.get("CPUPerc")),
            "mem_used_bytes": mem_used,
            "mem_limit_bytes": mem_limit,
            "mem_percent": _percent(row.get("MemPerc")),
            "pids": pids,
        })
    return containers


#: Container lifecycle events worth aggregating for health detection.
_EVENTS_OF_INTEREST = frozenset({"die", "oom", "restart", "kill", "start"})


def summarize_docker_events(stdout: str) -> List[Dict[str, Any]]:
    """``docker events --format '{{json .}}'`` stream → aggregated rows.

    Groups by (container name, event status), counting occurrences and
    keeping the latest ISO-ish timestamp seen.
    """
    agg: Dict[tuple, Dict[str, Any]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("Type") != "container":
            continue
        status = str(row.get("status") or row.get("Action") or "")
        # Compound actions like "health_status: unhealthy" keep the prefix.
        base_status = status.split(":", 1)[0].strip()
        if base_status not in _EVENTS_OF_INTEREST:
            continue
        actor = row.get("Actor") or {}
        attributes = actor.get("Attributes") or {}
        name = attributes.get("name") or str(actor.get("ID") or "")[:12]
        key = (name, base_status)
        entry = agg.setdefault(key, {
            "container": name, "event": base_status,
            "count": 0, "last_at": None,
        })
        entry["count"] += 1
        # ``time`` is epoch seconds; ``timeNano`` is higher precision.
        ts = row.get("time")
        if isinstance(ts, (int, float)):
            last = entry["last_at"]
            if last is None or ts > last:
                entry["last_at"] = ts
    return sorted(
        agg.values(),
        key=lambda e: (e["container"], e["event"]),
    )


# ---------------------------------------------------------------------------
# docker_log_summary — container-log aggregation (v2 contract)
# ---------------------------------------------------------------------------

# Combined/common access-log line: client ip … "METHOD /path HTTP/x" status
_ACCESS_LINE_RE = re.compile(
    r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)[^"]*"\s+(\d{3})\b'
)

# Error-ish keywords for app-log pattern grouping.
_ERRORISH_RE = re.compile(
    r"\b(error|exception|critical|fatal|panic|traceback|failed|failure)\b",
    re.IGNORECASE,
)

# Pattern normalisation: collapse volatile tokens so identical failures
# group together across occurrences.
_NUM_RE = re.compile(r"\d+")
_HEX_RE = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)
_PATTERN_MAX_CHARS = 120
_SAMPLE_LINE_MAX_CHARS = 200

#: Fraction of parseable lines above which a stream is treated as a
#: web access log rather than a generic app log.
_WEB_KIND_THRESHOLD = 0.5


def _access_hit(line: str):
    """Return (path, status) when *line* looks like an access-log line."""
    m = _ACCESS_LINE_RE.search(line)
    if m:
        return m.group(1), m.group(2)
    if line.lstrip().startswith("{"):
        # JSON access logs (Caddy/Traefik/nginx-json): status + a
        # path-ish field, possibly nested under "request".
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(row, dict):
            return None
        status = row.get("status")
        request = row.get("request") if isinstance(row.get("request"), dict) else {}
        path = (
            row.get("path") or row.get("uri")
            or request.get("uri") or request.get("path")
        )
        if isinstance(status, int) and path:
            return str(path), str(status)
    return None


def _normalise_pattern(line: str) -> str:
    out = _HEX_RE.sub("#", line)
    out = _NUM_RE.sub("#", out)
    return out.strip()[:_PATTERN_MAX_CHARS]


def summarize_container_log(stdout: str, top_n: int = 20) -> Dict[str, Any]:
    """Aggregate one container's log stream per the v2 contract.

    Returns ``{kind, status_mix, error_rate_4xx, error_rate_5xx,
    top_paths, error_patterns, lines_scanned}`` — web-style parsing when
    the stream looks like access logs (plain or JSON), error-pattern
    grouping otherwise. Aggregation happens before anything crosses the
    wire: that is both the cost control and the privacy control.
    """
    lines = [l for l in stdout.splitlines() if l.strip()]
    status_mix: Dict[str, int] = {}
    paths: Dict[str, int] = {}
    patterns: Dict[str, Dict[str, Any]] = {}
    access_hits = 0

    for line in lines:
        hit = _access_hit(line)
        if hit is not None:
            path, status = hit
            access_hits += 1
            status_mix[status] = status_mix.get(status, 0) + 1
            # Strip query strings so paths group by endpoint.
            paths[path.split("?", 1)[0]] = paths.get(path.split("?", 1)[0], 0) + 1
            continue
        if _ERRORISH_RE.search(line):
            key = _normalise_pattern(line)
            row = patterns.setdefault(key, {
                "pattern": key, "count": 0,
                "sample": line.strip()[:_SAMPLE_LINE_MAX_CHARS],
            })
            row["count"] += 1

    if not lines:
        kind = "unknown"
    elif access_hits / len(lines) >= _WEB_KIND_THRESHOLD:
        kind = "web"
    else:
        kind = "app"

    def _rate(prefix: str) -> float:
        if not access_hits:
            return 0.0
        n = sum(c for s, c in status_mix.items() if s.startswith(prefix))
        return round(n / access_hits, 4)

    top = max(1, top_n)
    return {
        "kind": kind,
        "status_mix": status_mix,
        "error_rate_4xx": _rate("4"),
        "error_rate_5xx": _rate("5"),
        "top_paths": [
            {"path": p, "requests": c}
            for p, c in sorted(paths.items(), key=lambda kv: kv[1],
                               reverse=True)[:top]
        ],
        "error_patterns": sorted(
            patterns.values(), key=lambda r: r["count"], reverse=True,
        )[:top],
        "lines_scanned": len(lines),
    }
