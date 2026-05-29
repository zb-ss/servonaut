"""Live resource-stats command + parser for the server actions dashboard.

A single read-only SSH command gathers CPU / memory / load / uptime / disk in
one round-trip; :func:`parse_live_stats` turns its stdout into a
:class:`LiveStats` dataclass.  Each field is parsed independently and degrades
to ``None`` on any failure, so a partial/odd remote response never raises.

Portability note: the command reads from ``/proc`` plus ``free``/``df`` only —
it deliberately avoids ``top`` and ``uptime -p``, which vary across distros
(``uptime -p`` is unsupported on older Amazon Linux ``procps``, and ``top`` is
absent from minimal AMIs).  ``/proc/stat``, ``/proc/loadavg``, ``/proc/uptime``,
``free`` and GNU ``df`` are present on every mainstream Linux (Ubuntu, Amazon
Linux 2/2023, RHEL, Debian…), so the panel renders consistently everywhere.

The command is run through the public ``MemoryService.make_ssh_runner`` which
imposes no write-guard, so the read-only contract lives here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

# Section markers — unlikely to collide with real command output.
_M_CPU = "SVN_CPU"
_M_MEM = "SVN_MEM"
_M_LOAD = "SVN_LOAD"
_M_UP = "SVN_UP"
_M_DISK = "SVN_DISK"

#: Read-only command emitted to the remote host.  CPU is sampled twice from
#: ``/proc/stat`` (0.3s apart) so the parser can compute a busy percentage the
#: canonical way without ``top``.  ``2>/dev/null`` keeps stderr out of stdout;
#: every stage tolerates a missing tool by simply producing no parsable line.
LIVE_STATS_COMMAND = (
    f"echo {_M_CPU}; grep '^cpu ' /proc/stat 2>/dev/null; "
    f"sleep 0.3; grep '^cpu ' /proc/stat 2>/dev/null; "
    f"echo {_M_MEM}; free -m 2>/dev/null | grep -iE '^Mem'; "
    f"echo {_M_LOAD}; cat /proc/loadavg 2>/dev/null; "
    f"echo {_M_UP}; cat /proc/uptime 2>/dev/null; "
    f"echo {_M_DISK}; df -P -BG / 2>/dev/null | tail -1"
)

_FLOAT_RE = re.compile(r"[\d.]+")


@dataclass(frozen=True)
class LiveStats:
    """Parsed live resource snapshot.  Any field may be ``None`` if unparsable."""

    cpu_pct: Optional[float] = None
    mem_used_mb: Optional[int] = None
    mem_total_mb: Optional[int] = None
    load_1m: Optional[float] = None
    load_5m: Optional[float] = None
    load_15m: Optional[float] = None
    uptime: Optional[str] = None
    disk_used_gb: Optional[int] = None
    disk_total_gb: Optional[int] = None
    disk_pct: Optional[int] = None

    @property
    def mem_pct(self) -> Optional[float]:
        """Used memory as a percentage of total, or ``None``."""
        if self.mem_total_mb and self.mem_used_mb is not None and self.mem_total_mb > 0:
            return round(self.mem_used_mb / self.mem_total_mb * 100, 1)
        return None


def _section(text: str, marker: str, next_markers: tuple[str, ...]) -> str:
    """Return the text between *marker* and the next of *next_markers*."""
    start = text.find(marker)
    if start == -1:
        return ""
    start += len(marker)
    end = len(text)
    for nxt in next_markers:
        idx = text.find(nxt, start)
        if idx != -1:
            end = min(end, idx)
    return text[start:end].strip()


def _cpu_from_proc_stat(cpu_sec: str) -> Optional[float]:
    """Compute busy CPU% from two ``/proc/stat`` ``cpu`` aggregate lines.

    Each line is ``cpu  user nice system idle iowait irq softirq steal …``.
    Busy% = 100 * (1 - delta_idle / delta_total) across the two samples.
    """
    lines = [ln for ln in cpu_sec.splitlines() if ln.strip().startswith("cpu ")]
    if len(lines) < 2:
        return None
    try:
        a = [int(x) for x in lines[0].split()[1:]]
        b = [int(x) for x in lines[-1].split()[1:]]
    except ValueError:
        return None
    if len(a) < 5 or len(b) < 5:
        return None
    # idle + iowait (fields index 3 and 4) count as "not busy".
    idle_a, idle_b = a[3] + a[4], b[3] + b[4]
    total_a, total_b = sum(a), sum(b)
    d_total = total_b - total_a
    d_idle = idle_b - idle_a
    if d_total <= 0:
        return None
    pct = 100.0 * (1.0 - d_idle / d_total)
    return round(max(0.0, min(100.0, pct)), 1)


def _format_uptime(seconds: float) -> str:
    """Format an uptime in seconds as e.g. ``up 5d 2h 13m``."""
    secs = int(seconds)
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts: List[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return "up " + " ".join(parts)


def parse_live_stats(stdout: str) -> LiveStats:
    """Parse the stdout of :data:`LIVE_STATS_COMMAND` into a :class:`LiveStats`.

    Defensive by design: each section is parsed in its own ``try`` and any
    failure leaves that field ``None`` rather than raising.
    """
    if not stdout:
        return LiveStats()

    cpu_sec = _section(stdout, _M_CPU, (_M_MEM, _M_LOAD, _M_UP, _M_DISK))
    mem_sec = _section(stdout, _M_MEM, (_M_LOAD, _M_UP, _M_DISK))
    load_sec = _section(stdout, _M_LOAD, (_M_UP, _M_DISK))
    up_sec = _section(stdout, _M_UP, (_M_DISK,))
    disk_sec = _section(stdout, _M_DISK, ())

    mem_used_mb: Optional[int] = None
    mem_total_mb: Optional[int] = None
    load_1m = load_5m = load_15m = None
    uptime: Optional[str] = None
    disk_used_gb: Optional[int] = None
    disk_total_gb: Optional[int] = None
    disk_pct: Optional[int] = None

    cpu_pct = _cpu_from_proc_stat(cpu_sec)

    # Memory: `free -m` Mem row → total used free shared buff/cache available.
    try:
        nums = [int(n) for n in re.findall(r"\d+", mem_sec)]
        if len(nums) >= 2:
            mem_total_mb = nums[0]
            mem_used_mb = nums[1]
    except ValueError:
        mem_used_mb = mem_total_mb = None

    # Load: /proc/loadavg → "0.40 0.55 0.60 1/234 5678".
    try:
        floats = _FLOAT_RE.findall(load_sec)
        if len(floats) >= 3:
            load_1m, load_5m, load_15m = (
                float(floats[0]),
                float(floats[1]),
                float(floats[2]),
            )
    except ValueError:
        load_1m = load_5m = load_15m = None

    # Uptime: /proc/uptime → "<up_seconds> <idle_seconds>".
    try:
        m = _FLOAT_RE.search(up_sec)
        if m:
            uptime = _format_uptime(float(m.group(0)))
    except (ValueError, AttributeError):
        uptime = None

    # Disk: `df -P -BG /` last row → FS 1G-blocks Used Avail Capacity Mounted.
    try:
        parts = disk_sec.split()
        if len(parts) >= 5:
            disk_total_gb = int(re.sub(r"\D", "", parts[1]) or 0)
            disk_used_gb = int(re.sub(r"\D", "", parts[2]) or 0)
            disk_pct = int(re.sub(r"\D", "", parts[4]) or 0)
    except (ValueError, IndexError):
        disk_used_gb = disk_total_gb = disk_pct = None

    return LiveStats(
        cpu_pct=cpu_pct,
        mem_used_mb=mem_used_mb,
        mem_total_mb=mem_total_mb,
        load_1m=load_1m,
        load_5m=load_5m,
        load_15m=load_15m,
        uptime=uptime,
        disk_used_gb=disk_used_gb,
        disk_total_gb=disk_total_gb,
        disk_pct=disk_pct,
    )
