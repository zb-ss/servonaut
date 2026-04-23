"""Disk module prober — reports local filesystem usage via ``df``.

Allowlisted commands:
  - df -h --output=source,pcent,target 2>/dev/null

The probe uses ``df``'s machine-friendly ``--output`` format so parsing
is a simple split; fallback parsing is included for systems whose
``df`` doesn't support ``--output`` (BusyBox, some macOS variants).

TTL: 1 hour — disk usage changes frequently.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import ModuleProber

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------

_TTL_1_HOUR = 3600

# Filesystems we never report because they're noise and not user-relevant.
_SKIP_FILESYSTEMS = frozenset({
    "tmpfs",
    "devtmpfs",
    "efivarfs",
    "none",
    "overlay",
    "squashfs",
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
})

# Row format after --output=source,pcent,target:
#   Filesystem  Use%  Mounted on
# e.g. "/dev/sda1  42%  /"
_PCENT_RE = re.compile(r"^(\d+)%$")

_CMD_DF = "df -h --output=source,pcent,target 2>/dev/null"


class DiskProber(ModuleProber):
    """Report per-mount filesystem usage."""

    name = "disk"
    ttl_seconds = _TTL_1_HOUR

    def __init__(self) -> None:
        super().__init__(requires_sudo=False, sudo_optional=False)

    def _commands(self) -> List[str]:
        return [_CMD_DF]

    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Return ``filesystems`` — list of {device, pct_used, mount}."""
        df_section = _extract_section(raw_output, _CMD_DF)
        filesystems: List[Dict[str, Any]] = []
        for raw_line in df_section.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("<") or line.startswith("["):
                continue
            # Skip header line ("Filesystem  Use%  Mounted on").
            if line.lower().startswith("filesystem"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            device = parts[0]
            pcent_token = parts[1]
            mount = " ".join(parts[2:])  # mounts with spaces are rare but possible

            m = _PCENT_RE.match(pcent_token)
            if not m:
                continue
            if device in _SKIP_FILESYSTEMS:
                continue
            filesystems.append({
                "device": device,
                "pct_used": int(m.group(1)),
                "mount": mount,
            })
        return {"filesystems": filesystems}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _extract_section(raw_output: str, cmd_prefix: str) -> str:
    """Extract the stdout block for *cmd_prefix* from *raw_output*."""
    marker = f"{cmd_prefix} →"
    start = raw_output.find(marker)
    if start == -1:
        return ""
    content_start = raw_output.find("\n", start)
    if content_start == -1:
        return ""
    content_start += 1

    next_marker = raw_output.find(" →\n", content_start)
    if next_marker == -1:
        return raw_output[content_start:]

    line_start = raw_output.rfind("\n", content_start, next_marker)
    if line_start == -1:
        return raw_output[content_start:next_marker]
    return raw_output[content_start:line_start]
