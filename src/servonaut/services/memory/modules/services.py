"""Services module prober — detects enabled systemd units.

Primary command:
  - systemctl list-unit-files --state=enabled --no-pager --no-legend --type=service 2>/dev/null

Fallback (when systemctl is unavailable):
  - service --status-all 2>&1 | head -100

TTL: 6 hours.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import ModuleProber

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------

_TTL_6_HOURS = 6 * 3600

# Regex to extract enabled service unit names from systemctl output.
# Each line looks like: "nginx.service  enabled  enabled"
_UNIT_RE = re.compile(r"^(\S+\.service)\s+enabled", re.MULTILINE)

# Regex to extract service names from `service --status-all` output.
# Lines look like: " [ + ]  nginx" or " [ - ]  nginx"
_SERVICE_STATUS_ALL_RE = re.compile(r"\[\s*[+\-\?]\s*\]\s+(\S+)", re.MULTILINE)

_PRIMARY_CMD = (
    "systemctl list-unit-files --state=enabled "
    "--no-pager --no-legend --type=service 2>/dev/null"
)
_FALLBACK_CMD = "service --status-all 2>&1 | head -100"


class ServicesProber(ModuleProber):
    """Detect enabled systemd service units.

    Falls back to ``service --status-all`` when systemctl is unavailable
    (e.g. non-systemd distros or container environments).
    """

    name = "services"
    ttl_seconds = _TTL_6_HOURS

    def __init__(self) -> None:
        super().__init__(requires_sudo=False, sudo_optional=True)

    def _commands(self) -> List[str]:
        return [_PRIMARY_CMD]

    def _fallback_commands(self) -> List[str]:
        return [_FALLBACK_CMD]

    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Extract enabled service unit names.

        Returns:
            Dict with key ``enabled_units`` → sorted list of service names.
        """
        # Try parsing systemctl output first.
        systemctl_section = _extract_section(raw_output, _PRIMARY_CMD)
        units = _UNIT_RE.findall(systemctl_section)
        if units:
            return {"enabled_units": sorted(units)}

        # Try parsing fallback output.
        fallback_section = _extract_section(raw_output, _FALLBACK_CMD)
        services = _SERVICE_STATUS_ALL_RE.findall(fallback_section)
        if services:
            return {"enabled_units": sorted(services)}

        return {"enabled_units": []}


# ---------------------------------------------------------------------------
# Helper (module-private)
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
