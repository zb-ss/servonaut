"""Network module prober — listening ports and firewall configuration snapshot.

Allowlisted commands:
  - ss -tln 2>/dev/null
  - iptables -S 2>/dev/null
  - ufw status 2>/dev/null

Only non-privileged variants are used so the prober works under the default
guard level without sudo.  When commands return permission errors they are
quietly dropped and flagged via truncation/partial semantics of the base
class (we never raise).

TTL: 1 day — listening sockets and firewall rules change infrequently.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import ModuleProber

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------

_TTL_1_DAY = 86400

# How many rows to keep per list (keeps JSON + summary bounded).
_MAX_SOCKETS = 50
_MAX_IPTABLES_RULES = 50

_CMD_SS = "ss -tln 2>/dev/null"
_CMD_IPTABLES = "iptables -S 2>/dev/null"
_CMD_UFW = "ufw status 2>/dev/null"

# `ss -tln` sample row:
#   LISTEN 0  128  127.0.0.1:3306  0.0.0.0:*
# We extract the port from the 4th whitespace-separated column (local address).
_SS_LISTEN_RE = re.compile(
    r"^LISTEN\s+\d+\s+\d+\s+(\S+?):(\d+)\s+",
    re.MULTILINE,
)

# UFW status header: "Status: active" or "Status: inactive".
_UFW_STATUS_RE = re.compile(r"Status:\s+(active|inactive)", re.IGNORECASE)


class NetworkProber(ModuleProber):
    """Snapshot listening sockets and firewall state (non-privileged only)."""

    name = "network"
    ttl_seconds = _TTL_1_DAY

    def __init__(self) -> None:
        super().__init__(requires_sudo=False, sudo_optional=False)

    def _commands(self) -> List[str]:
        return [_CMD_SS, _CMD_IPTABLES, _CMD_UFW]

    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Extract listening sockets and firewall rules from aggregated output."""
        ss_section = _extract_section(raw_output, _CMD_SS)
        sockets: List[str] = []
        seen: set = set()
        for match in _SS_LISTEN_RE.finditer(ss_section):
            host, port = match.group(1), match.group(2)
            key = f"{host}:{port}"
            if key in seen:
                continue
            seen.add(key)
            sockets.append(f"{port}:{host}")
            if len(sockets) >= _MAX_SOCKETS:
                break
        sockets.sort()

        iptables_section = _extract_section(raw_output, _CMD_IPTABLES)
        iptables_rules: List[str] = []
        for line in iptables_section.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("<"):
                continue
            if not stripped.startswith("-"):
                # Skip stray headers / error output.
                continue
            iptables_rules.append(stripped)
            if len(iptables_rules) >= _MAX_IPTABLES_RULES:
                break

        ufw_section = _extract_section(raw_output, _CMD_UFW)
        ufw_match = _UFW_STATUS_RE.search(ufw_section)
        if ufw_match:
            ufw_status = ufw_match.group(1).lower()
        elif ufw_section.strip() and not ufw_section.strip().startswith("<"):
            ufw_status = "unknown"
        else:
            ufw_status = "unknown"

        return {
            "listening_sockets": sockets,
            "iptables_rules": iptables_rules,
            "ufw_status": ufw_status,
        }


# ---------------------------------------------------------------------------
# Helpers
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
