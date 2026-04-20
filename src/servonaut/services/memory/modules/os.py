"""OS module prober — collects OS identity and kernel information.

Allowlisted commands:
  - cat /etc/os-release
  - uname -rma

TTL: 30 days (OS changes only on major upgrades).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .base import ModuleProber

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------

_TTL_30_DAYS = 30 * 86400

# Regex to extract key=value pairs from /etc/os-release.
_OS_RELEASE_RE = re.compile(r'^([A-Z_]+)="?([^"\n]*)"?\s*$', re.MULTILINE)


class OSProber(ModuleProber):
    """Probe OS identity and kernel information.

    Parses ``/etc/os-release`` for distribution metadata and ``uname -rma``
    for kernel version, architecture, and machine type.
    """

    name = "os"
    ttl_seconds = _TTL_30_DAYS

    def __init__(self) -> None:
        super().__init__(requires_sudo=False, sudo_optional=False)

    def _commands(self) -> List[str]:
        return [
            "cat /etc/os-release",
            "uname -rma",
        ]

    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Extract OS and kernel facts from aggregated command output.

        Returns:
            Dict with keys: ``id``, ``pretty_name``, ``version_id``,
            ``kernel``, ``arch``, ``machine``.
        """
        # Split the raw_output back into per-command sections.
        os_release_section = self._extract_section(raw_output, "cat /etc/os-release")
        uname_section = self._extract_section(raw_output, "uname -rma")

        # Parse /etc/os-release key=value pairs.
        os_release_data: Dict[str, str] = {}
        for match in _OS_RELEASE_RE.finditer(os_release_section):
            os_release_data[match.group(1)] = match.group(2)

        # Parse uname -rma output: kernel release, machine, arch, OS
        # Format: <kernel> <nodename> <release> <version> <machine> <os>
        # Example: 5.15.0-91-generic x86_64 x86_64 x86_64 GNU/Linux
        kernel: Optional[str] = None
        arch: Optional[str] = None
        machine: Optional[str] = None
        uname_line = uname_section.strip().splitlines()[0].strip() if uname_section.strip() else ""
        if uname_line and not uname_line.startswith("<"):
            parts = uname_line.split()
            if parts:
                kernel = parts[0]  # kernel release (e.g. 5.15.0-91-generic)
            # uname -rma: release, machine, processor, hw-platform, os
            # Actual field order varies; pick last-to-first for arch
            if len(parts) >= 2:
                # The architecture is typically the second-to-last or last
                # meaningful field.  On Linux, parts[-2] is the machine type.
                machine = parts[-1] if len(parts) >= 1 else None  # OS name
                # arch: processor field (index 2 from uname -rma)
                if len(parts) >= 3:
                    arch = parts[1]  # machine type

        return {
            "id": os_release_data.get("ID"),
            "pretty_name": os_release_data.get("PRETTY_NAME"),
            "version_id": os_release_data.get("VERSION_ID"),
            "kernel": kernel,
            "arch": arch,
            "machine": machine,
        }

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_section(raw_output: str, cmd_prefix: str) -> str:
        """Extract the stdout block for *cmd_prefix* from *raw_output*.

        The base class formats raw_output as ``"<cmd> →\\n<stdout>\\n"``.
        This helper returns only the stdout portion for the given command.
        """
        marker = f"{cmd_prefix} →"
        start = raw_output.find(marker)
        if start == -1:
            return ""
        # Content starts after the marker line.
        content_start = raw_output.find("\n", start)
        if content_start == -1:
            return ""
        content_start += 1  # skip the newline after the marker

        # Find the next command marker or end of string.
        next_marker = raw_output.find(" →\n", content_start)
        if next_marker == -1:
            return raw_output[content_start:]

        # Walk back to find the newline before the next command header.
        line_start = raw_output.rfind("\n", content_start, next_marker)
        if line_start == -1:
            return raw_output[content_start:next_marker]
        return raw_output[content_start:line_start]
