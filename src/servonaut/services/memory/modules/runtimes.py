"""Runtimes module prober — detects installed language runtimes and versions.

Allowlisted commands:
  - node -v 2>/dev/null
  - python3 -V 2>/dev/null
  - php -v 2>/dev/null | head -1
  - ruby -v 2>/dev/null
  - go version 2>/dev/null

TTL: 7 days.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .base import ModuleProber

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------

_TTL_7_DAYS = 7 * 86400

# Runtime name → regex that matches the version line emitted by the command.
# Each pattern captures the version string in group 1.
_RUNTIME_PATTERNS: Dict[str, re.Pattern] = {
    "node": re.compile(r"(v\d+\.\d+\.\d+)"),
    "python": re.compile(r"(Python\s+\d+\.\d+(?:\.\d+)?)"),
    "php": re.compile(r"(PHP\s+\d+\.\d+\.\d+[^\s]*)"),
    "ruby": re.compile(r"(ruby\s+\d+\.\d+\.\d+[^\s]*)"),
    "go": re.compile(r"(go\d+\.\d+(?:\.\d+)?)"),
}

# Map runtime name → the command whose output contains it.
_RUNTIME_CMD_MARKERS: Dict[str, str] = {
    "node": "node -v 2>/dev/null",
    "python": "python3 -V 2>/dev/null",
    "php": "php -v 2>/dev/null | head -1",
    "ruby": "ruby -v 2>/dev/null",
    "go": "go version 2>/dev/null",
}


class RuntimesProber(ModuleProber):
    """Detect installed runtimes (Node, Python, PHP, Ruby, Go) and their versions."""

    name = "runtimes"
    ttl_seconds = _TTL_7_DAYS

    def __init__(self) -> None:
        super().__init__(requires_sudo=False, sudo_optional=False)

    def _commands(self) -> List[str]:
        return list(_RUNTIME_CMD_MARKERS.values())

    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Extract runtime versions from aggregated command output.

        Returns:
            Dict with keys ``node``, ``python``, ``php``, ``ruby``, ``go``.
            Each value is the version string or ``None`` if not installed.
        """
        observed: Dict[str, Optional[str]] = {
            "node": None,
            "python": None,
            "php": None,
            "ruby": None,
            "go": None,
        }

        for runtime, cmd_marker in _RUNTIME_CMD_MARKERS.items():
            section = _extract_section(raw_output, cmd_marker)
            if not section or section.startswith("<"):
                continue
            match = _RUNTIME_PATTERNS[runtime].search(section)
            if match:
                observed[runtime] = match.group(1)

        return observed


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
