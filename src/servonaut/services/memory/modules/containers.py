"""Containers module prober — detects Docker/Podman/Kubernetes presence.

Allowlisted commands:
  - docker --version 2>/dev/null
  - docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null
  - podman --version 2>/dev/null
  - podman ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null
  - kubectl version --client -o json 2>/dev/null

When ``docker ps`` fails with a permission error (daemon requires root),
the prober still emits the version string if available and marks
``docker_running`` as ``False`` without raising.

TTL: 30 minutes — container state changes frequently.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from .base import ModuleProber

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------

_TTL_30_MIN = 30 * 60

# Version regex: Docker/Podman emit "Docker version 25.0.3, build ..." etc.
_DOCKER_VERSION_RE = re.compile(r"Docker\s+version\s+(\S+?)[,\s]", re.IGNORECASE)
_PODMAN_VERSION_RE = re.compile(r"podman\s+version\s+(\S+)", re.IGNORECASE)

# Permission-denied markers from the docker/podman CLIs.
_PERMISSION_DENIED_MARKERS = (
    "permission denied",
    "cannot connect to the docker daemon",
    "dial unix",
)

_CMD_DOCKER_VERSION = "docker --version 2>/dev/null"
_CMD_DOCKER_PS = (
    "docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null"
)
_CMD_PODMAN_VERSION = "podman --version 2>/dev/null"
_CMD_PODMAN_PS = (
    "podman ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null"
)
_CMD_KUBECTL_VERSION = "kubectl version --client -o json 2>/dev/null"


class ContainersProber(ModuleProber):
    """Detect Docker / Podman / kubectl installation and running containers."""

    name = "containers"
    ttl_seconds = _TTL_30_MIN

    def __init__(self) -> None:
        super().__init__(requires_sudo=False, sudo_optional=False)

    def _commands(self) -> List[str]:
        return [
            _CMD_DOCKER_VERSION,
            _CMD_DOCKER_PS,
            _CMD_PODMAN_VERSION,
            _CMD_PODMAN_PS,
            _CMD_KUBECTL_VERSION,
        ]

    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Parse installed runtimes and their running containers."""
        docker_version = _first_match(_DOCKER_VERSION_RE, _extract_section(raw_output, _CMD_DOCKER_VERSION))
        podman_version = _first_match(_PODMAN_VERSION_RE, _extract_section(raw_output, _CMD_PODMAN_VERSION))

        docker_section = _extract_section(raw_output, _CMD_DOCKER_PS)
        podman_section = _extract_section(raw_output, _CMD_PODMAN_PS)

        docker_containers = _parse_ps_output(docker_section)
        docker_running = (
            docker_version is not None
            and not _has_permission_error(docker_section)
        )
        podman_containers = _parse_ps_output(podman_section)

        k8s_client_version = _parse_kubectl_client_version(
            _extract_section(raw_output, _CMD_KUBECTL_VERSION)
        )

        return {
            "docker_running": docker_running,
            "docker_version": docker_version,
            "docker_containers": docker_containers,
            "podman_version": podman_version,
            "podman_containers": podman_containers,
            "k8s_client_version": k8s_client_version,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ps_output(section: str) -> List[Dict[str, str]]:
    """Parse ``docker/podman ps`` pipe-delimited rows into dicts.

    Rows with a permission-denied error are treated as "no containers" rather
    than being surfaced as truthy data.
    """
    if not section or _has_permission_error(section):
        return []
    containers: List[Dict[str, str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("<"):
            continue
        parts = stripped.split("|")
        if len(parts) < 3:
            continue
        containers.append({
            "name": parts[0].strip(),
            "image": parts[1].strip(),
            "status": parts[2].strip(),
        })
    return containers


def _has_permission_error(section: str) -> bool:
    """Return True if the section contains a permission-denied marker."""
    lowered = section.lower()
    return any(marker in lowered for marker in _PERMISSION_DENIED_MARKERS)


def _parse_kubectl_client_version(section: str) -> Optional[str]:
    """Extract the client Git version from ``kubectl version --client -o json``.

    Returns the ``gitVersion`` string (e.g. ``"v1.29.2"``) when available,
    otherwise ``None``.  Handles both the modern schema (``clientVersion.gitVersion``)
    and the legacy schema (top-level ``gitVersion``).
    """
    if not section or section.startswith("<"):
        return None
    try:
        data = json.loads(section)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    client = data.get("clientVersion")
    if isinstance(client, dict):
        version = client.get("gitVersion")
        if isinstance(version, str) and version:
            return version
    top_version = data.get("gitVersion")
    if isinstance(top_version, str) and top_version:
        return top_version
    return None


def _first_match(pattern: re.Pattern, section: str) -> Optional[str]:
    """Return ``group(1)`` of the first match or ``None``."""
    if not section:
        return None
    m = pattern.search(section)
    return m.group(1) if m else None


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
