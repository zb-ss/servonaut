"""Web stack module prober — detects nginx/apache versions and enabled sites.

Allowlisted commands:
  - nginx -v 2>&1
  - apache2 -v 2>/dev/null || httpd -v 2>/dev/null
  - ls /etc/nginx/sites-enabled/ 2>/dev/null
  - ls /etc/apache2/sites-enabled/ 2>/dev/null

Note: Only version strings and site-enabled directory listings are collected.
Config file contents are NOT read.

TTL: 1 day.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .base import ModuleProber

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------

_TTL_1_DAY = 86400

# nginx -v emits "nginx version: nginx/1.24.0" on stderr (redirected to stdout
# via 2>&1).
_NGINX_VERSION_RE = re.compile(r"nginx/(\S+)")

# apache2/httpd -v emits "Server version: Apache/2.4.58 ..."
_APACHE_VERSION_RE = re.compile(r"Apache/(\S+)")

_CMD_NGINX_VERSION = "nginx -v 2>&1"
_CMD_APACHE_VERSION = "apache2 -v 2>/dev/null || httpd -v 2>/dev/null"
_CMD_NGINX_SITES = "ls /etc/nginx/sites-enabled/ 2>/dev/null"
_CMD_APACHE_SITES = "ls /etc/apache2/sites-enabled/ 2>/dev/null"


class WebStackProber(ModuleProber):
    """Detect nginx/apache installation and enabled virtual-host sites.

    Only the version string and the site-enabled listing are captured.
    Config file contents are never read.
    """

    name = "web_stack"
    ttl_seconds = _TTL_1_DAY

    def __init__(self) -> None:
        super().__init__(requires_sudo=False, sudo_optional=False)

    def _commands(self) -> List[str]:
        return [
            _CMD_NGINX_VERSION,
            _CMD_APACHE_VERSION,
            _CMD_NGINX_SITES,
            _CMD_APACHE_SITES,
        ]

    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Extract web server versions and enabled site lists.

        Returns:
            Dict with keys:
            - ``nginx``: version string like ``"nginx/1.24.0"`` or ``None``.
            - ``apache``: version string like ``"Apache/2.4.58"`` or ``None``.
            - ``nginx_sites_enabled``: list of site names or ``[]``.
            - ``apache_sites_enabled``: list of site names or ``[]``.
        """
        nginx_version: Optional[str] = None
        apache_version: Optional[str] = None

        nginx_v_section = _extract_section(raw_output, _CMD_NGINX_VERSION)
        m = _NGINX_VERSION_RE.search(nginx_v_section)
        if m:
            nginx_version = f"nginx/{m.group(1)}"

        apache_v_section = _extract_section(raw_output, _CMD_APACHE_VERSION)
        m = _APACHE_VERSION_RE.search(apache_v_section)
        if m:
            apache_version = f"Apache/{m.group(1)}"

        nginx_sites_section = _extract_section(raw_output, _CMD_NGINX_SITES)
        nginx_sites = _parse_ls_output(nginx_sites_section)

        apache_sites_section = _extract_section(raw_output, _CMD_APACHE_SITES)
        apache_sites = _parse_ls_output(apache_sites_section)

        return {
            "nginx": nginx_version,
            "apache": apache_version,
            "nginx_sites_enabled": nginx_sites,
            "apache_sites_enabled": apache_sites,
        }


# ---------------------------------------------------------------------------
# Helpers (module-private)
# ---------------------------------------------------------------------------

def _parse_ls_output(section: str) -> List[str]:
    """Parse ``ls`` output into a list of file/dir names.

    Skips error lines (prefixed with ``<``) and blank lines.
    """
    lines = [
        line.strip()
        for line in section.splitlines()
        if line.strip() and not line.strip().startswith("<")
    ]
    return lines


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
