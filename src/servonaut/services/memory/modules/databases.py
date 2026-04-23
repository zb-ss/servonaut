"""Databases module prober — detects installed database engines and listening ports.

Allowlisted commands:
  - mysql --version 2>/dev/null
  - mariadb --version 2>/dev/null
  - psql --version 2>/dev/null
  - pg_lsclusters 2>/dev/null
  - redis-server --version 2>/dev/null
  - mongod --version 2>/dev/null
  - ss -tln 2>/dev/null

``ss -tln`` is the non-privileged fallback (no process names).  When sudo
is available callers may override with ``ss -tlnp`` via the allowlist, but
this prober deliberately sticks to the unprivileged variant so it never
needs sudo and is safe under the default guard level.

TTL: 1 day (installed databases rarely change).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .base import ModuleProber

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------

_TTL_1_DAY = 86400

# Ports we care about, mapped to their canonical service name.
_DB_PORTS: Dict[str, str] = {
    "3306": "mysql",
    "5432": "postgres",
    "27017": "mongodb",
    "6379": "redis",
    "9042": "cassandra",
    "11211": "memcached",
    "5984": "couchdb",
}

# Version regexes — each captures group(1) as the version string.
_MYSQL_RE = re.compile(r"mysql\s+Ver\s+(\S+)", re.IGNORECASE)
_MARIADB_RE = re.compile(r"mariadb\s+Ver\s+(\S+)", re.IGNORECASE)
_PSQL_RE = re.compile(r"psql\s+\(PostgreSQL\)\s+(\S+)", re.IGNORECASE)
_REDIS_RE = re.compile(r"Redis\s+server\s+v=(\S+)", re.IGNORECASE)
_MONGOD_RE = re.compile(r"db\s+version\s+v?(\S+)", re.IGNORECASE)

# Line format for `pg_lsclusters`: "16  main  5432  online  postgres  /var/lib/...".
_PG_CLUSTER_RE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+(\d+)\s+(\S+)",
    re.MULTILINE,
)

# Listen line from `ss -tln`:
#   LISTEN 0  128  127.0.0.1:3306  0.0.0.0:*
# We extract only the local address:port (4th column after splitting on whitespace).
_SS_LISTEN_RE = re.compile(
    r"^LISTEN\s+\d+\s+\d+\s+\S+?:(\d+)\s+",
    re.MULTILINE,
)

_CMD_MYSQL = "mysql --version 2>/dev/null"
_CMD_MARIADB = "mariadb --version 2>/dev/null"
_CMD_PSQL = "psql --version 2>/dev/null"
_CMD_PG_LS = "pg_lsclusters 2>/dev/null"
_CMD_REDIS = "redis-server --version 2>/dev/null"
_CMD_MONGOD = "mongod --version 2>/dev/null"
_CMD_SS = "ss -tln 2>/dev/null"


class DatabasesProber(ModuleProber):
    """Detect installed database engines and listening database ports."""

    name = "databases"
    ttl_seconds = _TTL_1_DAY

    def __init__(self) -> None:
        super().__init__(requires_sudo=False, sudo_optional=False)

    def _commands(self) -> List[str]:
        return [
            _CMD_MYSQL,
            _CMD_MARIADB,
            _CMD_PSQL,
            _CMD_PG_LS,
            _CMD_REDIS,
            _CMD_MONGOD,
            _CMD_SS,
        ]

    def _parse(self, raw_output: str) -> Dict[str, Any]:
        """Extract installed engines and listening DB ports.

        Returns:
            Dict with the Module Catalog keys.  Missing engines are ``None``;
            ``postgres_clusters`` and ``open_db_ports`` are lists (empty when none).
        """
        mysql_version = _first_match(_MYSQL_RE, _extract_section(raw_output, _CMD_MYSQL))
        mariadb_version = _first_match(_MARIADB_RE, _extract_section(raw_output, _CMD_MARIADB))
        postgres_version = _first_match(_PSQL_RE, _extract_section(raw_output, _CMD_PSQL))
        redis_version = _first_match(_REDIS_RE, _extract_section(raw_output, _CMD_REDIS))
        mongodb_version = _first_match(_MONGOD_RE, _extract_section(raw_output, _CMD_MONGOD))

        # Parse pg_lsclusters — list of {version, cluster, port, status}.
        postgres_clusters: List[Dict[str, Any]] = []
        pg_section = _extract_section(raw_output, _CMD_PG_LS)
        for match in _PG_CLUSTER_RE.finditer(pg_section):
            # Skip the column header row (``Ver Cluster Port Status Owner ...``).
            version_token = match.group(1)
            if not version_token.isdigit():
                continue
            postgres_clusters.append({
                "version": version_token,
                "cluster": match.group(2),
                "port": int(match.group(3)),
                "status": match.group(4),
            })

        # Parse ss -tln — collect listening ports we recognise as DB ports.
        ss_section = _extract_section(raw_output, _CMD_SS)
        open_db_ports: List[str] = []
        seen_ports: set = set()
        for match in _SS_LISTEN_RE.finditer(ss_section):
            port = match.group(1)
            if port in _DB_PORTS and port not in seen_ports:
                seen_ports.add(port)
                open_db_ports.append(f"{port}:{_DB_PORTS[port]}")
        open_db_ports.sort()

        return {
            "mysql_version": mysql_version,
            "mariadb_version": mariadb_version,
            "postgres_version": postgres_version,
            "postgres_clusters": postgres_clusters,
            "redis_version": redis_version,
            "mongodb_version": mongodb_version,
            "open_db_ports": open_db_ports,
        }


# ---------------------------------------------------------------------------
# Helpers (module-private)
# ---------------------------------------------------------------------------

def _first_match(pattern: re.Pattern, section: str) -> Optional[str]:
    """Return ``group(1)`` of the first match, or ``None``."""
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
