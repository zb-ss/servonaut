"""Discover database credentials from app config (.env, DATABASE_URL, etc.).

Backs ``db_setup_scan`` / the ``servonaut db setup`` CLI. The goal is to make
the DB introspection tools (db_processlist / db_top_queries) usable with zero
manual config: read the credentials the app already has — usually in a ``.env``
or ``wp-config.php`` on the managed box — and stage them so the operator can
commit them to the secret store with one confirmation.

CRITICAL SECURITY CONTRACT:
- This module PARSES text into :class:`DBCandidate` objects (plaintext password
  in-process only). The tool layer holds candidates in a SERVER-SIDE staging
  area and returns only :func:`redact` previews to the agent. The plaintext
  password must NEVER be placed in a tool result / model context — agents relay
  context to their model provider, which may log it.
- All file access is READ-ONLY (the on-box command uses ``find`` + ``sed -n``).

Parsing is pure and IO-free so it's unit-testable; the SSH round-trip / local
file read is done by the caller and the raw text handed in here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse, unquote

# Marker the on-box command prints before each file's contents.
FILE_MARKER = "===FILE:"

# Default port per engine.
_DEFAULT_PORT = {"mysql": 3306, "mariadb": 3306, "postgres": 5432, "postgresql": 5432}

# DATABASE_URL scheme → engine.
_SCHEME_ENGINE = {
    "mysql": "mysql", "mysql2": "mysql", "mariadb": "mysql",
    "postgres": "postgres", "postgresql": "postgres", "pgsql": "postgres",
}


@dataclass
class DBCandidate:
    """A discovered DB connection. ``password`` is plaintext — never serialize
    it into a tool result; only :func:`redact` it."""
    engine: str
    host: str
    port: int
    user: str
    password: str
    database: str = ""
    source: str = ""

    def is_usable(self) -> bool:
        # We're collecting the password; without it the profile would rely on
        # socket/trust auth and wouldn't need scanning anyway.
        return bool(self.password and self.host and self.user)


def redact(candidate: DBCandidate) -> Dict[str, object]:
    """Model-safe preview of a candidate (password masked)."""
    pw = candidate.password or ""
    if len(pw) <= 4:
        masked = "****"
    else:
        masked = "****" + pw[-3:]
    return {
        "engine": candidate.engine,
        "host": candidate.host,
        "port": candidate.port,
        "user": candidate.user,
        "database": candidate.database,
        "password_preview": masked,
        "source": candidate.source,
        # App/site label derived from the config path — the discriminator when
        # one instance hosts several DBs. "" for a single/default DB.
        "label": derive_app_label(candidate.source),
    }


def _strip(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return value


# Directory names that are framework/deploy scaffolding rather than the app's
# own identity — skipped when deriving a site label from a config path.
_LABEL_SKIP_DIRS = frozenset({
    "", "html", "public", "public_html", "htdocs", "web", "www", "current",
    "releases", "shared", "app", "src", "sites", "site", "wp-content",
    "config", "etc", "conf", "var", "srv", "opt", "home", "usr", "share",
    "nginx", "apache2", "httpd", "vhosts", "domains",
})

# The config filenames the scanner looks for — stripped off a path before we
# reach for the containing directory as the site label.
_LABEL_STRIP_FILES = frozenset({
    "configuration.php", "wp-config.php", "env.php", ".env", ".env.local",
    ".env.production", ".env.dev", ".env.staging",
})


def derive_app_label(source_path: str) -> str:
    """Derive a human-meaningful app/site label from a config file path.

    On a shared box each site's config lives under its own directory — often
    the domain (``/var/www/shop.example.com/.env``) or an app name
    (``/home/deploy/blog/current/.env``). This picks the most identifying
    path segment, preferring a domain-looking one, and skips framework/deploy
    scaffolding dirs (html, public, current, releases, …).

    Returns "" when nothing meaningful can be derived (e.g. a single site at a
    bare web root) — callers fall back to the unlabelled default.
    """
    if not source_path:
        return ""
    # Normalise + split; drop the trailing config filename if present.
    parts = [p for p in source_path.replace("\\", "/").split("/") if p]
    if parts and parts[-1].lower() in _LABEL_STRIP_FILES:
        parts = parts[:-1]
    if not parts:
        return ""
    # First choice: a segment that looks like a domain (has a dot, not just a
    # file extension) — walk deepest-first so the most specific wins.
    for seg in reversed(parts):
        low = seg.lower()
        if low in _LABEL_SKIP_DIRS:
            continue
        if "." in seg and not seg.startswith("."):
            return seg
    # Second choice: the deepest non-scaffolding directory name.
    for seg in reversed(parts):
        if seg.lower() not in _LABEL_SKIP_DIRS:
            return seg
    return ""


def sanitize_label(label: str) -> str:
    """Make a label safe for a secret name segment (no slashes/spaces)."""
    out = "".join(
        c if (c.isalnum() or c in ".-_") else "-" for c in (label or "").strip()
    )
    return out.strip("-").lower()


def _parse_dotenv(text: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.lower().startswith("export "):
            line = line[7:]
        key, _, val = line.partition("=")
        env[key.strip()] = _strip(val)
    return env


def _from_database_url(url: str, source: str) -> Optional[DBCandidate]:
    try:
        p = urlparse(url)
    except ValueError:
        return None
    engine = _SCHEME_ENGINE.get((p.scheme or "").lower())
    if not engine or not p.hostname:
        return None
    return DBCandidate(
        engine=engine,
        host=p.hostname,
        port=p.port or _DEFAULT_PORT.get(engine, 3306),
        user=unquote(p.username or "") or "root",
        password=unquote(p.password or ""),
        database=(p.path or "").lstrip("/"),
        source=source,
    )


def _from_dotenv_fields(env: Dict[str, str], source: str) -> Optional[DBCandidate]:
    # 1. Explicit DATABASE_URL (Rails / Node / generic) wins.
    for key in ("DATABASE_URL", "DB_URL", "DATABASE_DSN"):
        if env.get(key):
            cand = _from_database_url(env[key], source)
            if cand:
                return cand

    # 2. Laravel / framework DB_* fields.
    if env.get("DB_PASSWORD") or env.get("DB_USERNAME") or env.get("DB_HOST"):
        conn = (env.get("DB_CONNECTION") or "mysql").lower()
        engine = "postgres" if conn.startswith("pg") or conn == "postgres" else "mysql"
        return DBCandidate(
            engine=engine,
            host=env.get("DB_HOST", "127.0.0.1") or "127.0.0.1",
            port=int(env["DB_PORT"]) if env.get("DB_PORT", "").isdigit()
            else _DEFAULT_PORT.get(engine, 3306),
            user=env.get("DB_USERNAME", "") or env.get("DB_USER", "") or "root",
            password=env.get("DB_PASSWORD", ""),
            database=env.get("DB_DATABASE", "") or env.get("DB_NAME", ""),
            source=source,
        )

    # 3. docker-compose style POSTGRES_* / MYSQL_*.
    if env.get("POSTGRES_PASSWORD"):
        return DBCandidate(
            engine="postgres", host=env.get("POSTGRES_HOST", "127.0.0.1"),
            port=int(env["POSTGRES_PORT"]) if env.get("POSTGRES_PORT", "").isdigit() else 5432,
            user=env.get("POSTGRES_USER", "postgres"),
            password=env["POSTGRES_PASSWORD"],
            database=env.get("POSTGRES_DB", ""), source=source,
        )
    if env.get("MYSQL_PASSWORD") or env.get("MYSQL_ROOT_PASSWORD"):
        return DBCandidate(
            engine="mysql", host=env.get("MYSQL_HOST", "127.0.0.1"),
            port=int(env["MYSQL_PORT"]) if env.get("MYSQL_PORT", "").isdigit() else 3306,
            user=env.get("MYSQL_USER", "root"),
            password=env.get("MYSQL_PASSWORD") or env.get("MYSQL_ROOT_PASSWORD", ""),
            database=env.get("MYSQL_DATABASE", ""), source=source,
        )
    return None


_WP_DEFINE_RE = re.compile(
    r"""define\(\s*['"](DB_[A-Z]+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""",
)

# Joomla configuration.php: `public $host = 'localhost';` etc.
_JOOMLA_RE = re.compile(r"""public\s+\$(\w+)\s*=\s*['"]([^'"]*)['"]""")


def _split_host_port(host: str, default_port: int) -> tuple:
    host = host or "localhost"
    if ":" in host:
        h, _, p = host.partition(":")
        return (h or "127.0.0.1"), (int(p) if p.isdigit() else default_port)
    return host, default_port


def _from_joomla(text: str, source: str) -> Optional[DBCandidate]:
    found = {m.group(1): m.group(2) for m in _JOOMLA_RE.finditer(text)}
    # Joomla's JConfig always defines $password together with $db/$dbtype —
    # require that combo so we don't misfire on an unrelated `public $password`.
    if "password" not in found or not ("db" in found or "dbtype" in found):
        return None
    dbtype = (found.get("dbtype", "mysqli") or "mysqli").lower()
    engine = "postgres" if ("pgsql" in dbtype or "postgre" in dbtype) else "mysql"
    port = int(found["dbport"]) if found.get("dbport", "").isdigit() \
        else _DEFAULT_PORT.get(engine, 3306)
    host, port = _split_host_port(found.get("host", "localhost"), port)
    return DBCandidate(
        engine=engine, host=host, port=port,
        user=found.get("user", "") or "root",
        password=found.get("password", ""),
        database=found.get("db", ""), source=source,
    )


def _from_magento(text: str, source: str) -> Optional[DBCandidate]:
    # Magento app/etc/env.php — nested PHP array. Grab the first occurrence of
    # each connection key (the 'default' connection appears first).
    def grab(key: str) -> str:
        m = re.search(r"'%s'\s*=>\s*'([^']*)'" % key, text)
        return m.group(1) if m else ""

    pw, user = grab("password"), grab("username")
    if not pw and not user:
        return None
    host, port = _split_host_port(grab("host") or "localhost", 3306)
    return DBCandidate(
        engine="mysql", host=host, port=port, user=user or "root",
        password=pw, database=grab("dbname"), source=source,
    )


def _from_wp_config(text: str, source: str) -> Optional[DBCandidate]:
    found = {m.group(1): m.group(2) for m in _WP_DEFINE_RE.finditer(text)}
    if not found.get("DB_PASSWORD") and not found.get("DB_USER"):
        return None
    host = found.get("DB_HOST", "localhost") or "localhost"
    port = 3306
    if ":" in host:
        host, _, p = host.partition(":")
        if p.isdigit():
            port = int(p)
    return DBCandidate(
        engine="mysql", host=host or "127.0.0.1", port=port,
        user=found.get("DB_USER", "root"), password=found.get("DB_PASSWORD", ""),
        database=found.get("DB_NAME", ""), source=source,
    )


class DBCredentialScanner:
    """Parse app-config text into staged DB credential candidates."""

    # Read-only one-liner: find common config files under the search roots and
    # print each prefixed by a FILE marker. `sed -n` never writes.
    @staticmethod
    def build_scan_command(search_path: str = "") -> str:
        # Web apps nest deep on shared hosts (e.g. /home/<user>/<domain>/
        # <sub>/html/configuration.php), so search to depth 7. Known DB-config
        # filenames across stacks: dotenv, WordPress, Joomla (configuration.php),
        # Magento (app/etc/env.php). Config files are listed first so they're
        # never truncated by the line cap when many .env files exist.
        roots = search_path.strip() or ". /var/www /srv /home /opt /usr/share/nginx"
        names = (
            "\\( -name configuration.php -o -name wp-config.php -o -name env.php "
            "-o -name .env -o -name .env.local -o -name .env.production \\)"
        )
        return (
            f'for d in {roots}; do '
            f'find "$d" -maxdepth 7 -type f {names} 2>/dev/null; '
            f'done | head -60 | while read f; do '
            f'echo "{FILE_MARKER}$f==="; sed -n "1,250p" "$f"; done'
        )

    def parse(self, raw: str) -> List[DBCandidate]:
        """Parse the on-box / local scan output into usable candidates."""
        candidates: List[DBCandidate] = []
        for source, text in self._split_files(raw).items():
            cand = self._parse_one(text, source)
            if cand and cand.is_usable():
                candidates.append(cand)
        # De-dup identical (host,user,db) — same secret found in two files.
        seen = set()
        unique: List[DBCandidate] = []
        for c in candidates:
            key = (c.engine, c.host, c.port, c.user, c.database)
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique

    def parse_text(self, text: str, source: str) -> List[DBCandidate]:
        """Parse a single file's contents (local-path mode)."""
        cand = self._parse_one(text, source)
        return [cand] if cand and cand.is_usable() else []

    def _parse_one(self, text: str, source: str) -> Optional[DBCandidate]:
        low = source.lower()
        # Joomla configuration.php (JConfig) — check before dotenv since the
        # file is PHP and would otherwise be misread as KEY=VALUE.
        if low.endswith("configuration.php") or (
            "public $password" in text and ("public $db" in text or "public $dbtype" in text)
        ):
            j = _from_joomla(text, source)
            if j:
                return j
        # Magento app/etc/env.php.
        if low.endswith("env.php") or ("'connection'" in text and "'password'" in text):
            mg = _from_magento(text, source)
            if mg:
                return mg
        if "wp-config" in low or ("define(" in text and "DB_NAME" in text):
            wp = _from_wp_config(text, source)
            if wp:
                return wp
        env = _parse_dotenv(text)
        if env:
            return _from_dotenv_fields(env, source)
        return None

    def _split_files(self, raw: str) -> Dict[str, List[str]]:
        sections: Dict[str, str] = {}
        current = None
        buf: List[str] = []
        for line in raw.splitlines():
            if line.startswith(FILE_MARKER):
                if current is not None:
                    sections[current] = "\n".join(buf)
                current = line[len(FILE_MARKER):].rstrip("=").strip()
                buf = []
            elif current is not None:
                buf.append(line)
        if current is not None:
            sections[current] = "\n".join(buf)
        return sections
