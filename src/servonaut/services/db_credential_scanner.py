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

# Any config filename the scanner reads (dotenv variants, PHP configs, and
# compose YAML) — stripped off a path before deriving the site label so a
# ``.../shop.example.com/compose.prod.yaml`` labels as ``shop.example.com``,
# not ``compose.prod.yaml``.
_CONFIG_FILE_RE = re.compile(
    r"^(\.env(\..+)?|.*\.ya?ml|configuration\.php|wp-config\.php|env\.php)$",
    re.IGNORECASE,
)


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
    if parts and (parts[-1].lower() in _LABEL_STRIP_FILES
                  or _CONFIG_FILE_RE.match(parts[-1])):
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


def _dsn_keys(env: Dict[str, str]) -> List[str]:
    """URL/DSN keys to try, in priority order.

    Beyond the canonical ``DATABASE_URL`` / ``DB_URL`` / ``DATABASE_DSN``, apps
    frequently keep the real credential under an environment-suffixed variant
    (Symfony's ``DATABASE_URL_PROD``, ``DATABASE_URL_STAGING``, …) while the
    committed ``DATABASE_URL`` is a build-time placeholder. Collect every
    URL-ish key so the caller can pick the first that actually carries a
    password; prod-looking variants are tried ahead of the rest.
    """
    explicit = [k for k in ("DATABASE_URL", "DB_URL", "DATABASE_DSN") if env.get(k)]
    variants = [
        k for k in env
        if k not in explicit and env.get(k)
        and (k.startswith("DATABASE_URL") or k.startswith("DB_URL")
             or k.startswith("DATABASE_DSN"))
    ]
    variants.sort(key=lambda k: (0 if "PROD" in k.upper() else 1, k))
    return explicit + variants


def _from_dotenv_fields(env: Dict[str, str], source: str) -> Optional[DBCandidate]:
    # 1. DATABASE_URL (Rails / Node / Symfony / generic) wins — but a committed
    # placeholder with an empty password must not shadow a real *_PROD variant,
    # so try every URL-ish key and prefer the first USABLE (password-bearing)
    # parse. An unusable URL is only returned if nothing else matches.
    url_fallback: Optional[DBCandidate] = None
    for key in _dsn_keys(env):
        cand = _from_database_url(env[key], source)
        if cand is None:
            continue
        if cand.is_usable():
            return cand
        if url_fallback is None:
            url_fallback = cand

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
    # 4. Last resort: an unusable URL (e.g. placeholder) — kept so callers that
    # only want the shape still see it; parse()'s is_usable() filter drops it.
    return url_fallback


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


# ${VAR} / ${VAR:-default} interpolation in a compose file's environment block.
_INTERP_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _resolve_interpolation(value: str, sibling_env: Dict[str, str]) -> Optional[str]:
    """Resolve ``${VAR}`` / ``${VAR:-default}`` against a co-located ``.env``.

    Compose interpolates ``${VAR}`` from the project-root ``.env`` (or the host
    environment). We can only see the former, so resolve from ``sibling_env``,
    fall back to a ``:-default``, and otherwise treat the reference as
    unresolved (return ``None``) — we never invent a secret we can't see.
    """
    if not value or "${" not in value:
        return value
    unresolved = False

    def _repl(m: "re.Match") -> str:
        nonlocal unresolved
        name, default = m.group(1), m.group(2)
        if name in sibling_env:
            return sibling_env[name]
        if default is not None:
            return default
        unresolved = True
        return ""

    out = _INTERP_RE.sub(_repl, value)
    # If ANY referenced variable was unresolvable (no sibling value, no
    # default), drop the whole value rather than keep a partial — a
    # half-blanked string ("prefix-" from "prefix-${MISSING}") would be an
    # invented secret, and we never invent a credential we can't fully see.
    return None if unresolved else out


def _extract_compose_env(text: str) -> Dict[str, str]:
    """Collect KEY=VALUE pairs from every ``environment:`` block in a compose
    file. Handles both list form (``- KEY=VALUE``) and map form (``KEY: VALUE``),
    keyed by indentation. Bare list keys (``- KEY``, value from the host env)
    are skipped — we can't see that value.

    Limitations (acceptable for the common single-db-service layout): every
    service's ``environment:`` block is flattened into one dict, so a file where
    an app service and a db service carry *different* DB creds could mix them;
    and inline flow forms (``environment: {FOO: bar}`` / ``[FOO=bar]``) are not
    parsed — only block form."""
    out: Dict[str, str] = {}
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        # Enter an `environment:` block (with nothing meaningful on the same line).
        if stripped.split("#", 1)[0].rstrip() == "environment:":
            base_indent = len(line) - len(line.lstrip())
            i += 1
            while i < n:
                inner = lines[i]
                if not inner.strip():
                    i += 1
                    continue
                indent = len(inner) - len(inner.lstrip())
                if indent <= base_indent:
                    break  # dedent — block ended
                item = inner.strip()
                if item.startswith("#"):
                    i += 1
                    continue
                if item.startswith("- "):
                    item = item[2:].strip()
                    if "=" in item:
                        k, _, v = item.partition("=")
                        out[k.strip()] = _strip(v.strip())
                    # bare `- KEY` (host-env passthrough) → value unknown, skip.
                elif ":" in item:
                    k, _, v = item.partition(":")
                    out[k.strip()] = _strip(v.strip())
                i += 1
            continue
        i += 1
    return out


def _from_compose(
    text: str, source: str, env_by_dir: Optional[Dict[str, Dict[str, str]]] = None,
) -> Optional[DBCandidate]:
    """Parse a docker-compose file's ``environment:`` blocks into a candidate.

    ``${VAR}`` references are resolved against a ``.env`` in the same directory
    (compose's interpolation source) when one was seen in the same scan; the
    flattened key/value map is then fed through the shared dotenv field logic,
    so MYSQL_* / POSTGRES_* / DATABASE_URL all work identically to a real
    ``.env``."""
    raw_env = _extract_compose_env(text)
    if not raw_env:
        return None
    directory = source.rsplit("/", 1)[0] if "/" in source else ""
    sibling = (env_by_dir or {}).get(directory, {})
    resolved: Dict[str, str] = {}
    for key, val in raw_env.items():
        rv = _resolve_interpolation(val, sibling)
        if rv is not None:
            resolved[key] = rv
    return _from_dotenv_fields(resolved, source)


class DBCredentialScanner:
    """Parse app-config text into staged DB credential candidates."""

    # Read-only one-liner: find common config files under the search roots and
    # print each prefixed by a FILE marker. `sed -n` never writes.
    @staticmethod
    def build_scan_command(search_path: str = "") -> str:
        # Web apps nest deep on shared hosts (e.g. /home/<user>/<domain>/
        # <sub>/html/configuration.php), so search to depth 7. Known DB-config
        # filenames across stacks: dotenv, WordPress, Joomla (configuration.php),
        # Magento (app/etc/env.php), and docker-compose files (dockerised stacks
        # keep DB creds in `environment:` blocks, not always a readable .env).
        roots = search_path.strip() or ". /var/www /srv /home /opt /usr/share/nginx"
        names = (
            "\\( -name configuration.php -o -name wp-config.php -o -name env.php "
            "-o -name .env -o -name .env.local -o -name .env.production "
            "-o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' "
            "-o -name 'compose*.yml' -o -name 'compose*.yaml' \\)"
        )
        # Read via sed; if the file is owned by root/a deploy user and the
        # scanning account can't read it (common for prod .env), fall back to a
        # NON-interactive `sudo -n` read. Both are read-only. If sudo has no
        # NOPASSWD grant, `sudo -n` fails silently and the section is empty —
        # exactly the prior behaviour, so this only ever adds coverage.
        return (
            f'for d in {roots}; do '
            f'find "$d" -maxdepth 7 -type f {names} 2>/dev/null; '
            f'done | head -120 | while read f; do '
            f'echo "{FILE_MARKER}$f==="; '
            f'sed -n "1,400p" "$f" 2>/dev/null '
            f'|| sudo -n sed -n "1,400p" "$f" 2>/dev/null; '
            f'done'
        )

    def parse(self, raw: str) -> List[DBCandidate]:
        """Parse the on-box / local scan output into usable candidates."""
        sections = self._split_files(raw)
        # First pass: index every dotenv by its directory so a compose file can
        # resolve ${VAR} references against the .env compose interpolates from.
        env_by_dir: Dict[str, Dict[str, str]] = {}
        for source, text in sections.items():
            base = source.rsplit("/", 1)[-1].lower()
            if base in (".env", ".env.local", ".env.production", ".env.dev",
                        ".env.staging"):
                directory = source.rsplit("/", 1)[0] if "/" in source else ""
                env_by_dir.setdefault(directory, {}).update(_parse_dotenv(text))
        candidates: List[DBCandidate] = []
        for source, text in sections.items():
            cand = self._parse_one(text, source, env_by_dir)
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
        # A .env and its sibling compose file often describe the SAME connection
        # (compose interpolates ${VAR} from that .env), but one may carry a
        # database name the other lacks — leaving a redundant empty-database
        # twin. Drop an empty-database candidate only when a richer one shares
        # its (engine, host, port, user); distinct non-empty databases on the
        # same host/user (legitimate multi-site) are all preserved.
        conns_with_db = {
            (c.engine, c.host, c.port, c.user) for c in unique if c.database
        }
        return [
            c for c in unique
            if c.database
            or (c.engine, c.host, c.port, c.user) not in conns_with_db
        ]

    def parse_text(self, text: str, source: str) -> List[DBCandidate]:
        """Parse a single file's contents (local-path mode)."""
        cand = self._parse_one(text, source)
        return [cand] if cand and cand.is_usable() else []

    def _parse_one(
        self, text: str, source: str,
        env_by_dir: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> Optional[DBCandidate]:
        low = source.lower()
        # docker-compose / compose YAML — DB creds live in `environment:`.
        if low.endswith((".yml", ".yaml")):
            return _from_compose(text, source, env_by_dir)
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
