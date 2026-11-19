"""Client version comparison and version-policy client.

Implements the PEP 440 public-version comparison rules and the client for
``GET /api/v1/client/version-policy`` (plus the additive
``client_version_policy`` object returned by ``/api/entitlements``).

Network failures, invalid payloads, or missing caches fail open: local
operations are never blocked by version-policy checks.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Final, Optional, Tuple
from urllib.parse import urlsplit

from servonaut.runtime import data_root_for_home
from servonaut.utils.endpoints import API_URL_ENV, EndpointOverrideError, endpoint_or_default
from servonaut.utils.package_version import PackageVersion

logger = logging.getLogger(__name__)

_BIDI_CONTROLS: Final = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _terminal_safe(value: object) -> str:
    """Strip control characters and bidi overrides without importing vault."""
    return "".join(
        ch for ch in str(value)
        if not (ord(ch) < 32 or 127 <= ord(ch) <= 159 or ch in _BIDI_CONTROLS)
    )

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    HAS_HTTPX = False

_DEFAULT_API_BASE: Final = "https://api.servonaut.dev"
DEFAULT_UPDATE_URL: Final = "https://servonaut.dev/download"
VERSION_POLICY_PATH: Final = "/api/v1/client/version-policy"
VERSION_POLICY_FILENAME: Final = "version-policy.json"

# Protocol bounds for the version-policy response and on-disk cache.
DEFAULT_POLICY_TIMEOUT_SECONDS: Final = 5.0
DEFAULT_POLICY_CACHE_TTL_SECONDS: Final = 300.0
_MAX_CACHE_TTL_SECONDS: Final = 3600.0
_MAX_POLICY_BYTES: Final = 64 * 1024

_VALID_MODES: Final = frozenset({"off", "log", "enforce"})
_VALID_CHANNELS: Final = frozenset({"stable", "rc"})
_VALID_KINDS: Final = frozenset({"cli", "desktop", "relay", "mcp"})

# Local version segment permitted after ``+`` (PEP 440 local labels).
_LOCAL_SEGMENT_RE: Final = re.compile(r"^[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*$")
# Strict bounded contract version grammar: each numeric segment is capped at 9
# digits so untrusted server inputs cannot trigger Python's int-string limit.
_CONTRACT_VERSION_RE: Final = re.compile(
    r"^[0-9]{1,9}(?:\.[0-9]{1,9}){0,7}"
    r"(?:(?:a|b|rc)[0-9]{1,9})?"
    r"(?:\.post[0-9]{1,9})?"
    r"(?:\.dev[0-9]{1,9})?$"
)
_MAX_VERSION_STRING_LEN: Final = 128
_SAFE_URL_PATH_RE: Final = re.compile(r"^[A-Za-z0-9/._~:@!$&()*+,;=%-]*$")
_SAFE_URL_QUERY_RE: Final = re.compile(r"^[A-Za-z0-9/._~:@!$&()*+,;=%?-]*$")
_MAX_AGE_RE: Final = re.compile(r"(?:^|,)\s*max-age\s*=\s*([0-9]+)\s*(?:,|$)", re.IGNORECASE)
_UA_PREFIXES: Final = ("servonaut-cli/", "servonaut/")


def parse_contract_version(value: object) -> Optional[PackageVersion]:
    """Parse a normalized public PEP 440 version, stripping any ``+local`` suffix.

    Accepts ``N(.N)*[(a|b|rc)N][.postN][.devN]`` (with optional ``+local``)
    with bounded numeric segments. Non-normalized or oversized forms return
    ``None`` without raising.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > _MAX_VERSION_STRING_LEN:
        return None
    if "+" in text:
        public, local = text.split("+", 1)
        if not local or _LOCAL_SEGMENT_RE.fullmatch(local) is None:
            return None
        text = public
    if _CONTRACT_VERSION_RE.fullmatch(text) is None:
        return None
    return PackageVersion.parse(text)


def normalize_public_version(value: object) -> Optional[str]:
    """Return the normalized public PEP 440 version string, or ``None``."""
    parsed = parse_contract_version(value)
    if parsed is None:
        return None
    release = ".".join(str(part) for part in parsed.release)
    pre = ""
    if parsed.pre is not None:
        label = ("a", "b", "rc")[parsed.pre[0]]
        pre = f"{label}{parsed.pre[1]}"
    post = f".post{parsed.post}" if parsed.post is not None else ""
    dev = f".dev{parsed.dev}" if parsed.dev is not None else ""
    return f"{release}{pre}{post}{dev}"


def compare_versions(left: object, right: object) -> Optional[int]:
    """Compare two contract versions using PEP 440 ordering.

    Returns ``-1`` if ``left < right``, ``0`` if equal, ``1`` if ``left > right``,
    or ``None`` when either value is not a valid contract version.
    """
    parsed_left = parse_contract_version(left)
    parsed_right = parse_contract_version(right)
    if parsed_left is None or parsed_right is None:
        return None
    if parsed_left < parsed_right:
        return -1
    if parsed_left > parsed_right:
        return 1
    return 0


def is_version_allowed(client_version: object, minimum_version: object) -> bool:
    """Return whether *client_version* satisfies *minimum_version*.

    A missing or unparseable floor allows every client. An unknown or
    unparseable client version is never refused.
    """
    parsed_floor = parse_contract_version(minimum_version)
    if parsed_floor is None:
        return True
    parsed_client = parse_contract_version(client_version)
    if parsed_client is None:
        return True
    return parsed_client >= parsed_floor


def parse_client_signal(
    x_client: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract ``(version, channel, kind)`` from client headers per the contract.

    Checks ``X-Servonaut-Client`` first; if its version token does not parse,
    falls back to a ``servonaut-cli/<ver>`` or ``servonaut/<ver>`` User-Agent
    prefix. Unknown parameters or values are ignored.
    """
    if isinstance(x_client, str) and x_client.strip():
        parts = [part.strip() for part in x_client.split(";")]
        version = normalize_public_version(parts[0])
        if version is not None:
            channel: Optional[str] = None
            kind: Optional[str] = None
            for param in parts[1:]:
                if "=" not in param:
                    continue
                key, raw_val = param.split("=", 1)
                key = key.strip().lower()
                val = raw_val.strip().lower()
                if key == "channel" and val in _VALID_CHANNELS:
                    channel = val
                elif key == "kind" and val in _VALID_KINDS:
                    kind = val
            return version, channel, kind

    if isinstance(user_agent, str) and user_agent.strip():
        first_token = user_agent.strip().split(None, 1)[0]
        lowered = first_token.lower()
        for prefix in _UA_PREFIXES:
            if lowered.startswith(prefix):
                candidate = first_token[len(prefix):]
                version = normalize_public_version(candidate)
                if version is not None:
                    return version, None, None
                break

    return None, None, None


def safe_update_url(value: object, *, fallback: str = DEFAULT_UPDATE_URL) -> str:
    """Accept a safe ASCII HTTPS update URL on servonaut.dev, else return *fallback*."""
    if not isinstance(value, str):
        return fallback
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 512:
        return fallback
    # Allow printable ASCII only and reject whitespace, bidi overrides, and
    # markup / delimiter characters such as Rich ``[...]`` brackets.
    if any(ord(ch) <= 32 or ord(ch) >= 127 or ch in "[]<>\"'\\{}|^`" for ch in cleaned):
        return fallback
    try:
        parsed = urlsplit(cleaned)
        parsed.port
    except ValueError:
        return fallback
    if (
        parsed.scheme != "https"
        or parsed.netloc not in {"servonaut.dev", "www.servonaut.dev"}
        or parsed.username is not None
        or parsed.password is not None
        or _SAFE_URL_PATH_RE.fullmatch(parsed.path) is None
        or _SAFE_URL_QUERY_RE.fullmatch(parsed.query) is None
        or _SAFE_URL_PATH_RE.fullmatch(parsed.fragment) is None
    ):
        return fallback
    return cleaned


@dataclass(frozen=True)
class UpcomingMinimum:
    """Planned future minimum version announced ahead of enforcement."""

    minimum_version: str
    effective_at: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "minimum_version": self.minimum_version,
            "effective_at": self.effective_at,
        }


@dataclass(frozen=True)
class LatestVersions:
    """Latest known stable and candidate versions reported by the server."""

    stable: Optional[str] = None
    rc: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {"stable": self.stable, "rc": self.rc}


@dataclass(frozen=True)
class VersionPolicy:
    """Parsed payload from ``GET /api/v1/client/version-policy``."""

    mode: str = "off"
    minimum_version: Optional[str] = None
    upcoming: Optional[UpcomingMinimum] = None
    latest: LatestVersions = field(default_factory=LatestVersions)
    update_url: str = DEFAULT_UPDATE_URL
    update_hints: Dict[str, str] = field(default_factory=dict)
    fetched_at: float = 0.0

    @classmethod
    def from_dict(
        cls,
        data: Any,
        *,
        fetched_at: Optional[float] = None,
    ) -> Optional["VersionPolicy"]:
        """Parse a raw policy mapping defensively; return ``None`` if not a dict."""
        if not isinstance(data, Mapping):
            return None

        raw_mode = data.get("mode")
        mode = raw_mode if isinstance(raw_mode, str) and raw_mode in _VALID_MODES else "off"

        minimum_version = normalize_public_version(data.get("minimum_version"))

        upcoming: Optional[UpcomingMinimum] = None
        raw_upcoming = data.get("upcoming")
        if isinstance(raw_upcoming, Mapping):
            up_min = normalize_public_version(raw_upcoming.get("minimum_version"))
            up_at = raw_upcoming.get("effective_at")
            if up_min is not None and isinstance(up_at, str) and up_at.strip():
                upcoming = UpcomingMinimum(
                    minimum_version=up_min,
                    effective_at=_terminal_safe(up_at.strip()),
                )

        latest_stable: Optional[str] = None
        latest_rc: Optional[str] = None
        raw_latest = data.get("latest")
        if isinstance(raw_latest, Mapping):
            latest_stable = normalize_public_version(raw_latest.get("stable"))
            latest_rc = normalize_public_version(raw_latest.get("rc"))

        update_url = safe_update_url(data.get("update_url"))

        hints: Dict[str, str] = {}
        raw_hints = data.get("update_hints")
        if isinstance(raw_hints, Mapping):
            for key, val in raw_hints.items():
                if isinstance(key, str) and key.strip() and isinstance(val, str) and val.strip():
                    safe_key = _terminal_safe(key.strip())
                    safe_val = _terminal_safe(val.strip())
                    if safe_key and safe_val:
                        hints[safe_key] = safe_val

        ts = fetched_at
        if ts is None:
            raw_ts = data.get("fetched_at")
            if isinstance(raw_ts, (int, float)) and not isinstance(raw_ts, bool) and raw_ts >= 0:
                ts = float(raw_ts)
            else:
                ts = 0.0

        return cls(
            mode=mode,
            minimum_version=minimum_version,
            upcoming=upcoming,
            latest=LatestVersions(stable=latest_stable, rc=latest_rc),
            update_url=update_url,
            update_hints=hints,
            fetched_at=ts,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "minimum_version": self.minimum_version,
            "upcoming": self.upcoming.to_dict() if self.upcoming is not None else None,
            "latest": self.latest.to_dict(),
            "update_url": self.update_url,
            "update_hints": dict(self.update_hints),
            "fetched_at": self.fetched_at,
        }

    def is_below_floor(self, client_version: object) -> bool:
        """True when a floor is configured and *client_version* is below it."""
        if not self.minimum_version:
            return False
        return not is_version_allowed(client_version, self.minimum_version)

    def is_enforced_below_floor(self, client_version: object) -> bool:
        """True when mode is ``enforce`` and *client_version* is below the floor."""
        return self.mode == "enforce" and self.is_below_floor(client_version)

    def hint_for(self, install_key: str) -> str:
        """Return the hint for *install_key*, falling back to ``update_url``."""
        hint = self.update_hints.get(install_key)
        return hint if hint else self.update_url


def version_policy_cache_path(data_root: Optional[Path] = None) -> Path:
    """Return the path of the on-disk version-policy cache."""
    root = data_root if data_root is not None else data_root_for_home(Path.home())
    return root / VERSION_POLICY_FILENAME


def load_cached_version_policy(path: Optional[Path] = None) -> Optional[VersionPolicy]:
    """Read the last known cached :class:`VersionPolicy` from disk, or ``None``."""
    target = path if path is not None else version_policy_cache_path()
    try:
        raw = target.read_bytes()
    except OSError:
        return None
    if not raw or len(raw) > _MAX_POLICY_BYTES:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
        return VersionPolicy.from_dict(parsed)
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
        return None


def save_cached_version_policy(
    policy: VersionPolicy,
    path: Optional[Path] = None,
) -> bool:
    """Atomically persist *policy* to disk with owner-only permissions."""
    target = path if path is not None else version_policy_cache_path()
    try:
        encoded = json.dumps(policy.to_dict(), sort_keys=True).encode("utf-8")
        if len(encoded) > _MAX_POLICY_BYTES:
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(target.parent), prefix=".version-policy-", suffix=".tmp",
        )
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
            os.replace(tmp_name, target)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        return True
    except OSError as exc:
        logger.debug("Could not cache version policy at %s: %s", target, exc)
        return False


def _parse_cache_ttl(headers: Mapping[str, Any], default: float) -> float:
    cache_control: Any = ""
    try:
        for key, value in headers.items():
            if isinstance(key, str) and key.lower() == "cache-control":
                cache_control = value
                break
    except Exception:  # noqa: BLE001 — tolerate non-iterable header mappings
        cache_control = headers.get("cache-control") or headers.get("Cache-Control") or ""
    if not isinstance(cache_control, str) or not cache_control.strip():
        return default
    match = _MAX_AGE_RE.search(cache_control)
    if match is None:
        return default
    try:
        seconds = float(int(match.group(1)))
    except (ValueError, OverflowError, TypeError):
        return default
    if not math.isfinite(seconds):
        return default
    return min(max(0.0, seconds), _MAX_CACHE_TTL_SECONDS)


def _policy_api_base() -> str:
    return endpoint_or_default(API_URL_ENV, _DEFAULT_API_BASE)


class VersionPolicyClient:
    """Fetch and cache ``GET /api/v1/client/version-policy`` with offline fail-open.

    Requests are unauthenticated and carry ``X-Servonaut-Client``. When the
    endpoint is unreachable, misconfigured, or returns invalid data, the client
    returns the last cached policy (or ``None``) and never raises.
    """

    def __init__(
        self,
        *,
        cache_path: Optional[Path] = None,
        timeout: float = DEFAULT_POLICY_TIMEOUT_SECONDS,
        max_age_seconds: float = DEFAULT_POLICY_CACHE_TTL_SECONDS,
        transport: Optional[Any] = None,
        base_url_provider: Optional[Callable[[], str]] = None,
    ) -> None:
        self._cache_path = cache_path
        self._timeout = timeout
        self._max_age_seconds = max_age_seconds
        self._transport = transport
        self._base_url_provider = base_url_provider or _policy_api_base
        self._cached: Optional[VersionPolicy] = None
        self._cached_monotonic: Optional[float] = None
        self._effective_ttl: float = max_age_seconds

    def cached(self) -> Optional[VersionPolicy]:
        """Return the in-memory or last disk-cached policy without network I/O."""
        if self._cached is not None:
            return self._cached
        disk = load_cached_version_policy(self._cache_path)
        if disk is not None:
            self._cached = disk
        return disk

    async def fetch(self, *, force_refresh: bool = False) -> Optional[VersionPolicy]:
        """Return the current version policy, falling back to cache on error."""
        if (
            not force_refresh
            and self._cached is not None
            and self._cached_monotonic is not None
            and (time.monotonic() - self._cached_monotonic) < self._effective_ttl
        ):
            return self._cached

        if not HAS_HTTPX:
            return self.cached()

        try:
            base = self._base_url_provider().rstrip("/")
        except EndpointOverrideError as exc:
            logger.debug("Skipping version-policy fetch: %s", exc)
            return self.cached()
        except Exception as exc:  # noqa: BLE001 — fail open
            logger.debug("Could not resolve API base for version policy: %s", exc)
            return self.cached()

        from servonaut.services.client_identity import client_request_headers

        headers = {
            key: _terminal_safe(val).strip()
            for key, val in client_request_headers().items()
        }
        headers["Accept"] = "application/json"

        client_kwargs: Dict[str, Any] = {"timeout": self._timeout}
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        url = f"{base}{VERSION_POLICY_PATH}"
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.get(url, headers=headers)
            if response.status_code != 200:
                logger.debug(
                    "Version policy fetch returned HTTP %s; using cached policy",
                    response.status_code,
                )
                return self.cached()
            if len(response.content or b"") > _MAX_POLICY_BYTES:
                logger.debug("Version policy response exceeded size limit; ignoring")
                return self.cached()
            payload = response.json()
        except Exception as exc:  # noqa: BLE001 — offline fail-open
            logger.debug("Version policy fetch failed (offline fail-open): %s", exc)
            return self.cached()

        try:
            policy = VersionPolicy.from_dict(payload, fetched_at=time.time())
        except (ValueError, TypeError, RecursionError) as exc:
            logger.debug("Version policy payload parsing failed: %s", exc)
            return self.cached()
        if policy is None:
            logger.debug("Version policy payload was malformed; using cached policy")
            return self.cached()

        self._cached = policy
        self._cached_monotonic = time.monotonic()
        self._effective_ttl = _parse_cache_ttl(response.headers, self._max_age_seconds)
        save_cached_version_policy(policy, self._cache_path)
        return policy
