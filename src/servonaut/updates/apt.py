"""Detect APT-managed Linux packaged-desktop installations without side effects.

Classifies a running installation as APT-managed only when two cached facts
both hold:

1. An enabled official Servonaut APT source in ``/etc/apt/sources.list`` or
   ``/etc/apt/sources.list.d/*.{sources,list}`` points to the official HTTPS
   archive URI, uses an expected suite and component, matches the installed
   package's architecture, omits authentication-bypass options, and specifies a
   scoped ``Signed-By`` keyring (never relying on the global trust store).
2. The resolved Linux ``packaged-desktop`` executable (under the packaged
   install prefix) and its sibling ``servonaut-runtime.json`` build marker are
   regular files whose full path chain is root-owned and not group- or
   world-writable, exclusively owned by an installed (``ii``) ``servonaut``
   dpkg package verified via bounded, read-only ``dpkg-query`` calls from known
   system paths.

Cheap filesystem and source checks run before any ``dpkg-query`` subprocess.
Long-running processes warm the cache in a background thread off UI/handshake
paths; UI rendering and non-CLI HTTP error-formatting paths call
:func:`get_cached_apt_status`, a pure in-memory lookup with zero I/O.
Incomplete evidence or transient probe failures fall back to ``managed=False``
so callers show the standard download guidance, and transient failures are
never cached as a permanent negative result.
"""

from __future__ import annotations

import logging
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional, TYPE_CHECKING
from urllib.parse import urlsplit

from servonaut.runtime import (
    DistributionKind, RuntimeLayout, is_linux_packaged_desktop as is_apt_probe_candidate,
)
from servonaut.utils.process_cleanup import register_process_cleanup

if TYPE_CHECKING:
    from servonaut.services.apt_runtime import DpkgPackageState

logger = logging.getLogger(__name__)

APT_UPGRADE_COMMAND: Final = "sudo apt update && sudo apt install --only-upgrade servonaut"

_MARKER_FILENAME: Final = "servonaut-runtime.json"
_DPKG_TIMEOUT_ENV: Final = "SERVONAUT_DPKG_QUERY_TIMEOUT_SECONDS"
_DEFAULT_DPKG_TIMEOUT_SECONDS: Final = 3.0
_MIN_DPKG_TIMEOUT_SECONDS: Final = 0.5
_MAX_DPKG_TIMEOUT_SECONDS: Final = 30.0
_NEGATIVE_TTL_ENV: Final = "SERVONAUT_APT_NEGATIVE_TTL_SECONDS"
_DEFAULT_NEGATIVE_TTL_SECONDS: Final = 300.0
_MAX_NEGATIVE_TTL_SECONDS: Final = 3600.0
_MAX_PROBE_RETRIES: Final = 2

# Protocol bounds to keep local file reads and dpkg-query output bounded even
# against hostile or corrupted system files.
_MAX_SOURCE_FILE_BYTES: Final = 256 * 1024
_MAX_TOTAL_SOURCE_BYTES: Final = 2 * 1024 * 1024
_MAX_SOURCE_FILES: Final = 128
_MAX_DPKG_OUTPUT_BYTES: Final = 256 * 1024
_MAX_DPKG_STDERR_BYTES: Final = 4096
_DPKG_READ_CHUNK_BYTES: Final = 8192

_DEFAULT_PACKAGED_PREFIXES: Final[tuple[Path, ...]] = (Path("/opt/servonaut"),)
_DEFAULT_DPKG_QUERY_PATHS: Final[tuple[Path, ...]] = (
    Path("/usr/bin/dpkg-query"),
    Path("/bin/dpkg-query"),
)
_DEFAULT_DPKG_STATUS_PATH: Final = Path("/var/lib/dpkg/status")
_DEFAULT_SOURCES_LIST_PATH: Final = Path("/etc/apt/sources.list")
_DEFAULT_SOURCES_LIST_D_PATH: Final = Path("/etc/apt/sources.list.d")

# Per sources.list(5), sourceparts ignore hidden files and backup suffixes.
_SOURCEPART_NAME_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.(?:list|sources)$")
_DPKG_ARCH_RE: Final = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_FIELD_NAME_RE: Final = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")

_TRUTHY_APT_VALUES: Final = frozenset({"yes", "true", "1"})
_FALSY_APT_VALUES: Final = frozenset({"no", "false", "0"})
_FORBIDDEN_TRUTHY_OPTIONS: Final = frozenset({
    "trusted",
    "allow-insecure",
    "allow-weak",
    "allow-downgrade-to-insecure",
})
_REQUIRED_TRUTHY_OPTIONS: Final = frozenset({
    "check-valid-until",
    "check-date",
})
_PGP_BLOCK_BEGIN: Final = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
_PGP_BLOCK_END: Final = "-----END PGP PUBLIC KEY BLOCK-----"
_PGP_ARMOR_BODY_RE: Final = re.compile(r"^[A-Za-z0-9+/=]{4,}$")
_GLOBAL_TRUST_PATHS: Final[tuple[Path, ...]] = (
    Path("/etc/apt/trusted.gpg"),
    Path("/etc/apt/trusted.gpg.d"),
)


@dataclass(frozen=True)
class DpkgCommandResult:
    """Bounded result returned by a ``dpkg-query`` subprocess."""

    returncode: int
    stdout: str
    stderr: str = ""


DpkgRunner = Callable[[Sequence[str], float], DpkgCommandResult]


def _official_apt_defaults() -> tuple[str, frozenset[str], str, str]:
    """Import APT archive invariants lazily so startup avoids loading distribution/crypto."""
    from servonaut.distribution.trust_root import (
        OFFICIAL_APT_COMPONENT,
        OFFICIAL_APT_PACKAGE,
        OFFICIAL_APT_REPOSITORY_URI,
        OFFICIAL_APT_SUITES,
    )

    return (
        OFFICIAL_APT_REPOSITORY_URI,
        OFFICIAL_APT_SUITES,
        OFFICIAL_APT_COMPONENT,
        OFFICIAL_APT_PACKAGE,
    )


def _clamp_timeout(value: float) -> float:
    return max(_MIN_DPKG_TIMEOUT_SECONDS, min(value, _MAX_DPKG_TIMEOUT_SECONDS))


def _configured_dpkg_timeout() -> float:
    """Resolve the dpkg-query timeout from environment configuration."""
    raw = os.environ.get(_DPKG_TIMEOUT_ENV, "").strip()
    if not raw:
        return _DEFAULT_DPKG_TIMEOUT_SECONDS
    try:
        parsed = float(raw)
    except ValueError:
        return _DEFAULT_DPKG_TIMEOUT_SECONDS
    if not math.isfinite(parsed) or parsed <= 0:
        return _DEFAULT_DPKG_TIMEOUT_SECONDS
    return _clamp_timeout(parsed)


def _configured_negative_ttl() -> float:
    """Resolve the TTL for definitive negative dpkg answers from environment configuration."""
    raw = os.environ.get(_NEGATIVE_TTL_ENV, "").strip()
    if not raw:
        return _DEFAULT_NEGATIVE_TTL_SECONDS
    try:
        parsed = float(raw)
    except ValueError:
        return _DEFAULT_NEGATIVE_TTL_SECONDS
    if not math.isfinite(parsed) or parsed < 0:
        return _DEFAULT_NEGATIVE_TTL_SECONDS
    return min(parsed, _MAX_NEGATIVE_TTL_SECONDS)


@dataclass(frozen=True)
class AptDetectionConfig:
    """Configurable system paths, archive criteria, and bounds for APT detection."""

    official_uri: Optional[str] = None
    official_suites: Optional[frozenset[str]] = None
    official_component: Optional[str] = None
    package_name: Optional[str] = None
    packaged_prefixes: tuple[Path, ...] = _DEFAULT_PACKAGED_PREFIXES
    sources_list_path: Path = _DEFAULT_SOURCES_LIST_PATH
    sources_list_d_path: Path = _DEFAULT_SOURCES_LIST_D_PATH
    dpkg_status_path: Path = _DEFAULT_DPKG_STATUS_PATH
    dpkg_query_paths: tuple[Path, ...] = _DEFAULT_DPKG_QUERY_PATHS
    dpkg_timeout_seconds: Optional[float] = None
    negative_cache_ttl_seconds: Optional[float] = None
    require_root_owned: bool = True
    max_source_file_bytes: int = _MAX_SOURCE_FILE_BYTES
    max_total_source_bytes: int = _MAX_TOTAL_SOURCE_BYTES
    max_source_files: int = _MAX_SOURCE_FILES
    max_dpkg_output_bytes: int = _MAX_DPKG_OUTPUT_BYTES
    dpkg_runner: Optional[DpkgRunner] = None

    def resolved_official_uri(self) -> str:
        if self.official_uri is not None:
            return self.official_uri
        return _official_apt_defaults()[0]

    def resolved_official_suites(self) -> frozenset[str]:
        if self.official_suites is not None:
            return self.official_suites
        return _official_apt_defaults()[1]

    def resolved_official_component(self) -> str:
        if self.official_component is not None:
            return self.official_component
        return _official_apt_defaults()[2]

    def resolved_package_name(self) -> str:
        if self.package_name is not None:
            return self.package_name
        return _official_apt_defaults()[3]

    def effective_timeout(self) -> float:
        if self.dpkg_timeout_seconds is not None:
            if math.isfinite(self.dpkg_timeout_seconds) and self.dpkg_timeout_seconds > 0:
                return _clamp_timeout(self.dpkg_timeout_seconds)
        return _configured_dpkg_timeout()

    def effective_negative_ttl(self) -> float:
        if self.negative_cache_ttl_seconds is not None:
            if math.isfinite(self.negative_cache_ttl_seconds) and self.negative_cache_ttl_seconds >= 0:
                return min(self.negative_cache_ttl_seconds, _MAX_NEGATIVE_TTL_SECONDS)
        return _configured_negative_ttl()

    def cache_key_part(self) -> tuple[object, ...]:
        return (
            self.official_uri,
            tuple(sorted(self.official_suites)) if self.official_suites is not None else None,
            self.official_component,
            self.package_name,
            tuple(str(p) for p in self.packaged_prefixes),
            str(self.sources_list_path),
            str(self.sources_list_d_path),
            str(self.dpkg_status_path),
            tuple(str(p) for p in self.dpkg_query_paths),
            self.require_root_owned,
            self.dpkg_runner,
        )


@dataclass(frozen=True)
class AptSourceMatch:
    """One validated official Servonaut APT source entry."""

    source_path: str
    suites: tuple[str, ...]
    keyring_paths: tuple[str, ...]


@dataclass(frozen=True)
class AptInstallStatus:
    """Cached result of checking whether a Linux install is managed by APT."""

    managed: bool
    suite: Optional[str] = None
    suites: tuple[str, ...] = ()
    dpkg_owned: bool = False
    package_version: Optional[str] = None
    architecture: Optional[str] = None
    source_paths: tuple[str, ...] = ()
    keyring_paths: tuple[str, ...] = ()
    checked: bool = False

    @property
    def suite_display(self) -> Optional[str]:
        """Human-readable suite summary from configured APT sources."""
        if not self.suites:
            return self.suite
        if len(self.suites) == 1:
            return self.suites[0]
        return ", ".join(self.suites)


@dataclass(frozen=True)
class _ParsedSourceEntry:
    source_path: str
    suites: tuple[str, ...]
    keyring_paths: tuple[str, ...]
    arch_matcher: Callable[[str], bool]


@dataclass(frozen=True)
class _DpkgPackageState:
    installed: bool
    architecture: Optional[str] = None
    package_version: Optional[str] = None
    transient_error: bool = False
    definitive_missing: bool = False
    runtime_status: Optional[str] = None


@dataclass(frozen=True)
class _DpkgFileOwnership:
    owned: bool
    transient_error: bool = False
    definitive_missing: bool = False


@dataclass(frozen=True)
class _ProbeOutcome:
    status: AptInstallStatus
    cacheable: bool
    ttl_seconds: Optional[float] = None


@dataclass(frozen=True)
class _CacheEntry:
    fingerprint: tuple[object, ...]
    status: AptInstallStatus
    expires_at: Optional[float] = None


class _InFlightProbe:
    """Single-flight coordination state shared by concurrent callers for one key."""

    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: AptInstallStatus = AptInstallStatus(managed=False, checked=False)


_CACHE_LOCK = threading.Lock()
_CACHE: dict[tuple[object, ...], _CacheEntry] = {}
_PROCESS_STATUS_BY_PLATFORM: dict[str, AptInstallStatus] = {}
_PROCESS_STATUS_BY_RUNTIME: dict[tuple[str, str], AptInstallStatus] = {}
_IN_FLIGHT: dict[tuple[object, ...], _InFlightProbe] = {}
_KEY_LOCKS: dict[tuple[object, ...], threading.Lock] = {}


def reset_apt_status_cache_for_tests() -> None:
    """Clear the in-process APT status cache (test isolation helper)."""
    with _CACHE_LOCK:
        _CACHE.clear()
        _PROCESS_STATUS_BY_PLATFORM.clear()
        _PROCESS_STATUS_BY_RUNTIME.clear()
        _IN_FLIGHT.clear()
        _KEY_LOCKS.clear()


def seed_apt_status_cache_for_tests(
    status: AptInstallStatus,
    *,
    runtime: Optional[RuntimeLayout] = None,
    platform_name: str = "linux",
    config: Optional[AptDetectionConfig] = None,
) -> None:
    """Insert a precomputed status into the cache without running probes."""
    plat = platform_name.lower()
    cfg = config or AptDetectionConfig()
    with _CACHE_LOCK:
        _PROCESS_STATUS_BY_PLATFORM[plat] = status
        if runtime is not None:
            key = _cache_key(runtime, plat, cfg)
            _CACHE[key] = _CacheEntry(fingerprint=("seeded",), status=status)
            _PROCESS_STATUS_BY_RUNTIME[(plat, str(runtime.executable))] = status


def warm_apt_status_in_background(
    runtime: Optional[RuntimeLayout],
    *,
    platform_name: Optional[str] = None,
    config: Optional[AptDetectionConfig] = None,
) -> Optional[threading.Thread]:
    """Start a daemon thread to warm APT status without delaying caller startup."""
    if not is_apt_probe_candidate(runtime, platform_name=platform_name):
        return None

    def _run() -> None:
        try:
            refresh_apt_status(runtime, platform_name=platform_name, config=config)
        except Exception as exc:  # noqa: BLE001 — incomplete evidence falls back
            logger.debug("Background APT status warm-up failed: %s", exc)

    thread = threading.Thread(
        target=_run,
        name="servonaut-apt-warm",
        daemon=True,
    )
    thread.start()
    return thread


def _cache_key(
    runtime: RuntimeLayout,
    platform_name: str,
    config: AptDetectionConfig,
) -> tuple[object, ...]:
    return (
        platform_name,
        runtime.kind.value,
        runtime.is_frozen,
        str(runtime.executable),
        str(runtime.executable_root),
        config.cache_key_part(),
    )


def _lock_for_key(key: tuple[object, ...]) -> threading.Lock:
    with _CACHE_LOCK:
        lock = _KEY_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _KEY_LOCKS[key] = lock
        return lock


def get_cached_apt_status(
    runtime: Optional[RuntimeLayout] = None,
    *,
    platform_name: Optional[str] = None,
    config: Optional[AptDetectionConfig] = None,
) -> Optional[AptInstallStatus]:
    """Return the last cached :class:`AptInstallStatus` without any I/O.

    Safe to call on UI rendering and HTTP error-formatting paths. Returns
    ``None`` when no background probe has populated the cache yet.
    """
    plat = (platform_name if platform_name is not None else sys.platform).lower()
    if not plat.startswith("linux"):
        return AptInstallStatus(managed=False, checked=True)
    if runtime is not None and not is_apt_probe_candidate(runtime, platform_name=plat):
        return AptInstallStatus(managed=False, checked=True)

    cfg = config or AptDetectionConfig()
    now = time.monotonic()
    with _CACHE_LOCK:
        if runtime is not None:
            entry = _CACHE.get(_cache_key(runtime, plat, cfg))
            if entry is not None:
                if entry.expires_at is None or now < entry.expires_at:
                    return entry.status
                return None
            if config is None:
                return _PROCESS_STATUS_BY_RUNTIME.get((plat, str(runtime.executable)))
            return None
        return _PROCESS_STATUS_BY_PLATFORM.get(plat)


def refresh_apt_status(
    runtime: Optional[RuntimeLayout] = None,
    *,
    platform_name: Optional[str] = None,
    config: Optional[AptDetectionConfig] = None,
    force: bool = False,
) -> AptInstallStatus:
    """Inspect APT sources and dpkg ownership off the UI/HTTP path and cache the result.

    Computes a stat fingerprint of dpkg status, APT sources, runtime files, and
    all keyring paths referenced by official-URI source entries BEFORE probing,
    re-checks AFTER probing (discarding and re-probing if inputs changed in
    flight), serializes concurrent refreshes per cache key with a single-flight
    guard, and never caches transient ``dpkg-query`` failures as definitive.
    """
    plat = (platform_name if platform_name is not None else sys.platform).lower()
    if not plat.startswith("linux"):
        return AptInstallStatus(managed=False, checked=True)
    if not is_apt_probe_candidate(runtime, platform_name=plat):
        status = AptInstallStatus(managed=False, checked=True)
        with _CACHE_LOCK:
            if runtime is not None:
                _PROCESS_STATUS_BY_PLATFORM[plat] = status
        return status
    assert runtime is not None

    cfg = config or AptDetectionConfig()
    key = _cache_key(runtime, plat, cfg)

    # Single-flight join for concurrent non-forced refreshes on the same key.
    flight: Optional[_InFlightProbe] = None
    is_owner = False
    if not force:
        with _CACHE_LOCK:
            existing_flight = _IN_FLIGHT.get(key)
            if existing_flight is not None:
                flight = existing_flight
            else:
                flight = _InFlightProbe()
                _IN_FLIGHT[key] = flight
                is_owner = True
        if not is_owner:
            flight.event.wait()
            return flight.result

    key_lock = _lock_for_key(key)
    try:
        with key_lock:
            status = _refresh_locked(runtime, plat, cfg, key, force=force)
        if flight is not None:
            flight.result = status
        return status
    finally:
        if is_owner and flight is not None:
            with _CACHE_LOCK:
                if _IN_FLIGHT.get(key) is flight:
                    del _IN_FLIGHT[key]
            flight.event.set()


def _refresh_locked(
    runtime: RuntimeLayout,
    plat: str,
    cfg: AptDetectionConfig,
    key: tuple[object, ...],
    *,
    force: bool,
) -> AptInstallStatus:
    last_status = AptInstallStatus(managed=False, checked=False)
    for attempt in range(_MAX_PROBE_RETRIES):
        fp_before = _compute_fingerprint(runtime, cfg)
        if not force and attempt == 0:
            now = time.monotonic()
            with _CACHE_LOCK:
                existing = _CACHE.get(key)
            if (
                existing is not None
                and existing.fingerprint == fp_before
                and (existing.expires_at is None or now < existing.expires_at)
            ):
                with _CACHE_LOCK:
                    _PROCESS_STATUS_BY_PLATFORM[plat] = existing.status
                    _PROCESS_STATUS_BY_RUNTIME[(plat, str(runtime.executable))] = existing.status
                return existing.status

        outcome = _probe_apt_status(runtime, cfg)
        last_status = outcome.status
        fp_after = _compute_fingerprint(runtime, cfg)
        if fp_after != fp_before:
            # Inputs changed mid-probe: discard stale outcome and retry once.
            continue
        if not outcome.cacheable:
            # Transient failure with unchanged inputs: never cache as definitive negative.
            return outcome.status
        expires_at = (
            time.monotonic() + outcome.ttl_seconds
            if outcome.ttl_seconds is not None
            else None
        )
        with _CACHE_LOCK:
            _CACHE[key] = _CacheEntry(
                fingerprint=fp_before, status=outcome.status, expires_at=expires_at,
            )
            _PROCESS_STATUS_BY_PLATFORM[plat] = outcome.status
            _PROCESS_STATUS_BY_RUNTIME[(plat, str(runtime.executable))] = outcome.status
        return outcome.status

    # Inputs kept changing across retries: return latest without caching stale state.
    return AptInstallStatus(managed=False, checked=False) if not last_status.managed else last_status


# ---------------------------------------------------------------------------
# Fingerprinting for cache invalidation
# ---------------------------------------------------------------------------


def _stat_token(path: Path, *, follow_symlinks: bool = True) -> Optional[tuple[int, int, int, int]]:
    try:
        st = os.stat(path) if follow_symlinks else os.lstat(path)
    except OSError:
        return None
    return (st.st_mode, st.st_ino, st.st_size, st.st_mtime_ns)


def _list_sourcepart_files(directory: Path, *, max_files: int) -> list[Path]:
    """Return sorted regular ``.list`` / ``.sources`` files under *directory*."""
    try:
        if not directory.is_dir():
            return []
        names = sorted(
            name for name in os.listdir(directory)
            if _SOURCEPART_NAME_RE.fullmatch(name) is not None
        )
    except OSError:
        return []
    files: list[Path] = []
    for name in names[:max_files]:
        candidate = directory / name
        st = _stat_token(candidate, follow_symlinks=True)
        if st is not None and stat.S_ISREG(st[0]):
            files.append(candidate)
    return files


def _collect_official_uri_keyring_paths(config: AptDetectionConfig) -> tuple[str, ...]:
    """Return every keyring path referenced by any source entry for the official URI.

    Includes paths from both matched and rejected stanzas (e.g. a keyring file
    that does not exist yet) so creating or replacing that keyring invalidates
    the cache on the next refresh.
    """
    candidates = _iter_readable_source_files(config)
    official_uri = config.resolved_official_uri()
    found: set[str] = set()
    for _path, is_deb822, text in candidates:
        if is_deb822:
            for fields in _iter_deb822_stanzas(text):
                uris = fields.get("uris", "").split()
                if not any(_uri_matches_official(uri, official_uri) for uri in uris):
                    continue
                raw_sb = fields.get("signed-by", "")
                if not raw_sb or _PGP_BLOCK_BEGIN in raw_sb:
                    continue
                for token in _split_deb822_signed_by_tokens(raw_sb):
                    if _is_trackable_keyring_path(token):
                        found.add(token)
        else:
            for raw_line in text.splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) < 2 or parts[0] != "deb":
                    continue
                rest = parts[1].lstrip()
                sb_values: list[str] = []
                if rest.startswith("["):
                    close_idx = rest.find("]")
                    if close_idx == -1:
                        continue
                    opt_body = rest[1:close_idx]
                    rest = rest[close_idx + 1:].lstrip()
                    for token in opt_body.split():
                        if "=" in token and "+=" not in token and "-=" not in token:
                            raw_k, raw_v = token.split("=", 1)
                            if raw_k.strip().lower() == "signed-by":
                                sb_values.append(raw_v.strip())
                positional = rest.split()
                if not positional or not _uri_matches_official(positional[0], official_uri):
                    continue
                for val in sb_values:
                    for item in val.split(","):
                        cleaned = item.strip()
                        if _is_trackable_keyring_path(cleaned):
                            found.add(cleaned)
    return tuple(sorted(found))


def _is_trackable_keyring_path(raw_path: str) -> bool:
    cleaned = raw_path.strip()
    if not cleaned or any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        return False
    path = Path(cleaned)
    return path.is_absolute() and ".." not in path.parts


def _compute_fingerprint(
    runtime: RuntimeLayout,
    config: AptDetectionConfig,
) -> tuple[object, ...]:
    marker_path = runtime.executable_root / _MARKER_FILENAME
    try:
        resolved_exe = runtime.executable.resolve(strict=True)
        resolved_marker = marker_path.resolve(strict=True)
    except (OSError, RuntimeError):
        return (
            "unresolved",
            _stat_token(runtime.executable, follow_symlinks=False),
            _stat_token(marker_path, follow_symlinks=False),
        )
    if not (
        _is_under_packaged_prefix(resolved_exe, config.packaged_prefixes)
        and _is_under_packaged_prefix(resolved_marker, config.packaged_prefixes)
    ):
        return (
            "outside-prefix",
            _stat_token(runtime.executable, follow_symlinks=False),
            _stat_token(resolved_exe, follow_symlinks=True),
            _stat_token(marker_path, follow_symlinks=False),
            _stat_token(resolved_marker, follow_symlinks=True),
        )
    sourceparts = _list_sourcepart_files(
        config.sources_list_d_path, max_files=config.max_source_files,
    )
    sourcepart_tokens = tuple(
        (str(path), _stat_token(path, follow_symlinks=True))
        for path in sourceparts
    )
    keyring_paths = _collect_official_uri_keyring_paths(config)
    keyring_tokens = tuple(
        (
            kp,
            _stat_token(Path(kp), follow_symlinks=False),
            _stat_token(Path(kp), follow_symlinks=True),
        )
        for kp in keyring_paths
    )
    return (
        _stat_token(config.dpkg_status_path, follow_symlinks=True),
        _stat_token(config.sources_list_path, follow_symlinks=True),
        _stat_token(config.sources_list_d_path, follow_symlinks=True),
        sourcepart_tokens,
        _stat_token(runtime.executable, follow_symlinks=False),
        _stat_token(runtime.executable, follow_symlinks=True),
        _stat_token(marker_path, follow_symlinks=False),
        _stat_token(marker_path, follow_symlinks=True),
        keyring_tokens,
    )


# ---------------------------------------------------------------------------
# Fact 1 (cheap gate): resolved runtime files, packaged prefix & ownership chain
# ---------------------------------------------------------------------------


def _stat_for_ownership(path: Path) -> os.stat_result:
    """Narrow stat seam used solely for ownership and permission verification."""
    return os.stat(path)


def _is_root_managed_path(path: Path) -> bool:
    """True when *path* is owned by root and not group- or world-writable."""
    try:
        st = _stat_for_ownership(path)
    except OSError:
        return False
    return st.st_uid == 0 and (st.st_mode & 0o022) == 0


def _is_root_managed_chain(path: Path) -> bool:
    """True when *path* and every ancestor directory up to root are root-managed."""
    current = path
    while True:
        if not _is_root_managed_path(current):
            return False
        parent = current.parent
        if parent == current:
            return True
        current = parent


def _is_under_packaged_prefix(path: Path, prefixes: Sequence[Path]) -> bool:
    if not prefixes:
        return True
    for prefix in prefixes:
        try:
            resolved_prefix = prefix.resolve()
        except OSError:
            resolved_prefix = prefix
        try:
            if path.is_relative_to(resolved_prefix):
                return True
        except ValueError:
            continue
    return False


def _resolve_verified_runtime_files(
    runtime: RuntimeLayout,
    config: AptDetectionConfig,
) -> Optional[tuple[Path, Path]]:
    """Resolve and validate the executable and marker before touching sources or dpkg."""
    try:
        exe_path = runtime.executable.resolve(strict=True)
        marker_path = (runtime.executable_root / _MARKER_FILENAME).resolve(strict=True)
    except (OSError, RuntimeError):
        return None

    if not exe_path.is_file() or not marker_path.is_file():
        return None

    if exe_path.parent != marker_path.parent:
        return None

    if not (
        _is_under_packaged_prefix(exe_path, config.packaged_prefixes)
        and _is_under_packaged_prefix(marker_path, config.packaged_prefixes)
    ):
        return None

    if config.require_root_owned:
        if not (_is_root_managed_chain(exe_path) and _is_root_managed_chain(marker_path)):
            return None

    from servonaut.services.apt_runtime import dpkg_generation_paths

    try:
        packaged_paths = dpkg_generation_paths(exe_path)
        if packaged_paths is None:
            return exe_path, marker_path
        for path in packaged_paths:
            resolved = path.resolve(strict=True)
            if not _is_under_packaged_prefix(resolved, config.packaged_prefixes):
                return None
            if config.require_root_owned and not _is_root_managed_chain(resolved):
                return None
    except (OSError, ValueError, RuntimeError):
        return None
    return packaged_paths


# ---------------------------------------------------------------------------
# Bounded, read-only dpkg-query subprocess execution and parsing
# ---------------------------------------------------------------------------


_ACTIVE_PROCS_LOCK = threading.Lock()
_ACTIVE_DPKG_PROCS: set[subprocess.Popen[bytes]] = set()


def _kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    killpg = getattr(os, "killpg", None)
    sigkill = getattr(signal, "SIGKILL", None)
    try:
        if callable(killpg) and sigkill is not None and proc.pid > 0:
            killpg(proc.pid, sigkill)
        else:
            proc.kill()
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=1.0)
    except (OSError, subprocess.SubprocessError):
        pass


def _terminate_active_dpkg_procs() -> None:
    """Ensure any in-flight dpkg-query process group is terminated on interpreter exit."""
    with _ACTIVE_PROCS_LOCK:
        procs = list(_ACTIVE_DPKG_PROCS)
        _ACTIVE_DPKG_PROCS.clear()
    for proc in procs:
        if proc.poll() is None:
            _kill_process_group(proc)


register_process_cleanup(_terminate_active_dpkg_procs)


def _default_dpkg_runner(
    argv: Sequence[str],
    timeout: float,
    *,
    max_output_bytes: int = _MAX_DPKG_OUTPUT_BYTES,
) -> DpkgCommandResult:
    """Run ``dpkg-query`` read-only, streaming output in bounded chunks up to cap."""
    env = {
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
    }
    deadline = time.monotonic() + timeout
    popen_kwargs: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": env,
    }
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True
    proc = subprocess.Popen(list(argv), **popen_kwargs)  # type: ignore[arg-type]
    with _ACTIVE_PROCS_LOCK:
        _ACTIVE_DPKG_PROCS.add(proc)

    stdout_chunks: list[bytes] = []
    stdout_len = 0
    stderr_chunks: list[bytes] = []
    stderr_kept = 0
    stderr_total = 0

    selector = selectors.DefaultSelector()
    try:
        assert proc.stdout is not None and proc.stderr is not None
        set_blocking = getattr(os, "set_blocking", None)
        if callable(set_blocking):
            set_blocking(proc.stdout.fileno(), False)
            set_blocking(proc.stderr.fileno(), False)
        selector.register(proc.stdout, selectors.EVENT_READ, data="stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, data="stderr")

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(proc)
                raise subprocess.TimeoutExpired(argv, timeout)
            events = selector.select(timeout=remaining)
            if not events:
                _kill_process_group(proc)
                raise subprocess.TimeoutExpired(argv, timeout)
            for key, _mask in events:
                fd = key.fileobj.fileno()  # type: ignore[union-attr]
                try:
                    chunk = os.read(fd, _DPKG_READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                except OSError:
                    selector.unregister(key.fileobj)
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    stdout_len += len(chunk)
                    if stdout_len > max_output_bytes:
                        _kill_process_group(proc)
                        raise ValueError("dpkg-query output exceeded safety limit")
                    stdout_chunks.append(chunk)
                else:
                    stderr_total += len(chunk)
                    if stderr_kept < _MAX_DPKG_STDERR_BYTES:
                        take = _MAX_DPKG_STDERR_BYTES - stderr_kept
                        stderr_chunks.append(chunk[:take])
                        stderr_kept += min(len(chunk), take)
                    if stderr_total > max_output_bytes:
                        _kill_process_group(proc)
                        raise ValueError("dpkg-query stderr exceeded safety limit")

        remaining = deadline - time.monotonic()
        if remaining <= 0 and proc.poll() is None:
            _kill_process_group(proc)
            raise subprocess.TimeoutExpired(argv, timeout)
        try:
            returncode = proc.wait(timeout=max(0.05, remaining))
        except subprocess.TimeoutExpired:
            _kill_process_group(proc)
            raise
    finally:
        with _ACTIVE_PROCS_LOCK:
            _ACTIVE_DPKG_PROCS.discard(proc)
        selector.close()
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    return DpkgCommandResult(
        returncode=returncode,
        stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
        stderr=b"".join(stderr_chunks).decode("utf-8", errors="replace"),
    )


def _locate_dpkg_query(paths: Sequence[Path]) -> Optional[Path]:
    """Return the first executable ``dpkg-query`` binary from known system paths."""
    for candidate in paths:
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _resolve_dpkg_runner(config: AptDetectionConfig) -> Optional[tuple[DpkgRunner, str]]:
    if config.dpkg_runner is not None:
        binary = str(config.dpkg_query_paths[0]) if config.dpkg_query_paths else "/usr/bin/dpkg-query"
        return config.dpkg_runner, binary
    dpkg_query = _locate_dpkg_query(config.dpkg_query_paths)
    if dpkg_query is None:
        return None
    cap = config.max_dpkg_output_bytes

    def _bounded_runner(argv: Sequence[str], timeout: float) -> DpkgCommandResult:
        return _default_dpkg_runner(argv, timeout, max_output_bytes=cap)

    return _bounded_runner, str(dpkg_query)


def _parse_dpkg_status_fields(stdout: str) -> Optional[tuple[str, str, str]]:
    """Parse ``${db:Status-Abbrev}\\t${Architecture}\\t${Version}`` output."""
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    parts = lines[0].split("\t")
    if len(parts) != 3:
        return None
    status_abbrev, arch, version = (part.strip() for part in parts)
    if not status_abbrev:
        return None
    if not arch or _DPKG_ARCH_RE.fullmatch(arch) is None:
        return None
    if not version or any(ord(ch) < 32 or ord(ch) == 127 for ch in version):
        return None
    return status_abbrev, arch, version


def _parse_dpkg_status_line(stdout: str) -> Optional[tuple[str, str]]:
    """Parse an installed (``ii``) ``dpkg-query -W`` status line."""
    parsed = _parse_dpkg_status_fields(stdout)
    if parsed is None:
        return None
    status_abbrev, arch, version = parsed
    if status_abbrev != "ii":
        return None
    return arch, version


def _parse_dpkg_search_output(
    stdout: str,
    *,
    package_name: str,
    architecture: str,
) -> set[str]:
    """Return paths exclusively owned by *package_name* from ``dpkg-query -S``."""
    accepted_owners = {package_name, f"{package_name}:{architecture}"}
    owned: set[str] = set()
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("diversion ", "local diversion ")):
            return set()
        if ": " not in line:
            return set()
        owners_part, path_part = line.split(": ", 1)
        owners = [item.strip() for item in owners_part.split(",") if item.strip()]
        if not owners or not all(owner in accepted_owners for owner in owners):
            continue
        owned.add(path_part.strip())
    return owned


def _is_definitive_dpkg_not_installed(stderr: str) -> bool:
    lowered = stderr.lower()
    return "no packages found" in lowered or "not installed" in lowered


def _is_definitive_dpkg_path_unowned(stderr: str) -> bool:
    return "no path found" in stderr.lower()


def _probe_dpkg_package_state(
    runner: DpkgRunner,
    binary: str,
    config: AptDetectionConfig,
) -> _DpkgPackageState:
    timeout = config.effective_timeout()
    package_name = config.resolved_package_name()
    try:
        status_res = runner(
            (
                binary,
                "-W",
                "-f=${db:Status-Abbrev}\t${Architecture}\t${Version}\n",
                "--",
                package_name,
            ),
            timeout,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        logger.debug("dpkg-query package status check failed: %s", exc)
        return _DpkgPackageState(installed=False, transient_error=True)

    if status_res.returncode != 0:
        if status_res.returncode == 1 and _is_definitive_dpkg_not_installed(status_res.stderr):
            return _DpkgPackageState(
                installed=False, transient_error=False, definitive_missing=True, runtime_status="not-installed",
            )
        return _DpkgPackageState(installed=False, transient_error=True)
    if len(status_res.stdout.encode("utf-8")) > config.max_dpkg_output_bytes:
        return _DpkgPackageState(installed=False, transient_error=True)

    parsed = _parse_dpkg_status_fields(status_res.stdout)
    if parsed is None:
        return _DpkgPackageState(installed=False, transient_error=False)
    status_abbrev, architecture, package_version = parsed
    if status_abbrev != "ii":
        # Mid-upgrade dpkg states (unpacked, half-configured, half-installed,
        # triggers pending) are transient; do not cache them permanently.
        in_transition = status_abbrev.startswith("i") and status_abbrev != "ii"
        return _DpkgPackageState(
            installed=False, transient_error=in_transition,
            architecture=architecture, package_version=package_version,
            runtime_status={"rc": "config-files", "hi": "installed"}.get(status_abbrev),
        )
    return _DpkgPackageState(
        installed=True,
        architecture=architecture,
        package_version=package_version,
        transient_error=False,
        runtime_status="installed",
    )


def _probe_dpkg_file_ownership(
    runner: DpkgRunner,
    binary: str,
    exe_path: Path,
    marker_path: Path,
    *,
    architecture: str,
    config: AptDetectionConfig,
) -> _DpkgFileOwnership:
    timeout = config.effective_timeout()
    package_name = config.resolved_package_name()
    try:
        search_res = runner(
            (binary, "-S", "--", str(exe_path), str(marker_path)),
            timeout,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        logger.debug("dpkg-query file ownership check failed: %s", exc)
        return _DpkgFileOwnership(owned=False, transient_error=True)

    if search_res.returncode != 0:
        if search_res.returncode == 1 and _is_definitive_dpkg_path_unowned(search_res.stderr):
            return _DpkgFileOwnership(
                owned=False, transient_error=False, definitive_missing=True,
            )
        return _DpkgFileOwnership(owned=False, transient_error=True)
    if len(search_res.stdout.encode("utf-8")) > config.max_dpkg_output_bytes:
        return _DpkgFileOwnership(owned=False, transient_error=True)

    owned_paths = _parse_dpkg_search_output(
        search_res.stdout,
        package_name=package_name,
        architecture=architecture,
    )
    if str(exe_path) not in owned_paths or str(marker_path) not in owned_paths:
        return _DpkgFileOwnership(owned=False, transient_error=False)
    return _DpkgFileOwnership(owned=True, transient_error=False)


def read_apt_runtime_package(
    runtime: RuntimeLayout,
    package: str,
    *,
    verify_ownership: bool,
    config: Optional[AptDetectionConfig] = None,
) -> DpkgPackageState | None:
    """Read the package on a worker thread, for both official-feed and standalone .deb installs."""
    from servonaut.services.apt_runtime import DpkgPackageState

    cfg = config or AptDetectionConfig()
    if package != cfg.resolved_package_name():
        return None
    resolved = _resolve_dpkg_runner(cfg)
    if resolved is None:
        return None
    runner, binary = resolved
    state = _probe_dpkg_package_state(runner, binary, cfg)
    if state.runtime_status is None:
        return None
    if verify_ownership:
        paths = _resolve_verified_runtime_files(runtime, cfg)
        if state.runtime_status != "installed" or paths is None or not state.architecture:
            return None
        owned = _probe_dpkg_file_ownership(runner, binary, *paths, architecture=state.architecture, config=cfg)
        if not owned.owned:
            return None
    return DpkgPackageState(state.runtime_status, state.package_version or "")


# ---------------------------------------------------------------------------
# Fact 2: bounded APT source parsers (deb822 and one-line)
# ---------------------------------------------------------------------------


def _canonical_uri(uri: str) -> Optional[tuple[str, str, Optional[int], str]]:
    """Normalize an HTTPS APT archive URI for strict comparison, or None."""
    cleaned = uri.strip()
    if not cleaned or any(ord(ch) <= 32 or ord(ch) >= 127 for ch in cleaned):
        return None
    try:
        parsed = urlsplit(cleaned)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    effective_port = None if port in (None, 443) else port
    path = parsed.path.rstrip("/") or "/"
    return ("https", parsed.hostname.lower(), effective_port, path)


def _uri_matches_official(uri: str, official_uri: str) -> bool:
    expected = _canonical_uri(official_uri)
    candidate = _canonical_uri(uri)
    return expected is not None and candidate is not None and candidate == expected


def _is_global_trust_path(path: Path) -> bool:
    if path.parent == Path("/etc/apt") and path.name.startswith("trusted.gpg"):
        return True
    resolved_parts = path.parts
    for global_path in _GLOBAL_TRUST_PATHS:
        g_parts = global_path.parts
        if resolved_parts[:len(g_parts)] == g_parts:
            return True
    return False


def _validate_keyring_file_path(
    raw_path: str,
    *,
    keyring_exists: Optional[Callable[[Path], bool]] = None,
) -> Optional[str]:
    """Validate one scoped keyring file path and confirm it exists as a regular file."""
    cleaned = raw_path.strip()
    if not cleaned or any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        return None
    path = Path(cleaned)
    if not path.is_absolute() or ".." in path.parts:
        return None
    if _is_global_trust_path(path):
        return None
    if keyring_exists is not None:
        return str(path) if keyring_exists(path) else None
    try:
        resolved = path.resolve(strict=True)
        if _is_global_trust_path(resolved):
            return None
        st = os.stat(resolved)
    except (OSError, RuntimeError):
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size <= 0:
        return None
    return str(path)


def _is_inline_pgp_block(value: str) -> bool:
    """True when *value* contains a bounded inline ASCII-armored PGP public key."""
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if len(lines) < 3:
        return False
    if lines[0] != _PGP_BLOCK_BEGIN or lines[-1] != _PGP_BLOCK_END:
        return False
    body = [line for line in lines[1:-1] if line != "."]
    if not body:
        return False
    # Require at least one base64 key-material line (not just armor headers).
    return any(_PGP_ARMOR_BODY_RE.fullmatch(line) is not None for line in body)


def _split_deb822_signed_by_tokens(value: str) -> list[str]:
    """Split deb822 ``Signed-By`` paths on whitespace or commas (matching apt)."""
    return [tok for tok in re.split(r"[\s,]+", value.strip()) if tok]


def _validate_signed_by_deb822(
    value: str,
    *,
    keyring_exists: Optional[Callable[[Path], bool]] = None,
) -> Optional[tuple[str, ...]]:
    """Return validated keyring paths (empty tuple for valid inline PGP), or None."""
    if not value or not value.strip():
        return None
    if _PGP_BLOCK_BEGIN in value:
        return () if _is_inline_pgp_block(value) else None
    tokens = _split_deb822_signed_by_tokens(value)
    if not tokens:
        return None
    validated: list[str] = []
    for token in tokens:
        checked = _validate_keyring_file_path(token, keyring_exists=keyring_exists)
        if checked is None:
            return None
        validated.append(checked)
    return tuple(validated)


def _validate_signed_by_oneline(
    values: Sequence[str],
    *,
    keyring_exists: Optional[Callable[[Path], bool]] = None,
) -> Optional[tuple[str, ...]]:
    """Validate one-line ``signed-by=`` option value(s)."""
    raw_paths: list[str] = []
    for val in values:
        for item in val.split(","):
            stripped = item.strip()
            if stripped:
                raw_paths.append(stripped)
    if not raw_paths:
        return None
    validated: list[str] = []
    for raw_path in raw_paths:
        checked = _validate_keyring_file_path(raw_path, keyring_exists=keyring_exists)
        if checked is None:
            return None
        validated.append(checked)
    return tuple(validated)


def _has_auth_bypass_options(options: dict[str, list[str]]) -> bool:
    """True when any APT authentication/expiry bypass option is active."""
    for name in _FORBIDDEN_TRUTHY_OPTIONS:
        vals = options.get(name)
        if vals is not None:
            if not vals or any(v.strip().lower() not in _FALSY_APT_VALUES for v in vals):
                return True
    for name in _REQUIRED_TRUTHY_OPTIONS:
        vals = options.get(name)
        if vals is not None:
            if not vals or any(v.strip().lower() not in _TRUTHY_APT_VALUES for v in vals):
                return True
    return False


def _split_arch_tokens(raw: Optional[str]) -> list[str]:
    if raw is None:
        return []
    return [tok.strip() for tok in re.split(r"[\s,]+", raw.strip()) if tok.strip()]


def _arch_matches_deb822(
    raw_arches: Optional[str],
    host_arch: str,
    *,
    raw_added: Optional[str] = None,
    raw_removed: Optional[str] = None,
) -> bool:
    removed_set = set(_split_arch_tokens(raw_removed))
    if host_arch in removed_set:
        return False
    if raw_arches is not None:
        base_tokens = _split_arch_tokens(raw_arches)
        if not base_tokens:
            return False
        allowed = (set(base_tokens) | set(_split_arch_tokens(raw_added))) - removed_set
        return host_arch in allowed
    return True


def _arch_matches_oneline(
    exact: Sequence[str],
    added: Sequence[str],
    removed: Sequence[str],
    host_arch: str,
) -> bool:
    def _split(values: Sequence[str]) -> set[str]:
        out: set[str] = set()
        for val in values:
            for item in val.split(","):
                cleaned = item.strip()
                if cleaned:
                    out.add(cleaned)
        return out

    removed_set = _split(removed)
    if host_arch in removed_set:
        return False
    if exact:
        allowed = (_split(exact) | _split(added)) - removed_set
        return host_arch in allowed
    return True


def _iter_deb822_stanzas(text: str) -> list[dict[str, str]]:
    """Parse well-formed deb822 stanzas; skip malformed stanzas cleanly."""
    if "\x00" in text:
        return []
    stanzas: list[list[str]] = []
    current: list[str] = []
    for raw_line in text.splitlines():
        if raw_line.startswith("#"):
            continue
        if not raw_line.strip():
            if current:
                stanzas.append(current)
                current = []
            continue
        current.append(raw_line)
    if current:
        stanzas.append(current)

    parsed: list[dict[str, str]] = []
    for stanza_lines in stanzas:
        fields: dict[str, str] = {}
        last_key: Optional[str] = None
        malformed = False
        for line in stanza_lines:
            if line[0] in (" ", "\t"):
                if last_key is None:
                    malformed = True
                    break
                fields[last_key] = f"{fields[last_key]}\n{line[1:]}"
                continue
            if ":" not in line:
                malformed = True
                break
            raw_key, raw_val = line.split(":", 1)
            key = raw_key.strip().lower()
            if not key or _FIELD_NAME_RE.fullmatch(key) is None or key in fields:
                malformed = True
                break
            fields[key] = raw_val.strip()
            last_key = key
        if not malformed:
            parsed.append(fields)
    return parsed


def _parse_deb822_entries(
    text: str,
    *,
    source_path: str,
    official_uri: Optional[str] = None,
    official_suites: Optional[Iterable[str]] = None,
    official_component: Optional[str] = None,
    keyring_exists: Optional[Callable[[Path], bool]] = None,
) -> list[_ParsedSourceEntry]:
    default_uri, default_suites, default_component, _ = _official_apt_defaults()
    resolved_uri = default_uri if official_uri is None else official_uri
    expected_suites = set(default_suites if official_suites is None else official_suites)
    resolved_component = default_component if official_component is None else official_component
    entries: list[_ParsedSourceEntry] = []

    for fields in _iter_deb822_stanzas(text):
        enabled = fields.get("enabled")
        if enabled is not None and enabled.strip().lower() not in _TRUTHY_APT_VALUES:
            continue

        types = fields.get("types", "").split()
        if "deb" not in types:
            continue

        option_map = {k: [v] for k, v in fields.items()}
        if _has_auth_bypass_options(option_map):
            continue

        raw_arches = fields.get("architectures")
        if raw_arches is not None and not _split_arch_tokens(raw_arches):
            continue
        raw_added = fields.get("architectures-add")
        raw_removed = fields.get("architectures-remove")

        uris = fields.get("uris", "").split()
        if not uris or not all(_uri_matches_official(uri, resolved_uri) for uri in uris):
            continue

        raw_suites = fields.get("suites", "").split()
        if not raw_suites or not all(s in expected_suites for s in raw_suites):
            continue

        components = fields.get("components", "").split()
        if resolved_component not in components:
            continue

        signed_by = _validate_signed_by_deb822(
            fields.get("signed-by", ""),
            keyring_exists=keyring_exists,
        )
        if signed_by is None:
            continue

        def _make_matcher(
            arches: Optional[str] = raw_arches,
            added: Optional[str] = raw_added,
            removed: Optional[str] = raw_removed,
        ) -> Callable[[str], bool]:
            return lambda arch: _arch_matches_deb822(
                arches, arch, raw_added=added, raw_removed=removed,
            )

        entries.append(
            _ParsedSourceEntry(
                source_path=source_path,
                suites=tuple(dict.fromkeys(raw_suites)),
                keyring_paths=signed_by,
                arch_matcher=_make_matcher(),
            )
        )
    return entries


def parse_deb822_sources(
    text: str,
    *,
    source_path: str,
    host_arch: str,
    official_uri: Optional[str] = None,
    official_suites: Optional[Iterable[str]] = None,
    official_component: Optional[str] = None,
    keyring_exists: Optional[Callable[[Path], bool]] = None,
) -> list[AptSourceMatch]:
    """Parse deb822 ``.sources`` text and return validated official Servonaut entries."""
    entries = _parse_deb822_entries(
        text,
        source_path=source_path,
        official_uri=official_uri,
        official_suites=official_suites,
        official_component=official_component,
        keyring_exists=keyring_exists,
    )
    return [
        AptSourceMatch(
            source_path=entry.source_path,
            suites=entry.suites,
            keyring_paths=entry.keyring_paths,
        )
        for entry in entries
        if entry.arch_matcher(host_arch)
    ]


def _parse_oneline_entries(
    text: str,
    *,
    source_path: str,
    official_uri: Optional[str] = None,
    official_suites: Optional[Iterable[str]] = None,
    official_component: Optional[str] = None,
    keyring_exists: Optional[Callable[[Path], bool]] = None,
) -> list[_ParsedSourceEntry]:
    if "\x00" in text:
        return []
    default_uri, default_suites, default_component, _ = _official_apt_defaults()
    resolved_uri = default_uri if official_uri is None else official_uri
    expected_suites = set(default_suites if official_suites is None else official_suites)
    resolved_component = default_component if official_component is None else official_component
    entries: list[_ParsedSourceEntry] = []

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        parts = line.split(None, 1)
        if len(parts) < 2 or parts[0] != "deb":
            continue
        rest = parts[1].lstrip()

        options: dict[str, list[str]] = {}
        arch_exact: list[str] = []
        arch_added: list[str] = []
        arch_removed: list[str] = []

        if rest.startswith("["):
            close_idx = rest.find("]")
            if close_idx == -1:
                continue
            opt_body = rest[1:close_idx]
            if "[" in opt_body:
                continue
            rest = rest[close_idx + 1:].lstrip()
            malformed_opt = False
            for token in opt_body.split():
                if "+=" in token:
                    raw_k, raw_v = token.split("+=", 1)
                    op = "+="
                elif "-=" in token:
                    raw_k, raw_v = token.split("-=", 1)
                    op = "-="
                elif "=" in token:
                    raw_k, raw_v = token.split("=", 1)
                    op = "="
                else:
                    malformed_opt = True
                    break
                key = raw_k.strip().lower()
                val = raw_v.strip()
                if not key or not val:
                    malformed_opt = True
                    break
                if key == "arch":
                    if op == "=":
                        arch_exact.append(val)
                    elif op == "+=":
                        arch_added.append(val)
                    else:
                        arch_removed.append(val)
                else:
                    if op != "=":
                        # Non-arch +/- modifiers on security options are rejected safely.
                        malformed_opt = True
                        break
                    options.setdefault(key, []).append(val)
            if malformed_opt:
                continue

        if _has_auth_bypass_options(options):
            continue

        signed_by = _validate_signed_by_oneline(
            options.get("signed-by", ()),
            keyring_exists=keyring_exists,
        )
        if signed_by is None:
            continue

        positional = rest.split()
        if len(positional) < 3:
            continue
        uri, suite, *components = positional
        if not _uri_matches_official(uri, resolved_uri):
            continue
        if suite not in expected_suites:
            continue
        if resolved_component not in components:
            continue

        def _make_matcher(
            exact: tuple[str, ...] = tuple(arch_exact),
            added: tuple[str, ...] = tuple(arch_added),
            removed: tuple[str, ...] = tuple(arch_removed),
        ) -> Callable[[str], bool]:
            return lambda arch: _arch_matches_oneline(exact, added, removed, arch)

        entries.append(
            _ParsedSourceEntry(
                source_path=source_path,
                suites=(suite,),
                keyring_paths=signed_by,
                arch_matcher=_make_matcher(),
            )
        )
    return entries


def parse_oneline_sources(
    text: str,
    *,
    source_path: str,
    host_arch: str,
    official_uri: Optional[str] = None,
    official_suites: Optional[Iterable[str]] = None,
    official_component: Optional[str] = None,
    keyring_exists: Optional[Callable[[Path], bool]] = None,
) -> list[AptSourceMatch]:
    """Parse one-line ``.list`` text and return validated official Servonaut entries."""
    entries = _parse_oneline_entries(
        text,
        source_path=source_path,
        official_uri=official_uri,
        official_suites=official_suites,
        official_component=official_component,
        keyring_exists=keyring_exists,
    )
    return [
        AptSourceMatch(
            source_path=entry.source_path,
            suites=entry.suites,
            keyring_paths=entry.keyring_paths,
        )
        for entry in entries
        if entry.arch_matcher(host_arch)
    ]


def _read_bounded_utf8(path: Path, *, max_bytes: int) -> Optional[str]:
    """Read a regular UTF-8 text file up to *max_bytes*; return None on limit or error."""
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
    except OSError:
        return None
    if len(raw) > max_bytes or b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _iter_readable_source_files(config: AptDetectionConfig) -> list[tuple[Path, bool, str]]:
    """Read bounded source files from ``sources.list`` and ``sources.list.d``."""
    candidates: list[tuple[Path, bool]] = []
    if _stat_token(config.sources_list_path, follow_symlinks=True) is not None:
        candidates.append((config.sources_list_path, False))
    for path in _list_sourcepart_files(
        config.sources_list_d_path, max_files=config.max_source_files,
    ):
        candidates.append((path, path.name.endswith(".sources")))

    readable: list[tuple[Path, bool, str]] = []
    total_bytes = 0
    for path, is_deb822 in candidates:
        remaining = config.max_total_source_bytes - total_bytes
        if remaining <= 0:
            break
        try:
            st = os.stat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_size > config.max_source_file_bytes:
            continue
        if st.st_size > remaining:
            break
        text = _read_bounded_utf8(path, max_bytes=min(config.max_source_file_bytes, remaining))
        if text is None:
            continue
        total_bytes += len(text.encode("utf-8"))
        readable.append((path, is_deb822, text))
    return readable


def _scan_apt_source_entries(
    config: AptDetectionConfig,
    *,
    keyring_exists: Optional[Callable[[Path], bool]] = None,
) -> list[_ParsedSourceEntry]:
    entries: list[_ParsedSourceEntry] = []
    official_uri = config.resolved_official_uri()
    official_suites = config.resolved_official_suites()
    official_component = config.resolved_official_component()
    for path, is_deb822, text in _iter_readable_source_files(config):
        if is_deb822:
            entries.extend(
                _parse_deb822_entries(
                    text,
                    source_path=str(path),
                    official_uri=official_uri,
                    official_suites=official_suites,
                    official_component=official_component,
                    keyring_exists=keyring_exists,
                )
            )
        else:
            entries.extend(
                _parse_oneline_entries(
                    text,
                    source_path=str(path),
                    official_uri=official_uri,
                    official_suites=official_suites,
                    official_component=official_component,
                    keyring_exists=keyring_exists,
                )
            )
    return entries


def scan_apt_sources(
    config: AptDetectionConfig,
    *,
    host_arch: str,
    keyring_exists: Optional[Callable[[Path], bool]] = None,
) -> list[AptSourceMatch]:
    """Scan ``/etc/apt/sources.list`` and ``/etc/apt/sources.list.d`` with strict bounds."""
    entries = _scan_apt_source_entries(config, keyring_exists=keyring_exists)
    return [
        AptSourceMatch(
            source_path=entry.source_path,
            suites=entry.suites,
            keyring_paths=entry.keyring_paths,
        )
        for entry in entries
        if entry.arch_matcher(host_arch)
    ]


def _probe_apt_status(
    runtime: RuntimeLayout,
    config: AptDetectionConfig,
) -> _ProbeOutcome:
    # Gate 1 (cheap): verify resolved packaged-desktop files, prefix, and root ownership chain.
    verified_files = _resolve_verified_runtime_files(runtime, config)
    if verified_files is None:
        return _ProbeOutcome(
            status=AptInstallStatus(managed=False, dpkg_owned=False, checked=True),
            cacheable=True,
        )
    exe_path, marker_path = verified_files

    # Gate 2 (cheap): parse APT sources BEFORE running any dpkg-query subprocess.
    candidate_entries = _scan_apt_source_entries(config)
    if not candidate_entries:
        return _ProbeOutcome(
            status=AptInstallStatus(managed=False, dpkg_owned=False, checked=True),
            cacheable=True,
        )

    # Gate 3: locate dpkg-query from fixed system paths and check installed state (-W).
    resolved_runner = _resolve_dpkg_runner(config)
    if resolved_runner is None:
        return _ProbeOutcome(
            status=AptInstallStatus(managed=False, dpkg_owned=False, checked=True),
            cacheable=True,
        )
    runner, binary = resolved_runner

    pkg_state = _probe_dpkg_package_state(runner, binary, config)
    if pkg_state.transient_error:
        return _ProbeOutcome(
            status=AptInstallStatus(managed=False, dpkg_owned=False, checked=False),
            cacheable=False,
        )
    if not pkg_state.installed or not pkg_state.architecture:
        return _ProbeOutcome(
            status=AptInstallStatus(managed=False, dpkg_owned=False, checked=True),
            cacheable=True,
            ttl_seconds=config.effective_negative_ttl() if pkg_state.definitive_missing else None,
        )

    # Gate 4: filter parsed source entries against the installed package architecture
    # before paying for dpkg-query -S.
    matched_entries = [
        entry for entry in candidate_entries
        if entry.arch_matcher(pkg_state.architecture)
    ]
    if not matched_entries:
        return _ProbeOutcome(
            status=AptInstallStatus(
                managed=False,
                dpkg_owned=False,
                package_version=pkg_state.package_version,
                architecture=pkg_state.architecture,
                checked=True,
            ),
            cacheable=True,
        )

    # Gate 5: verify exclusive dpkg ownership of both the resolved executable and marker (-S).
    ownership = _probe_dpkg_file_ownership(
        runner,
        binary,
        exe_path,
        marker_path,
        architecture=pkg_state.architecture,
        config=config,
    )
    if ownership.transient_error:
        return _ProbeOutcome(
            status=AptInstallStatus(managed=False, dpkg_owned=False, checked=False),
            cacheable=False,
        )
    if not ownership.owned:
        return _ProbeOutcome(
            status=AptInstallStatus(managed=False, dpkg_owned=False, checked=True),
            cacheable=True,
            ttl_seconds=config.effective_negative_ttl() if ownership.definitive_missing else None,
        )

    all_suites: list[str] = []
    source_paths: list[str] = []
    keyring_paths: list[str] = []
    for entry in matched_entries:
        for suite in entry.suites:
            if suite not in all_suites:
                all_suites.append(suite)
        if entry.source_path not in source_paths:
            source_paths.append(entry.source_path)
        for kp in entry.keyring_paths:
            if kp not in keyring_paths:
                keyring_paths.append(kp)

    # Order deterministically; if candidate is enabled alongside stable, candidate
    # is the rolling superset suite.
    ordered_suites = tuple(sorted(all_suites))
    effective_suite = "candidate" if "candidate" in ordered_suites else ordered_suites[0]
    return _ProbeOutcome(
        status=AptInstallStatus(
            managed=True,
            suite=effective_suite,
            suites=ordered_suites,
            dpkg_owned=True,
            package_version=pkg_state.package_version,
            architecture=pkg_state.architecture,
            source_paths=tuple(source_paths),
            keyring_paths=tuple(keyring_paths),
            checked=True,
        ),
        cacheable=True,
    )
