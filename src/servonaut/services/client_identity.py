"""Process-level client identity, version header, and update-required copy.

The running version is captured once at startup and never re-read from package
metadata later in the process lifetime, so an in-place upgrade performed by
another process cannot cause running code to report a newer version than the
modules it actually loaded.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Final, Optional

from servonaut import __version__, get_version
from servonaut.runtime import DistributionKind, RuntimeLayout
from servonaut.services.version_policy import (
    DEFAULT_UPDATE_URL,
    _terminal_safe,
    normalize_public_version,
    parse_contract_version,
    safe_update_url,
)

if TYPE_CHECKING:
    from servonaut.updates.apt import AptDetectionConfig

CLIENT_HEADER_NAME: Final = "X-Servonaut-Client"
VALID_CLIENT_CHANNELS: Final = frozenset({"stable", "rc"})
VALID_CLIENT_KINDS: Final = frozenset({"cli", "desktop", "relay", "mcp"})

_UPGRADE_HEADER_RE: Final = re.compile(r"servonaut/([^\s,;]+)", re.IGNORECASE)
_MARKER_FILENAME: Final = "servonaut-runtime.json"


def _capture_startup_version() -> str:
    """Capture and normalize the running version once at startup."""
    raw = get_version()
    normalized = normalize_public_version(raw)
    if normalized is not None:
        return normalized
    fallback = normalize_public_version(__version__)
    return fallback if fallback is not None else __version__


# Captured once when this module first loads; never re-queries package metadata.
_STARTUP_VERSION: Final[str] = _capture_startup_version()


def _normalize_kind(kind: Optional[str]) -> str:
    if not isinstance(kind, str):
        return "cli"
    cleaned = kind.strip().lower()
    if cleaned == "tui":
        return "cli"
    if cleaned in VALID_CLIENT_KINDS:
        return cleaned
    return "cli"


def _chosen_desktop_channel(runtime: RuntimeLayout) -> Optional[str]:
    """The channel a packaged desktop user picked, which outranks the build's."""
    if getattr(runtime, "kind", None) is not DistributionKind.PACKAGED_DESKTOP:
        return None
    data_root = getattr(runtime, "data_root", None)
    if data_root is None:
        return None
    from servonaut.updates.channel_preference import read_channel_preference

    return read_channel_preference(data_root)


def _derive_channel(
    version: str,
    *,
    explicit_channel: Optional[str] = None,
    runtime: Optional[RuntimeLayout] = None,
) -> str:
    if isinstance(explicit_channel, str):
        cleaned = explicit_channel.strip().lower()
        if cleaned == "preview":
            return "rc"
        if cleaned in VALID_CLIENT_CHANNELS:
            return cleaned
    if runtime is not None:
        chosen = _chosen_desktop_channel(runtime)
        if chosen is not None:
            return chosen
        if getattr(runtime, "release_channel", None) == "preview":
            return "rc"
    parsed = parse_contract_version(version)
    if parsed is not None and parsed.is_prerelease:
        return "rc"
    return "stable"


@dataclass(frozen=True)
class ClientIdentity:
    """Immutable running client identity captured for HTTP headers."""

    version: str
    channel: str
    kind: str
    install_kind: Optional[DistributionKind] = None

    def header_value(self, *, kind: Optional[str] = None) -> str:
        """Format ``X-Servonaut-Client`` for this identity (or an explicit *kind*)."""
        resolved_kind = _normalize_kind(kind) if kind is not None else self.kind
        return _terminal_safe(
            f"{self.version}; channel={self.channel}; kind={resolved_kind}"
        ).strip()

    def user_agent(self) -> str:
        """Return the matching ``User-Agent`` value using the captured version."""
        raw = f"servonaut-cli/{self.version}" if self.version else "servonaut-cli"
        return _terminal_safe(raw).strip()


_IDENTITY_LOCK = threading.Lock()
_CURRENT_IDENTITY: Optional[ClientIdentity] = None
_CURRENT_RUNTIME: Optional[RuntimeLayout] = None
_ALLOW_LAZY_APT_PROBE: bool = False


def configure_client_identity(
    *,
    kind: str = "cli",
    runtime: Optional[RuntimeLayout] = None,
    channel: Optional[str] = None,
    version: Optional[str] = None,
    allow_lazy_apt_probe: Optional[bool] = None,
) -> ClientIdentity:
    """Set the process-wide client identity from startup facts.

    Uses the startup-captured version (or *runtime*'s product version when
    supplied) and never re-reads ``importlib.metadata``.
    """
    runtime_version = getattr(runtime, "product_version", None) if runtime is not None else None
    raw_version = (
        version
        if version is not None
        else (runtime_version if isinstance(runtime_version, str) and runtime_version else _STARTUP_VERSION)
    )
    resolved_version = normalize_public_version(raw_version) or _STARTUP_VERSION
    resolved_kind = _normalize_kind(kind)
    resolved_channel = _derive_channel(
        resolved_version,
        explicit_channel=channel,
        runtime=runtime,
    )
    raw_install_kind = getattr(runtime, "kind", None) if runtime is not None else None
    install_kind = raw_install_kind if isinstance(raw_install_kind, DistributionKind) else None
    with _IDENTITY_LOCK:
        global _CURRENT_IDENTITY, _CURRENT_RUNTIME, _ALLOW_LAZY_APT_PROBE
        if install_kind is None and _CURRENT_IDENTITY is not None:
            install_kind = _CURRENT_IDENTITY.install_kind
        if runtime is not None:
            _CURRENT_RUNTIME = runtime
        if allow_lazy_apt_probe is not None:
            _ALLOW_LAZY_APT_PROBE = allow_lazy_apt_probe
        identity = ClientIdentity(
            version=resolved_version,
            channel=resolved_channel,
            kind=resolved_kind,
            install_kind=install_kind,
        )
        _CURRENT_IDENTITY = identity
        return identity


def get_client_identity(*, kind: Optional[str] = None) -> ClientIdentity:
    """Return the process's captured :class:`ClientIdentity`."""
    with _IDENTITY_LOCK:
        global _CURRENT_IDENTITY
        if _CURRENT_IDENTITY is None:
            _CURRENT_IDENTITY = ClientIdentity(
                version=_STARTUP_VERSION,
                channel=_derive_channel(_STARTUP_VERSION),
                kind="cli",
            )
        identity = _CURRENT_IDENTITY
    if kind is not None:
        resolved_kind = _normalize_kind(kind)
        if resolved_kind != identity.kind:
            return ClientIdentity(
                version=identity.version,
                channel=identity.channel,
                kind=resolved_kind,
                install_kind=identity.install_kind,
            )
    return identity


def client_header_value(*, kind: Optional[str] = None) -> str:
    """Return the ``X-Servonaut-Client`` header value for this process."""
    return get_client_identity().header_value(kind=kind)


def client_request_headers(
    *,
    kind: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, str]:
    """Build standard ``User-Agent`` and ``X-Servonaut-Client`` headers."""
    identity = get_client_identity()
    return {
        "User-Agent": user_agent if user_agent is not None else identity.user_agent(),
        CLIENT_HEADER_NAME: identity.header_value(kind=kind),
    }


def reset_client_identity_for_tests() -> None:
    """Clear the configured process identity and APT cache (test isolation helper)."""
    with _IDENTITY_LOCK:
        global _CURRENT_IDENTITY, _CURRENT_RUNTIME, _ALLOW_LAZY_APT_PROBE
        _CURRENT_IDENTITY = None
        _CURRENT_RUNTIME = None
        _ALLOW_LAZY_APT_PROBE = False
    apt_module = sys.modules.get("servonaut.updates.apt")
    if apt_module is not None:
        apt_module.reset_apt_status_cache_for_tests()


def parse_upgrade_header(value: object) -> str:
    """Extract a normalized version from an HTTP ``Upgrade: servonaut/<ver>`` header."""
    if not isinstance(value, str) or not value.strip():
        return ""
    match = _UPGRADE_HEADER_RE.search(value)
    if match is None:
        return ""
    return normalize_public_version(match.group(1)) or ""


def detect_install_kind_fast(
    runtime: Optional[RuntimeLayout] = None,
) -> Optional[DistributionKind]:
    """Resolve install kind without spawning subprocesses (e.g. pipx).

    Uses *runtime* when supplied, else the install kind captured at startup,
    else a fast path/marker inspection suitable for error formatting paths.
    """
    if runtime is not None:
        raw_kind = getattr(runtime, "kind", None)
        if isinstance(raw_kind, DistributionKind):
            return raw_kind
    captured = get_client_identity().install_kind
    if captured is not None:
        return captured

    try:
        exe = Path(sys.executable)
        marker_path = exe.parent / _MARKER_FILENAME
        if marker_path.is_file():
            data = json.loads(marker_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                dist = data.get("distribution")
                if dist == DistributionKind.PACKAGED_DESKTOP.value:
                    return DistributionKind.PACKAGED_DESKTOP
                if dist == DistributionKind.FROZEN_CLI.value:
                    return DistributionKind.FROZEN_CLI
    except Exception:  # noqa: BLE001 — heuristic must never raise
        pass

    if getattr(sys, "frozen", False):
        return DistributionKind.FROZEN_CLI

    try:
        exe_parts = [part.lower() for part in Path(sys.executable).parts]
        if "pipx" in exe_parts and "venvs" in exe_parts:
            return DistributionKind.PIPX
        pipx_venvs = os.environ.get("PIPX_LOCAL_VENVS", "").strip()
        if pipx_venvs:
            try:
                Path(sys.executable).resolve().relative_to(Path(pipx_venvs).resolve())
                return DistributionKind.PIPX
            except ValueError:
                pass
    except OSError:
        pass

    return None


_APT_UPGRADE_CMD: Final = "sudo apt update && sudo apt install --only-upgrade servonaut"


def _header_case_insensitive(headers: Any, name: str) -> Optional[str]:
    """Return the value of *name* from a mapping/headers object case-insensitively."""
    if headers is None:
        return None
    target = name.lower()
    if isinstance(headers, Mapping):
        for key, value in headers.items():
            if isinstance(key, str) and key.lower() == target and isinstance(value, str):
                return value
        return None
    getter = getattr(headers, "get", None)
    if callable(getter):
        val = getter(name) or getter(target) or getter(name.title())
        if isinstance(val, str):
            return val
    return None


def is_apt_managed_install(
    *,
    runtime: Optional[RuntimeLayout] = None,
    platform_name: Optional[str] = None,
    allow_probe: bool = False,
    config: Optional[AptDetectionConfig] = None,
) -> bool:
    """Return True only when cached (or probed) dpkg + APT source facts agree.

    By default (``allow_probe=False``) this reads the in-memory cache populated
    off the UI and HTTP paths, performing no filesystem or subprocess I/O.
    Standalone Linux ``.deb`` installs, non-Linux hosts, non-packaged runtimes
    (pipx/pip/source/frozen-cli), and incomplete evidence all return ``False``
    so callers fall back to the standard download guidance.
    """
    plat = (platform_name if platform_name is not None else sys.platform).lower()
    if not plat.startswith("linux"):
        return False
    if runtime is not None and (
        getattr(runtime, "kind", None) is not DistributionKind.PACKAGED_DESKTOP
        or not bool(getattr(runtime, "is_frozen", False))
    ):
        return False
    if allow_probe:
        from servonaut.updates.apt import refresh_apt_status

        return refresh_apt_status(runtime=runtime, platform_name=plat, config=config).managed
    from servonaut.updates.apt import get_cached_apt_status

    cached = get_cached_apt_status(runtime=runtime, platform_name=plat, config=config)
    return bool(cached is not None and cached.managed)


def _sanitize_update_hints(raw: Any) -> Dict[str, str]:
    """Extract terminal-safe non-empty string hints from a mapping."""
    if not isinstance(raw, Mapping):
        return {}
    cleaned: Dict[str, str] = {}
    for key, val in raw.items():
        if not isinstance(key, str) or not isinstance(val, str):
            continue
        safe_key = _terminal_safe(key).strip().lower()
        safe_val = _terminal_safe(val).strip()
        if safe_key and safe_val:
            cleaned[safe_key] = safe_val
    return cleaned


def _resolve_apt_for_426(
    *,
    runtime: Optional[RuntimeLayout],
    platform_name: str,
    apt_managed: Optional[bool],
    allow_lazy_probe: bool,
) -> bool:
    if apt_managed is not None:
        return apt_managed
    from servonaut.updates.apt import get_cached_apt_status

    cached = get_cached_apt_status(runtime=runtime, platform_name=platform_name)
    if cached is not None:
        return cached.managed
    if allow_lazy_probe and runtime is not None:
        return is_apt_managed_install(
            runtime=runtime, platform_name=platform_name, allow_probe=True,
        )
    return is_apt_managed_install(runtime=runtime, platform_name=platform_name)


def _install_hint_key(
    install_kind: Optional[DistributionKind | str] = None,
    *,
    runtime: Optional[RuntimeLayout] = None,
    platform_name: Optional[str] = None,
    apt_managed: Optional[bool] = None,
    allow_lazy_probe: bool = False,
) -> Optional[str]:
    """Map an install kind to its server ``update_hints`` key."""
    if install_kind == "apt":
        return "apt"
    if isinstance(install_kind, str):
        try:
            install_kind = DistributionKind(install_kind)
        except ValueError:
            return None
    if install_kind is DistributionKind.PIPX:
        return "pipx"
    if install_kind is DistributionKind.PIP:
        return "pip"
    if install_kind is DistributionKind.SOURCE:
        return "source"
    if install_kind is DistributionKind.PACKAGED_DESKTOP:
        plat = (platform_name if platform_name is not None else sys.platform).lower()
        if plat.startswith("linux"):
            if _resolve_apt_for_426(
                runtime=runtime,
                platform_name=plat,
                apt_managed=apt_managed,
                allow_lazy_probe=allow_lazy_probe,
            ):
                return "apt"
        return "desktop"
    if install_kind is DistributionKind.FROZEN_CLI:
        return "desktop"
    return None


def install_update_step(
    install_kind: Optional[DistributionKind | str] = None,
    *,
    runtime: Optional[RuntimeLayout] = None,
    platform_name: Optional[str] = None,
    update_url: Optional[str] = None,
    apt_managed: Optional[bool] = None,
    allow_lazy_probe: bool = False,
) -> str:
    """Return the install-specific remediation step for an update-required error."""
    resolved_url = safe_update_url(update_url, fallback=DEFAULT_UPDATE_URL)
    plat = (platform_name if platform_name is not None else sys.platform).lower()

    if install_kind == "apt":
        return f"run: {_APT_UPGRADE_CMD}"
    if isinstance(install_kind, str):
        try:
            install_kind = DistributionKind(install_kind)
        except ValueError:
            install_kind = None

    if install_kind is DistributionKind.PIPX:
        return "run: pipx upgrade servonaut"
    if install_kind is DistributionKind.PIP:
        return "run: pip install --upgrade servonaut"
    if install_kind is DistributionKind.PACKAGED_DESKTOP:
        if plat.startswith("linux"):
            if _resolve_apt_for_426(
                runtime=runtime,
                platform_name=plat,
                apt_managed=apt_managed,
                allow_lazy_probe=allow_lazy_probe,
            ):
                return f"run: {_APT_UPGRADE_CMD}"
        return f"download: {resolved_url}"
    if install_kind is DistributionKind.FROZEN_CLI:
        return f"download: {resolved_url}"
    if install_kind is DistributionKind.SOURCE:
        return "update your source checkout and reinstall"
    return f"update at {resolved_url}"


def _extract_update_context(
    error_or_version: Any,
) -> tuple[str, str, Dict[str, str]]:
    """Pull validated ``(minimum_version, update_url, update_hints)``."""
    if error_or_version is None:
        return "", DEFAULT_UPDATE_URL, {}
    if isinstance(error_or_version, str):
        return normalize_public_version(error_or_version) or "", DEFAULT_UPDATE_URL, {}

    details = getattr(error_or_version, "details", None)
    details_map = details if isinstance(details, Mapping) else {}

    min_ver = normalize_public_version(getattr(error_or_version, "minimum_version", None)) or ""
    if not min_ver:
        min_ver = normalize_public_version(details_map.get("minimum_version")) or ""
    if not min_ver:
        headers = getattr(error_or_version, "response_headers", None)
        min_ver = parse_upgrade_header(_header_case_insensitive(headers, "upgrade"))

    raw_url = getattr(error_or_version, "update_url", None) or details_map.get("update_url")
    hints = _sanitize_update_hints(details_map.get("update_hints"))
    hints.update(_sanitize_update_hints(getattr(error_or_version, "update_hints", None)))
    return min_ver, safe_update_url(raw_url, fallback=DEFAULT_UPDATE_URL), hints


def format_update_required_message(
    error_or_version: Any = None,
    *,
    runtime: Optional[RuntimeLayout] = None,
    install_kind: Optional[DistributionKind | str] = None,
    platform_name: Optional[str] = None,
    update_url: Optional[str] = None,
    update_hints: Optional[Mapping[str, str]] = None,
    apt_managed: Optional[bool] = None,
    client_kind: Optional[str] = None,
) -> str:
    """Build one consistent, terminal-safe update-required message."""
    min_ver, extracted_url, extracted_hints = _extract_update_context(error_or_version)
    resolved_url = safe_update_url(update_url, fallback=extracted_url)
    resolved_install: Optional[DistributionKind | str] = (
        install_kind if install_kind is not None else detect_install_kind_fast(runtime)
    )
    merged_hints = dict(extracted_hints)
    merged_hints.update(_sanitize_update_hints(update_hints))

    with _IDENTITY_LOCK:
        captured_runtime = _CURRENT_RUNTIME
        lazy_probe = _ALLOW_LAZY_APT_PROBE
    effective_runtime = runtime if runtime is not None else captured_runtime

    hint_key = _install_hint_key(
        resolved_install,
        runtime=effective_runtime,
        platform_name=platform_name,
        apt_managed=apt_managed,
        allow_lazy_probe=lazy_probe,
    )
    step = (
        merged_hints[hint_key]
        if hint_key is not None and hint_key in merged_hints
        else install_update_step(
            resolved_install,
            runtime=effective_runtime,
            platform_name=platform_name,
            update_url=resolved_url,
            apt_managed=apt_managed,
            allow_lazy_probe=lazy_probe,
        )
    )
    if min_ver:
        message = (
            "This version of Servonaut is too old for team and cloud features. "
            f"Update to {min_ver} or later to continue ({step})."
        )
    else:
        message = (
            "This version of Servonaut is too old for team and cloud features. "
            f"Update Servonaut to continue ({step})."
        )
    if client_kind == "mcp":
        message += " Reconnect the MCP server after updating."
    elif client_kind == "relay":
        message += " Restart the relay after updating."
    return _terminal_safe(message)


def format_update_required_from_response(
    response: Any,
    *,
    runtime: Optional[RuntimeLayout] = None,
    install_kind: Optional[DistributionKind | str] = None,
    platform_name: Optional[str] = None,
    apt_managed: Optional[bool] = None,
) -> str:
    """Extract version details from an HTTP 426 response and format the message."""
    min_ver = ""
    update_url = DEFAULT_UPDATE_URL
    update_hints: Dict[str, str] = {}
    try:
        body = response.json()
    except Exception:  # noqa: BLE001 — tolerate plain text / HTML / empty bodies
        body = None
    if isinstance(body, Mapping):
        err_obj = body.get("error")
        if isinstance(err_obj, Mapping):
            details = err_obj.get("details")
            if isinstance(details, Mapping):
                min_ver = normalize_public_version(details.get("minimum_version")) or ""
                update_url = safe_update_url(details.get("update_url"), fallback=DEFAULT_UPDATE_URL)
                update_hints = _sanitize_update_hints(details.get("update_hints"))
        elif isinstance(err_obj, str):
            min_ver = normalize_public_version(body.get("minimum_version")) or ""
            update_url = safe_update_url(body.get("update_url"), fallback=DEFAULT_UPDATE_URL)
            update_hints = _sanitize_update_hints(body.get("update_hints"))

    if not min_ver:
        headers = getattr(response, "headers", None)
        min_ver = parse_upgrade_header(_header_case_insensitive(headers, "upgrade"))

    return format_update_required_message(
        min_ver,
        runtime=runtime,
        install_kind=install_kind,
        platform_name=platform_name,
        update_url=update_url,
        update_hints=update_hints,
        apt_managed=apt_managed,
    )


def response_is_update_required(response: Any) -> bool:
    """True only when an HTTP response carries a genuine client-update-required signal.

    A genuine signal is either an error envelope with code
    ``client_update_required`` (nested or flat), or HTTP 426 carrying an
    ``Upgrade: servonaut/<version>`` header. A bare or proxy HTTP 426 without
    either marker returns ``False``.
    """
    status = getattr(response, "status_code", None)
    if not isinstance(status, int) or status < 400:
        return False
    try:
        body = response.json()
    except Exception:  # noqa: BLE001
        body = None
    if isinstance(body, Mapping):
        err_obj = body.get("error")
        if isinstance(err_obj, Mapping) and err_obj.get("code") == "client_update_required":
            return True
        if isinstance(err_obj, str) and err_obj == "client_update_required":
            return True
    if status == 426:
        headers = getattr(response, "headers", None)
        if parse_upgrade_header(_header_case_insensitive(headers, "upgrade")):
            return True
    return False
