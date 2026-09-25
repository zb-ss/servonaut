"""Packaged frontend asset verification, route mapping, and CSP policy.

Loads and verifies frontend assets against the immutable assets lock,
computes transformed payloads, and constructs strict CSP headers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Final, Literal
from urllib.parse import urlparse

WEBGL_REGISTRATION: Final[bytes] = (
    b"this.webglAddon=new p.WebglAddon,this.terminal.loadAddon(this.webglAddon),"
)
DEFAULT_FONT_SIZE: Final[int] = 14
MAX_ASSET_BYTES: Final[int] = 4 * 1024 * 1024  # 4 MiB bounded payload

_REMOTE_HOST_RE: Final[re.Pattern[str]] = re.compile(r"https?://", re.IGNORECASE)


class DesktopAssetError(RuntimeError):
    """Raised when asset validation, hash verification, or CSP policy fails."""


def canvas_renderer(source: bytes) -> bytes:
    """Remove redundant WebGL registration from upstream textual.js bundle."""
    count = source.count(WEBGL_REGISTRATION)
    if count != 1:
        raise DesktopAssetError(
            f"Expected exactly 1 WebGL registration in renderer bundle, found {count}"
        )
    return source.replace(WEBGL_REGISTRATION, b"", 1)


def render_index_html(source: bytes, font_size: int = DEFAULT_FONT_SIZE) -> bytes:
    """Substitute template font-size into index.html."""
    placeholder = b"FONT_SIZE"
    if placeholder not in source:
        raise DesktopAssetError("index.html missing 'FONT_SIZE' placeholder")
    return source.replace(placeholder, str(font_size).encode("ascii"), 1)


def build_csp_header(
    origin: str,
    *,
    style_mode: Literal["relaxation", "nonce"] = "relaxation",
    nonce: str | None = None,
) -> str:
    """Construct and validate strict Content-Security-Policy header.

    Policy requirements:
    - default-src 'none'
    - explicit loopback ws:// connect-src matching assigned host/port
    - script-src 'self' only (no inline script, no unsafe-eval, no CDNs)
    - style-src 'self' with reviewed unsafe-inline relaxation OR response nonce
    - font-src 'self'
    - img-src 'self' data:
    - frame-ancestors 'none'
    - base-uri 'none'
    - form-action 'none'
    """
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"}:
        raise DesktopAssetError(
            f"Origin scheme must be http or https, got {parsed.scheme!r}"
        )
    hostname = parsed.hostname
    if hostname not in {"127.0.0.1", "localhost"}:
        raise DesktopAssetError(f"Origin must be loopback, got {hostname!r}")
    port = parsed.port
    if port is None:
        port = 80 if parsed.scheme == "http" else 443

    ws_origin = f"ws://{hostname}:{port}"

    if style_mode == "nonce":
        if not nonce or not re.match(r"^[A-Za-z0-9+/=_-]{16,64}$", nonce):
            raise DesktopAssetError("Valid nonce required for nonce style_mode")
        style_directive = f"style-src 'self' 'nonce-{nonce}'"
    elif style_mode == "relaxation":
        style_directive = "style-src 'self' 'unsafe-inline'"
    else:
        raise DesktopAssetError(f"Unknown style_mode: {style_mode!r}")

    directives = [
        "default-src 'none'",
        "script-src 'self'",
        style_directive,
        "font-src 'self'",
        "img-src 'self' data:",
        f"connect-src {ws_origin}",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'none'",
    ]

    csp = "; ".join(directives)
    validate_csp_header(csp)
    return csp


def validate_csp_header(csp: str) -> None:
    """Validate Content-Security-Policy directives against security requirements."""
    directives = [d.strip() for d in csp.split(";") if d.strip()]
    directive_map: dict[str, list[str]] = {}

    for d in directives:
        parts = d.split()
        if not parts:
            continue
        name = parts[0].lower()
        directive_map[name] = parts[1:]

    if "default-src" not in directive_map:
        raise DesktopAssetError("CSP missing required 'default-src' directive")
    if directive_map["default-src"] != ["'none'"]:
        raise DesktopAssetError(
            f"CSP 'default-src' must be exactly 'none', got {directive_map['default-src']}"
        )

    for name, values in directive_map.items():
        for val in values:
            if val in {"'unsafe-eval'", "unsafe-eval"}:
                raise DesktopAssetError(
                    f"Forbidden unsafe-eval in CSP directive {name}"
                )
            if val == "*":
                raise DesktopAssetError(
                    f"Forbidden wildcard '*' in CSP directive {name}"
                )
            if name == "script-src" and val in {"'unsafe-inline'", "unsafe-inline"}:
                raise DesktopAssetError("Forbidden 'unsafe-inline' in script-src")
            if name in {"script-src", "connect-src"} and val in {"data:", "blob:"}:
                raise DesktopAssetError(f"Forbidden '{val}' in CSP directive {name}")
            if _REMOTE_HOST_RE.match(val):
                raise DesktopAssetError(
                    f"Forbidden remote host in CSP directive {name}: {val}"
                )


def _find_repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    return current.parents[3]


def find_upstream_static_dir() -> Path | None:
    try:
        from importlib import resources

        res = resources.files("textual_serve").joinpath("static")
        p = Path(str(res))
        if p.is_dir():
            return p
    except (ImportError, TypeError, AttributeError):
        pass

    env_dir = os.environ.get("SERVONAUT_TEXTUAL_SERVE_STATIC_DIR")
    if env_dir:
        p = Path(env_dir).resolve()
        if p.is_dir():
            return p

    return None


_find_upstream_static_dir = find_upstream_static_dir


def _is_frozen_bundle() -> bool:
    return bool(getattr(sys, "frozen", False))


def _source_frontend_dir(root: Path, repo: Path) -> Path:
    candidates = [
        root / "packaging" / "desktop_shell" / "frontend",
        root.parent / "packaging" / "desktop_shell" / "frontend",
        root.parent.parent / "packaging" / "desktop_shell" / "frontend",
        repo / "packaging" / "desktop_shell" / "frontend",
        root / "frontend",
    ]
    for c in candidates:
        if (c / "assets.lock.json").is_file():
            return c
    return repo / "packaging" / "desktop_shell" / "frontend"


def load_and_verify_assets(
    frontend_dir: Path | None = None,
    *,
    repo_root: Path | None = None,
) -> tuple[dict[str, tuple[bytes, str]], dict[str, str]]:
    """Load and verify packaged frontend assets against assets.lock.json.

    A frozen bundle trusts only the staged frontend inside its own resource
    root (``repo_root``), never a source checkout it may sit below.

    Returns:
        tuple of (routes_map, manifest_dict) where routes_map maps:
        exact route -> (bytes_content, content_type_str).

    Raises:
        DesktopAssetError: If any asset is missing, tampered, or invalid.
    """
    frozen = _is_frozen_bundle()
    if frozen and frontend_dir is None and repo_root is None:
        raise DesktopAssetError("A frozen bundle must name its resource root")
    repo = _find_repo_root()
    root = repo_root or repo
    base_dir = frontend_dir
    if base_dir is None:
        base_dir = root / "frontend" if frozen else _source_frontend_dir(root, repo)

    lock_file = base_dir / "assets.lock.json"
    if not lock_file.is_file():
        raise DesktopAssetError(f"Assets lock not found: {lock_file}")

    try:
        lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
    except Exception as error:
        raise DesktopAssetError(f"Failed to parse assets lock: {error}") from error

    if lock_data.get("schema_version") != 1:
        raise DesktopAssetError("Unsupported assets.lock.json schema version")

    assets_lock: dict[str, dict[str, object]] = lock_data.get("assets", {})
    if not assets_lock:
        raise DesktopAssetError("Empty assets section in assets.lock.json")

    licenses_file = base_dir / "licenses.json"
    if not licenses_file.is_file() and not frozen:
        licenses_file = (
            repo / "packaging" / "desktop_shell" / "frontend" / "licenses.json"
        )
    if not licenses_file.is_file():
        raise DesktopAssetError(f"Licenses file not found: {licenses_file}")

    try:
        licenses_data = json.loads(licenses_file.read_text(encoding="utf-8"))
    except Exception as error:
        raise DesktopAssetError(f"Failed to parse licenses.json: {error}") from error

    declared_licenses = set(licenses_data.get("licenses", {}).keys())
    for asset_name, item in assets_lock.items():
        lic = item.get("license")
        if lic not in declared_licenses:
            raise DesktopAssetError(
                f"Asset {asset_name} references undeclared license {lic!r}"
            )

    upstream_dir = _find_upstream_static_dir()

    routes: dict[str, tuple[bytes, str]] = {}
    manifest: dict[str, str] = {}

    is_staged_dir = (base_dir / "manifest.json").is_file()
    if frozen and not is_staged_dir:
        raise DesktopAssetError(f"Frozen bundle frontend is not staged: {base_dir}")

    if is_staged_dir:
        expected_files = set(assets_lock.keys()) | {
            "manifest.json",
            "assets.lock.json",
            "licenses.json",
        }
        actual_files = {p.name for p in base_dir.iterdir()}
        unlisted = actual_files - expected_files
        if unlisted:
            raise DesktopAssetError(
                f"Unlisted files in staged frontend directory: {sorted(unlisted)}"
            )
        missing_files = set(assets_lock.keys()) - actual_files
        if missing_files:
            raise DesktopAssetError(f"Missing staged assets: {sorted(missing_files)}")

        for p in base_dir.iterdir():
            if p.is_symlink():
                raise DesktopAssetError(f"Symlink rejected in staged assets: {p.name}")

    for asset_name, item in sorted(assets_lock.items()):
        route = str(item["route"])
        content_type = str(item["content_type"])
        expected_source_sha = str(item["source_sha256"])
        expected_source_size = int(item["source_size"])
        expected_trans_sha = str(item["transformed_sha256"])
        expected_trans_size = int(item["transformed_size"])
        transform_name = item.get("transform")

        if is_staged_dir and (base_dir / asset_name).is_file():
            file_path = base_dir / asset_name
            if file_path.is_symlink():
                raise DesktopAssetError(f"Symlink rejected: {file_path}")
            transformed_bytes = file_path.read_bytes()
            if len(transformed_bytes) > MAX_ASSET_BYTES:
                raise DesktopAssetError(f"Asset {asset_name} exceeds size limit")
            actual_sha = hashlib.sha256(transformed_bytes).hexdigest()
            if actual_sha != expected_trans_sha:
                raise DesktopAssetError(
                    f"Staged hash mismatch for {asset_name}: "
                    f"expected {expected_trans_sha}, got {actual_sha}"
                )
            if len(transformed_bytes) != expected_trans_size:
                raise DesktopAssetError(
                    f"Staged size mismatch for {asset_name}: "
                    f"expected {expected_trans_size}, got {len(transformed_bytes)}"
                )
        else:
            # Source mode
            source_spec = str(item["source"])
            if source_spec.startswith("packaging/"):
                src_file = repo / source_spec
                if not src_file.is_file():
                    src_file = root / source_spec
                if not src_file.is_file():
                    raise DesktopAssetError(f"Missing source asset: {src_file}")
                source_bytes = src_file.read_bytes()
            elif source_spec.startswith("textual_serve:"):
                rel = source_spec.split("textual_serve:", 1)[1]
                if rel.startswith("static/"):
                    rel = rel.split("static/", 1)[1]
                if upstream_dir is None:
                    raise DesktopAssetError(
                        f"Upstream textual_serve static dir not found for {asset_name}"
                    )
                src_file = upstream_dir / rel
                if not src_file.is_file():
                    raise DesktopAssetError(f"Missing upstream source: {src_file}")
                source_bytes = src_file.read_bytes()
            else:
                raise DesktopAssetError(f"Unknown source spec: {source_spec}")

            if len(source_bytes) > MAX_ASSET_BYTES:
                raise DesktopAssetError(f"Asset {asset_name} exceeds size limit")

            actual_src_sha = hashlib.sha256(source_bytes).hexdigest()
            if actual_src_sha != expected_source_sha:
                raise DesktopAssetError(
                    f"Source hash mismatch for {asset_name}: "
                    f"expected {expected_source_sha}, got {actual_src_sha}"
                )
            if len(source_bytes) != expected_source_size:
                raise DesktopAssetError(
                    f"Source size mismatch for {asset_name}: "
                    f"expected {expected_source_size}, got {len(source_bytes)}"
                )

            if transform_name == "canvas_renderer_no_webgl":
                transformed_bytes = canvas_renderer(source_bytes)
            elif transform_name == "template_font_size":
                transformed_bytes = render_index_html(source_bytes)
            elif transform_name is None:
                transformed_bytes = source_bytes
            else:
                raise DesktopAssetError(f"Unknown transform: {transform_name}")

            actual_trans_sha = hashlib.sha256(transformed_bytes).hexdigest()
            if actual_trans_sha != expected_trans_sha:
                raise DesktopAssetError(
                    f"Transformed hash mismatch for {asset_name}: "
                    f"expected {expected_trans_sha}, got {actual_trans_sha}"
                )
            if len(transformed_bytes) != expected_trans_size:
                raise DesktopAssetError(
                    f"Transformed size mismatch for {asset_name}: "
                    f"expected {expected_trans_size}, got {len(transformed_bytes)}"
                )

        routes[route] = (transformed_bytes, content_type)
        manifest[route] = expected_trans_sha

        # Alias "/" and "/index.html"
        if route == "/":
            routes["/index.html"] = (transformed_bytes, content_type)
            manifest["/index.html"] = expected_trans_sha

    # Add /licenses.json route
    licenses_bytes = licenses_file.read_bytes()
    licenses_sha = hashlib.sha256(licenses_bytes).hexdigest()
    routes["/licenses.json"] = (licenses_bytes, "application/json; charset=utf-8")
    manifest["/licenses.json"] = licenses_sha

    return routes, manifest
