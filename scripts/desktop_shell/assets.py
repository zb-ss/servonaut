"""Packaged desktop frontend staging, transforms, hashing, and CSP policy."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from .model import (
    DesktopPolicyValidationError,
    load_assets_lock,
    load_frontend_licenses,
)

WEBGL_REGISTRATION = (
    b"this.webglAddon=new p.WebglAddon,this.terminal.loadAddon(this.webglAddon),"
)

_FORBIDDEN_CSP_TERMS = frozenset(
    {
        "'unsafe-eval'",
        "unsafe-eval",
        "*",
        "data:",  # in script-src/connect-src
        "blob:",
    }
)

_REMOTE_HOST_RE = re.compile(r"https?://", re.IGNORECASE)

_FRONTEND_POLICY_DIR = (
    Path(__file__).resolve().parents[2] / "packaging" / "desktop_shell" / "frontend"
)
_MANIFEST_NAME = "manifest.json"
_LOCK_NAME = "assets.lock.json"
_LICENSES_NAME = "licenses.json"


class AssetPolicyError(DesktopPolicyValidationError):
    """Raised when asset validation, transform, staging, or CSP policy fails."""


@dataclass(frozen=True)
class StagedFrontend:
    """Staged frontend runtime assets verified against exact locks."""

    staged_dir: Path
    assets: dict[str, tuple[bytes, str]]
    manifest: dict[str, str]
    csp_header: str


def canvas_renderer(source: bytes) -> bytes:
    """Remove redundant WebGL registration from upstream textual-serve bundle."""
    count = source.count(WEBGL_REGISTRATION)
    if count != 1:
        raise AssetPolicyError(
            f"Expected exactly 1 WebGL registration in renderer bundle, found {count}"
        )
    return source.replace(WEBGL_REGISTRATION, b"", 1)


def render_index_html(source: bytes, font_size: int = 14) -> bytes:
    """Substitute template font-size into index.html."""
    placeholder = b"FONT_SIZE"
    if placeholder not in source:
        raise AssetPolicyError("index.html missing 'FONT_SIZE' placeholder")
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
    """
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"}:
        raise AssetPolicyError(
            f"Origin scheme must be http or https, got {parsed.scheme!r}"
        )
    hostname = parsed.hostname
    if hostname not in {"127.0.0.1", "localhost"}:
        raise AssetPolicyError(f"Origin must be loopback, got {hostname!r}")
    port = parsed.port
    if port is None:
        port = 80 if parsed.scheme == "http" else 443

    ws_origin = f"ws://{hostname}:{port}"

    if style_mode == "nonce":
        if not nonce or not re.match(r"^[A-Za-z0-9+/=_-]{16,64}$", nonce):
            raise AssetPolicyError("Valid nonce required for nonce style_mode")
        style_directive = f"style-src 'self' 'nonce-{nonce}'"
    elif style_mode == "relaxation":
        style_directive = "style-src 'self' 'unsafe-inline'"
    else:
        raise AssetPolicyError(f"Unknown style_mode: {style_mode!r}")

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
        raise AssetPolicyError("CSP missing required 'default-src' directive")
    if directive_map["default-src"] != ["'none'"]:
        raise AssetPolicyError(
            f"CSP 'default-src' must be exactly 'none', got {directive_map['default-src']}"
        )

    for name, values in directive_map.items():
        for val in values:
            if val in {"'unsafe-eval'", "unsafe-eval"}:
                raise AssetPolicyError(f"Forbidden unsafe-eval in CSP directive {name}")
            if val == "*":
                raise AssetPolicyError(
                    f"Forbidden wildcard '*' in CSP directive {name}"
                )
            if name == "script-src" and val in {"'unsafe-inline'", "unsafe-inline"}:
                raise AssetPolicyError("Forbidden 'unsafe-inline' in script-src")
            if _REMOTE_HOST_RE.match(val):
                raise AssetPolicyError(
                    f"Forbidden remote host in CSP directive {name}: {val}"
                )


def find_upstream_static_dir(custom_path: Path | None = None) -> Path | None:
    """Attempt to locate upstream textual-serve static assets directory."""
    if custom_path is not None:
        resolved = custom_path.resolve()
        if resolved.is_dir():
            return resolved

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


def stage_frontend_assets(
    target_dir: Path,
    *,
    lock_path: Path | None = None,
    licenses_path: Path | None = None,
    upstream_source_dir: Path | None = None,
    font_size: int = 14,
    origin: str = "http://127.0.0.1:0",
    style_mode: Literal["relaxation", "nonce"] = "relaxation",
    nonce: str | None = None,
) -> StagedFrontend:
    """Stage, transform, and verify frontend assets into target_dir.

    The staged directory also carries the lock and license inventory, which the
    packaged runtime needs to verify and serve the assets.
    """
    lock_file = lock_path or _FRONTEND_POLICY_DIR / _LOCK_NAME
    licenses_file = licenses_path or _FRONTEND_POLICY_DIR / _LICENSES_NAME
    locks = load_assets_lock(lock_file)
    licenses = load_frontend_licenses(licenses_file)

    reserved = set(locks) & {_MANIFEST_NAME, _LOCK_NAME, _LICENSES_NAME}
    if reserved:
        raise AssetPolicyError(
            f"Asset names collide with staged files: {sorted(reserved)}"
        )

    for asset_name, asset_lock in locks.items():
        if asset_lock.license_id not in licenses:
            raise AssetPolicyError(
                f"Asset {asset_name} references undeclared license {asset_lock.license_id!r}"
            )

    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    repo_root = Path(__file__).resolve().parents[2]
    upstream_dir = find_upstream_static_dir(upstream_source_dir)

    staged_assets: dict[str, tuple[bytes, str]] = {}
    manifest: dict[str, str] = {}

    for asset_name, lock in sorted(locks.items()):
        source_data: bytes
        if lock.source.startswith("packaging/"):
            source_file = repo_root / lock.source
            if not source_file.is_file():
                raise AssetPolicyError(f"Missing packaged source asset: {source_file}")
            source_data = source_file.read_bytes()
            if source_file.suffix in {".js", ".html", ".css", ".json"}:
                source_data = source_data.replace(b"\r\n", b"\n")
        elif lock.source.startswith("textual_serve:"):
            rel = lock.source.split("textual_serve:", 1)[1]
            if rel.startswith("static/"):
                rel = rel.split("static/", 1)[1]
            if upstream_dir is None:
                raise AssetPolicyError(
                    f"Upstream static directory not found for asset {asset_name}"
                )
            source_file = upstream_dir / rel
            if not source_file.is_file():
                raise AssetPolicyError(f"Missing upstream source asset: {source_file}")
            source_data = source_file.read_bytes()
        else:
            raise AssetPolicyError(f"Unknown source prefix in lock: {lock.source}")

        actual_source_sha = hashlib.sha256(source_data).hexdigest()
        if actual_source_sha != lock.source_sha256:
            raise AssetPolicyError(
                f"Source hash mismatch for {asset_name}: expected {lock.source_sha256}, got {actual_source_sha}"
            )
        if len(source_data) != lock.source_size:
            raise AssetPolicyError(
                f"Source size mismatch for {asset_name}: expected {lock.source_size}, got {len(source_data)}"
            )

        transformed: bytes
        if lock.transform == "canvas_renderer_no_webgl":
            transformed = canvas_renderer(source_data)
        elif lock.transform == "template_font_size":
            transformed = render_index_html(source_data, font_size=font_size)
        elif lock.transform is None:
            transformed = source_data
        else:
            raise AssetPolicyError(
                f"Unknown transform {lock.transform!r} for {asset_name}"
            )

        actual_trans_sha = hashlib.sha256(transformed).hexdigest()
        if actual_trans_sha != lock.transformed_sha256:
            raise AssetPolicyError(
                f"Transformed hash mismatch for {asset_name}: expected {lock.transformed_sha256}, got {actual_trans_sha}"
            )
        if len(transformed) != lock.transformed_size:
            raise AssetPolicyError(
                f"Transformed size mismatch for {asset_name}: expected {lock.transformed_size}, got {len(transformed)}"
            )

        out_path = target_dir / asset_name
        if out_path.is_symlink():
            raise AssetPolicyError(f"Refusing to write to symlink: {out_path}")
        out_path.write_bytes(transformed)
        out_path.chmod(0o644)

        staged_assets[lock.route] = (transformed, lock.content_type)
        manifest[lock.route] = actual_trans_sha

    manifest_file = target_dir / _MANIFEST_NAME
    manifest_file.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_file.chmod(0o644)
    for source, name in ((lock_file, _LOCK_NAME), (licenses_file, _LICENSES_NAME)):
        _stage_policy_copy(source, target_dir / name)

    csp = build_csp_header(origin, style_mode=style_mode, nonce=nonce)

    return StagedFrontend(
        staged_dir=target_dir,
        assets=staged_assets,
        manifest=manifest,
        csp_header=csp,
    )


def verify_staged_assets(
    staged_dir: Path,
    lock_path: Path | None = None,
    licenses_path: Path | None = None,
) -> bool:
    """Verify a staged directory holds exactly the locked assets and policy files.

    Rejects symlinks, unlisted or missing files, tampered assets, a manifest that
    differs from the lock, and lock or license copies that differ from policy.
    """
    lock_file = lock_path or _FRONTEND_POLICY_DIR / _LOCK_NAME
    licenses_file = licenses_path or _FRONTEND_POLICY_DIR / _LICENSES_NAME
    locks = load_assets_lock(lock_file)
    staged_dir = staged_dir.resolve()
    if not staged_dir.is_dir():
        raise AssetPolicyError(f"Staged directory not found: {staged_dir}")

    expected_files = set(locks) | {_MANIFEST_NAME, _LOCK_NAME, _LICENSES_NAME}
    actual_files = {p.name for p in staged_dir.iterdir()}

    unlisted = actual_files - expected_files
    if unlisted:
        raise AssetPolicyError(
            f"Unlisted files in staged frontend directory: {sorted(unlisted)}"
        )

    missing = expected_files - actual_files
    if missing:
        raise AssetPolicyError(f"Missing staged assets: {sorted(missing)}")

    for p in staged_dir.iterdir():
        if p.is_symlink():
            raise AssetPolicyError(f"Symlink found in staged assets: {p.name}")
        if not p.is_file():
            raise AssetPolicyError(f"Non-file item in staged assets: {p.name}")

    for asset_name, lock in locks.items():
        file_path = staged_dir / asset_name
        data = file_path.read_bytes()
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != lock.transformed_sha256:
            raise AssetPolicyError(
                f"Staged hash mismatch for {asset_name}: expected {lock.transformed_sha256}, got {actual_sha}"
            )
        if len(data) != lock.transformed_size:
            raise AssetPolicyError(
                f"Staged size mismatch for {asset_name}: expected {lock.transformed_size}, got {len(data)}"
            )

    try:
        raw_manifest = json.loads(
            (staged_dir / _MANIFEST_NAME).read_text(encoding="utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssetPolicyError("Staged manifest is not valid JSON") from error
    expected_manifest = {lock.route: lock.transformed_sha256 for lock in locks.values()}
    if raw_manifest != expected_manifest:
        raise AssetPolicyError("Staged manifest does not match the assets lock")

    for source, name in ((lock_file, _LOCK_NAME), (licenses_file, _LICENSES_NAME)):
        if (staged_dir / name).read_bytes() != source.read_bytes():
            raise AssetPolicyError(
                f"Staged {name} differs from the reviewed policy copy"
            )

    return True


def _stage_policy_copy(source: Path, destination: Path) -> None:
    if destination.is_symlink():
        raise AssetPolicyError(f"Refusing to write to symlink: {destination}")
    destination.write_bytes(source.read_bytes())
    destination.chmod(0o644)


def load_staged_assets(
    staged_dir: Path, lock_path: Path | None = None
) -> dict[str, tuple[bytes, str]]:
    """Load verified route -> (bytes, content_type) mapping from staged directory."""
    verify_staged_assets(staged_dir, lock_path=lock_path)
    locks = load_assets_lock(lock_path)
    result: dict[str, tuple[bytes, str]] = {}
    for asset_name, lock in locks.items():
        content = (staged_dir / asset_name).read_bytes()
        result[lock.route] = (content, lock.content_type)
    return result
