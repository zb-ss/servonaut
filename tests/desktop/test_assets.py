"""Tests for frontend asset loading, verification, and CSP policy."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from servonaut.desktop.assets import (
    MAX_ASSET_BYTES,
    WEBGL_REGISTRATION,
    DesktopAssetError,
    build_csp_header,
    canvas_renderer,
    load_and_verify_assets,
    render_index_html,
    validate_csp_header,
)


def test_load_and_verify_all_packaged_assets() -> None:
    """Packaged assets must verify completely against the assets lock and licenses."""
    routes, manifest = load_and_verify_assets()

    expected_routes = {
        "/",
        "/index.html",
        "/bootstrap.js",
        "/style.css",
        "/textual.js",
        "/xterm.css",
        "/mono.ttf",
        "/licenses.json",
    }
    assert set(routes.keys()) == expected_routes
    assert set(manifest.keys()) == expected_routes

    # Check content types
    assert routes["/"][1] == "text/html; charset=utf-8"
    assert routes["/index.html"][1] == "text/html; charset=utf-8"
    assert routes["/bootstrap.js"][1] == "text/javascript; charset=utf-8"
    assert routes["/style.css"][1] == "text/css; charset=utf-8"
    assert routes["/textual.js"][1] == "text/javascript; charset=utf-8"
    assert routes["/xterm.css"][1] == "text/css; charset=utf-8"
    assert routes["/mono.ttf"][1] == "font/ttf"
    assert routes["/licenses.json"][1] == "application/json; charset=utf-8"

    # Check size bounds and hash equality
    for route, (data, _) in routes.items():
        assert 0 < len(data) <= MAX_ASSET_BYTES
        sha = hashlib.sha256(data).hexdigest()
        assert sha == manifest[route]


def test_render_index_html_substitution() -> None:
    source = b'<html><div data-font-size="FONT_SIZE"></div></html>'
    rendered = render_index_html(source, font_size=18)
    assert rendered == b'<html><div data-font-size="18"></div></html>'

    with pytest.raises(DesktopAssetError, match="missing 'FONT_SIZE' placeholder"):
        render_index_html(b"<html>no placeholder</html>", font_size=14)


def test_canvas_renderer_removes_webgl() -> None:
    source = b"prefix;" + WEBGL_REGISTRATION + b"suffix;"
    cleaned = canvas_renderer(source)
    assert cleaned == b"prefix;suffix;"
    assert WEBGL_REGISTRATION not in cleaned

    # Zero count
    with pytest.raises(
        DesktopAssetError, match="Expected exactly 1 WebGL registration"
    ):
        canvas_renderer(b"no registration")

    # Multiple count
    with pytest.raises(
        DesktopAssetError, match="Expected exactly 1 WebGL registration"
    ):
        canvas_renderer(WEBGL_REGISTRATION + WEBGL_REGISTRATION)


def test_build_csp_header_valid_origin() -> None:
    csp = build_csp_header("http://127.0.0.1:45678")
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "connect-src ws://127.0.0.1:45678" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "form-action 'none'" in csp


def test_build_csp_header_nonce_mode() -> None:
    nonce = "abcdef1234567890abcdef"
    csp = build_csp_header("http://127.0.0.1:45678", style_mode="nonce", nonce=nonce)
    assert f"style-src 'self' 'nonce-{nonce}'" in csp
    assert "unsafe-inline" not in csp


def test_build_csp_header_rejects_non_loopback() -> None:
    with pytest.raises(DesktopAssetError, match="Origin must be loopback"):
        build_csp_header("http://example.com:8000")

    with pytest.raises(DesktopAssetError, match="Origin must be loopback"):
        build_csp_header("http://0.0.0.0:8000")


def test_validate_csp_header_security_rejections() -> None:
    # Missing default-src
    with pytest.raises(DesktopAssetError, match="missing required 'default-src'"):
        validate_csp_header("script-src 'self'")

    # default-src not 'none'
    with pytest.raises(DesktopAssetError, match="must be exactly 'none'"):
        validate_csp_header("default-src 'self'")

    # unsafe-eval in any directive
    with pytest.raises(DesktopAssetError, match="Forbidden unsafe-eval"):
        validate_csp_header("default-src 'none'; script-src 'self' 'unsafe-eval'")

    # Wildcard in any directive
    with pytest.raises(DesktopAssetError, match="Forbidden wildcard"):
        validate_csp_header("default-src 'none'; img-src *")

    # unsafe-inline in script-src
    with pytest.raises(
        DesktopAssetError, match="Forbidden 'unsafe-inline' in script-src"
    ):
        validate_csp_header("default-src 'none'; script-src 'self' 'unsafe-inline'")

    # Remote origin
    with pytest.raises(DesktopAssetError, match="Forbidden remote host"):
        validate_csp_header("default-src 'none'; connect-src https://evil.com")


def test_asset_tamper_detected_in_staged_frontend(tmp_path: Path) -> None:
    """Tampering with any staged asset byte must fail verification."""
    staged = tmp_path / "frontend"
    staged.mkdir()

    routes, manifest = load_and_verify_assets()

    # Stage files
    repo_root = Path(__file__).resolve().parents[2]
    lock_file = (
        repo_root / "packaging" / "desktop_shell" / "frontend" / "assets.lock.json"
    )
    lic_file = repo_root / "packaging" / "desktop_shell" / "frontend" / "licenses.json"

    staged_lock = json.loads(lock_file.read_text(encoding="utf-8"))
    for asset_name, item in staged_lock["assets"].items():
        route = item["route"]
        data, _ = routes[route]
        (staged / asset_name).write_bytes(data)

    (staged / "assets.lock.json").write_text(lock_file.read_text(encoding="utf-8"))
    (staged / "licenses.json").write_text(lic_file.read_text(encoding="utf-8"))
    (staged / "manifest.json").write_text(json.dumps(manifest))

    # Verify initial staged passes
    loaded, _ = load_and_verify_assets(staged)
    assert len(loaded) == len(routes)

    # Tamper with 1 byte of bootstrap.js
    tampered = staged / "bootstrap.js"
    tampered.write_bytes(b"// tampered\n" + tampered.read_bytes())

    with pytest.raises(DesktopAssetError, match="hash mismatch for bootstrap.js"):
        load_and_verify_assets(staged)


def test_staged_symlink_rejected(tmp_path: Path) -> None:
    """Symlinks inside staged assets must be strictly rejected."""
    staged = tmp_path / "frontend"
    staged.mkdir()

    routes, manifest = load_and_verify_assets()
    repo_root = Path(__file__).resolve().parents[2]
    lock_file = (
        repo_root / "packaging" / "desktop_shell" / "frontend" / "assets.lock.json"
    )
    lic_file = repo_root / "packaging" / "desktop_shell" / "frontend" / "licenses.json"

    staged_lock = json.loads(lock_file.read_text(encoding="utf-8"))
    for asset_name, item in staged_lock["assets"].items():
        route = item["route"]
        data, _ = routes[route]
        (staged / asset_name).write_bytes(data)

    (staged / "assets.lock.json").write_text(lock_file.read_text(encoding="utf-8"))
    (staged / "licenses.json").write_text(lic_file.read_text(encoding="utf-8"))
    (staged / "manifest.json").write_text(json.dumps(manifest))

    # Replace style.css with symlink
    style = staged / "style.css"
    style.unlink()
    style.symlink_to(staged / "bootstrap.js")

    with pytest.raises(DesktopAssetError, match="Symlink rejected"):
        load_and_verify_assets(staged)


def test_staged_unlisted_file_rejected(tmp_path: Path) -> None:
    """Unlisted files inside staged frontend directory must be rejected."""
    staged = tmp_path / "frontend"
    staged.mkdir()

    routes, manifest = load_and_verify_assets()
    repo_root = Path(__file__).resolve().parents[2]
    lock_file = (
        repo_root / "packaging" / "desktop_shell" / "frontend" / "assets.lock.json"
    )
    lic_file = repo_root / "packaging" / "desktop_shell" / "frontend" / "licenses.json"

    staged_lock = json.loads(lock_file.read_text(encoding="utf-8"))
    for asset_name, item in staged_lock["assets"].items():
        route = item["route"]
        data, _ = routes[route]
        (staged / asset_name).write_bytes(data)

    (staged / "assets.lock.json").write_text(lock_file.read_text(encoding="utf-8"))
    (staged / "licenses.json").write_text(lic_file.read_text(encoding="utf-8"))
    (staged / "manifest.json").write_text(json.dumps(manifest))

    # Add extra unlisted file
    (staged / "unlisted.txt").write_text("rogue file")

    with pytest.raises(DesktopAssetError, match="Unlisted files"):
        load_and_verify_assets(staged)
