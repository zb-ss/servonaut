"""Contract tests for desktop frontend assets, staging, transforms, licenses, and CSP."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.desktop_shell.assets import (
    WEBGL_REGISTRATION,
    AssetPolicyError,
    build_csp_header,
    canvas_renderer,
    find_upstream_static_dir,
    load_staged_assets,
    render_index_html,
    stage_frontend_assets,
    validate_csp_header,
    verify_staged_assets,
)
from scripts.desktop_shell.model import (
    load_assets_lock,
    load_frontend_licenses,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FRONTEND_ROOT = _REPO_ROOT / "packaging" / "desktop_shell" / "frontend"
_LOCK_PATH = _FRONTEND_ROOT / "assets.lock.json"
_LICENSES_PATH = _FRONTEND_ROOT / "licenses.json"


def test_packaged_frontend_source_files_exist() -> None:
    for name in ("index.html", "bootstrap.js", "style.css"):
        file_path = _FRONTEND_ROOT / name
        assert file_path.is_file(), f"Missing required file {name}"
        assert not file_path.is_symlink(), f"{name} must not be a symlink"


def test_index_html_structure_and_security() -> None:
    html = (_FRONTEND_ROOT / "index.html").read_text(encoding="utf-8")
    assert "<!doctype html>" in html.lower()
    assert "<title>Servonaut</title>" in html
    assert 'data-font-size="FONT_SIZE"' in html
    assert 'id="terminal"' in html
    assert 'rel="stylesheet" href="/xterm.css"' in html
    assert 'rel="stylesheet" href="/style.css"' in html
    assert 'src="/bootstrap.js"' in html

    # Strict frontend security checks
    assert "<script>" not in html, "index.html must not contain inline scripts"
    assert "onload=" not in html, "index.html must not contain inline event handlers"
    assert "onclick=" not in html
    assert "onerror=" not in html
    assert "http://" not in html, "index.html must not reference external resources"
    assert "https://" not in html


def test_bootstrap_js_protocol_and_security() -> None:
    js = (_FRONTEND_ROOT / "bootstrap.js").read_text(encoding="utf-8")
    assert '"use strict";' in js
    assert "window.startServonaut = (token) =>" in js
    assert "delete window.startServonaut;" in js
    assert '["servonaut.desktop.v1", `auth.${token}`]' in js
    assert "servonaut-probe" not in js, "Must use desktop v1 protocol, not probe"
    assert 'token = "";' in js, (
        "Token must be erased immediately after WebSocket creation"
    )
    assert 'target.origin !== expected.origin || target.pathname !== "/ws"' in js
    assert 'document.body.classList.add("-startup-error");' in js


def test_style_css_properties() -> None:
    css = (_FRONTEND_ROOT / "style.css").read_text(encoding="utf-8")
    assert "#0c181f" in css
    assert "Roboto Mono" in css
    assert "url('/mono.ttf')" in css
    assert "overflow: hidden" in css


def test_assets_lock_manifest_schema_and_completeness() -> None:
    locks = load_assets_lock(_LOCK_PATH)
    expected_assets = {
        "index.html",
        "bootstrap.js",
        "style.css",
        "textual.js",
        "xterm.css",
        "mono.ttf",
    }
    assert set(locks.keys()) == expected_assets

    for name, lock in locks.items():
        assert lock.route.startswith("/")
        assert len(lock.source_sha256) == 64
        assert len(lock.transformed_sha256) == 64
        assert lock.source_size > 0
        assert lock.transformed_size > 0
        assert "/" in lock.content_type

    # Verify packaged asset hashes directly match on-disk files
    for name in ("index.html", "bootstrap.js", "style.css"):
        lock = locks[name]
        data = (_FRONTEND_ROOT / name).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(data).hexdigest() == lock.source_sha256
        assert len(data) == lock.source_size


def test_frontend_licenses_inventory() -> None:
    licenses = load_frontend_licenses(_LICENSES_PATH)
    locks = load_assets_lock(_LOCK_PATH)

    # All license references in lock must be declared
    for asset_name, lock in locks.items():
        assert lock.license_id in licenses, (
            f"{asset_name} references undeclared license"
        )

    assert "servonaut" in licenses
    assert licenses["servonaut"].spdx_expression == "MIT"
    assert "Servonaut Authors" in licenses["servonaut"].copyright

    assert "textual_serve" in licenses
    assert licenses["textual_serve"].spdx_expression == "MIT"
    assert licenses["textual_serve"].upstream_version == "1.1.3"

    assert "xterm" in licenses
    assert licenses["xterm"].spdx_expression == "MIT"
    assert "xterm.js authors" in licenses["xterm"].copyright

    assert "roboto_mono" in licenses
    assert licenses["roboto_mono"].spdx_expression == "Apache-2.0"
    assert "Roboto Mono Project Authors" in licenses["roboto_mono"].copyright
    assert licenses["roboto_mono"].upstream_version == "3.000"


def test_canvas_renderer_transform() -> None:
    dummy_source = b"before;" + WEBGL_REGISTRATION + b"after;"
    transformed = canvas_renderer(dummy_source)
    assert transformed == b"before;after;"

    with pytest.raises(AssetPolicyError, match="Expected exactly 1"):
        canvas_renderer(b"no registration here")

    with pytest.raises(AssetPolicyError, match="Expected exactly 1"):
        canvas_renderer(dummy_source + WEBGL_REGISTRATION)


def test_render_index_html_transform() -> None:
    source = b'<html><div data-font-size="FONT_SIZE"></div></html>'
    transformed = render_index_html(source, font_size=16)
    assert transformed == b'<html><div data-font-size="16"></div></html>'

    with pytest.raises(AssetPolicyError, match="missing 'FONT_SIZE'"):
        render_index_html(b"<html>no placeholder</html>", font_size=14)


def test_frontend_staging_synthetic_pipeline(tmp_path: Path) -> None:
    """Test frontend staging, manifest generation, restaging, and security boundaries with synthetic assets."""
    upstream_dir = tmp_path / "mock_upstream"
    upstream_dir.mkdir()
    (upstream_dir / "js").mkdir()
    (upstream_dir / "fonts").mkdir()

    # Upstream source files
    mock_js = b"console.log('init');" + WEBGL_REGISTRATION + b"console.log('ready');"
    mock_js_file = upstream_dir / "js" / "mock.js"
    mock_js_file.write_bytes(mock_js)
    mock_js_sha = hashlib.sha256(mock_js).hexdigest()

    mock_js_transformed = canvas_renderer(mock_js)
    mock_js_trans_sha = hashlib.sha256(mock_js_transformed).hexdigest()

    mock_font = b"mock-ttf-binary-data"
    mock_font_file = upstream_dir / "fonts" / "mock.ttf"
    mock_font_file.write_bytes(mock_font)
    mock_font_sha = hashlib.sha256(mock_font).hexdigest()

    # Read packaged index.html and calculate transformed
    index_html = (_FRONTEND_ROOT / "index.html").read_bytes()
    index_html_sha = hashlib.sha256(index_html).hexdigest()
    index_transformed = render_index_html(index_html, font_size=14)
    index_trans_sha = hashlib.sha256(index_transformed).hexdigest()

    synthetic_lock = {
        "schema_version": 1,
        "assets": {
            "index.html": {
                "source": "packaging/desktop_shell/frontend/index.html",
                "route": "/",
                "content_type": "text/html; charset=utf-8",
                "source_sha256": index_html_sha,
                "source_size": len(index_html),
                "transformed_sha256": index_trans_sha,
                "transformed_size": len(index_transformed),
                "transform": "template_font_size",
                "license": "servonaut",
            },
            "mock.js": {
                "source": "textual_serve:static/js/mock.js",
                "route": "/mock.js",
                "content_type": "text/javascript; charset=utf-8",
                "source_sha256": mock_js_sha,
                "source_size": len(mock_js),
                "transformed_sha256": mock_js_trans_sha,
                "transformed_size": len(mock_js_transformed),
                "transform": "canvas_renderer_no_webgl",
                "license": "textual_serve",
            },
            "mock.ttf": {
                "source": "textual_serve:static/fonts/mock.ttf",
                "route": "/mock.ttf",
                "content_type": "font/ttf",
                "source_sha256": mock_font_sha,
                "source_size": len(mock_font),
                "transformed_sha256": mock_font_sha,
                "transformed_size": len(mock_font),
                "transform": None,
                "license": "roboto_mono",
            },
        },
    }

    lock_file = tmp_path / "synthetic.lock.json"
    lock_file.write_text(json.dumps(synthetic_lock), encoding="utf-8")

    stage_dir = tmp_path / "stage1"
    staged = stage_frontend_assets(
        stage_dir,
        lock_path=lock_file,
        upstream_source_dir=upstream_dir,
        origin="http://127.0.0.1:9090",
    )

    assert len(staged.assets) == 3
    assert "/" in staged.assets
    assert "/mock.js" in staged.assets
    assert "/mock.ttf" in staged.assets
    assert (stage_dir / "manifest.json").is_file()
    assert verify_staged_assets(stage_dir, lock_path=lock_file)

    loaded = load_staged_assets(stage_dir, lock_path=lock_file)
    assert len(loaded) == 3
    assert loaded["/"][1] == "text/html; charset=utf-8"
    assert loaded["/mock.js"][1] == "text/javascript; charset=utf-8"
    assert loaded["/mock.ttf"][1] == "font/ttf"

    # Restaging equality
    stage2_dir = tmp_path / "stage2"
    staged2 = stage_frontend_assets(
        stage2_dir,
        lock_path=lock_file,
        upstream_source_dir=upstream_dir,
        origin="http://127.0.0.1:9090",
    )
    assert staged.manifest == staged2.manifest
    for name in ("index.html", "mock.js", "mock.ttf", "manifest.json"):
        assert (stage_dir / name).read_bytes() == (stage2_dir / name).read_bytes()

    # Unlisted extra file rejection
    (stage_dir / "extra.js").write_text("console.log('bad');", encoding="utf-8")
    with pytest.raises(AssetPolicyError, match="Unlisted files"):
        verify_staged_assets(stage_dir, lock_path=lock_file)
    (stage_dir / "extra.js").unlink()

    # Tampered file content rejection
    orig_mock = (stage_dir / "mock.js").read_bytes()
    (stage_dir / "mock.js").write_bytes(orig_mock + b"\n/* tampered */")
    with pytest.raises(AssetPolicyError, match="Staged hash mismatch"):
        verify_staged_assets(stage_dir, lock_path=lock_file)
    (stage_dir / "mock.js").write_bytes(orig_mock)

    # Symlink rejection
    (stage_dir / "mock.js").unlink()
    (stage_dir / "mock.js").symlink_to(_FRONTEND_ROOT / "bootstrap.js")
    with pytest.raises(AssetPolicyError, match="Symlink found"):
        verify_staged_assets(stage_dir, lock_path=lock_file)


@pytest.mark.skipif(
    find_upstream_static_dir() is None,
    reason="Requires upstream textual-serve static assets directory",
)
def test_frontend_staging_and_verification(tmp_path: Path) -> None:
    staged = stage_frontend_assets(tmp_path, origin="http://127.0.0.1:8080")
    assert len(staged.assets) == 6
    assert "/" in staged.assets
    assert "/bootstrap.js" in staged.assets
    assert "/style.css" in staged.assets
    assert "/textual.js" in staged.assets
    assert "/xterm.css" in staged.assets
    assert "/mono.ttf" in staged.assets

    assert (tmp_path / "manifest.json").is_file()
    assert verify_staged_assets(tmp_path)

    loaded = load_staged_assets(tmp_path)
    assert len(loaded) == 6
    assert loaded["/"][1] == "text/html; charset=utf-8"
    assert loaded["/bootstrap.js"][1] == "text/javascript; charset=utf-8"


@pytest.mark.skipif(
    find_upstream_static_dir() is None,
    reason="Requires upstream textual-serve static assets directory",
)
def test_staged_assets_offline_restaging_equality(tmp_path: Path) -> None:
    dir1 = tmp_path / "stage1"
    dir2 = tmp_path / "stage2"

    staged1 = stage_frontend_assets(dir1)
    staged2 = stage_frontend_assets(dir2)

    assert staged1.manifest == staged2.manifest
    for name in (
        "index.html",
        "bootstrap.js",
        "style.css",
        "textual.js",
        "xterm.css",
        "mono.ttf",
        "manifest.json",
    ):
        assert (dir1 / name).read_bytes() == (dir2 / name).read_bytes()


@pytest.mark.skipif(
    find_upstream_static_dir() is None,
    reason="Requires upstream textual-serve static assets directory",
)
def test_verify_staged_assets_rejects_tampering_and_unlisted_files(
    tmp_path: Path,
) -> None:
    stage_frontend_assets(tmp_path)

    # Unlisted extra file
    (tmp_path / "extra.js").write_text("console.log('injected');", encoding="utf-8")
    with pytest.raises(AssetPolicyError, match="Unlisted files"):
        verify_staged_assets(tmp_path)
    (tmp_path / "extra.js").unlink()

    # Tampered file content
    orig_css = (tmp_path / "style.css").read_bytes()
    (tmp_path / "style.css").write_bytes(orig_css + b"\n/* tampered */")
    with pytest.raises(AssetPolicyError, match="Staged hash mismatch"):
        verify_staged_assets(tmp_path)
    (tmp_path / "style.css").write_bytes(orig_css)

    # Symlink rejection
    (tmp_path / "style.css").unlink()
    (tmp_path / "style.css").symlink_to(_FRONTEND_ROOT / "style.css")
    with pytest.raises(AssetPolicyError, match="Symlink found"):
        verify_staged_assets(tmp_path)


def test_csp_header_generation_and_validation() -> None:
    # Relaxation mode
    csp_relax = build_csp_header("http://127.0.0.1:8080", style_mode="relaxation")
    assert "default-src 'none'" in csp_relax
    assert "script-src 'self'" in csp_relax
    assert "style-src 'self' 'unsafe-inline'" in csp_relax
    assert "connect-src ws://127.0.0.1:8080" in csp_relax
    assert "font-src 'self'" in csp_relax
    assert "img-src 'self' data:" in csp_relax

    # Nonce mode
    csp_nonce = build_csp_header(
        "http://127.0.0.1:9090", style_mode="nonce", nonce="testNonce1234567890"
    )
    assert "style-src 'self' 'nonce-testNonce1234567890'" in csp_nonce
    assert "connect-src ws://127.0.0.1:9090" in csp_nonce

    # Nonce mode requires valid nonce
    with pytest.raises(AssetPolicyError):
        build_csp_header("http://127.0.0.1:9090", style_mode="nonce", nonce=None)


def test_csp_validation_rejects_insecure_policies() -> None:
    # Missing default-src
    with pytest.raises(AssetPolicyError, match="missing required 'default-src'"):
        validate_csp_header("script-src 'self'")

    # default-src not 'none'
    with pytest.raises(AssetPolicyError, match="must be exactly 'none'"):
        validate_csp_header("default-src 'self'; script-src 'self'")

    # Forbidden unsafe-eval
    with pytest.raises(AssetPolicyError, match="Forbidden unsafe-eval"):
        validate_csp_header("default-src 'none'; script-src 'self' 'unsafe-eval'")

    # Forbidden wildcard
    with pytest.raises(AssetPolicyError, match="Forbidden wildcard"):
        validate_csp_header("default-src 'none'; script-src *")

    # Forbidden unsafe-inline in script-src
    with pytest.raises(
        AssetPolicyError, match="Forbidden 'unsafe-inline' in script-src"
    ):
        validate_csp_header("default-src 'none'; script-src 'self' 'unsafe-inline'")

    # Forbidden remote host / CDN
    with pytest.raises(AssetPolicyError, match="Forbidden remote host"):
        validate_csp_header(
            "default-src 'none'; script-src 'self' https://cdn.jsdelivr.net"
        )
