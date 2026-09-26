"""Structural integrity tests for the split CSS bundle.

Guards three properties:

1. Every entry in CSS_FILES exists on disk and lives under src/servonaut/styles/.
2. The App's stylesheet loads without errors (no StylesheetError on boot).
   The boot runs in a child process with a throwaway HOME and no network, so
   it never reads the developer's own ``~/.servonaut`` or calls PyPI.
3. The CSS bundle has not grown since the original split (size guard): the
   concatenated size of CSS_FILES must be smaller than or equal to the
   original pre-split app.css.  This catches accidental rule duplication or
   unintended file additions.  After the dedup pass (commit 2), the bundle is
   intentionally smaller than the original, so byte-identity is no longer the
   right invariant — the size guard is the correct ongoing sentinel.
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

from servonaut.styles import CSS_FILES
from tests._hermetic_app import SENTINEL_USERNAME, run_hermetic_app

STYLES_ROOT = pathlib.Path(__file__).parent.parent / "src" / "servonaut" / "styles"


# ---------------------------------------------------------------------------
# 1. Every CSS_FILES entry must exist and live under styles/
# ---------------------------------------------------------------------------

def test_all_css_files_exist():
    """Every entry in CSS_FILES must be an existing file under styles/."""
    missing = [f for f in CSS_FILES if not f.exists()]
    assert missing == [], f"Missing CSS files: {missing}"


def test_all_css_files_under_styles_root():
    """Every entry in CSS_FILES must be under src/servonaut/styles/."""
    outside = [f for f in CSS_FILES if not str(f).startswith(str(STYLES_ROOT))]
    assert outside == [], f"CSS files outside styles/ root: {outside}"


def test_css_files_list_has_expected_count():
    """CSS_FILES must list exactly 31 entries (one per split slice)."""
    assert len(CSS_FILES) == 31, f"Expected 31 CSS files, got {len(CSS_FILES)}"


# ---------------------------------------------------------------------------
# 2. App stylesheet loads without StylesheetError
# ---------------------------------------------------------------------------

def test_app_stylesheet_loads_without_error(tmp_path):
    """The full CSS bundle must parse and load without raising StylesheetError.

    Boots the real app over a throwaway HOME whose config carries a sentinel
    value. The app reporting the sentinel back proves it used that HOME; the
    child's audit hook proves it opened nothing under the real one and made
    no network call.
    """
    report = run_hermetic_app(tmp_path, "boot")

    error = report["error"]
    if error and "StylesheetError" in error:
        pytest.fail(f"StylesheetError during App boot:\n{error}")
    assert error is None, f"App boot failed:\n{error}\n{report['stderr']}"

    result = report["result"]
    home = pathlib.Path(report["home"])
    assert result["screen"] == "InstanceListScreen"
    assert result["default_username"] == SENTINEL_USERNAME
    assert pathlib.Path(result["config_path"]).is_relative_to(home)
    assert pathlib.Path(result["data_root"]).is_relative_to(home)
    assert report["home_accesses"] == [], "boot touched the real home directory"
    assert report["network_attempts"] == [], "boot attempted network access"


# ---------------------------------------------------------------------------
# 3. Bundle size guard — must not exceed the original pre-split app.css
# ---------------------------------------------------------------------------

def test_css_bundle_has_not_grown():
    """The concatenated CSS_FILES must not be larger than the original app.css.

    After the dedup pass the bundle is intentionally smaller, so byte-identity
    is no longer the invariant.  This size guard catches accidental rule
    duplication or unintended additions while remaining valid post-dedup.

    If git history is unavailable (e.g. shallow clone), this test is skipped
    rather than failing spuriously.
    """
    golden_bytes: bytes | None = None
    for ref in ("HEAD:src/servonaut/app.css", "HEAD^:src/servonaut/app.css"):
        result = subprocess.run(
            ["git", "show", ref],
            capture_output=True,
            cwd=pathlib.Path(__file__).parent.parent,
        )
        if result.returncode == 0:
            golden_bytes = result.stdout
            break

    if golden_bytes is None:
        pytest.skip("git golden copy of src/servonaut/app.css not available in history")

    rebuilt = b"".join(f.read_bytes() for f in CSS_FILES)
    assert len(rebuilt) <= len(golden_bytes), (
        f"CSS bundle grew: {len(rebuilt)} bytes > original {len(golden_bytes)} bytes. "
        "Check for accidental rule duplication or extra files in CSS_FILES."
    )
