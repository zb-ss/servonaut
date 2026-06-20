"""Structural integrity tests for the split CSS bundle.

Guards three properties:

1. Every entry in CSS_FILES exists on disk and lives under src/servonaut/styles/.
2. The App's stylesheet loads without errors (no StylesheetError on boot).
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
from textual.css.errors import StylesheetError

from servonaut.styles import CSS_FILES

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
    """CSS_FILES must list exactly 29 entries (one per split slice)."""
    assert len(CSS_FILES) == 29, f"Expected 29 CSS files, got {len(CSS_FILES)}"


# ---------------------------------------------------------------------------
# 2. App stylesheet loads without StylesheetError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_app_stylesheet_loads_without_error():
    """The full CSS bundle must parse and load without raising StylesheetError."""
    from servonaut.app import ServonautApp

    app = ServonautApp()
    try:
        async with app.run_test(size=(120, 40)):
            # If we reach here, no StylesheetError was raised during mount.
            pass
    except StylesheetError as exc:
        pytest.fail(f"StylesheetError during App boot: {exc}")


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
