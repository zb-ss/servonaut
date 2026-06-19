"""Structural and byte-preservation tests for the split CSS bundle.

Guards three properties that must hold forever after the app.css → styles/
refactor:

1. Every entry in CSS_FILES exists on disk and lives under src/servonaut/styles/.
2. The App's stylesheet loads without errors (no StylesheetError on boot).
3. The concatenation of all CSS_FILES in order is byte-for-byte identical to
   the pre-split app.css captured in git (byte-preservation golden guard).
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

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
# 3. Byte-preservation golden guard
# ---------------------------------------------------------------------------

def test_css_files_concatenation_matches_git_golden():
    """The concatenated CSS_FILES must be byte-for-byte identical to the
    pre-split app.css as stored in the git index at HEAD~1 (or HEAD if this
    is the commit that introduced the split).

    Falls back to comparing against HEAD:src/servonaut/app.css if that ref
    exists, or skips if git history is not available.
    """
    # Try to get the golden from git history: check HEAD then HEAD^
    # (the split commit may have already removed app.css from HEAD).
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
        pytest.skip("git golden copy of src/servonaut/app.css not available")

    rebuilt = b"".join(f.read_bytes() for f in CSS_FILES)
    assert rebuilt == golden_bytes, (
        "CSS_FILES concatenation does not match the git golden copy of app.css. "
        "A boundary was shifted or a file was edited — byte-preservation violated."
    )
