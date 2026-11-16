"""Structural integrity tests for the split CSS bundle.

Guards three properties:

1. Every entry in CSS_FILES exists on disk and lives under src/servonaut/styles/.
2. The App's stylesheet loads without errors (no StylesheetError on boot).
   The boot runs in a child process with a throwaway HOME and no network, so
   it never reads the developer's own ``~/.servonaut`` or calls PyPI.
3. Stylesheets stay within an explicit byte budget, including new files that
   have not yet been registered in CSS_FILES.
"""
from __future__ import annotations

import pathlib

import pytest

from servonaut.styles import CSS_FILES
from tests._hermetic_app import SENTINEL_USERNAME, run_hermetic_app

STYLES_ROOT = pathlib.Path(__file__).parent.parent / "src" / "servonaut" / "styles"
# The stylesheets total 313,723 bytes. Raising this budget requires deliberate
# review so accidental duplication cannot silently increase every app start.
CSS_SIZE_BUDGET_BYTES = 330_000


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


def test_css_files_list_has_no_duplicates_or_unregistered_styles():
    """Every maintained stylesheet is loaded exactly once."""
    assert len(CSS_FILES) == len(set(CSS_FILES)), "Duplicate stylesheet registration"
    assert set(CSS_FILES) == set(STYLES_ROOT.rglob("*.tcss"))


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
# 3. Bundle size guard — all maintained stylesheets fit the reviewed budget
# ---------------------------------------------------------------------------

def test_css_bundle_has_not_grown():
    """All maintained stylesheets fit the budget without needing git history."""
    stylesheets = [path for path in STYLES_ROOT.rglob("*")
                   if path.is_file() and path.suffix in {".tcss", ".css"}]
    assert stylesheets, "No stylesheets found under styles/"
    total_bytes = sum(path.stat().st_size for path in stylesheets)
    assert total_bytes <= CSS_SIZE_BUDGET_BYTES, (
        f"CSS bundle grew: {total_bytes} bytes > {CSS_SIZE_BUDGET_BYTES} byte budget. "
        "Check for duplicated rules before deliberately reviewing the budget."
    )
