"""Capture a screen as SVG and compare it with the committed snapshot.

:func:`capture_svg` runs an app under Textual's ``run_test``, lets a scenario
drive it and returns ``App.export_screenshot()``, Textual's own SVG export.
:func:`check_snapshot` compares that SVG with
``__snapshots__/<module>/<test>.svg``:

- a match passes;
- a mismatch fails, naming the snapshot, and writes the new rendering and a
  unified diff under ``__failures__/`` (ignored by Git) for inspection;
- a missing snapshot fails and says how to create it;
- with ``--update-snapshots`` the snapshot is (re)written instead, and the
  Textual version that rendered it is recorded in ``TEXTUAL_VERSION``.

Textual's rendering can change between its releases, so a mismatch message
says when the installed Textual differs from the recorded one.

The failure files hold only the rendering and the diff, nothing about the
machine that produced them.

This module has no ``test_`` prefix and is not collected.
"""

from __future__ import annotations

import asyncio
import difflib
import re
from pathlib import Path
from typing import Any, Awaitable, Callable, Tuple

import pytest
import textual
from textual.app import App

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
SNAPSHOT_DIR = _HERE / "__snapshots__"
FAILURE_DIR = _HERE / "__failures__"
VERSION_FILE = SNAPSHOT_DIR / "TEXTUAL_VERSION"
UPDATE_OPTION = "--update-snapshots"

# Rich prefixes every class and clip-path id in an SVG export with
# "terminal-<hash of the whole content>-". Dropping the hash keeps the ids
# stable, so a one-cell change shows up as a one-line diff rather than a
# change to every line of the file.
_UNIQUE_ID = re.compile(r"\bterminal-\d+-")

Scenario = Callable[[Any], Awaitable[None]]

# How long to wait between the exports compared while a screen settles, and
# how many exports to take before giving up.
_SETTLE_DELAY = 0.1
_SETTLE_ATTEMPTS = 30


def normalize_svg(svg: str) -> str:
    """*svg* with Rich's content-derived id prefix removed."""
    return _UNIQUE_ID.sub("terminal-", svg)


def capture_svg(app: App, size: Tuple[int, int], scenario: Scenario) -> str:
    """Run *app* at *size*, let *scenario* drive it, and return the SVG export.

    The export is taken once the screen has settled: two exports in a row,
    :data:`_SETTLE_DELAY` seconds apart, must be identical. Some updates
    (the footer's key list after a focus change, a list's highlight) land a
    frame or two after the event that caused them, so a single export could
    catch either state.
    """

    async def run() -> str:
        async with app.run_test(size=size) as pilot:
            await scenario(pilot)
            previous = None
            for _ in range(_SETTLE_ATTEMPTS):
                await pilot.wait_for_scheduled_animations()
                await pilot.pause(_SETTLE_DELAY)
                # simplify merges neighbouring cells of one style, so how
                # Textual splits a line into segments, which is invisible on
                # screen, does not change the snapshot.
                current = app.export_screenshot(simplify=True)
                if current == previous:
                    return current
                previous = current
        raise AssertionError(
            f"the screen was still changing after {_SETTLE_ATTEMPTS} frames; "
            "a snapshot needs a screen that stops changing (a spinner or a "
            "blinking cursor never does)"
        )

    return normalize_svg(asyncio.run(run()))


def snapshot_path(node: pytest.Item) -> Path:
    """Where the snapshot for test *node* is stored."""
    return SNAPSHOT_DIR / node.path.stem / f"{node.name}.svg"


def check_snapshot(node: pytest.Item, svg: str, *, update: bool) -> None:
    """Compare *svg* with the stored snapshot of *node*, or store it."""
    expected_path = snapshot_path(node)
    relative = expected_path.relative_to(_REPO_ROOT)
    failure_svg = FAILURE_DIR / expected_path.parent.name / expected_path.name
    failure_diff = failure_svg.with_suffix(".diff")
    for stale in (failure_svg, failure_diff):
        stale.unlink(missing_ok=True)

    if update:
        expected_path.parent.mkdir(parents=True, exist_ok=True)
        expected_path.write_text(svg, encoding="utf-8", newline="\n")
        VERSION_FILE.write_text(f"{textual.__version__}\n", encoding="utf-8", newline="\n")
        return
    if not expected_path.exists():
        pytest.fail(
            f"no snapshot at {relative}; run the test with {UPDATE_OPTION}, "
            "then review the new SVG before committing it",
            pytrace=False,
        )
    expected = expected_path.read_text(encoding="utf-8")
    if expected == svg:
        return

    failure_svg.parent.mkdir(parents=True, exist_ok=True)
    failure_svg.write_text(svg, encoding="utf-8", newline="\n")
    diff = difflib.unified_diff(
        expected.splitlines(keepends=True),
        svg.splitlines(keepends=True),
        fromfile=f"{relative} (stored)",
        tofile=f"{relative} (rendered)",
    )
    failure_diff.write_text("".join(diff), encoding="utf-8", newline="\n")
    pytest.fail(
        f"{relative} does not match the rendering; the new rendering is in "
        f"{failure_svg.relative_to(_REPO_ROOT)} and the diff in "
        f"{failure_diff.relative_to(_REPO_ROOT)}. If the change is intended, "
        f"rerun with {UPDATE_OPTION}.{_version_note()}",
        pytrace=False,
    )


def _version_note() -> str:
    """A hint when the installed Textual is not the one the snapshots came from."""
    try:
        recorded = VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if not recorded or recorded == textual.__version__:
        return ""
    return (
        f" The snapshots were rendered with Textual {recorded} and this run "
        f"uses {textual.__version__}; the difference may come from Textual."
    )
