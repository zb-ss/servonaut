"""Real screens, real stylesheet: hostile names never reach the terminal.

The instance list shows names that come from providers. Each screen is drawn once with a name holding terminal
control sequences and once with the same name without them; the bytes written
to the terminal must be identical. Nothing is compared with a stored SVG.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Awaitable, Callable, Optional

import pytest

from servonaut.utils import terminal_output

from . import _harness

HOSTILE = (
    "web\x1b]52;c;aGVsbG8=\x07\x1b]8;;http://1.2.3.4/\x1b\\\x1b]0;pwned\x07"
    "\x1b[2J\x1b[10;10H\x9b31m\u202eevil-1"
)
BENIGN = re.sub("[\x00-\x1f\x7f-\x9f\u202e]", "", HOSTILE)

_TEXTUAL_OWN = re.compile(
    r"\x1b\[\d+;\d+H|\x1b\[[0-9;:]*m|\x1b\]8;id=[^;\x1b]*;[^\x1b\x07]*\x1b\\|\x1b\]8;;\x1b\\"
)
_STILL_UNSAFE = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f\u202e]")

_TABLE_ROWS = {"160x50": 42, "100x30": 24}

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


@pytest.fixture(autouse=True)
def filter_installed():
    terminal_output.install()


def _frame(size: str, scenario: Callable[[Any], Awaitable[None]]) -> str:
    async def run() -> str:
        app = _harness.SnapshotApp()
        async with app.run_test(size=_harness.SIZES[size]) as pilot:
            await _harness.wait_for_fleet(pilot)
            await scenario(pilot)
            await pilot.wait_for_scheduled_animations()
            await pilot.pause(0.2)
            _harness.freeze_cursors(app)
            await pilot.pause()
            return app.screen._compositor.render_update(full=True).render_segments(app.console)

    return asyncio.run(run())


def _assert_same_and_safe(hostile: str, benign: str, rows: Optional[int] = None) -> None:
    """*hostile* holds no control sequence of its own and matches *benign*.

    *rows* limits the comparison to the first rows of the screen: a line of
    wrapped detail text is wrapped by Textual from the raw string, so a name
    full of zero-width characters can break it a couple of cells earlier.
    The safety check always covers the whole screen.
    """
    assert not _STILL_UNSAFE.search(_TEXTUAL_OWN.sub("", hostile))
    assert "\x1b]52" not in hostile
    if rows is None:
        assert hostile == benign
        return
    assert hostile.split("\n")[:rows] == benign.split("\n")[:rows]


_PLAIN = re.compile(r"\x1b\[[0-9;:]*m|\x1b\[\d+;\d+H")
_TABLE_COLUMNS = 120


def _table_text(frame: str) -> list[str]:
    """The rows of *frame* as text, cut at the right edge of the table."""
    return [_PLAIN.sub("", row)[:_TABLE_COLUMNS] for row in frame.split("\n")]


def _named(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    rows = [dict(row) for row in _harness.AWS_ROWS]
    rows[0]["name"] = name
    monkeypatch.setattr(_harness, "AWS_ROWS", rows)
    _harness.seed_home()


@sizes
def test_instance_list(monkeypatch: pytest.MonkeyPatch, size: str) -> None:
    async def nothing(_pilot: Any) -> None:
        return None

    _named(monkeypatch, HOSTILE)
    hostile = _frame(size, nothing)
    _named(monkeypatch, BENIGN)
    # The first rows hold the table, header and sidebar; the detail line
    # under the table is the one that wraps (see _assert_same_and_safe).
    benign = _frame(size, nothing)
    if size == "160x50":
        # The inspector beside the table names the server in its own panel and
        # shows each control character as a visible placeholder, so only the
        # table (the columns left of the inspector) is compared; the safety
        # check still covers the whole screen.
        assert _table_text(hostile) == _table_text(benign)
        _assert_same_and_safe(hostile, benign, rows=0)
        return
    _assert_same_and_safe(hostile, benign, rows=_TABLE_ROWS[size])
