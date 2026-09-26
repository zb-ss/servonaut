"""Tests for SafeHeader, the header that survives being removed while it mounts."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from textual.app import App, ComposeResult
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widgets import Header, Static

from servonaut.widgets.safe_header import SafeHeader

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "servonaut"


class _HeaderScreen(Screen):
    TITLE = "Screen title"
    SUB_TITLE = "Screen sub-title"

    def __init__(self, header_type: type[Header]) -> None:
        super().__init__()
        self._header_type = header_type

    def compose(self) -> ComposeResult:
        yield self._header_type()


class _OpenAndCloseApp(App):
    """Opens a screen with a header and closes it within one handler.

    The app runs callbacks queued while it is busy only after the current
    handler returns, so the header is fully removed before any title refresh
    it queued while mounting gets to run. That is the ordering a screen hits
    when it is closed while it is still opening.
    """

    def __init__(self, header_type: type[Header]) -> None:
        super().__init__()
        self._header_type = header_type

    async def on_mount(self) -> None:
        await self.push_screen(_HeaderScreen(self._header_type))
        await self.pop_screen()


class _HostApp(App):
    def __init__(self) -> None:
        super().__init__()
        self.screen_under_test = _HeaderScreen(SafeHeader)

    def on_mount(self) -> None:
        self.push_screen(self.screen_under_test)


def _shown_title(screen: Screen) -> str:
    title = screen.query_one("HeaderTitle", Static)
    return title.render().plain


@pytest.mark.xfail(
    raises=NoMatches,
    strict=False,
    reason="Textual's Header refreshes its title from a callback that can outlive it",
)
@pytest.mark.asyncio
async def test_stock_header_crashes_when_closed_before_its_title_refresh():
    """Show the scenario below reaches the race SafeHeader exists for."""
    app = _OpenAndCloseApp(Header)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()


@pytest.mark.asyncio
async def test_safe_header_survives_being_closed_before_its_title_refresh():
    app = _OpenAndCloseApp(SafeHeader)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        assert not isinstance(app.screen, _HeaderScreen)


@pytest.mark.asyncio
async def test_safe_header_shows_the_title_and_follows_changes():
    app = _HostApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        screen = app.screen_under_test
        assert _shown_title(screen) == "Screen title — Screen sub-title"

        screen.sub_title = "Updated"
        assert _shown_title(screen) == "Screen title — Updated"

        screen.title = None
        app.title = "App title"
        assert _shown_title(screen) == "App title — Updated"


@pytest.mark.asyncio
async def test_safe_header_is_found_and_styled_as_a_header():
    app = _HostApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        header = app.screen_under_test.query_one(Header)
        assert isinstance(header, SafeHeader)
        assert header.region.height == 1


def test_screens_use_safe_header():
    """Every Servonaut screen gets the guarded header, not Textual's own."""
    offenders = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        if path.name == "safe_header.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module is not None
                and node.module.startswith("textual.widgets")
                and any(alias.name == "Header" for alias in node.names)
            ):
                offenders.append(f"{path.relative_to(SRC_ROOT)}:{node.lineno}")
    assert offenders == [], (
        "import SafeHeader from servonaut.widgets.safe_header instead of "
        f"textual's Header: {offenders}"
    )
