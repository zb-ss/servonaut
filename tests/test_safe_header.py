"""Tests for SafeHeader, the header that survives being removed while it mounts."""

from __future__ import annotations

import ast
import gc
import hashlib
import inspect
import textwrap
from pathlib import Path

import pytest
from textual.app import App, ComposeResult
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widgets import Header, Static

from servonaut.widgets.safe_header import SafeHeader

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "servonaut"

# SHA-256 of the source of Textual's Header._on_mount, which SafeHeader
# replaces outright. Unchanged from Textual 8.0.0 through 8.2.8.
_UPSTREAM_HEADER_ON_MOUNT_SHA256 = (
    "b9434f369cf94f16503206b4a21ae9a6fade36c592fe6e57b33fe1f11d136897"
)


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


def _close_unstarted_title_refreshes() -> int:
    """Close the stock header's title refreshes that were queued but never run.

    Python warns when an unstarted coroutine is garbage collected, which
    can happen during whichever test runs next. Closing them here keeps
    that warning out of the rest of the suite.
    """
    closed = 0
    for obj in gc.get_objects():
        if (
            inspect.iscoroutine(obj)
            and obj.__qualname__ == "Header._on_mount.<locals>.set_title"
            and inspect.getcoroutinestate(obj) == inspect.CORO_CREATED
        ):
            obj.close()
            closed += 1
    return closed


@pytest.mark.xfail(
    raises=NoMatches,
    strict=False,
    reason="Textual's Header refreshes its title from a callback that can outlive it",
)
@pytest.mark.asyncio
async def test_stock_header_crashes_when_closed_before_its_title_refresh():
    """Show the scenario below reaches the race SafeHeader exists for."""
    app = _OpenAndCloseApp(Header)
    try:
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
    finally:
        _close_unstarted_title_refreshes()


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


def test_upstream_header_mount_handler_is_the_one_safe_header_replaces():
    """SafeHeader skips Header._on_mount and reimplements what it does.

    If a Textual release changes that handler, SafeHeader may now be
    missing whatever the new version adds, so this fails until someone
    re-checks it.
    """
    source = textwrap.dedent(inspect.getsource(Header._on_mount))
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    assert digest == _UPSTREAM_HEADER_ON_MOUNT_SHA256, (
        "Textual's Header._on_mount has changed. SafeHeader "
        "(src/servonaut/widgets/safe_header.py) replaces that handler "
        "entirely: compare it with the new upstream version, carry over "
        "anything the new version adds, then update "
        "_UPSTREAM_HEADER_ON_MOUNT_SHA256 in this file."
    )


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _stock_header_uses(source: str) -> list[int]:
    """Line numbers where *source* imports or references Textual's Header.

    Covers ``from textual.widgets import Header`` and attribute access
    through any name bound to the ``textual.widgets`` module, such as
    ``widgets.Header`` after ``from textual import widgets`` or
    ``textual.widgets.Header`` after ``import textual.widgets``.
    """
    tree = ast.parse(source)
    module_names = {"textual.widgets"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "textual":
            module_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "widgets"
            )
        elif isinstance(node, ast.Import):
            module_names.update(
                alias.asname
                for alias in node.names
                if alias.name == "textual.widgets" and alias.asname
            )
    lines = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and node.module.startswith("textual.widgets")
            and any(alias.name == "Header" for alias in node.names)
        ) or (
            isinstance(node, ast.Attribute)
            and node.attr == "Header"
            and _dotted_name(node.value) in module_names
        ):
            lines.append(node.lineno)
    return sorted(lines)


@pytest.mark.parametrize(
    "source",
    (
        "from textual.widgets import Footer, Header",
        "from textual.widgets._header import Header",
        "from textual import widgets\nwidgets.Header()",
        "from textual import widgets as tw\ntw.Header()",
        "import textual.widgets\ntextual.widgets.Header()",
        "import textual.widgets as tw\ntw.Header()",
    ),
)
def test_stock_header_check_catches_imports_and_attribute_access(source):
    assert _stock_header_uses(source)


@pytest.mark.parametrize(
    "source",
    (
        "from servonaut.widgets.safe_header import SafeHeader\nSafeHeader()",
        "from textual.widgets import Footer\nFooter()",
        "request.Header",
    ),
)
def test_stock_header_check_ignores_other_code(source):
    assert _stock_header_uses(source) == []


def test_screens_use_safe_header():
    """Every Servonaut screen gets the guarded header, not Textual's own."""
    offenders = [
        f"{path.relative_to(SRC_ROOT)}:{line}"
        for path in sorted(SRC_ROOT.rglob("*.py"))
        if path.name != "safe_header.py"
        for line in _stock_header_uses(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], (
        "use SafeHeader from servonaut.widgets.safe_header instead of "
        f"textual's Header: {offenders}"
    )
