"""Clicks on drawn text run only the actions the app's own widgets draw.

1. Fingerprints of the Textual code the override depends on.
2. The policy table.
3. The real ``ServonautApp`` class, with the parser backstop suspended so the
   policy is shown to hold on its own: an action named by outside text does
   nothing, while Markdown links and scroll bars keep working.
"""
from __future__ import annotations

import hashlib
import inspect
import textwrap

import pytest
import textual._event_broker as event_broker
from textual.app import App
from textual.containers import VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.scrollbar import ScrollBar, ScrollBarRender
from textual.widgets import Button, DataTable, Markdown, Static
from textual.widgets._markdown import MarkdownBlock, MarkdownTableCellContents
from textual.renderables.bar import Bar

from servonaut.app import ServonautApp
from servonaut.utils import markup_backstop
from servonaut.utils.click_policy import click_action_allowed
from servonaut.utils.markup import is_web_url


def _digest(function) -> str:
    return hashlib.sha256(textwrap.dedent(inspect.getsource(function)).encode()).hexdigest()


_UPSTREAM_SOURCE_SHA256 = {
    "App._broker_event": "6b454d5cd2204807f04732720b289cdca905b9ae694298a6f79c60783c469dd0",
    "App.open_url": "99252935fe4e1474ba8b56159a0e642a257ce61726e9f52836af47551f277757",
    "extract_handler_actions": "83883ab79baf3d987c29d6f11ab0d1f0920423b7944f15906b7558d46a947298",
    "ScrollBarRender.render_bar": "70213f6683fbd5cc51b8a8645e4afe1a372960bed4864fa349a8546c20620517",
    "MarkdownBlock._token_to_content": "7cc227faf7cd686ede886b325cd0ec4a9a9d4d48d389b81cf01ac0e7074191a1",
    "Bar.__rich_console__": "3e06bed214c64815741b4da5b2ca6226adf30ead5fe6fd04c62b1045a89317f1",
}


def _upstream():
    return {
        "App._broker_event": App._broker_event,
        "App.open_url": App.open_url,
        "extract_handler_actions": event_broker.extract_handler_actions,
        "ScrollBarRender.render_bar": ScrollBarRender.render_bar,
        "MarkdownBlock._token_to_content": MarkdownBlock._token_to_content,
        "Bar.__rich_console__": Bar.__rich_console__,
    }


@pytest.mark.parametrize("name", sorted(_UPSTREAM_SOURCE_SHA256))
def test_upstream_code_is_what_the_click_policy_was_written_against(name) -> None:
    assert _digest(_upstream()[name]) == _UPSTREAM_SOURCE_SHA256[name]


def test_the_override_is_the_only_path_for_style_actions() -> None:
    # Every widget hands a clicked style to the app's broker; nothing else runs it.
    from textual.widget import Widget

    assert "self.app._broker_event(" in inspect.getsource(Widget.broker_event)
    assert "_broker_event" not in inspect.getsource(App.run_action)
    assert ServonautApp._broker_event is not App._broker_event


# ---------------------------------------------------------------------------
# The policy table
# ---------------------------------------------------------------------------

class _Plain:
    pass


@pytest.mark.parametrize(
    ("action", "widget", "allowed"),
    [
        ("link('https://example.invalid')", MarkdownBlock.__new__(MarkdownBlock), True),
        (("link", ("https://example.invalid",)), MarkdownBlock.__new__(MarkdownBlock), True),
        ("link('https://example.invalid')", MarkdownTableCellContents.__new__(MarkdownTableCellContents), True),
        ("grab", MarkdownTableCellContents.__new__(MarkdownTableCellContents), False),
        ("grab", ScrollBar.__new__(ScrollBar), True),
        ("scroll_up", ScrollBar.__new__(ScrollBar), True),
        ("scroll_down", ScrollBar.__new__(ScrollBar), True),
        ("link('https://example.invalid')", _Plain(), False),
        ("grab", _Plain(), False),
        ("grab", MarkdownBlock.__new__(MarkdownBlock), False),
        ("app.quit", _Plain(), False),
        ("app.link('x')", MarkdownBlock.__new__(MarkdownBlock), False),
        ("screen.dismiss(True)", MarkdownBlock.__new__(MarkdownBlock), False),
        ("screen.start", ScrollBar.__new__(ScrollBar), False),
        ("not an action", MarkdownBlock.__new__(MarkdownBlock), False),
        (None, MarkdownBlock.__new__(MarkdownBlock), False),
        (("a", "b", "c"), MarkdownBlock.__new__(MarkdownBlock), False),
        ("", MarkdownBlock.__new__(MarkdownBlock), False),
    ],
)
def test_policy_table(action, widget, allowed) -> None:
    assert click_action_allowed(action, widget) is allowed


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://example.invalid/a?b=c", True),
        ("http://example.invalid", True),
        ("HTTPS://example.invalid", True),
        ("file:///etc/passwd", False),
        ("smb://host/share", False),
        ("ms-settings:network", False),
        ("javascript:alert(1)", False),
        ("https:///no-host", False),
        ("https://example.invalid/a b", False),
        ("https://example.invalid/\x1b[8m", False),
        (" https://example.invalid", False),
        ("", False),
        (None, False),
    ],
)
def test_only_web_urls_open(url, allowed) -> None:
    assert is_web_url(url) is allowed


# ---------------------------------------------------------------------------
# The real app class
# ---------------------------------------------------------------------------

class _Confirm(ModalScreen):
    def compose(self):
        yield Static("Delete [@click=screen.dismiss(True)]server-1[/]?", id="question")
        yield Button("No", id="no")


class _Body(Screen):
    def __init__(self, mode: str) -> None:
        super().__init__()
        self.mode = mode
        self.started = 0

    def action_start(self) -> None:
        self.started += 1

    def compose(self):
        if self.mode == "static":
            yield Static(
                "[@click=app.ran]a[/] [@click=screen.start]b[/] [@click=app.quit]c[/] "
                "[@click=app.toggle_demo]d[/] [@click=record]e[/] [@click=app.focus('x')]f[/]",
                id="target",
            )
        elif self.mode == "table":
            yield DataTable(id="target")
        elif self.mode == "markdown":
            yield Markdown(
                "[web](https://example.invalid/a) [file](file:///etc/passwd) [share](smb://host/s)",
                id="target",
            )
        elif self.mode == "markdown_table":
            yield Markdown(
                "| name |\n|---|\n| [cell](https://example.invalid/t) |\n| [bad](file:///etc/passwd) |",
                id="target",
            )
        elif self.mode == "scroll":
            with VerticalScroll(id="target"):
                for index in range(80):
                    yield Static(f"row {index}")
        else:
            yield Static("base")


class _OutsideTextApp(ServonautApp):
    def __init__(self, mode: str) -> None:
        super().__init__()
        # The app installs the parser backstop when it starts; this test is
        # about the click policy alone.
        markup_backstop.uninstall()
        self.mode = mode
        self.ran = 0
        self.modal_result = "unset"

    def on_mount(self, event) -> None:  # skip the real start-up
        event.prevent_default()

    def action_ran(self) -> None:
        self.ran += 1

    def get_default_screen(self):
        return _Body(self.mode)


def _clickable_cells(app):
    width, height = app.size
    cells = []
    for y in range(height):
        for x in range(width):
            try:
                style = app.screen.get_style_at(x, y)
            except Exception:  # noqa: BLE001 - an undrawn cell
                continue
            if style is not None and any(key.startswith("@click") for key in (style.meta or {})):
                cells.append((x, y))
    return cells


async def _click_every_cell(pilot, app) -> int:
    cells = _clickable_cells(app)
    seen = set()
    for x, y in cells:
        await pilot.click(offset=(x, y))
        await pilot.pause()
        seen.add((x, y))
    return len(seen)


@pytest.fixture
def raw_parsers():
    """The test app reads outside markup as upstream does; only the click policy stands."""
    yield
    markup_backstop.install()


@pytest.mark.asyncio
async def test_actions_named_by_static_text_do_nothing(raw_parsers) -> None:
    app = _OutsideTextApp("static")
    demo_before = app.demo_mode
    async with app.run_test(size=(100, 12)) as pilot:
        await pilot.pause()
        assert _clickable_cells(app), "the sample text must carry actions for the test to mean anything"
        await _click_every_cell(pilot, app)
        assert app.ran == 0
        assert app.screen.started == 0
        assert app.demo_mode == demo_before
        assert app.is_running


@pytest.mark.asyncio
async def test_actions_named_by_a_table_cell_do_nothing(raw_parsers) -> None:
    app = _OutsideTextApp("table")
    async with app.run_test(size=(100, 12)) as pilot:
        table = app.query_one(DataTable)
        table.add_columns("name", "n")
        table.add_row("a", "1")
        table.add_row("[@click=app.ran]name[/] [@click=screen.start]go[/]", "2")
        await pilot.pause()
        assert _clickable_cells(app)
        await _click_every_cell(pilot, app)
        assert app.ran == 0
        assert app.screen.started == 0


@pytest.mark.asyncio
async def test_a_modal_cannot_be_answered_by_text_inside_it(raw_parsers) -> None:
    app = _OutsideTextApp("none")
    async with app.run_test(size=(100, 12)) as pilot:
        app.push_screen(_Confirm(), callback=lambda result: setattr(app, "modal_result", result))
        await pilot.pause()
        assert _clickable_cells(app)
        await _click_every_cell(pilot, app)
        assert app.modal_result == "unset"
        assert isinstance(app.screen, _Confirm)


@pytest.mark.asyncio
async def test_markdown_links_open_only_web_addresses(raw_parsers, monkeypatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr(App, "open_url", lambda self, url, *, new_tab=True: opened.append(url))
    app = _OutsideTextApp("markdown")
    async with app.run_test(size=(100, 12), notifications=True) as pilot:
        await pilot.pause()
        cells = _clickable_cells(app)
        assert cells
        await _click_every_cell(pilot, app)
        assert set(opened) == {"https://example.invalid/a"}
        assert any("Only web links" in n.message for n in app._notifications)


@pytest.mark.asyncio
async def test_scroll_bar_track_still_scrolls(raw_parsers) -> None:
    app = _OutsideTextApp("scroll")
    async with app.run_test(size=(60, 12)) as pilot:
        await pilot.pause()
        scroller = app.query_one("#target")
        assert scroller.scroll_y == 0
        bar = scroller.vertical_scrollbar
        region = bar.region
        await pilot.click(offset=(region.x, region.y + region.height - 2))
        await pilot.pause()
        assert scroller.scroll_y > 0


@pytest.mark.asyncio
async def test_scroll_bar_thumb_can_be_dragged(raw_parsers) -> None:
    app = _OutsideTextApp("scroll")
    async with app.run_test(size=(60, 12)) as pilot:
        await pilot.pause()
        scroller = app.query_one("#target")
        region = scroller.vertical_scrollbar.region
        await pilot.mouse_down(offset=(region.x, region.y + 1))
        await pilot.hover(offset=(region.x, region.y + region.height - 2))
        await pilot.mouse_up(offset=(region.x, region.y + region.height - 2))
        await pilot.pause()
        assert scroller.scroll_y > 0


@pytest.mark.asyncio
async def test_a_link_in_a_markdown_table_cell_opens_through_the_web_check(raw_parsers, monkeypatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr(App, "open_url", lambda self, url, *, new_tab=True: opened.append(url))
    app = _OutsideTextApp("markdown_table")
    async with app.run_test(size=(100, 14)) as pilot:
        await pilot.pause()
        cells = _clickable_cells(app)
        assert cells
        await _click_every_cell(pilot, app)
        assert set(opened) == {"https://example.invalid/t"}
