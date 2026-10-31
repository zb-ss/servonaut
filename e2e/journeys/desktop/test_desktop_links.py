"""Journey: open links and copy text in the desktop window.

A web view opens no window for a script, so a link the user clicks in the
terminal has to reach the app, which opens it in the system browser. On
Linux the window also owns the clipboard: a copy goes to the page, which
writes it. These journeys click and select in headless Chromium and check
what reaches the browser launcher and the page's clipboard.

The links sit on a small screen pushed over the real app, one of each kind:
a hyperlink the app draws (OSC 8), an address in plain text, and Markdown
links whose text is their address.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Iterator
from typing import Any, TypeVar

import pytest
from textual.screen import Screen
from textual.widgets import Markdown, Static

from e2e.harness import fleet
from e2e.harness.desktop import (
    DEFAULT_TIMEOUT,
    DesktopTimeout,
    input_fence,
    open_session,
    settled_region,
)

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio]

T = TypeVar("T")

HYPERLINK = "https://servonaut.dev/docs/hyperlink"
PLAIN = "https://servonaut.dev/docs/plain"
CLICKED = "https://servonaut.dev/docs/clicked"
CTRL_CLICKED = "https://servonaut.dev/docs/ctrl-clicked"
PLAIN_PREFIX = "Plain address: "
MARKDOWN_PREFIX = "See "
LINK_HINT = "Ctrl+click to open the link"
# How long a person holds a click. The app redraws the row on the press, and
# the terminal must still count press and release as one click on the link.
# Part of the input, not a wait for the app.
CLICK_HOLD_SECONDS = 0.15


class LinksScreen(Screen[None]):
    def compose(self):
        yield Static(f'[link="{HYPERLINK}"]Read the docs[/link]', id="hyperlink")
        yield Static(f"{PLAIN_PREFIX}{PLAIN}", id="plain", markup=False)
        yield Markdown(
            f"{MARKDOWN_PREFIX}[{CLICKED}]({CLICKED})\n\n"
            f"{MARKDOWN_PREFIX}[{CTRL_CLICKED}]({CTRL_CLICKED})",
            id="markdown",
        )


class Browser:
    """Stands in for the system browser; records each address it is given."""

    def __init__(self) -> None:
        self._opened: list[str] = []
        self._lock = threading.Lock()

    def __call__(self, url: str, new: int = 0) -> bool:
        with self._lock:
            self._opened.append(url)
        return True

    def settled(self) -> list[str]:
        """What it was given once every launch the app started has run."""
        for thread in threading.enumerate():
            if thread.name == "desktop-open-url":
                thread.join(5.0)
        with self._lock:
            return list(self._opened)


@pytest.fixture
def browser(monkeypatch) -> Iterator[Browser]:
    import webbrowser

    recorder = Browser()
    monkeypatch.setattr(webbrowser, "open", recorder)
    yield recorder


async def _eventually(check: Callable[[], Awaitable[T]], desc: str) -> T:
    """Poll an async *check* of the page until it is truthy."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + DEFAULT_TIMEOUT
    while True:
        value = await check()
        if value:
            return value
        if loop.time() >= deadline:
            raise DesktopTimeout(f"timed out waiting for {desc}")
        await asyncio.sleep(0.02)


def _seed_fleet(seed) -> None:
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)


async def _show_links(page, desktop_app) -> Screen[None]:
    app = desktop_app.app
    # Run in the app's own context, as the app's own code would.
    app.call_later(app.push_screen, LinksScreen())
    await desktop_app.tui.wait_for_screen("LinksScreen")
    for text in ("Read the docs", PLAIN, CLICKED, CTRL_CLICKED):
        await page.wait_for_text(text)
    return app.screen


async def _cell_of(desktop_app, widget: Any, offset: int) -> tuple[int, int]:
    """The terminal cell *offset* characters into *widget*'s first line."""
    region = await settled_region(desktop_app, widget)
    content = widget.content_region
    assert region.width and content.width > offset, f"{widget!r} is not on screen"
    return content.x + offset, content.y


def _cell_of_text(desktop_app, text: str, offset: int) -> tuple[int, int]:
    """The terminal cell *offset* characters into *text* where the screen draws it."""
    from rich.cells import cell_len

    for row, line in enumerate(desktop_app.tui.rendered_text().splitlines()):
        if text in line:
            # Wide characters (emoji) earlier on the row take two cells.
            return cell_len(line[: line.index(text)]) + offset, row
    raise AssertionError(f"{text!r} is not on the screen")


async def _markdown_link_cell(desktop_app, screen: Screen[None], index: int) -> tuple[int, int]:
    paragraph = screen.query_one("#markdown", Markdown).query("MarkdownParagraph")[index]
    return await _cell_of(desktop_app, paragraph, len(MARKDOWN_PREFIX) + 5)


async def _hover_link(page, column: int, row: int) -> None:
    """Point at a link and wait for the terminal to show it as one."""
    await page.hover_cell(column, row)
    await _eventually(
        lambda: page.page.evaluate(
            "() => document.querySelector('.xterm-screen')"
            ".classList.contains('xterm-cursor-pointer')"
        ),
        "the terminal to show a link under the pointer",
    )


async def _click(page, column: int, row: int) -> None:
    """Press and release on one cell, held as long as a person holds it."""
    await page.hover_cell(column, row)
    await page.page.mouse.down()
    await asyncio.sleep(CLICK_HOLD_SECONDS)
    await page.page.mouse.up()


async def _ctrl_click(page, column: int, row: int) -> None:
    await page.page.keyboard.down("Control")
    try:
        await _click(page, column, row)
    finally:
        await page.page.keyboard.up("Control")


def _links_sent(page) -> list[str]:
    return [
        message[1]
        for message in page.sent
        if isinstance(message, list) and len(message) == 2 and message[0] == "open_url"
    ]


def _hint(page) -> Callable[[], Awaitable[Any]]:
    return lambda: page.page.get_attribute("#terminal", "title")


async def test_a_hyperlink_opens_in_the_browser_on_a_click(desktop, seed, browser):
    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as session:
        page = await open_session(session, app)
        screen = await _show_links(page, app)
        column, row = await _cell_of(app, screen.query_one("#hyperlink"), 4)

        # The text is not the address: pointing at it says where it goes.
        await _hover_link(page, column, row)
        assert await _eventually(_hint(page), "the link's address") == f"Opens {HYPERLINK}"
        await _click(page, column, row)
        await input_fence(page, app)

        assert _links_sent(page) == [HYPERLINK]
        assert browser.settled() == [HYPERLINK]
        # No confirm() dialog and no window.open: nothing for the page to report.
        assert page.errors() == []


async def test_an_address_in_the_text_opens_on_ctrl_click(desktop, seed, browser):
    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as session:
        page = await open_session(session, app)
        screen = await _show_links(page, app)
        column, row = await _cell_of(app, screen.query_one("#plain"), len(PLAIN_PREFIX) + 5)

        # The pointer over the address tells the user how to open it.
        await _hover_link(page, column, row)
        assert await _eventually(_hint(page), "the link hint") == LINK_HINT

        # A plain click is the app's: it opens nothing.
        await page.click_cell(column, row)
        await input_fence(page, app)
        assert _links_sent(page) == []
        assert browser.settled() == []

        # Another cell of the address: two clicks on one cell are a double
        # click, which selects (and copies) the line.
        column += 3
        await _hover_link(page, column, row)
        await _ctrl_click(page, column, row)
        await input_fence(page, app)
        assert _links_sent(page) == [PLAIN]
        assert browser.settled() == [PLAIN]

        # The fence moved the pointer off the address: the hint is gone.
        async def no_hint() -> bool:
            return await _hint(page)() is None

        await _eventually(no_hint, "the link hint to go")
        assert page.errors() == []


async def test_a_markdown_link_opens_once_however_it_is_clicked(desktop, seed, browser):
    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as session:
        page = await open_session(session, app)
        screen = await _show_links(page, app)

        # A click is the app's own: it opens the link, the page sends nothing.
        column, row = await _markdown_link_cell(app, screen, 0)
        await _hover_link(page, column, row)
        await _click(page, column, row)
        await input_fence(page, app)
        assert _links_sent(page) == []
        assert browser.settled() == [CLICKED]

        # Ctrl+click reaches the app twice, as its own click and as the
        # address the terminal found, and still opens one tab.
        column, row = await _markdown_link_cell(app, screen, 1)
        await _hover_link(page, column, row)
        await _ctrl_click(page, column, row)
        await input_fence(page, app)
        assert _links_sent(page) == [CTRL_CLICKED]
        assert browser.settled() == [CLICKED, CTRL_CLICKED]
        assert page.errors() == []


async def test_selecting_an_address_copies_it_to_the_clipboard(desktop, seed, browser):
    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as session:
        await session.context.grant_permissions(["clipboard-read", "clipboard-write"])
        page = await open_session(session, app)
        screen = await _show_links(page, app)
        start, row = await _cell_of(app, screen.query_one("#plain", Static), len(PLAIN_PREFIX))
        end = start + len(PLAIN) - 1

        await page.hover_cell(start, row)
        await page.page.mouse.down()
        for column in (start + 5, start + 15, end):
            await page.hover_cell(column, row)
        await page.page.mouse.up()
        await input_fence(page, app)

        copied = await _eventually(
            lambda: page.page.evaluate("() => navigator.clipboard.readText()"),
            "the copy on the page's clipboard",
        )
        assert copied == PLAIN
        assert app.app.clipboard == PLAIN
        assert any(str(note.message).startswith("Copied") for note in app.notifications)
        # Selecting is not clicking a link.
        assert browser.settled() == []
        assert page.errors() == []


# -- the links and copies of real screens -------------------------------------

# Polls the sign-in keeps waiting through (one a second): long enough to read
# the address and click it.
_SIGN_IN_PENDING_POLLS = 120


async def test_the_sign_in_address_opens_in_the_browser(desktop, seed, fake_cloud, browser):
    from e2e.harness.desktop import click_widget, nav
    from e2e.harness.fake_cloud.state import USER_CODE

    _seed_fleet(seed)
    fake_cloud.configure(token_outcomes=["pending"] * _SIGN_IN_PENDING_POLLS)
    async with desktop.in_process() as app, desktop.browser() as session:
        page = await open_session(session, app)
        await nav(page, app, "nav_login")
        await app.tui.wait_for_screen("LoginScreen")
        await click_widget(page, app, app.tui.on_screen("#btn_login"))
        await app.tui.wait_until(
            lambda: f"Code: {USER_CODE}" in app.tui.rendered_text(), desc="the code shown"
        )
        address = f"{fake_cloud.url}/device"
        await page.wait_for_text(address)

        column, row = _cell_of_text(app, address, 3)
        await _hover_link(page, column, row)
        assert await _eventually(_hint(page), "the link's address") == f"Opens {address}"
        await _click(page, column, row)
        await input_fence(page, app)

        assert _links_sent(page) == [address]
        assert browser.settled() == [address]
        assert page.errors() == []


async def test_copying_a_fleet_row_puts_it_on_the_clipboard(desktop, seed, browser):
    from servonaut.widgets.instance_table import InstanceTable

    _seed_fleet(seed)
    first = fleet.AWS_FLEET[0]
    async with desktop.in_process() as app, desktop.browser() as session:
        await session.context.grant_permissions(["clipboard-read", "clipboard-write"])
        page = await open_session(session, app)
        await page.focus_terminal()
        table = app.tui.on_screen(InstanceTable)
        await app.tui.wait_until(lambda: table.has_focus, desc="the fleet table focused")

        await page.press("y")
        await app.tui.wait_for_toast(rf"^Copied: {first.name}$")
        copied = await _eventually(
            lambda: page.page.evaluate("() => navigator.clipboard.readText()"),
            "the row on the page's clipboard",
        )
        assert copied.startswith(f"{first.name}  ")
        assert app.app.clipboard == copied
        assert page.errors() == []
