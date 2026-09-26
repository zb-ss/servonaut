"""Journey: use Servonaut in the desktop window.

The desktop app shows the TUI in a web page served from loopback. These
journeys load that page in headless Chromium, hand it its session token the
way the desktop window does, and then use the app with the mouse, the
keyboard and the clipboard while the window changes size. The host and the
real app run in this process, so each step is checked twice: in what the
terminal received (what the user sees drawn) and in the app's own state.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from e2e.harness import fleet
from e2e.harness.desktop import DesktopTimeout, wait_until

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio]

FLEET_NAMES = [host.name for host in fleet.AWS_FLEET]
# Text from several scripts: the paste must arrive intact.
PASTED_TEXT = "café Δ 你好"
# The host never gives the app more columns than this, however wide the window.
MAX_COLUMNS = 500


def _seed_fleet(seed) -> None:
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)


async def _open_session(browser, desktop_app):
    """Load the frontend and start the session, as the desktop window does."""
    page = await browser.new_page()
    assert await page.open(desktop_app.origin) == 200
    assert await page.page.title() == "Servonaut"
    await page.start_session(desktop_app.token.encoded_value())
    await page.wait_for_first_output()
    await desktop_app.wait_for_app("InstanceListScreen")
    return page


def _fleet_rows(desktop_app) -> list[str]:
    return [row[1] for row in desktop_app.tui.table_rows("InstanceTable")]


async def _click_widget(page, desktop_app, widget) -> None:
    """Click the middle of *widget* where the terminal draws it."""
    assert desktop_app.tui.is_reachable(widget), f"{widget!r} is hidden"
    region = widget.region
    assert region.width and region.height, f"{widget!r} is not on screen"
    await page.click_cell(region.x + region.width // 2, region.y + region.height // 2)


async def _scroll_into_view(page, desktop_app, widget, container) -> None:
    """Scroll *container* with the mouse wheel until all of *widget* shows."""
    tui = desktop_app.tui
    for _ in range(20):
        if widget.region.height and container.region.contains_region(widget.region):
            return
        area = container.region
        await page.hover_cell(area.x + area.width // 2, area.y + area.height // 2)
        before = container.scroll_y
        await page.page.mouse.wheel(0, 120)
        await tui.wait_until(lambda: container.scroll_y != before, desc="the sidebar scrolled")
        await tui.settle()
    raise AssertionError(f"{widget!r} never scrolled into view")


async def _nav(page, desktop_app, nav_id: str) -> None:
    """Click a sidebar entry, opening its section first, like a user."""
    from textual.widgets import Button

    from servonaut.widgets.sidebar_section import SidebarSection

    tui = desktop_app.tui
    assert tui.nav_reachable(nav_id), f"{nav_id} is not available"
    button = tui.nav_button(nav_id)
    section = next((node for node in button.ancestors if isinstance(node, SidebarSection)), None)
    if section is not None and section.collapsed:
        await _click_widget(page, desktop_app, section.query_one("Button.section-header", Button))
        await tui.wait_until(lambda: not section.collapsed, desc=f"section of {nav_id} open")
        await tui.settle()
    button = tui.nav_button(nav_id)
    await _scroll_into_view(page, desktop_app, button, tui.on_screen("#sidebar-scroll"))
    await _click_widget(page, desktop_app, button)


async def test_the_app_renders_in_the_page(desktop, seed):
    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await _open_session(browser, app)
        # The fleet the user has cached is drawn in the terminal...
        for name in FLEET_NAMES:
            await page.wait_for_text(name)
        assert _fleet_rows(app) == FLEET_NAMES
        # ...at the size the page measured for its window.
        assert (app.app.size.width, app.app.size.height) == (
            page.dimensions["width"],
            page.dimensions["height"],
        )
        assert "-connected" in (await page.page.get_attribute("#terminal", "class") or "")
        assert await page.page.locator("canvas.xterm-text-layer").count() == 1
        # Everything the page loaded, and its socket, came from the host itself.
        host = urlsplit(app.origin).netloc
        assert {urlsplit(url).netloc for url, _ in browser.requests()} == {host}
        assert [urlsplit(socket.url).netloc for socket in page.sockets] == [host]
        assert page.errors() == []


async def test_sidebar_navigation_with_the_mouse(desktop, seed):
    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await _open_session(browser, app)
        tour = [
            ("nav_custom_servers", "CustomServersScreen", "Custom Servers"),
            ("nav_keys", "KeyManagementScreen", "SSH Key Management"),
            # Settings sits in a section that starts collapsed.
            ("nav_settings", "SettingsScreen", "Settings"),
            ("nav_list", "InstanceListScreen", FLEET_NAMES[0]),
        ]
        for nav_id, screen, visible_text in tour:
            mark = page.output_mark()
            await _nav(page, app, nav_id)
            await app.tui.wait_for_screen(screen)
            await page.wait_for_text(visible_text, since=mark)
            # Every screen keeps the sidebar, so the tour can go on.
            assert app.tui.nav_reachable("nav_list"), f"no way back from {screen}"
        assert page.errors() == []


class TypingWentNowhere(AssertionError):
    """Keys typed into the window reached no widget."""


@pytest.mark.xfail(
    strict=True,
    raises=TypingWentNowhere,
    reason="Known bug: in the desktop window no widget has keyboard focus when the "
    "window gains focus, so typing does not reach the fleet search box (the "
    "terminal app starts with it focused). The web driver blurs the app while "
    "the sidebar still holds the initial focus; the sidebar is made unfocusable "
    "right after, so focus is never restored.",
)
async def test_typing_right_after_the_window_gains_focus_searches_the_fleet(desktop, seed):
    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await _open_session(browser, app)
        # The window becomes the active one; the user starts typing.
        await page.focus_terminal()
        await wait_until(lambda: app.app.app_focus, desc="the app to have focus")
        before = len(page.sent)
        await page.type("edge")
        await wait_until(lambda: "edge" in page.stdin_sent(before), desc="the keys sent")
        try:
            await wait_until(
                lambda: _fleet_rows(app) == ["edge-1"], timeout=5, desc="typing filters the fleet"
            )
        except DesktopTimeout:
            raise TypingWentNowhere(f"focused widget: {app.tui.focused_id()}") from None


async def test_keyboard_search_help_and_command_palette(desktop, seed):
    from servonaut.widgets.instance_table import InstanceTable

    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await _open_session(browser, app)
        tui = app.tui
        # Click into the search box, then type: the fleet is filtered.
        await _click_widget(page, app, tui.on_screen("#search_input"))
        await tui.wait_until(lambda: tui.focused_id() == "search_input", desc="search focused")
        await page.type("edge")
        await tui.wait_until(lambda: _fleet_rows(app) == ["edge-1"], desc="fleet filtered")
        await tui.wait_until(lambda: "app-1" not in tui.rendered_text(), desc="filter drawn")
        # Home, then delete to the end, clears it again.
        await page.press("Home", "Control+k")
        await tui.wait_until(lambda: _fleet_rows(app) == FLEET_NAMES, desc="filter cleared")

        # Tab moves the focus on to the fleet table, where single keys act.
        table = tui.on_screen(InstanceTable)
        visited = []
        for _ in range(8):
            if table.has_focus:
                break
            focused = app.app.focused
            visited.append(repr(focused))
            await page.press("Tab")
            await tui.wait_until(lambda: app.app.focused is not focused, desc="focus moved")
        assert table.has_focus, f"Tab never reached the fleet table: {visited}"

        mark = page.output_mark()
        await page.press("?")
        await tui.wait_for_screen("HelpScreen")
        await page.wait_for_text("Navigation", since=mark)
        await page.press("Escape")
        await tui.wait_for_screen("InstanceListScreen")

        # The command palette: ctrl+p, a query, Enter.
        await page.press("Control+p")
        await tui.wait_for_screen("CommandPalette")
        await page.type("Go to SSH Keys")
        await tui.wait_until(
            lambda: _palette_highlight(tui).startswith("Go to SSH Keys"), desc="palette entry"
        )
        mark = page.output_mark()
        await page.press("Enter")
        await tui.wait_for_screen("KeyManagementScreen")
        await page.wait_for_text("SSH Key Management", since=mark)
        await page.press("Escape")
        await tui.wait_for_screen("InstanceListScreen")
        assert page.errors() == []


def _palette_highlight(tui) -> str:
    from textual.command import CommandList

    command_list = tui.on_screen(CommandList)
    index = command_list.highlighted
    if index is None:
        return ""
    prompt = command_list.get_option_at_index(index).prompt
    return getattr(prompt, "plain", str(prompt))


async def test_paste_reaches_the_focused_input(desktop, seed):
    from textual.widgets import Input

    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await _open_session(browser, app)
        tui = app.tui
        search = tui.on_screen("#search_input", Input)
        await _click_widget(page, app, search)
        await tui.wait_until(lambda: search.has_focus, desc="search box focused")

        mark = page.output_mark()
        await page.paste(PASTED_TEXT)
        await tui.wait_until(lambda: search.value == PASTED_TEXT, desc="pasted text in the box")
        await page.wait_for_text("café", since=mark)
        # Nothing in the fleet matches it.
        await tui.wait_until(lambda: _fleet_rows(app) == [], desc="no match")

        await page.press("Home", "Control+k")
        await tui.wait_until(lambda: search.value == "", desc="search box cleared")
        await page.paste("bastion")
        await tui.wait_until(lambda: _fleet_rows(app) == ["bastion-1"], desc="paste filtered")
        assert page.errors() == []


async def test_resizing_the_window_resizes_the_app(desktop, seed):
    _seed_fleet(seed)
    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await _open_session(browser, app)
        tui = app.tui

        def app_size() -> tuple[int, int]:
            return (app.app.size.width, app.app.size.height)

        # Mark the output first: the app may repaint before resize() returns.
        mark = page.output_mark()
        smaller = await page.resize(900, 560)
        assert smaller["width"] < 160 and smaller["height"] < 37, smaller
        await tui.wait_until(
            lambda: app_size() == (smaller["width"], smaller["height"]), desc="app resized"
        )
        await page.wait_for_text(FLEET_NAMES[0], since=mark)

        # A window wider than the host allows keeps working at the limit.
        wide = await page.resize(5000, 700)
        assert wide["width"] > MAX_COLUMNS, wide
        await tui.wait_until(
            lambda: app_size() == (MAX_COLUMNS, wide["height"]), desc="app at the column limit"
        )

        mark = page.output_mark()
        normal = await page.resize(1280, 800)
        await tui.wait_until(
            lambda: app_size() == (normal["width"], normal["height"]), desc="app resized back"
        )
        await page.wait_for_text(FLEET_NAMES[-1], since=mark)
        assert "-closed" not in await page.body_classes()
        assert app.app.is_running
        assert page.errors() == []
        await wait_until(lambda: tui.screen_name() == "InstanceListScreen", desc="still on fleet")
