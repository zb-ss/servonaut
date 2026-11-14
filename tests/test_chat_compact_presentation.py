"""Short native chat panels retain readable replies and an identifiable editor."""

from __future__ import annotations

import asyncio

import pytest
from textual.widget import Widget
from textual.widgets import Button, Footer, Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.services.chat_service import ChatSession
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from tests._async_bounds import wait_until
from tests.test_fleet_workspace_layout import _LayoutHost, _open_chat
from tests.test_selection_copy import _Clipboard, _drag
from tests.test_selection_copy import clipboard as clipboard

pytestmark = pytest.mark.usefixtures("navigation_open")


THEMES = ("servonaut", "servonaut-light", "ansi-dark", "ansi-light")


@pytest.fixture(autouse=True)
def _no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)


def _painted(app: _LayoutHost, widget: Widget) -> str:
    region = widget.region
    strips = app.screen._compositor.render_strips()
    return "\n".join(
        strips[y].crop(region.x, region.right).text
        for y in range(region.y, region.bottom)
    )


async def _actions(app: _LayoutHost, family: str) -> None:
    if family == "actions":
        await app.push_screen(ServerActionsScreen(app.instances[0]))


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("family,width", [("fleet", 109), ("actions", 101)])
async def test_short_chat_keeps_six_reply_rows_and_all_native_actions(
    theme: str, family: str, width: int,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    app.theme = theme
    async with app.run_test(size=(width, 30)) as pilot:
        await _actions(app, family)
        panel = await _open_chat(app, pilot)
        messages = panel.query_one("#chat-messages")
        await messages.mount(Static("\n".join(f"reply line {n}" for n in range(12))))
        await pilot.pause()
        assert messages.content_region.height >= 6
        assert messages.scrollable_content_region.height >= 6
        assert "Servonaut AI Assistant" in _painted(app, panel.query_one("#chat-logo"))
        assert "MCP server online" in _painted(app, panel.query_one("#chat-logo"))
        footer = app.screen.query_one(Footer)
        for name in ("new", "history", "provider", "close", "mic", "convo", "send"):
            button = panel.query_one(f"#btn-chat-{name}", Button)
            assert panel.region.contains_region(button.region)
            assert button.region.bottom <= footer.region.y
            assert app.get_widget_at(*button.region.center)[0] is button
            assert button.label.plain.strip() in _painted(app, button)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("family,width", [("fleet", 109), ("actions", 101)])
async def test_height_state_uses_row_allocation_and_clears_on_collapse(
    family: str, width: int,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    async with app.run_test(size=(width, 50)) as pilot:
        await _actions(app, family)
        panel = await _open_chat(app, pilot)
        screen = app.screen
        row = screen.query_one("#main-layout")

        async def resize_content_to(height: int) -> None:
            """Size the terminal so the chat row is *height* rows tall.

            The rows around the chat row (header, notification lane, footer)
            change with the terminal's height class, so the terminal height is
            found from the layout, not from a fixed overhead.
            """
            terminal = app.size.height - row.content_region.height + height
            for _ in range(6):
                await pilot.resize_terminal(width, terminal)
                await pilot.pause()
                if row.content_region.height == height:
                    return
                terminal += height - row.content_region.height
            raise AssertionError(f"no terminal height gives a {height}-row chat row")

        # Six transcript rows fit at 25.
        for height in (24, 25, 26, 24):
            await resize_content_to(height)
            assert row.content_region.height == height
            assert screen.has_class("-chat-compact") is (height < 25)
            header = panel.query_one("#chat-header")
            logo = panel.query_one("#chat-logo")
            assert panel.region.contains_region(header.region)
            assert header.region.contains_region(logo.region)
            assert "Servonaut AI Assistant" in _painted(app, logo)
            assert "MCP server online" in _painted(app, logo)
            for name in ("new", "history", "provider", "close"):
                button = panel.query_one(f"#btn-chat-{name}", Button)
                assert header.region.contains_region(button.region)
                assert button.label.plain in _painted(app, button)
                assert app.get_widget_at(*button.region.center)[0] is button
            assert header.region.bottom <= panel.query_one("#chat-messages").region.y
            assert panel.query_one("#chat-messages").scrollable_content_region.height >= 6
        await pilot.press("f2")
        await wait_until(lambda: panel._collapsed)
        await pilot.pause()
        assert not screen.has_class("-chat-compact")
        await pilot.press("f2")
        await wait_until(lambda: not panel._collapsed)
        await pilot.pause()
        assert screen.has_class("-chat-compact")
        await resize_content_to(26)
        assert not screen.has_class("-chat-compact")
        await resize_content_to(24)
        assert screen.has_class("-chat-compact")
        await pilot.press("f3")
        await wait_until(lambda: not panel.is_attached)
        await wait_until(lambda: not screen.has_class("-chat-compact"))
        await wait_until(lambda: screen.query_one(
            "#workspace_chat", Button,
        ).label.plain == "Open chat")
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ("ansi-dark", "ansi-light"))
@pytest.mark.parametrize("size", [(109, 30), (100, 30)])
async def test_ansi_composer_has_painted_bounds_and_copies_literal_selection(
    theme: str, size: tuple[int, int], clipboard: _Clipboard,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    app.theme = theme
    async with app.run_test(size=size) as pilot:
        panel = await _open_chat(app, pilot)
        editor = panel.query_one("#chat-input", TextArea)
        editor.load_text("draft Ω [b] literal\nsecond line")
        await pilot.pause()
        document, outer = editor.document, editor.region
        assert outer.height == 4 and editor.content_region.height >= 2
        for focused in (False, True):
            (editor if focused else panel.query_one("#btn-chat-history")).focus()
            await pilot.pause()
            lines = _painted(app, editor).splitlines()
            assert lines[0].startswith("╭") and lines[0].endswith("╮")
            assert lines[-1].startswith("╰") and lines[-1].endswith("╯")
            assert editor.region == outer
        clipboard.calls.clear()
        await _drag(pilot, editor, (0, 0), (7, 0))
        assert editor.selected_text == "draft Ω"
        assert clipboard.calls == ["draft Ω"]
        assert app.focused is editor and editor.document is document
        assert editor.text == "draft Ω [b] literal\nsecond line"
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_compact_transitions_keep_draft_scroll_worker_and_tab_order(theme: str) -> None:
    app = _LayoutHost(navigation_visible=False)
    app.theme = theme
    async with app.run_test(size=(109, 40)) as pilot:
        panel = await _open_chat(app, pilot)
        editor = panel.query_one("#chat-input", TextArea)
        draft = "\n".join(f"draft line {n}" for n in range(20))
        editor.load_text(draft)
        editor.selection = Selection((12, 2), (13, 6))
        await pilot.pause()
        editor.scroll_to(y=12, animate=False)
        await pilot.pause()
        document, selection, scroll = editor.document, editor.selection, editor.scroll_offset
        session = panel._session = ChatSession()
        release = asyncio.Event()
        worker = panel.run_worker(release.wait(), name="pending-reply")
        try:
            for width, height in ((109, 30), (100, 30), (109, 40), (109, 30)):
                await pilot.resize_terminal(width, height)
                await pilot.pause()
                assert app.screen.query_one(ChatPanel) is panel
                assert panel._session is session and not worker.is_finished
                assert editor.document is document and editor.text == draft
                assert editor.selection == selection and editor.scroll_offset == scroll
                row = panel.query_one("#chat-input-row")
                assert row.region.contains_region(editor.region)
                assert editor.region.height == 4
                for name in ("mic", "convo", "send"):
                    button = panel.query_one(f"#btn-chat-{name}", Button)
                    assert button.region.height == 3
                    assert panel.region.contains_region(button.region)
                    assert row.region.contains_region(button.region)
                    if app.screen.has_class("-chat-replace"):
                        assert editor.region.right <= button.region.x
                    else:
                        assert editor.region.bottom <= button.region.y
                assert panel.query_one("#chat-messages").scrollable_content_region.height >= 4
            app.action_toggle_navigation()
            await pilot.pause()
            assert app.screen.query_one(Sidebar).display
            assert app.screen.has_class("-chat-replace")
            assert app.screen.has_class("-chat-compact")
            app.action_toggle_navigation()
            await pilot.pause()
            assert not app.screen.has_class("-chat-replace")
            await pilot.press("f2", "f2")
            await pilot.pause()
            assert editor.document is document and editor.selection == selection
            assert editor.scroll_offset == scroll and not worker.is_finished
            editor.focus()
            await wait_until(lambda: app.focused is editor)
            for name in ("mic", "convo", "send"):
                await pilot.press("tab")
                button = panel.query_one(f"#btn-chat-{name}", Button)
                await wait_until(lambda: app.focused is button)
                assert app.get_widget_at(*button.region.center)[0] is button
        finally:
            release.set()
            await worker.wait()
        assert app._exception is None
