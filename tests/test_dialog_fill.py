"""Mounted fill surfaces with native editor and picker scroll ownership."""

from __future__ import annotations

import pytest
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, OptionList, Static, TextArea
from textual.widgets.option_list import Option

from servonaut.widgets.dialogs import (
    DialogActions,
    DialogContent,
    DialogFrame,
    DialogNotificationSpace,
)
from tests.test_basic_dialogs import BasicDialogHost, assert_exposed


DOCUMENT = "  " + "\n".join(
    f"Example line {index + 1}: [literal] " + "readable content " * 16
    for index in range(80)
) + "\n  "


class EditorSurface(ModalScreen[str | None]):
    """Fixture surface: no clipboard, files, services or utility-screen handlers."""

    DEFAULT_CLASSES = "dialog-screen"
    AUTO_FOCUS = "#utility-editor"
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, *, soft_wrap: bool = False, read_only: bool = False) -> None:
        super().__init__()
        self._soft_wrap = soft_wrap
        self._read_only = read_only

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("Review example text", id="utility-heading"),
            body=DialogContent(
                Static("Select text or edit the example document.", id="utility-caption"),
                TextArea(
                    DOCUMENT, soft_wrap=self._soft_wrap, read_only=self._read_only,
                    show_line_numbers=True, id="utility-editor",
                ),
                id="utility-content",
            ),
            status=Static("Example document stays in memory.", id="utility-status"),
            actions=DialogActions(
                Button("Cancel", id="utility-cancel"),
                Button("Save", id="utility-save", variant="primary"),
                id="utility-actions",
            ),
            size="fill", id="utility-frame",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(
            self.query_one(TextArea).text if event.button.id == "utility-save" else None
        )

    def action_cancel(self) -> None:
        self.dismiss(None)


class PickerSurface(ModalScreen[str | None]):
    """Use OptionList directly, retaining its native focus, hit testing and keys."""

    DEFAULT_CLASSES = "dialog-screen"
    AUTO_FOCUS = "#utility-options"
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("Choose an example item", id="utility-heading"),
            body=OptionList(
                *(Option(f"Example choice {index + 1}", id=str(index)) for index in range(60)),
                id="utility-options",
            ),
            status=Static("Choose one item or cancel.", id="utility-status"),
            actions=DialogActions(Button("Cancel", id="utility-cancel"), id="utility-actions"),
            size="fill", id="utility-frame",
        )

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option_id)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class CatalogSurface(ModalScreen[None]):
    """Standard frame with a fixed disclosure and one native catalog viewport."""

    DEFAULT_CLASSES = "dialog-screen"
    AUTO_FOCUS = "#utility-catalog"
    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    CatalogSurface #utility-catalog {
        height: 1fr;
        max-height: 9;
    }
    """

    def compose(self) -> ComposeResult:
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("Review example catalog", id="utility-heading"),
            body=DialogContent(
                Static("Review the browser action before choosing an example item.", id="utility-caption"),
                VerticalScroll(
                    *(Static(f"Example item {index + 1}") for index in range(60)),
                    id="utility-catalog",
                ),
            ),
            status=Static("No external action has started.", id="utility-status"),
            actions=DialogActions(Button("Cancel", id="utility-cancel")),
            size="standard", id="utility-frame",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


def surface(kind: str) -> EditorSurface | PickerSurface:
    return EditorSurface() if kind == "editor" else PickerSurface()


def assert_controls_exposed(app: BasicDialogHost, screen: ModalScreen) -> None:
    frame = screen.query_one(DialogFrame)
    for selector in ("#utility-heading", "#utility-status", "#utility-cancel"):
        assert_exposed(app, screen, screen.query_one(selector))
    if screen.query("#utility-caption"):
        assert_exposed(app, screen, screen.query_one("#utility-caption"))
    for button in screen.query_one(DialogActions).query(Button):
        assert_exposed(app, screen, button)
    # Four native alert rows plus two footer-clearance rows remain below.
    # Hidden spacers do not have a public compositor region in Textual.
    assert frame.region.bottom <= screen.region.bottom - 6


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("kind", ["editor", "picker"])
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
async def test_fill_preserves_usable_child_viewport_and_pinned_controls(
    size: tuple[int, int], kind: str, theme: str,
) -> None:
    app = BasicDialogHost()
    app.theme = theme
    screen = surface(kind)
    results = []
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        app.push_screen(screen, results.append)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        child = screen.query_one(TextArea if kind == "editor" else OptionList)
        assert screen.focused is child
        assert int(size[0] * 0.85) <= frame.region.width <= int(size[0] * 0.94)
        assert frame.region.height >= int(size[1] * 0.55)
        assert frame.content_region.contains_region(child.region)
        assert child.content_size.height >= 4
        assert_controls_exposed(app, screen)
        await pilot.press("escape")
        await pilot.pause()
        assert results == [None] and app.focused is origin


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("soft_wrap", [False, True])
@pytest.mark.parametrize("read_only", [False, True])
async def test_textarea_owns_scroll_and_full_literal_selection(
    size: tuple[int, int], soft_wrap: bool, read_only: bool,
) -> None:
    app = BasicDialogHost()
    screen = EditorSurface(soft_wrap=soft_wrap, read_only=read_only)
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        editor = screen.query_one(TextArea)
        content = screen.query_one(DialogContent)
        positions = [button.region for button in screen.query_one(DialogActions).query(Button)]
        await pilot.press("pagedown", "pagedown", "end")
        await pilot.pause()
        assert editor.scroll_y > 0
        if not soft_wrap:
            assert editor.scroll_x > 0
        assert content.scroll_x == content.scroll_y == 0
        assert content not in screen.focus_chain
        assert screen.query_one(DialogFrame).border_subtitle == ""
        assert screen.focused is editor
        assert_controls_exposed(app, screen)
        await pilot.press("f7")
        await pilot.pause()
        assert editor.selected_text == DOCUMENT
        assert editor.text == DOCUMENT
        if read_only:
            await pilot.press("x")
            assert editor.text == DOCUMENT
        assert [button.region for button in screen.query_one(DialogActions).query(Button)] == positions
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_editor_native_replace_undo_and_explicit_save_round_trip(size: tuple[int, int]) -> None:
    app = BasicDialogHost()
    screen = EditorSurface()
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        editor = screen.query_one(TextArea)
        await pilot.press("f7", "x")
        await pilot.pause()
        assert editor.text == "x"
        await pilot.press("ctrl+z")
        await pilot.pause()
        assert editor.text == DOCUMENT
        assert results == []
        assert await pilot.click(screen.query_one("#utility-save", Button))
        await pilot.pause()
        assert results == [DOCUMENT]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("submit", ["enter", "click"])
async def test_direct_option_list_keeps_native_scroll_selection_and_hint(
    size: tuple[int, int], submit: str,
) -> None:
    app = BasicDialogHost()
    screen = PickerSurface()
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        options = screen.query_one(OptionList)
        frame = screen.query_one(DialogFrame)
        assert frame.border_subtitle == "Scroll for all details"
        await pilot.press("end")
        await pilot.pause()
        assert options.highlighted == 59 and options.scroll_y > 0
        assert_controls_exposed(app, screen)
        if submit == "enter":
            await pilot.press("enter")
        else:
            await pilot.press("home")
            await pilot.pause()
            assert await pilot.click(options, offset=(
                options.content_region.x - options.region.x + 1,
                options.content_region.y - options.region.y,
            ))
        await pilot.pause()
        assert results == ["59" if submit == "enter" else "0"]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("kind", ["editor", "picker"])
async def test_fill_toasts_never_move_cached_cancel_or_cover_child_controls(
    size: tuple[int, int], kind: str,
) -> None:
    app = BasicDialogHost()
    screen = surface(kind)
    results = []
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        cancel = screen.query_one("#utility-cancel", Button)
        initial = frame.region, cancel.region
        point = (cancel.region.x + cancel.region.width // 2, cancel.region.y + 1)
        for phase in (3, 0, 2):
            app.clear_notifications()
            for number in range(phase):
                app.notify(f"Example message {number + 1}.\nSecond row.\nThird row.", title="Example", timeout=60)
            await pilot.pause()
            assert (frame.region, cancel.region) == initial
            assert_controls_exposed(app, screen)
            assert app.get_widget_at(*point)[0] is cancel
            if phase:
                assert not screen.query_one("ToastRack").region.overlaps(frame.region)
        assert await pilot.click(offset=point)
        await pilot.pause()
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
@pytest.mark.parametrize("kind", ["editor", "picker"])
async def test_mousewheel_scrolls_native_child_without_scrolling_frame(
    size: tuple[int, int], kind: str,
) -> None:
    app = BasicDialogHost()
    screen = surface(kind)
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        child = screen.query_one(TextArea if kind == "editor" else OptionList)
        frame = screen.query_one(DialogFrame)
        initial = frame.region
        child.post_message(events.MouseScrollDown(child, 2, 2, 0, 0, 0, False, False, False))
        await pilot.pause()
        assert child.scroll_y > 0
        assert frame.scroll_y == 0 and frame.region == initial
        assert_controls_exposed(app, screen)
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["editor", "picker"])
async def test_fill_resize_keeps_native_focus_and_reserved_lane(kind: str) -> None:
    app = BasicDialogHost()
    screen = surface(kind)
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        child = screen.query_one(TextArea if kind == "editor" else OptionList)
        original = child.region
        await pilot.resize_terminal(160, 50)
        await pilot.pause()
        assert child.region.width > original.width and child.region.height > original.height
        assert screen.focused is child
        assert_controls_exposed(app, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert child.region == original and screen.focused is child
        assert_controls_exposed(app, screen)
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_standard_content_keeps_disclosure_and_only_child_catalog_scrolls(
    size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    screen = CatalogSurface()
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        catalog = screen.query_one("#utility-catalog", VerticalScroll)
        content = screen.query_one(DialogContent)
        frame = screen.query_one(DialogFrame)
        assert screen.focused is catalog
        assert catalog.max_scroll_y > 0 and catalog.size.height <= 9
        assert content.scroll_y == 0 and not content.allow_vertical_scroll
        assert frame.border_subtitle == ""
        assert_controls_exposed(app, screen)
        await pilot.press("pagedown")
        await pilot.pause()
        assert catalog.scroll_y > 0 and content.scroll_y == 0
        assert frame.border_subtitle == ""
        assert_controls_exposed(app, screen)
        painted = " ".join(" ".join(strip.text for strip in screen._compositor.render_strips()).split())
        assert "Review the browser action before choosing an example item." in painted
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_non_scrolling_overflow_never_advertises_a_frame_scroll_action(
    size: tuple[int, int],
) -> None:
    """A clipped fixed region must not promise keyboard scrolling it cannot do."""
    class FixedOverflowSurface(ModalScreen):
        DEFAULT_CLASSES = "dialog-screen"

        def compose(self) -> ComposeResult:
            yield DialogNotificationSpace()
            yield DialogFrame(
                heading=Static("Fixed example region"),
                body=DialogContent(
                    Static("\n".join(f"Example fixed row {i + 1}" for i in range(80))),
                ),
                actions=DialogActions(Button("Close")),
                size="fill",
            )

    app = BasicDialogHost()
    screen = FixedOverflowSurface()
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        await pilot.pause()
        content = screen.query_one(DialogContent)
        assert content.max_scroll_y > 0
        assert not content.allow_vertical_scroll and content not in screen.focus_chain
        assert screen.query_one(DialogFrame).border_subtitle == ""
