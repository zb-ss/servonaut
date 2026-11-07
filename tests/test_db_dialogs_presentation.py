"""DB credential dialogs keep exact results, focus and visible choices in the frame."""

from __future__ import annotations

import pytest
from textual.widgets import Button, Checkbox, Input

from servonaut.screens.db_coverage_view import ConfirmDbRemoveModal
from servonaut.screens.db_credential_scan import _DbLabelPromptModal
from servonaut.widgets.dialogs import DialogBody, DialogFrame
from tests._async_bounds import wait_until
from tests.test_basic_dialogs import BasicDialogHost, assert_exposed
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted


LONG_SITE = "shop.example.com/" + "nested-path-segment/" * 40


async def _open(app: BasicDialogHost, pilot, screen, results: list) -> None:
    app.push_screen(screen, results.append)
    await wait_until(lambda: app.screen is screen)
    await pilot.pause()


def _assert_visible_without_scrolling(app: BasicDialogHost, screen, *selectors: str) -> dict:
    # No scroll_visible first: every choice must already be on screen.
    regions = {}
    for selector in selectors:
        widget = screen.query_one(selector)
        assert widget.region.width and widget.region.height, selector
        # Inside the frame's content box and the screen, and hit at every cell.
        assert_exposed(app, screen, widget)
        painted = _painted(app, widget)
        if isinstance(widget, (Button, Checkbox)):
            assert widget.label.plain in painted, selector
        elif isinstance(widget, Input) and widget.value:
            assert widget.value in painted, selector
        regions[selector] = widget.region
    return regions


def _painted_words(app: BasicDialogHost, region) -> str:
    """The text painted in *region*, with line wraps folded to single spaces."""
    rows = app.screen._compositor.render_strips()
    return " ".join(
        " ".join(rows[y].crop(region.x, region.right).text.split())
        for y in range(region.y, region.bottom)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("has_secret,toggle,expected", [
    (True, False, True), (True, True, False), (False, False, False),
])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_remove_returns_the_checkbox_choice(
    has_secret: bool, toggle: bool, expected: bool, size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=size) as pilot:
        screen = ConfirmDbRemoveModal(site="shop.example.com", has_secret=has_secret)
        await _open(app, pilot, screen, results)
        checkbox = screen.query_one("#db_remove_delete_secret", Checkbox)
        assert checkbox.value is has_secret and checkbox.disabled is (not has_secret)
        _assert_visible_without_scrolling(app, screen, "#db_remove_delete_secret",
                                          "#btn_db_remove_confirm", "#btn_db_remove_cancel")
        if toggle:
            # A native click on the enabled toggle, not a value assignment.
            assert await pilot.click("#db_remove_delete_secret")
            await wait_until(lambda: checkbox.value is (not has_secret))
        await _click(pilot, "#btn_db_remove_confirm")
        await wait_until(lambda: app.screen is not screen)
        assert results == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["escape", "button"])
async def test_remove_cancel_routes_return_none(route: str) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        screen = ConfirmDbRemoveModal(site="shop.example.com", has_secret=True)
        await _open(app, pilot, screen, results)
        if route == "button":
            await _click(pilot, "#btn_db_remove_cancel")
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [None] and app.focused is origin


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_remove_long_site_scrolls_the_body_while_choices_stay_visible(
    size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=size) as pilot:
        screen = ConfirmDbRemoveModal(site=LONG_SITE, has_secret=True)
        await _open(app, pilot, screen, results)
        body = screen.query_one(DialogBody)
        assert body.allow_vertical_scroll and body.max_scroll_y > 0
        assert screen.query_one(DialogFrame).has_class("dialog-danger")
        targets = ("#db_remove_delete_secret", "#btn_db_remove_confirm", "#btn_db_remove_cancel")
        regions = _assert_visible_without_scrolling(app, screen, *targets)
        body.focus()
        await wait_until(lambda: screen.focused is body)
        await pilot.press("end")
        await wait_until(lambda: body.scroll_y == body.max_scroll_y)
        await pilot.pause()
        assert body.scroll_y > 0 and screen.query_one(DialogFrame).max_scroll_y == 0
        # The body's last sentence is painted: the native End reached the bottom.
        assert "can no longer resolve it by name." in _painted_words(
            app, body.scrollable_content_region,
        )
        # Every choice is still exposed, painted and hit at the same cells.
        assert _assert_visible_without_scrolling(app, screen, *targets) == regions


@pytest.mark.asyncio
@pytest.mark.parametrize("value,expected", [
    ("  shop  ", "shop"), ("", ""), ("   ", ""),
])
@pytest.mark.parametrize("route", ["enter", "button"])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_label_prompt_returns_the_stripped_label(
    value: str, expected: str, route: str, size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=size) as pilot:
        screen = _DbLabelPromptModal(initial="derived-label")
        await _open(app, pilot, screen, results)
        field = screen.query_one("#db_label_input", Input)
        assert app.focused is field and field.value == "derived-label"
        _assert_visible_without_scrolling(app, screen, "#db_label_input",
                                          "#btn_db_label_store", "#btn_db_label_cancel")
        field.value = value
        if route == "enter":
            await pilot.press("enter")
        else:
            await _click(pilot, "#btn_db_label_store")
        await wait_until(lambda: app.screen is not screen)
        # An empty label is a valid answer: store the server's only database.
        assert results == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["escape", "button"])
async def test_label_prompt_cancel_routes_return_none(route: str) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        screen = _DbLabelPromptModal(initial="derived-label")
        await _open(app, pilot, screen, results)
        if route == "button":
            await _click(pilot, "#btn_db_label_cancel")
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [None] and app.focused is origin
