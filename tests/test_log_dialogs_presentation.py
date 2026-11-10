"""Log path dialogs keep their typed results, focus and validation in the frame."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from textual.widgets import Button, Input, OptionList

from servonaut.screens.log_picker import (
    ADD_PATH_SENTINEL, EDIT_PATH_SENTINEL, REMOVE_PATH_SENTINEL,
    AddDirectoryModal, AddPathModal, EditPathModal, LogPickerModal, ManagePathsModal,
)
from servonaut.widgets.dialogs import DialogFrame
from tests._async_bounds import wait_until
from tests.test_basic_dialogs import BasicDialogHost
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


INSTANCE = {"id": "id-web-1", "name": "web-1"}
LOGS = ["/var/log/syslog", "/var/log/app.log"]


def _service() -> SimpleNamespace:
    return SimpleNamespace(get_custom_paths=Mock(return_value=["/srv/app/custom.log"]))


def _picker() -> LogPickerModal:
    return LogPickerModal(
        available_logs=list(LOGS), discovered_logs=[], current_log=LOGS[0],
        classify_fn=lambda path: "active", instance=dict(INSTANCE),
        log_viewer_service=_service(),
    )


async def _open(app: BasicDialogHost, pilot, screen, results: list) -> None:
    app.push_screen(screen, results.append)
    await wait_until(lambda: app.screen is screen)
    await pilot.pause()


def _assert_framed(app: BasicDialogHost, screen, *selectors: str) -> None:
    frame = screen.query_one(DialogFrame)
    for selector in selectors:
        widget = screen.query_one(selector)
        assert frame.region.contains_region(widget.region), selector
        assert app.get_widget_at(*widget.region.center)[0] is widget or widget in (
            app.get_widget_at(*widget.region.center)[0].ancestors
        )
        if isinstance(widget, Button):
            assert widget.label.plain in _painted(app, widget)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_log_picker_focus_filter_and_enter_return_the_exact_path(size: tuple[int, int]) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=size) as pilot:
        screen = _picker()
        await _open(app, pilot, screen, results)
        assert app.focused is screen.query_one("#log_picker_search", Input)
        _assert_framed(app, screen, "#log_picker_search", "#log_picker_list", "#log_picker_cancel")
        await pilot.press(*"app")
        count = screen.query_one("#log_picker_count")
        # Wait for the debounced filter, not just any populated list.
        await wait_until(lambda: "match" in count.render().plain)
        await pilot.pause()
        await pilot.press("enter")
        await wait_until(lambda: app.screen is not screen)
        assert results == ["/var/log/app.log"]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["escape", "button"])
async def test_log_picker_cancel_routes_close_the_same_way(route: str) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        screen = _picker()
        await _open(app, pilot, screen, results)
        if route == "button":
            await _click(pilot, "#log_picker_cancel")
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen and results == [None])
        # Cancellation returns None so the caller can resume its paused viewer.
        assert results == [None] and app.focused is origin


@pytest.mark.asyncio
async def test_log_picker_f2_opens_manage_paths_and_forwards_its_result() -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = _picker()
        await _open(app, pilot, screen, results)
        await pilot.press("f2")
        await wait_until(lambda: isinstance(app.screen, ManagePathsModal))
        await _click(pilot, "#manage_add_file")
        await wait_until(lambda: results == [ADD_PATH_SENTINEL])
        assert screen not in app.screen_stack


@pytest.mark.asyncio
@pytest.mark.parametrize("modal,input_id,submit_id,accepted,expected", [
    (AddPathModal, "#add_path_input", "#add_path_submit", "/var/log/app.log", "/var/log/app.log"),
    (AddDirectoryModal, "#add_dir_input", "#add_dir_submit", "/var/log/app", "adddir:/var/log/app"),
])
@pytest.mark.parametrize("route", ["enter", "button"])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_path_inputs_validate_then_return_exact_results(
    modal: type, input_id: str, submit_id: str, accepted: str, expected: str,
    route: str, size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=size) as pilot:
        screen = modal()
        await _open(app, pilot, screen, results)
        field = screen.query_one(input_id, Input)
        assert app.focused is field
        _assert_framed(app, screen, input_id, submit_id)
        for rejected in ("   ", "relative/path.log"):
            field.value = rejected
            if route == "enter":
                field.focus()
                await pilot.press("enter")
            else:
                await _click(pilot, submit_id)
            await pilot.pause()
            assert app.screen is screen and results == []
        field.value = "  " + accepted + "  "
        if route == "enter":
            field.focus()
            await pilot.press("enter")
        else:
            await _click(pilot, submit_id)
        await wait_until(lambda: app.screen is not screen)
        assert results == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize("modal,cancel_id", [
    (AddPathModal, "#add_path_cancel"), (AddDirectoryModal, "#add_dir_cancel"),
])
@pytest.mark.parametrize("route", ["escape", "button"])
async def test_path_input_cancel_keeps_the_original_pop(modal: type, cancel_id: str, route: str) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        screen = modal()
        await _open(app, pilot, screen, results)
        if route == "button":
            await _click(pilot, cancel_id)
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [] and app.focused is origin


@pytest.mark.asyncio
@pytest.mark.parametrize("value,expected", [
    ("/var/log/new.log", f"{EDIT_PATH_SENTINEL}/var/log/old.log\n/var/log/new.log"),
    ("dir:/var/log/app", f"{EDIT_PATH_SENTINEL}/var/log/old.log\ndir:/var/log/app"),
    ("/var/log/old.log", None),
])
@pytest.mark.parametrize("route", ["enter", "button"])
async def test_edit_path_keeps_cursor_validation_and_typed_result(
    value: str, expected: str | None, route: str,
) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=(100, 30)) as pilot:
        screen = EditPathModal(current_path="/var/log/old.log")
        await _open(app, pilot, screen, results)
        field = screen.query_one("#edit_path_input", Input)
        assert app.focused is field and field.cursor_position == len("/var/log/old.log")
        _assert_framed(app, screen, "#edit_path_input", "#edit_path_submit", "#edit_path_cancel")
        field.value = value
        if route == "enter":
            await pilot.press("enter")
        else:
            await _click(pilot, "#edit_path_submit")
        await wait_until(lambda: app.screen is not screen)
        # An unchanged path keeps the original pop, so no result arrives.
        assert results == ([] if expected is None else [expected])


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_manage_paths_actions_are_framed_and_return_exact_sentinels(size: tuple[int, int]) -> None:
    app = BasicDialogHost()
    async with app.run_test(size=size) as pilot:
        for button, expected in (
            ("#manage_add_file", ADD_PATH_SENTINEL),
            ("#manage_remove", f"{REMOVE_PATH_SENTINEL}/srv/app/custom.log"),
        ):
            results: list = []
            screen = ManagePathsModal(custom_paths=["/srv/app/custom.log"], instance=dict(INSTANCE))
            await _open(app, pilot, screen, results)
            _assert_framed(app, screen, "#manage_paths_list", "#manage_browse", "#manage_add_file",
                           "#manage_add_dir", "#manage_edit", "#manage_remove", "#manage_close")
            options = screen.query_one("#manage_paths_list", OptionList)
            options.highlighted = 0
            await pilot.pause()
            await _click(pilot, button)
            await wait_until(lambda: app.screen is not screen)
            assert results == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize("nested,fill,expected", [
    ("#manage_add_dir", "/var/log/app", "adddir:/var/log/app"),
    ("#manage_edit", "/var/log/renamed.log",
     f"{EDIT_PATH_SENTINEL}/srv/app/custom.log\n/var/log/renamed.log"),
])
async def test_manage_paths_forwards_nested_dialog_results_once(nested: str, fill: str, expected: str) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = ManagePathsModal(custom_paths=["/srv/app/custom.log"], instance=dict(INSTANCE))
        await _open(app, pilot, screen, results)
        screen.query_one("#manage_paths_list", OptionList).highlighted = 0
        await pilot.pause()
        await _click(pilot, nested)
        child_type = AddDirectoryModal if nested == "#manage_add_dir" else EditPathModal
        await wait_until(lambda: isinstance(app.screen, child_type))
        child = app.screen
        child.query_one(Input).value = fill
        child.query_one(Input).focus()
        await pilot.press("enter")
        await wait_until(lambda: screen not in app.screen_stack)
        assert results == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["escape", "button"])
async def test_manage_paths_close_returns_none_to_the_caller(route: str) -> None:
    app = BasicDialogHost()
    results: list = []
    async with app.run_test(size=(100, 30)) as pilot:
        screen = ManagePathsModal(custom_paths=[], instance=dict(INSTANCE))
        await _open(app, pilot, screen, results)
        if route == "button":
            await _click(pilot, "#manage_close")
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen and results == [None])
        assert results == [None]
